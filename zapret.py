#!/usr/bin/env python3
"""macOS controller: official tpws TCP engine and experimental Discord UDP relay."""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SOURCE = Path(__file__).resolve().parent
ROOT = Path('/Library/Application Support/ZapretMac')
LABEL = 'local.zapret.macos'
PLIST = Path('/Library/LaunchDaemons/' + LABEL + '.plist')
ANCHOR = 'com.apple/zapret-macos'
HOSTS = Path('/etc/hosts')
HOST_BEGIN = '# BEGIN ZAPRET-MACOS'
HOST_END = '# END ZAPRET-MACOS'
FLOW_URL = 'https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/'
API_URL = 'https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest'
DEFAULTS = dict(strategy='split', game_filter=False, game_tcp='1024-65535',
                ipset='loaded', quic_fallback=False, ipv6=True, auto_update_check=False,
                voice_udp=False, voice_profile='fake', voice_ports='3478,5349,19294-19344,50000-65535')
BASE_PORTS = '80,443,2053,2083,2087,2096,8443'
PRIVATE4 = ['0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']
PRIVATE6 = ['::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
LIST_FILES = ['list-general.txt', 'list-google.txt', 'list-exclude.txt',
              'ipset-all.txt', 'ipset-exclude.txt']
USER_FILES = ['list-general-user.txt', 'list-exclude-user.txt',
              'ipset-user.txt', 'ipset-exclude-user.txt']


class Error(Exception):
    pass


def version(root=ROOT):
    path = root / 'VERSION'
    if not path.exists():
        path = SOURCE / 'VERSION'
    return path.read_text(encoding='utf-8').strip()


def stamp():
    return dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')


def run(args, *, check=True, timeout=30, input=None):
    result = subprocess.run([str(a) for a in args], input=input,
                            capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise Error(f'{args[0]}: {result.stderr.strip() or result.stdout.strip()}')
    return result


def require_mac(root=False):
    if sys.platform != 'darwin':
        raise Error('Эта операция требует macOS. Здесь доступны только tests и plan.')
    if root and os.geteuid() != 0:
        raise Error('Запустите service.command или повторите команду через sudo.')


def atomic_write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise Error(f'Нельзя изменять символическую ссылку: {path}')
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(text if isinstance(text, bytes) else text.encode('utf-8'))
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def strategies(root=ROOT):
    return json.loads((root / 'strategies.json').read_text(encoding='utf-8'))


def ports(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', value):
        raise Error('Порты: например, 1024-1934,1936-65535.')
    for item in value.split(','):
        pair = [int(n) for n in item.split('-')]
        if min(pair) < 1 or max(pair) > 65535 or pair[0] > pair[-1]:
            raise Error('Диапазон портов должен находиться внутри 1…65535.')
    return value


def validate_config(cfg, root=ROOT):
    if set(cfg) != set(DEFAULTS):
        raise Error('Неверные поля config.json.')
    if cfg['strategy'] not in strategies(root):
        raise Error('Неизвестная стратегия.')
    if cfg['ipset'] not in ('none', 'loaded', 'any'):
        raise Error('IPSet должен быть none, loaded или any.')
    ports(cfg['game_tcp'])
    for key in ('game_filter', 'quic_fallback', 'ipv6', 'auto_update_check', 'voice_udp'):
        if not isinstance(cfg[key], bool):
            raise Error(f'{key}: требуется true или false.')
    if cfg['voice_profile'] not in ('relay', 'fake', 'ttl3', 'ttl5', 'ttl7', 'ttl9'):
        raise Error('Неизвестный профиль UDP голоса.')
    ports(cfg['voice_ports'])
    if any(int(item.split('-')[0]) < 1024 and item != '443' for item in cfg['voice_ports'].split(',')):
        raise Error('UDP голосового режима: порты 1024…65535 и при необходимости 443.')
    if cfg['voice_udp'] and cfg['quic_fallback'] and '443' in cfg['voice_ports'].split(','):
        raise Error('Для UDP/443 голоса сначала отключите QUIC → TCP.')
    return cfg


def config(root=ROOT):
    cfg = dict(DEFAULTS)
    if (root / 'config.json').exists():
        cfg.update(json.loads((root / 'config.json').read_text(encoding='utf-8')))
    return validate_config(cfg, root)


def entries(text, kind, allow_empty=False):
    values = []
    for line in text.lstrip('\ufeff').splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if kind == 'ip':
            try:
                line = str(ipaddress.ip_network(line, strict=False))
            except ValueError:
                raise Error(f'Некорректный IP/CIDR: {line}') from None
        else:
            line = line.lower().rstrip('.')
            # zapret uses ^domain for an exact match instead of a suffix match.
            domain = line.removeprefix('^')
            if len(domain) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?', domain):
                raise Error(f'Некорректный домен: {line}')
        if line not in values:
            values.append(line)
    if not values and not allow_empty:
        raise Error('Получен пустой список; прежняя версия сохранена.')
    return values


def load_entries(path, kind, allow_empty=True):
    return entries(Path(path).read_text(encoding='utf-8-sig'), kind, allow_empty)


def prepare_lists(root=ROOT):
    files = root / 'lists'
    output = root / 'runtime'
    output.mkdir(exist_ok=True)
    merged = {}
    groups = dict(general=['list-general.txt', 'list-general-user.txt'],
                  google=['list-google.txt'],
                  excluded_hosts=['list-exclude.txt', 'list-exclude-user.txt'],
                  ips=['ipset-all.txt', 'ipset-user.txt'],
                  excluded_ips=['ipset-exclude.txt', 'ipset-exclude-user.txt'])
    for name, inputs in groups.items():
        kind = 'ip' if name in ('ips', 'excluded_ips') else 'host'
        values = []
        for filename in inputs:
            values.extend(load_entries(files / filename, kind))
        if name == 'excluded_ips':
            values.extend(PRIVATE4 + PRIVATE6)
        merged[name] = list(dict.fromkeys(values))
        # tpws rejects an entirely empty hostlist; a reserved dummy never matches.
        fallback = '192.0.2.1/32' if kind == 'ip' else 'unused.invalid'
        atomic_write(output / (name + '.txt'), '\n'.join(merged[name] or [fallback]) + '\n')
    for version in (4, 6):
        values = [v for v in merged['excluded_ips'] if ipaddress.ip_network(v).version == version]
        atomic_write(output / f'excluded{version}.txt', '\n'.join(values) + '\n')
    return merged


def engine_args(cfg, root=ROOT, socks=False):
    rt = root / 'runtime'
    args = [str(root / 'bin' / 'tpws'), '--port=' + ('987' if socks else '988'),
            '--bind-addr=127.0.0.1', '--user=root']
    if socks:
        args.append('--socks')
    elif cfg['ipv6']:
        args += ['--bind-iface6=lo0', '--bind-linklocal=force', '--bind-wait-ip=10']
    native = strategies(root)[cfg['strategy']]['args']
    exclusions = [f'--hostlist-exclude={rt / "excluded_hosts.txt"}',
                  f'--ipset-exclude={rt / "excluded_ips.txt"}']
    profiles = [(['--filter-tcp=443', f'--hostlist={rt / "google.txt"}'], native),
                (['--filter-tcp=' + ('1024-65535' if cfg['voice_udp'] else '2053,2083,2087,2096,8443'),
                  '--hostlist-domains=discord.media,discord.gg'], native),
                (['--filter-tcp=80,443', f'--hostlist={rt / "general.txt"}'], native)]
    if cfg['ipset'] != 'none':
        scope = [f'--ipset={rt / "ips.txt"}'] if cfg['ipset'] == 'loaded' else []
        profiles.append((['--filter-tcp=80,443,8443'] + scope, native))
        if cfg['game_filter']:
            # HTTP/TLS-only options do not apply to arbitrary game payloads.
            game = [] if cfg['strategy'] == 'passthrough' else ['--split-pos=1', '--split-any-protocol']
            if '--disorder' in native:
                game.append('--disorder')
            profiles.append((['--filter-tcp=' + cfg['game_tcp']] + scope, game))
    for filters, modifications in profiles:
        args += filters + exclusions + modifications + ['--tamper-cutoff=n3', '--new']
    # Explicit catch-all profile forwards unmatched connections unchanged.
    return args


def pf_rules(cfg, root=ROOT, linklocal='fe80::1'):
    if not re.fullmatch(r'fe80:[0-9a-f:]+', linklocal):
        raise Error('Не найден корректный IPv6 link-local адрес lo0.')
    port_spec = BASE_PORTS
    if cfg['voice_udp']:
        # Discord announces its voice WebSocket port dynamically.
        port_spec += ',1024-65535'
    if cfg['game_filter'] and cfg['ipset'] != 'none':
        port_spec += ',' + ports(cfg['game_tcp'])
    port_spec = port_spec.replace('-', ':')
    rt = root / 'runtime'
    rows = [f'table <zmac_ex4> persist file "{rt / "excluded4.txt"}"']
    if cfg['ipv6']:
        rows.append(f'table <zmac_ex6> persist file "{rt / "excluded6.txt"}"')
    rows.append(f'rdr pass on lo0 inet proto tcp from !127.0.0.0/8 to any port {{{port_spec}}} -> 127.0.0.1 port 988')
    if cfg['ipv6']:
        rows.append(f'rdr pass on lo0 inet6 proto tcp from !::1 to any port {{{port_spec}}} -> {linklocal} port 988')
    if cfg['quic_fallback']:
        rows.append('block return out quick inet proto udp from any to !<zmac_ex4> port 443 user { >root }')
        if cfg['ipv6']:
            rows.append('block return out quick inet6 proto udp from any to !<zmac_ex6> port 443 user { >root }')
    rows.append(f'pass out route-to (lo0 127.0.0.1) inet proto tcp from !127.0.0.0/8 to !<zmac_ex4> port {{{port_spec}}} user {{ >root }} label "zapret-macos"')
    if cfg['ipv6']:
        rows.append(f'pass out route-to (lo0 {linklocal}) inet6 proto tcp from !::1 to !<zmac_ex6> port {{{port_spec}}} user {{ >root }} label "zapret-macos"')
    return '\n'.join(rows) + '\n'


def pf(*args, **kwargs):
    return run(['/sbin/pfctl', *args], **kwargs)


def clear_anchor():
    # Replaces only our rules. Never flush global rules, states, or Apple's anchors.
    pf('-a', ANCHOR, '-f', '-', input='', check=False)


def release_pf(root=ROOT):
    clear_anchor()
    from voice_controller import clear_udp
    clear_udp()
    path = root / 'runtime' / 'pf-token.json'
    if path.exists():
        token = json.loads(path.read_text())['token']
        if re.fullmatch(r'\d+', str(token)):
            pf('-X', str(token), check=False)
        path.unlink(missing_ok=True)


def ensure_pf_hooks():
    active_filter = pf('-sr').stdout
    active_rdr = pf('-sn').stdout
    hook = '"com.apple/*"'
    if hook in active_filter and hook in active_rdr:
        return
    if active_filter.strip() or active_rdr.strip():
        raise Error('Активный PF не содержит стандартных com.apple/* hooks. '
                    'Проверьте вашу конфигурацию PF; её правила не заменены.')
    main = Path('/etc/pf.conf').read_text()
    if not re.search(r'^\s*rdr-anchor\s+"com\.apple/\*"', main, re.M) or not re.search(r'^\s*anchor\s+"com\.apple/\*"', main, re.M):
        raise Error('/etc/pf.conf не содержит стандартных com.apple/* hooks.')
    if re.search(r'^\s*set\s+skip\s+on\s+.*\blo0\b', main, re.M):
        raise Error('set skip on lo0 в pf.conf несовместим с прозрачным обходом.')
    pf('-n', '-f', '/etc/pf.conf')
    pf('-f', '/etc/pf.conf')


def apply_pf(cfg, root=ROOT):
    ll = 'fe80::1'
    if cfg['ipv6']:
        found = re.search(r'inet6\s+(fe80:[0-9a-f:]+)', run(['/sbin/ifconfig', 'lo0']).stdout)
        if not found:
            raise Error('На lo0 нет IPv6 link-local. Отключите IPv6 в настройках пакета.')
        ll = found.group(1)
    path = root / 'runtime' / 'anchor.conf'
    atomic_write(path, pf_rules(cfg, root, ll))
    pf('-n', '-a', ANCHOR, '-f', path)
    ensure_pf_hooks()
    enabled = pf('-E')
    token = re.search(r'Token\s*:\s*(\d+)', enabled.stdout + enabled.stderr)
    if not token:
        raise Error('pfctl не вернул токен PF; правила обхода не загружены.')
    write_json(root / 'runtime' / 'pf-token.json', dict(token=token.group(1)))
    pf('-a', ANCHOR, '-f', path)


def get_state(root=ROOT):
    path = root / 'runtime' / 'state.json'
    return json.loads(path.read_text()) if path.exists() else {}


def is_running(root=ROOT):
    state = get_state(root)
    pid = state.get('pid')
    if not isinstance(pid, int) or pid < 2:
        return False
    result = run(['/bin/ps', '-p', str(pid), '-o', 'command='], check=False)
    return result.returncode == 0 and str(root / 'zapret.py') in result.stdout and 'supervise' in result.stdout


def wait_ready(child, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if child.poll() is not None:
            raise Error('tpws завершился до запуска. Посмотрите logs/service.log.')
        try:
            with socket.create_connection(('127.0.0.1', 988), timeout=0.15):
                return
        except OSError:
            time.sleep(0.15)
    raise Error('tpws не открыл порт 988 за 15 секунд.')


def supervise(root=ROOT):
    require_mac(True)
    import fcntl
    root.joinpath('runtime').mkdir(exist_ok=True)
    service_lock = (root / 'runtime' / 'service.lock').open('a')
    try:
        fcntl.flock(service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        service_lock.close()
        raise Error('Другой supervisor уже запущен.') from None
    if is_running(root):
        raise Error('Другой экземпляр ZapretMac уже работает.')
    stop_requested = False
    child = None
    from voice_controller import Backend
    udp_backend = Backend(root)

    def stop_signal(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    state_path = root / 'runtime' / 'state.json'
    # Recover our stale anchor/token after an interrupted previous run.
    release_pf(root)
    try:
        while not stop_requested:
            cfg = config(root)
            prepare_lists(root)
            args = engine_args(cfg, root)
            run(args + ['--dry-run'])
            write_json(state_path, dict(pid=os.getpid(), phase='starting', strategy=cfg['strategy']))
            child = subprocess.Popen(args)
            wait_ready(child)
            if stop_requested:
                break
            apply_pf(cfg, root)
            udp_backend.start(cfg, cancelled=lambda: stop_requested)
            write_json(state_path, dict(pid=os.getpid(), engine_pid=child.pid,
                                       phase='running', strategy=cfg['strategy'], voice_udp=udp_backend.active))
            print(f'Обход включён: {cfg["strategy"]}', flush=True)
            while not stop_requested and child.poll() is None:
                udp_backend.check()
                time.sleep(0.25)
            udp_backend.stop()
            release_pf(root)
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            if not stop_requested:
                print('tpws завершился. Правила сняты; повтор через 3 секунды.', flush=True)
                write_json(state_path, dict(pid=os.getpid(), phase='recovering', strategy=cfg['strategy']))
                for _ in range(12):
                    if stop_requested:
                        break
                    time.sleep(0.25)
    finally:
        udp_backend.stop()
        release_pf(root)
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        state_path.unlink(missing_ok=True)
        service_lock.close()


def launch_loaded():
    return run(['/bin/launchctl', 'print', 'system/' + LABEL], check=False).returncode == 0


def stop(root=ROOT):
    require_mac(True)
    if launch_loaded():
        run(['/bin/launchctl', 'bootout', 'system/' + LABEL])
    if is_running(root):
        os.kill(get_state(root)['pid'], signal.SIGTERM)
        for _ in range(100):
            if not is_running(root):
                break
            time.sleep(0.1)
        if is_running(root):
            raise Error('Supervisor не завершился. Проверьте logs/service.log.')
    release_pf(root)
    root.joinpath('runtime', 'state.json').unlink(missing_ok=True)


def start(root=ROOT):
    require_mac(True)
    if is_running(root):
        print('Обход уже запущен.')
        return
    if launch_loaded():
        run(['/bin/launchctl', 'bootout', 'system/' + LABEL])
    if PLIST.exists():
        run(['/bin/launchctl', 'enable', 'system/' + LABEL])
        run(['/bin/launchctl', 'bootstrap', 'system', PLIST])
        process = None
    else:
        root.joinpath('logs').mkdir(exist_ok=True)
        with (root / 'logs' / 'service.log').open('ab') as log:
            process = subprocess.Popen([sys.executable, '-u', str(root / 'zapret.py'), 'supervise'],
                                       stdout=log, stderr=log, start_new_session=True)
    for _ in range(500):
        state = get_state(root)
        if state.get('phase') == 'running' and is_running(root):
            print('Обход включён. Перезапустите уже открытые приложения/соединения.')
            return
        if process and process.poll() is not None:
            break
        time.sleep(0.1)
    # Prevent launchd's retry policy from looping after an initial configuration failure.
    stop(root)
    raise Error(f'Обход не запущен. Подробности: {root / "logs/service.log"}')


def restart(root=ROOT):
    stop(root)
    start(root)


def autostart(enabled, root=ROOT):
    require_mac(True)
    stop(root)
    if enabled:
        data = dict(Label=LABEL,
                    ProgramArguments=[sys.executable, '-u', str(root / 'zapret.py'), 'supervise'],
                    RunAtLoad=True, KeepAlive=True, ThrottleInterval=10, ExitTimeOut=20,
                    StandardOutPath=str(root / 'logs' / 'service.log'),
                    StandardErrorPath=str(root / 'logs' / 'service.log'))
        atomic_write(PLIST, plistlib.dumps(data))
        start(root)
    else:
        PLIST.unlink(missing_ok=True)
    print('Автозапуск ' + ('включён.' if enabled else 'удалён; обход остановлен.'))


def download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'ZapretMac/' + version()})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise Error('Ответ сервера превышает допустимый размер.')
    return raw.decode('utf-8-sig')


def update_lists(root=ROOT):
    require_mac(True)
    pending = {}
    for name in LIST_FILES:
        remote = '.service/ipset-service.txt' if name == 'ipset-all.txt' else 'lists/' + name
        value = entries(download(FLOW_URL + remote), 'ip' if name.startswith('ipset') else 'host')
        pending[name] = '\n'.join(value) + '\n'
    backup = root / 'backups' / ('lists-' + stamp())
    backup.mkdir(parents=True)
    for name in pending:
        shutil.copy2(root / 'lists' / name, backup / name)
    written = []
    try:
        for name, text in pending.items():
            atomic_write(root / 'lists' / name, text)
            written.append(name)
    except Exception:
        for name in written:
            shutil.copy2(backup / name, root / 'lists' / name)
        raise
    print('Списки обновлены. Пользовательские файлы сохранены. Резервная копия:', backup)
    if is_running(root):
        restart(root)


def check_updates(root=ROOT):
    remote = json.loads(download(API_URL))
    print('Последний релиз Flowseal:', remote['tag_name'])
    print('Списки в комплекте: Flowseal 1.10.3; macOS-стратегии: собственные tpws-профили.')
    print(remote['html_url'])
    print('Обновление Windows-релиза не устанавливается как macOS-программа.')


def hosts_entries(text):
    rows = []
    for line in text.splitlines():
        parts = line.split('#', 1)[0].split()
        if not parts:
            continue
        if len(parts) < 2:
            raise Error('Некорректная строка hosts.')
        try:
            address = ipaddress.ip_address(parts[0])
        except ValueError:
            raise Error('Некорректный IP в hosts.') from None
        if not address.is_global:
            raise Error('Загруженный hosts содержит не публичный адрес.')
        domains = entries('\n'.join(parts[1:]), 'host')
        if any(d == 'localhost' or d.endswith('.local') for d in domains):
            raise Error('Внешний hosts не может заменять локальные имена.')
        rows.append(str(address) + ' ' + ' '.join(domains))
    if not rows:
        raise Error('Пустой hosts не применяется.')
    return rows


def strip_hosts_block(text):
    if HOST_BEGIN not in text and HOST_END not in text:
        return text
    if text.count(HOST_BEGIN) != 1 or text.count(HOST_END) != 1 or text.index(HOST_BEGIN) > text.index(HOST_END):
        raise Error('Повреждён блок ZapretMac в /etc/hosts; исправьте маркеры вручную.')
    return re.sub(r'^' + re.escape(HOST_BEGIN) + r'\n.*?^' + re.escape(HOST_END) + r'\n?', '', text, flags=re.M | re.S)


def manage_hosts(apply, root=ROOT):
    require_mac(True)
    original = HOSTS.read_text()
    clean = strip_hosts_block(original)
    if apply:
        rows = hosts_entries(download(FLOW_URL + '.service/hosts'))
        added = {domain for line in rows for domain in line.split()[1:]}
        present = {domain.lower() for line in clean.splitlines() for domain in line.split('#', 1)[0].split()[1:]}
        conflicts = sorted(added & present)
        if conflicts:
            raise Error('В hosts уже есть ваши записи для: ' + ', '.join(conflicts[:8]) + '. Устраните конфликт перед обновлением.')
        result = clean.rstrip('\n') + '\n\n' + HOST_BEGIN + '\n' + '\n'.join(rows) + '\n' + HOST_END + '\n'
    else:
        result = clean
    if result == original:
        print('Блок ZapretMac отсутствует.')
        return
    backup = root / 'backups' / ('hosts-' + stamp())
    atomic_write(backup, original)
    atomic_write(HOSTS, result, HOSTS.stat().st_mode & 0o777)
    run(['/usr/bin/dscacheutil', '-flushcache'], check=False)
    run(['/usr/bin/killall', '-HUP', 'mDNSResponder'], check=False)
    print('hosts обновлён. Исходный файл:', backup)


def original_user():
    import pwd
    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    if uid == 0:
        raise Error('Запустите service.command из вашей обычной учётной записи.')
    return pwd.getpwuid(uid)


def clean_discord_cache(root=ROOT):
    require_mac(True)
    user = original_user()
    running = run(['/usr/bin/pgrep', '-u', str(user.pw_uid), '-if', '/Discord[^/]*/.*MacOS|/Discord[^/]*/.*Helper'], check=False)
    if running.returncode == 0:
        raise Error('Полностью закройте Discord перед очисткой кеша.')
    base = Path(user.pw_dir) / 'Library' / 'Application Support'
    moved = 0
    for name in ('discord', 'discordcanary', 'discordptb'):
        app = base / name
        for folder in ('Cache', 'Code Cache', 'GPUCache'):
            path = app / folder
            if path.is_dir() and not path.is_symlink():
                path.rename(app / (folder + '.zapret-backup-' + stamp()))
                moved += 1
    print(f'Перемещено папок кеша: {moved}. Копии сохранены рядом с исходными папками.')


def curl_test(target):
    name, url = target
    args = ['/usr/bin/curl', '--http1.1', '--noproxy', '*', '--connect-timeout', '5',
            '--max-time', '12', '--silent', '--show-error', '--output', '/dev/null',
            '--write-out', '%{http_code} %{time_total}', '--range', '0-0', url]
    # Transparent PF intentionally exempts root, so tests must use the invoking user.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        args = ['/usr/bin/sudo', '-u', '#' + str(original_user().pw_uid), '--'] + args
    result = run(args, check=False, timeout=16)
    parts = result.stdout.strip().split()
    code = parts[0] if parts else '000'
    elapsed = parts[1] if len(parts) > 1 else '?'
    return dict(name=name, url=url, tls_reached=result.returncode == 0 and code != '000',
                http=code, seconds=elapsed, error=result.stderr.strip())


def targets(root=ROOT):
    rows = []
    for line in (root / 'targets.txt').read_text().splitlines():
        found = re.fullmatch(r'\s*(\w+)\s*=\s*"(https://[^"\s]+)"\s*', line)
        if found:
            rows.append(found.groups())
    return rows


def network_tests(root=ROOT, quiet=False):
    require_mac()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(curl_test, targets(root)))
    if not quiet:
        for row in rows:
            print(f'{row["name"]:24} HTTP {row["http"]:3}  {row["seconds"]} s  '
                  + ('TLS получен' if row['tls_reached'] else row['error']))
        print('Это TCP/TLS-проверка. Голос Discord, QUIC и воспроизведение видео не проверяются.')
    return rows


def test_strategies(root=ROOT):
    require_mac(True)
    previous = config(root)
    was_running = is_running(root)
    rows = []
    report = root / 'logs' / ('tests-' + stamp() + '.csv')
    try:
        stop(root)
        names = ['passthrough'] + [n for n in strategies(root) if n != 'passthrough']
        for name in names:
            print('Проверка:', name, flush=True)
            cfg = dict(previous, strategy=name)
            write_json(root / 'config.json', cfg)
            start(root)
            for row in network_tests(root, quiet=True):
                rows.append(dict(strategy=name, **row))
            stop(root)
            count = sum(r['tls_reached'] for r in rows if r['strategy'] == name)
            print(f'Ответы TLS: {count}/{len(targets(root))}', flush=True)
    finally:
        try:
            stop(root)
        finally:
            write_json(root / 'config.json', previous)
            if rows:
                with report.open('w', newline='', encoding='utf-8') as output:
                    writer = csv.DictWriter(output, fieldnames=['strategy', 'name', 'url', 'tls_reached', 'http', 'seconds', 'error'])
                    writer.writeheader()
                    writer.writerows(rows)
        if was_running:
            start(root)
    print('Отчёт:', report)
    print('Прежняя стратегия восстановлена. Выберите профиль по результатам и проверьте приложения.')


def diagnostics(root=ROOT):
    require_mac()
    cfg = config(root)
    print('macOS:', run(['/usr/bin/sw_vers', '-productVersion']).stdout.strip())
    print('Архитектура:', run(['/usr/bin/uname', '-m']).stdout.strip())
    print('Движок:', run([root / 'bin' / 'tpws', '--version'], check=False).stdout.strip())
    print('Конфигурация:', json.dumps(cfg, ensure_ascii=False))
    print('Supervisor:', get_state(root))
    if os.geteuid() == 0:
        print('PF:', pf('-s', 'info', check=False).stdout[:600])
        print('Наши правила:', pf('-a', ANCHOR, '-sr', check=False).stdout)
        print('Перенаправления:', pf('-a', ANCHOR, '-sn', check=False).stdout)
        from voice_controller import UDP_ANCHOR, show_status
        show_status(root)
        print('UDP-правила:', pf('-a', UDP_ANCHOR, '-sr', check=False).stdout)
        print('UDP-перенаправления:', pf('-a', UDP_ANCHOR, '-sn', check=False).stdout)
    print('Системные прокси:', run(['/usr/sbin/scutil', '--proxy']).stdout.strip())
    print('Маршрут:', run(['/sbin/route', '-n', 'get', 'default'], check=False).stdout.strip())
    try:
        print('DNS discord.com:', sorted({item[4][0] for item in socket.getaddrinfo('discord.com', 443)}))
    except OSError as error:
        print('Ошибка DNS:', error)
    print('IPv6 lo0:', run(['/sbin/ifconfig', 'lo0'], check=False).stdout.strip())
    print('Порты:', run(['/usr/sbin/lsof', '-nP', '-iTCP:988', '-sTCP:LISTEN'], check=False).stdout.strip())
    for name in ('service.log', 'udp.log'):
        log = root / 'logs' / name
        if log.exists():
            with log.open('rb') as source:
                source.seek(max(0, log.stat().st_size - 4000))
                print(name + ':\n' + source.read().decode('utf-8', errors='replace'))
    print('VPN и Internet Sharing могут мешать PF. Запросы root не перехватываются.')


def status(root=ROOT):
    cfg = config(root)
    active = is_running(root)
    print('Версия:', version(root))
    print('Обход:', 'РАБОТАЕТ' if active and get_state(root).get('phase') == 'running' else 'ОСТАНОВЛЕН / ЗАПУСКАЕТСЯ')
    print('Активная стратегия:', get_state(root).get('strategy', '—'))
    print('Выбранная стратегия:', cfg['strategy'])
    print('Автозапуск:', PLIST.exists())
    print('UDP Discord:', 'экспериментальный режим включён' if cfg['voice_udp'] else 'отключён')


def install(binary, source=SOURCE, root=ROOT):
    require_mac(True)
    if root.exists():
        stop(root)
    for folder in ('bin', 'lists', 'runtime', 'logs', 'backups', 'licenses', 'payloads'):
        path = root / folder
        if path.is_symlink():
            raise Error('Каталог установки содержит символическую ссылку.')
        path.mkdir(parents=True, exist_ok=True)
    for name in ('zapret.py', 'discord_udp.py', 'voice_controller.py', 'strategies.json', 'VERSION', 'targets.txt'):
        shutil.copyfile(source / name, root / name)
        os.chmod(root / name, 0o644)
    shutil.copyfile(binary, root / 'bin' / 'tpws')
    os.chmod(root / 'bin' / 'tpws', 0o755)
    shutil.copy2(source / 'payloads' / 'discord-fake.bin', root / 'payloads' / 'discord-fake.bin')
    write_json(root / 'installation.json', dict(user_uid=original_user().pw_uid))
    for path in (source / 'lists').iterdir():
        if path.is_file() and not (root / 'lists' / path.name).exists():
            shutil.copyfile(path, root / 'lists' / path.name)
    for path in (source / 'licenses').iterdir():
        if path.is_file():
            shutil.copyfile(path, root / 'licenses' / path.name)
    if not (root / 'config.json').exists():
        write_json(root / 'config.json', DEFAULTS)
    prepare_lists(root)
    run(engine_args(config(root), root) + ['--dry-run'])
    print('Установка завершена. Настройки предыдущей установки сохранены.')


def uninstall(root=ROOT):
    require_mac(True)
    stop(root)
    PLIST.unlink(missing_ok=True)
    manage_hosts(False, root)
    for path in (root / 'bin' / 'tpws', root / 'zapret.py', root / 'discord_udp.py', root / 'voice_controller.py', root / 'strategies.json', root / 'targets.txt', root / 'VERSION'):
        path.unlink(missing_ok=True)
    print('Движок и автозапуск удалены. Настройки, списки и резервные копии сохранены в:', root)


def choose_strategy(root=ROOT):
    names = list(strategies(root))
    for number, name in enumerate(names, 1):
        print(f'{number}. {name}: {strategies(root)[name]["title"]}')
    choice = input('Номер (Enter — отмена): ').strip()
    if choice:
        index = int(choice) - 1
        if index < 0 or index >= len(names):
            raise Error('Неизвестный номер.')
        cfg = config(root)
        cfg['strategy'] = names[index]
        write_json(root / 'config.json', cfg)
        if is_running(root):
            restart(root)


def menu(root=ROOT):
    require_mac(True)
    if config(root)['auto_update_check']:
        try:
            check_updates(root)
        except Exception as error:
            print('Проверка обновлений:', error)
    while True:
        cfg = config(root)
        print('\nZapretMac ' + version(root) + ' — TCP и экспериментальный Discord UDP')
        status(root)
        print(f'\n1. Включить / перезапустить\n2. Остановить\n3. Выбрать стратегию\n'
              f'4. Включить автозапуск\n5. Удалить автозапуск и остановить\n'
              f'6. Статус\n7. Game Filter TCP [{cfg["game_filter"]}] / порты\n'
              f'8. IPSet [{cfg["ipset"]}]\n9. QUIC → TCP [{cfg["quic_fallback"]}]\n'
              f'10. Обновить списки\n11. Применить hosts Flowseal\n12. Удалить наш блок hosts\n'
              f'13. Проверить обновления Flowseal\n14. Проверка обновлений при открытии [{cfg["auto_update_check"]}]\n'
              f'15. Диагностика\n16. Проверка сайтов\n17. Проверка всех TCP-стратегий\n'
              f'18. Сохранить и очистить кеш Discord\n19. IPv6 [{cfg["ipv6"]}]\n'
              f'20. Открыть папку пользовательских списков\n21. Режим голоса Discord\n0. Выход')
        try:
            choice = input('Выберите пункт: ').strip()
            if choice == '0':
                return
            if choice == '1': restart(root)
            elif choice == '2': stop(root)
            elif choice == '3': choose_strategy(root)
            elif choice == '4': autostart(True, root)
            elif choice == '5': autostart(False, root)
            elif choice == '6': status(root)
            elif choice == '7':
                print('Игровой фильтр поддерживает TCP. Для голоса Discord используйте пункт 21.')
                value = input('Порты TCP или off (Enter — без изменений): ').strip()
                if value:
                    cfg['game_filter'] = value != 'off'
                    if value != 'off': cfg['game_tcp'] = ports(value)
                    write_json(root / 'config.json', cfg)
                    if is_running(root): restart(root)
            elif choice == '8':
                value = input('IPSet: none / loaded / any: ').strip()
                cfg['ipset'] = value
                validate_config(cfg, root)
                write_json(root / 'config.json', cfg)
                if is_running(root): restart(root)
            elif choice in ('9', '14', '19'):
                key = {'9': 'quic_fallback', '14': 'auto_update_check', '19': 'ipv6'}[choice]
                if choice == '9':
                    print('Опция блокирует UDP/443 для всех обычных приложений; поддерживающие fallback переходят на TCP.')
                cfg[key] = not cfg[key]
                validate_config(cfg, root)
                write_json(root / 'config.json', cfg)
                if key != 'auto_update_check' and is_running(root): restart(root)
            elif choice == '10': update_lists(root)
            elif choice == '11': manage_hosts(True, root)
            elif choice == '12': manage_hosts(False, root)
            elif choice == '13': check_updates(root)
            elif choice == '15': diagnostics(root)
            elif choice == '16': network_tests(root)
            elif choice == '17': test_strategies(root)
            elif choice == '18': clean_discord_cache(root)
            elif choice == '20':
                user = original_user()
                run(['/usr/bin/sudo', '-u', '#' + str(user.pw_uid), '/usr/bin/open', root / 'lists'])
            elif choice == '21':
                from voice_controller import voice_menu
                voice_menu(root)
            else: print('Неизвестный пункт.')
        except (Error, OSError, ValueError, subprocess.TimeoutExpired, urllib.error.URLError) as error:
            print('Ошибка:', error)
        input('Enter — вернуться в меню…')


def main():
    parser = argparse.ArgumentParser(description='ZapretMac: TCP bypass and experimental Discord UDP')
    parser.add_argument('command', choices=['install', 'uninstall', 'menu', 'supervise', 'start', 'stop',
                        'restart', 'status', 'autostart-on', 'autostart-off', 'update-lists',
                        'check-updates', 'hosts-apply', 'hosts-remove', 'diagnostics',
                        'test-sites', 'test-strategies', 'cache-discord', 'plan',
                        'voice-menu', 'voice-status', 'voice-observe'])
    parser.add_argument('--engine', type=Path)
    args = parser.parse_args()
    if args.command == 'plan':
        cfg = config(SOURCE)
        with tempfile.TemporaryDirectory(prefix='zapret-plan-') as temp:
            preview = Path(temp)
            shutil.copytree(SOURCE / 'lists', preview / 'lists')
            shutil.copy2(SOURCE / 'strategies.json', preview / 'strategies.json')
            prepare_lists(preview)
            print(pf_rules(cfg, preview))
            print(json.dumps(engine_args(cfg, preview), indent=2, ensure_ascii=False))
        return
    require_mac(args.command not in ('test-sites', 'status', 'check-updates', 'diagnostics'))
    commands = {'uninstall': uninstall, 'menu': menu, 'supervise': supervise, 'start': start,
                'stop': stop, 'restart': restart, 'status': status, 'update-lists': update_lists,
                'check-updates': check_updates, 'diagnostics': diagnostics, 'test-sites': network_tests,
                'test-strategies': test_strategies, 'cache-discord': clean_discord_cache,
                'hosts-apply': lambda: manage_hosts(True), 'hosts-remove': lambda: manage_hosts(False),
                'autostart-on': lambda: autostart(True), 'autostart-off': lambda: autostart(False)}
    from voice_controller import voice_menu, show_status, observe
    commands.update({'voice-menu': voice_menu, 'voice-status': show_status, 'voice-observe': observe})
    if args.command == 'install':
        if not args.engine or not args.engine.is_file():
            raise Error('Укажите существующий tpws через --engine.')
        install(args.engine)
    else:
        commands[args.command]()


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError, ValueError, subprocess.TimeoutExpired, urllib.error.URLError) as error:
        print('Ошибка:', error, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nОперация прервана.', file=sys.stderr)
        sys.exit(130)
