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
import stat
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
                voice_udp=False, voice_profile='fake', voice_ports='3478,5349,19294-19344,50000-65535',
                autostart=True)
BASE_PORTS = '80,443,2053,2083,2087,2096,8443'
PRIVATE4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']
PRIVATE6 = ['::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
LIST_FILES = ['list-general.txt', 'list-google.txt', 'list-exclude.txt',
              'ipset-all.txt', 'ipset-exclude.txt']
USER_FILES = ['list-general-user.txt', 'list-exclude-user.txt',
              'ipset-user.txt', 'ipset-exclude-user.txt']


class Error(Exception):
    pass


@contextlib.contextmanager
def control_lock(root=ROOT):
    """Serialize configuration operations, separate from the supervisor lock."""
    if sys.platform != 'darwin':
        yield
        return
    import fcntl
    directory = root / 'runtime'
    if root.is_symlink() or directory.is_symlink():
        raise Error('Каталог блокировки содержит символическую ссылку.')
    if not directory.exists():
        yield  # Fresh installation has no configuration to serialize yet.
        return
    info = directory.stat()
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_mode & 0o022):
        raise Error('Каталог блокировки должен принадлежать root и запрещать чужую запись.')
    fd = os.open(directory / 'control.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (os.geteuid() == 0 and info.st_uid != 0):
            raise Error('Некорректный файл блокировки.')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error('Другая операция уже меняет настройки. Дождитесь её завершения.') from None
        yield


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
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', value):
        raise Error('Порты: например, 1024-1934,1936-65535.')
    for item in value.split(','):
        pair = [int(n) for n in item.split('-')]
        if min(pair) < 1 or max(pair) > 65535 or pair[0] > pair[-1]:
            raise Error('Диапазон портов должен находиться внутри 1…65535.')
    return value


def validate_config(cfg, root=ROOT):
    if not isinstance(cfg, dict) or set(cfg) != set(DEFAULTS):
        raise Error('Неверные поля config.json.')
    if not isinstance(cfg['strategy'], str) or cfg['strategy'] not in strategies(root):
        raise Error('Неизвестная стратегия.')
    if cfg['ipset'] not in ('none', 'loaded', 'any'):
        raise Error('IPSet должен быть none, loaded или any.')
    ports(cfg['game_tcp'])
    for key in ('game_filter', 'quic_fallback', 'ipv6', 'auto_update_check', 'voice_udp', 'autostart'):
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
        saved = json.loads((root / 'config.json').read_text(encoding='utf-8'))
        if not isinstance(saved, dict):
            raise Error('config.json должен содержать JSON-объект с настройками.')
        cfg.update(saved)
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
    pf('-a', ANCHOR, '-f', '-', input='')


def cleanup_steps(*steps):
    """Finish every independent cleanup step, then report the first failure."""
    failures = []
    for action in steps:
        try:
            action()
        except BaseException as error:
            failures.append(error)
    if failures:
        for error in failures[1:]:
            print('Дополнительная ошибка очистки:', error, file=sys.stderr)
        raise failures[0]


def release_pf(root=ROOT):
    from voice_controller import clear_udp

    def release_token():
        path = root / 'runtime' / 'pf-token.json'
        if path.exists():
            try:
                token = json.loads(path.read_text(encoding='utf-8'))['token']
            except (ValueError, KeyError, TypeError):
                raise Error('Повреждён runtime/pf-token.json; токен PF сохранён для диагностики.') from None
            if not re.fullmatch(r'\d+', str(token)):
                raise Error('Некорректный токен PF в runtime/pf-token.json.')
            # Keep the token for a retry if pfctl could not release our reference.
            pf('-X', str(token))
            path.unlink(missing_ok=True)

    cleanup_steps(clear_anchor, clear_udp, release_token)


def ensure_pf_hooks():
    def check_loopback():
        # set skip is an interface flag, not a filter/NAT rule. Reading only
        # -sr/-sn misses active configurations which bypass our lo0 rdr rules.
        interfaces = pf('-v', '-s', 'Interfaces').stdout
        if re.search(r'^\s*lo0\s+\(skip\)(?:\s|$)', interfaces, re.M):
            raise Error('Активный PF пропускает lo0 (set skip on lo0); прозрачный обход невозможен.')

    active_filter = pf('-sr').stdout
    active_rdr = pf('-sn').stdout
    filter_hook = re.search(r'^[ \t]*anchor[ \t]+"com\.apple/\*"[ \t]+all[ \t]*$', active_filter, re.M)
    rdr_hook = re.search(r'^[ \t]*rdr-anchor[ \t]+"com\.apple/\*"[ \t]+all[ \t]*$', active_rdr, re.M)
    if filter_hook and rdr_hook:
        check_loopback()
        return
    if active_filter.strip() or active_rdr.strip():
        raise Error('Активный PF не содержит стандартных com.apple/* hooks. '
                    'Проверьте вашу конфигурацию PF; её правила не заменены.')
    main = Path('/etc/pf.conf').read_text()
    source_rules = {' '.join(line.split('#', 1)[0].split()) for line in main.splitlines()}
    if any(not source_rules.intersection({f'{kind} "com.apple/*"', f'{kind} "com.apple/*" all'})
           for kind in ('anchor', 'rdr-anchor')):
        raise Error('/etc/pf.conf не содержит стандартных com.apple/* hooks без ограничений.')
    if re.search(r'^\s*set\s+skip\s+on\s+.*\blo0\b', main, re.M):
        raise Error('set skip on lo0 в pf.conf несовместим с прозрачным обходом.')
    pf('-n', '-f', '/etc/pf.conf')
    pf('-f', '/etc/pf.conf')
    # Macros and multiline interface lists can hide skip flags in source text.
    check_loopback()


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
    try:
        write_json(root / 'runtime' / 'pf-token.json', dict(token=token.group(1)))
    except BaseException:
        # No persisted token means a future stop cannot release this PF reference.
        pf('-X', token.group(1))
        raise
    pf('-a', ANCHOR, '-f', path)


def get_state(root=ROOT):
    path = root / 'runtime' / 'state.json'
    try:
        state = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}
    if not isinstance(state, dict):
        raise Error('Некорректный runtime/state.json: ожидается JSON-объект.')
    return state


def is_running(root=ROOT):
    state = get_state(root)
    pid = state.get('pid')
    if type(pid) is not int or pid < 2:
        return False
    return matches_stale_child(pid, 'supervisor', root)


def matches_stale_child(pid, kind, root=ROOT):
    """Check the saved PID's UID and exact program identity before any signal."""
    if type(pid) is not int or pid < 2 or pid == os.getpid():
        return False
    result = run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=,command='],
                 check=False, timeout=2)
    found = re.fullmatch(r'\s*(\d+)[ \t]+([^\r\n]+)\s*', result.stdout)
    if result.returncode or not found or int(found.group(1)) != 0:
        return False
    command = found.group(2).strip()
    if kind == 'engine':
        executable = str(root / 'bin' / 'tpws')
        return command == executable or command.startswith(executable + ' ')
    if kind == 'udp':
        suffix = f' -u {root / "discord_udp.py"} serve --root {root}'
    elif kind == 'supervisor':
        suffix = f' -u {root / "zapret.py"} supervise'
    else:
        return False
    if not command.endswith(suffix):
        return False
    interpreter = command[:-len(suffix)]
    # An interpreter upgrade must not hide an orphan launched by the old Python.
    if interpreter == sys.executable:
        return True
    # ps flattens argv, so an absolute Python-looking tail can actually belong
    # to a shell command. Reject option/additional executable boundaries while
    # preserving ordinary directory names such as "Python Tools".
    if re.search(r'\s(?:-\S|[/\\]|[A-Za-z]:[/\\])', interpreter):
        return False
    executable = Path(interpreter)
    return bool(executable.is_absolute() and re.fullmatch(r'[Pp]ython(?:3(?:\.\d+)*)?', executable.name))


def recover_stale_children(root=ROOT):
    """Recover recorded children left by SIGKILL, without searching ports/PIDs."""
    if is_running(root):
        return
    state = get_state(root)
    def terminate(pid, kind):
        if type(pid) is not int or pid < 2 or pid in (os.getpid(), state.get('pid')):
            return
        if not matches_stale_child(pid, kind, root):
            return
        def wait_stopped():
            end = time.monotonic() + 3
            while time.monotonic() < end:
                if not matches_stale_child(pid, kind, root):
                    return True
                time.sleep(0.1)
            return not matches_stale_child(pid, kind, root)

        if is_running(root):
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        if wait_stopped():
            return
        # Identity is checked again after the grace period: the PID can be reused.
        if is_running(root) or not matches_stale_child(pid, kind, root):
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        if not wait_stopped():
            raise Error(f'Не удалось завершить оставшийся процесс {kind}, PID {pid}.')

    def recover_udp():
        status_path = root / 'runtime' / 'udp-status.json'
        try:
            status = json.loads(status_path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return
        except ValueError:
            raise Error('Некорректный runtime/udp-status.json: PID relay не подтверждён.') from None
        if not isinstance(status, dict):
            raise Error('Некорректный runtime/udp-status.json: PID relay не подтверждён.')
        terminate(status.get('pid'), 'udp')

    # Corrupt UDP telemetry cannot prevent recovery of a verified engine PID.
    cleanup_steps(lambda: terminate(state.get('engine_pid'), 'engine'), recover_udp)


def wait_ready(child, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if child.poll() is not None:
            raise Error('tpws завершился до запуска. Посмотрите logs/service.log.')
        # Inspect the listening socket without creating a direct connection.
        # A root connection has no PF NAT state and makes transparent tpws log
        # a misleading DIOCNATLOOK error during otherwise successful startup.
        listeners = run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(child.pid),
                         '-iTCP:988', '-sTCP:LISTEN', '-Fpn'], check=False, timeout=2)
        if child.poll() is not None:
            raise Error('tpws завершился до запуска. Посмотрите logs/service.log.')
        if listeners.returncode not in (0, 1):
            raise Error('Не удалось проверить владельца TCP-порта 988: '
                        + listeners.stderr.strip())
        owner = None
        for line in listeners.stdout.splitlines():
            if line.startswith('p'):
                owner = line[1:]
            elif listeners.returncode == 0 and owner == str(child.pid) and line == 'n127.0.0.1:988':
                return
        time.sleep(0.15)
    raise Error('tpws не подтвердил собственный TCP listener 127.0.0.1:988 вовремя.')


def supervise(root=ROOT):
    require_mac(True)
    import fcntl
    root.joinpath('runtime').mkdir(exist_ok=True)
    service_lock = (root / 'runtime' / 'service.lock').open('a')
    try:
        try:
            fcntl.flock(service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error('Другой supervisor уже запущен.') from None
        if is_running(root):
            raise Error('Другой экземпляр ZapretMac уже работает.')
        stop_requested = False
        child = None
        child_stopped = True
        recovery_done = False
        from voice_controller import Backend
        udp_backend = Backend(root)

        def stop_signal(signum, frame):
            nonlocal stop_requested
            stop_requested = True

        def stop_child():
            nonlocal child_stopped
            if child.poll() is None:
                try:
                    child.terminate()
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=5)
            child_stopped = True

        signal.signal(signal.SIGTERM, stop_signal)
        signal.signal(signal.SIGINT, stop_signal)
        state_path = root / 'runtime' / 'state.json'
        try:
            # Recover our stale anchor/token after an interrupted previous run.
            cleanup_steps(lambda: release_pf(root), lambda: recover_stale_children(root))
            recovery_done = True
            while not stop_requested:
                cfg = config(root)
                prepare_lists(root)
                args = engine_args(cfg, root)
                run(args + ['--dry-run'])
                write_json(state_path, dict(pid=os.getpid(), phase='starting', strategy=cfg['strategy']))
                child = subprocess.Popen(args)
                child_stopped = False
                write_json(state_path, dict(pid=os.getpid(), engine_pid=child.pid,
                                           phase='starting', strategy=cfg['strategy']))
                wait_ready(child)
                if stop_requested:
                    break
                apply_pf(cfg, root)
                udp_backend.start(cfg, cancelled=lambda: stop_requested)
                write_json(state_path, dict(pid=os.getpid(), engine_pid=child.pid,
                                           phase='running', strategy=cfg['strategy'], voice_udp=udp_backend.active))
                print(f'Сервис запущен: {cfg["strategy"]}', flush=True)
                while not stop_requested and child.poll() is None:
                    udp_backend.check()
                    time.sleep(0.25)
                cleanup_steps(udp_backend.stop, lambda: release_pf(root), stop_child)
                child = None
                if not stop_requested:
                    print('tpws завершился. Правила сняты; повтор через 3 секунды.', flush=True)
                    write_json(state_path, dict(pid=os.getpid(), phase='recovering', strategy=cfg['strategy']))
                    for _ in range(12):
                        if stop_requested:
                            break
                        time.sleep(0.25)
        finally:
            cleanup_steps(udp_backend.stop, lambda: release_pf(root),
                          lambda: stop_child() if child else None,
                          lambda: state_path.unlink(missing_ok=True) if recovery_done and child_stopped else None)
    finally:
        service_lock.close()


def launch_loaded():
    return run(['/bin/launchctl', 'print', 'system/' + LABEL], check=False).returncode == 0


def stop(root=ROOT):
    require_mac(True)
    # Freeze the PID before any operation that can make the state disappear or
    # replace it. A later state file must never select a different signal target.
    saved_pid = get_state(root).get('pid')

    def check_replacement():
        current_pid = get_state(root).get('pid')
        if current_pid not in (None, saved_pid):
            raise Error('Состояние сервиса изменилось: появился другой supervisor. Повторите остановку.')

    if launch_loaded():
        check_replacement()
        run(['/bin/launchctl', 'bootout', 'system/' + LABEL])
    if is_running(root):
        check_replacement()
        if matches_stale_child(saved_pid, 'supervisor', root):
            check_replacement()
            try:
                os.kill(saved_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for _ in range(100):
            check_replacement()
            if not matches_stale_child(saved_pid, 'supervisor', root):
                break
            time.sleep(0.1)
        if matches_stale_child(saved_pid, 'supervisor', root):
            raise Error('Supervisor не завершился. Проверьте logs/service.log.')

    # The supervisor takes this same lock before startup. Holding it after the
    # previous process exits prevents a new service from acquiring PF while we
    # release the old rules, recover children, and remove old metadata.
    service_lock = None
    try:
        if sys.platform == 'darwin' and (root / 'runtime').is_dir():
            import fcntl
            service_lock = (root / 'runtime' / 'service.lock').open('a')
            lock_deadline = None
            while True:
                try:
                    fcntl.flock(service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    # Normal shutdown removes state just before closing the
                    # lock. Allow that short gap, while preserving new owners.
                    check_replacement()
                    now = time.monotonic()
                    if lock_deadline is None:
                        lock_deadline = now + 2
                    elif now >= lock_deadline:
                        raise Error('Supervisor запускается или завершает работу. Повторите остановку.') from None
                    time.sleep(0.05)
        check_replacement()
        if is_running(root):
            raise Error('Supervisor ещё работает; его правила и состояние сохранены.')
        cleanup_steps(lambda: release_pf(root), lambda: recover_stale_children(root))
        check_replacement()
        if is_running(root):
            raise Error('Появился новый supervisor; его состояние сохранено.')
        root.joinpath('runtime', 'state.json').unlink(missing_ok=True)
    finally:
        if service_lock is not None:
            service_lock.close()


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
            print('Сервис запущен. Перезапустите уже открытые приложения/соединения.')
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
    if PLIST.is_symlink():
        raise Error('Файл автозапуска содержит символическую ссылку.')
    cfg = config(root)
    cfg['autostart'] = enabled
    validate_config(cfg, root)
    paths = (PLIST, root / 'config.json')
    saved = {p: p.read_bytes() if p.exists() else None for p in paths}
    was_running = is_running(root)
    stop(root)
    try:
        if enabled:
            data = dict(Label=LABEL,
                        ProgramArguments=[sys.executable, '-u', str(root / 'zapret.py'), 'supervise'],
                        RunAtLoad=True, KeepAlive=True, ThrottleInterval=10, ExitTimeOut=20,
                        StandardOutPath=str(root / 'logs' / 'service.log'),
                        StandardErrorPath=str(root / 'logs' / 'service.log'))
            atomic_write(PLIST, plistlib.dumps(data))
            write_json(root / 'config.json', cfg)
            start(root)
        else:
            PLIST.unlink(missing_ok=True)
            write_json(root / 'config.json', cfg)
    except BaseException as error:
        def restore(path, content):
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, content)
        failures = []
        for action in [lambda: stop(root)] + [lambda p=p, b=b: restore(p, b) for p, b in saved.items()]:
            try:
                action()
            except BaseException as failure:
                failures.append(str(failure))
        if was_running and not failures:
            try:
                start(root)
            except BaseException as failure:
                failures.append(str(failure))
        if failures:
            raise Error(f'Автозапуск не изменён полностью: {error}; откат: {"; ".join(failures)}') from error
        raise
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
    # Rollback reads these files as root; other users must not replace them.
    backup.mkdir(mode=0o700, parents=True)
    for name in pending:
        shutil.copy2(root / 'lists' / name, backup / name)
    attempted = []
    try:
        for name, text in pending.items():
            # An interrupt can arrive after os.replace committed the new file
            # but before atomic_write returns. Include that file in the rollback.
            attempted.append(name)
            atomic_write(root / 'lists' / name, text)
    except BaseException:
        rollback_errors = []
        for name in attempted:
            try:
                saved = backup / name
                atomic_write(root / 'lists' / name, saved.read_bytes(), saved.stat().st_mode & 0o777)
            except BaseException as error:
                rollback_errors.append((name, error))
        for name, error in rollback_errors:
            detail = str(error) or type(error).__name__
            print(f'Ошибка отката списка {name}: {detail}. '
                  f'Резервная копия: {backup / name}', file=sys.stderr)
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
    pattern = r'^' + re.escape(HOST_BEGIN) + r'\n.*?^' + re.escape(HOST_END) + r'(?:\n|$)'
    clean, removed = re.subn(pattern, '', text, flags=re.M | re.S)
    if removed != 1:
        raise Error('Маркеры ZapretMac в /etc/hosts должны находиться на отдельных строках.')
    return clean


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
    try:
        uid = int(os.environ.get('SUDO_UID', os.getuid()))
        if uid < 1:
            raise Error('Запустите service.command из вашей обычной учётной записи.')
        return pwd.getpwuid(uid)
    except (ValueError, KeyError, OverflowError):
        raise Error('Не найдена обычная учётная запись пользователя SUDO_UID.') from None


def clean_discord_cache(root=ROOT):
    require_mac(True)
    user = original_user()
    running = run(['/usr/bin/pgrep', '-u', str(user.pw_uid), '-if', '/Discord[^/]*/.*MacOS|/Discord[^/]*/.*Helper'], check=False)
    if running.returncode == 0:
        raise Error('Полностью закройте Discord перед очисткой кеша.')
    if running.returncode != 1:
        raise Error('Не удалось проверить, закрыт ли Discord; кеш сохранён. '
                    + getattr(running, 'stderr', '').strip())
    result = run(['/usr/bin/sudo', '-u', '#' + str(user.pw_uid), '--', sys.executable,
                  Path(__file__).with_name('discord_cache.py'), user.pw_dir], timeout=None)
    report = json.loads(result.stdout)
    print(f'Очищено папок кэша: {len(report["moved"])}. Резервные копии сохранены рядом.')
    if report['skipped']:
        print('Пропущены ссылки или неподходящие пути:', ', '.join(report['skipped']))
    print('Данные входа и настройки аккаунта сохранены. Очистка кэша не проверяет доступ к серверу обновлений.')
    return report


def curl_test(target, family=None):
    name, url = target
    args = ['/usr/bin/curl', '--http1.1', '--noproxy', '*', '--connect-timeout', '5',
            '--max-time', '12', '--silent', '--show-error', '--output', '/dev/null',
            '--write-out', '%{http_code} %{time_total}', '--range', '0-0', url]
    if family is not None:
        if family not in (4, 6):
            raise Error('Для проверки нужен IPv4 или IPv6.')
        args.insert(1, '--ipv' + str(family))
        name += 'IPv' + str(family)
    # Transparent PF intentionally exempts root, so tests must use the invoking user.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        args = ['/usr/bin/sudo', '-u', '#' + str(original_user().pw_uid), '--'] + args
    try:
        result = run(args, check=False, timeout=16)
    except subprocess.TimeoutExpired:
        return dict(name=name, url=url, tls_reached=False, transfer_complete=False,
                    http='000', seconds='16', error='Таймаут проверки')
    parts = result.stdout.strip().split()
    code = parts[0] if parts else '000'
    elapsed = parts[1] if len(parts) > 1 else '?'
    reached = bool(re.fullmatch('[1-5][0-9]{2}', code))
    return dict(name=name, url=url, tls_reached=reached, transfer_complete=reached and result.returncode == 0,
                http=code, seconds=elapsed, error=result.stderr.strip())


def targets(root=ROOT):
    rows = []
    for line in (root / 'targets.txt').read_text().splitlines():
        found = re.fullmatch(r'\s*(\w+)\s*=\s*"(https://[^"\s]+)"\s*', line)
        if found:
            rows.append(found.groups())
    return rows


def discord_tests(families=False, app_ip=None):
    from discord_probe import CHECKS, FAMILY_CHECKS
    checks = CHECKS[:2] if app_ip is not None else (FAMILY_CHECKS if families else CHECKS)
    args = [sys.executable, str(Path(__file__).with_name('discord_probe.py'))]
    if families:
        args.append('--families')
    if app_ip is not None:
        args += ['--app-ip', str(app_ip)]
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        args = ['/usr/bin/sudo', '-u', '#' + str(original_user().pw_uid), '--'] + args
    try:
        result = run(args, check=False, timeout=60)
        if result.returncode:
            raise Error('Проверки приложения завершились с ошибкой: ' + result.stderr.strip()[:300])
        rows = json.loads(result.stdout)
        if (not isinstance(rows, list) or len(rows) != len(checks)
                or {r.get('name') for r in rows if isinstance(r, dict)} != set(checks)
                or any(not isinstance(r, dict)
                       or any(not isinstance(r.get(k), str) for k in ('name', 'url', 'http', 'seconds', 'error'))
                       or type(r.get('application_ok')) is not bool or type(r.get('tls_reached')) is not bool
                       or (families and 'peer_ips' in r and (not isinstance(r['peer_ips'], list)
                                                           or any(not isinstance(ip, str) for ip in r['peer_ips'])))
                       for r in rows)):
            raise Error('Некорректный отчёт проверок приложения')
        return rows
    except (Error, OSError, ValueError, subprocess.TimeoutExpired) as error:
        return [dict(name=name, url='', http='---', seconds='?', tls_reached=False,
                     application_ok=False, error=str(error)) for name in checks]


def connection_details(root, rows):
    """Read-only family/hosts diagnostics; never used as a strategy score."""
    from strategy_picker import REQUIRED
    from discord_probe import CHECKS
    failed = [(r['name'], r['url']) for r in rows if r['name'] in REQUIRED and not r['tls_reached']]
    app_failed = any(r['name'] in CHECKS and r.get('application_ok') is False for r in rows)
    if not failed and not app_failed:
        return
    print('Discord недоступен. Сравниваем IPv4 и IPv6; настройки сети не меняются…', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        tasks = [pool.submit(curl_test, target, family) for target in failed for family in (4, 6)]
        app = pool.submit(discord_tests, families=True) if app_failed else None
        families = [task.result() for task in tasks]
        if app is not None:
            families += app.result()
    for result in families:
        detail = (('Проверка пройдена' if result['application_ok'] else result['error'])
                  if 'application_ok' in result else ('TLS получен' if result['tls_reached'] else result['error']))
        print(f'{result["name"]:24} HTTP {result["http"]}: '
              + detail)
        if result.get('peer_ips'):
            print('  Адреса попыток подключения:', ', '.join(result['peer_ips']))
    hosts = []
    try:
        for line in HOSTS.read_text().splitlines():
            parts = line.split('#', 1)[0].split()
            if len(parts) >= 2 and any(re.search(r'(^|\.)discord(?:app)?\.(?:com|net|gg)$', v.lower().rstrip('.'))
                                       for v in parts[1:]):
                hosts.append(' '.join(parts))
        print('Записи Discord в /etc/hosts:', '\n' + '\n'.join(hosts[:20]) if hosts else 'нет')
    except OSError as error:
        print('Не удалось прочитать /etc/hosts:', error)
    path = root / 'logs' / ('connection-' + stamp() + '.json')
    try:
        write_json(path, dict(checks=rows, families=families, discord_hosts=hosts))
        print('Отчёт подключения:', path)
    except OSError as error:
        print('Не удалось сохранить отчёт подключения:', error)


def network_tests(root=ROOT, quiet=False):
    require_mac()
    if not quiet:
        print('Проверяем адреса и этапы загрузки Discord…', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        app = pool.submit(discord_tests)
        rows = list(pool.map(curl_test, targets(root)))
        rows += app.result()
    if not quiet:
        for row in rows:
            if 'application_ok' in row:
                detail = 'Проверка пройдена' if row['application_ok'] else row['error']
            elif row['tls_reached']:
                detail = 'TLS получен'
                if row.get('transfer_complete') is False:
                    detail += '; загрузка не завершена: ' + row['error']
            else:
                detail = row['error']
            print(f'{row["name"]:24} HTTP {row["http"]:3}  {row["seconds"]} s  '
                  + detail)
        print('Проверены TLS, страница, один JavaScript, API, WebSocket Hello и серверы обновлений Discord. '
              'Из файлов обновления прочитан только первый 1 КиБ; установка обновления, '
              'вход в аккаунт, голос и видео не проверяются.')
        connection_details(root, rows)
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
            current = network_tests(root, quiet=True)
            for row in current:
                rows.append(dict(strategy=name, **row))
            stop(root)
            count = sum(r['tls_reached'] for r in rows if r['strategy'] == name)
            print(f'Ответы TLS: {count}/{len(current)}', flush=True)
    finally:
        def restore_service():
            write_json(root / 'config.json', previous)
            if was_running:
                start(root)

        def save_report():
            if rows:
                report.parent.mkdir(parents=True, exist_ok=True)
                with report.open('w', newline='', encoding='utf-8') as output:
                    writer = csv.DictWriter(output, fieldnames=['strategy', 'name', 'url', 'tls_reached',
                                           'transfer_complete', 'application_ok', 'http', 'seconds', 'error'])
                    writer.writeheader()
                    writer.writerows(rows)

        cleanup_steps(lambda: stop(root), restore_service, save_report)
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
    print('Сервис:', 'ЗАПУЩЕН' if active and get_state(root).get('phase') == 'running' else 'ОСТАНОВЛЕН / ЗАПУСКАЕТСЯ')
    print('Активная стратегия:', get_state(root).get('strategy', '—'))
    print('Выбранная стратегия:', cfg['strategy'])
    print('Автозапуск:', PLIST.exists())
    print('UDP Discord:', 'экспериментальный режим включён' if cfg['voice_udp'] else 'отключён')


def install(binary, source=SOURCE, root=ROOT):
    require_mac(True)
    folders = ('bin', 'lists', 'runtime', 'logs', 'backups', 'licenses', 'payloads')
    copies = [(source / name, root / name, 0o644)
              for name in ('zapret.py', 'discord_udp.py', 'discord_probe.py', 'voice_controller.py', 'discord_cache.py',
                           'strategy_picker.py', 'application_update.py', 'discord_recovery.py',
                           'strategies.json', 'VERSION', 'targets.txt')]
    copies += [(Path(binary), root / 'bin' / 'tpws', 0o755),
               (source / 'payloads' / 'discord-fake.bin', root / 'payloads' / 'discord-fake.bin', 0o644)]
    for folder in ('lists', 'licenses'):
        for path in (source / folder).iterdir():
            if path.is_file():
                copies.append((path, root / folder / path.name, 0o644))

    # Validate every destination before stopping a working installation or writing
    # as root. Atomic replacement also avoids following destination hard links.
    protected = [root.parent, root, *(root / folder for folder in folders),
                 root / 'config.json', root / 'installation.json', *(dst for _, dst, _ in copies)]
    for folder in folders:
        if (root / folder).is_dir():
            protected.extend((root / folder).rglob('*'))
    for path in protected:
        if path.is_symlink():
            raise Error(f'Путь установки содержит символическую ссылку: {path}')
    directories = [root.parent, root, *(root / folder for folder in folders)]
    for path in directories:
        if path.exists() and not path.is_dir():
            raise Error(f'Ожидался каталог установки: {path}')
        if path.exists() and hasattr(os, 'geteuid') and os.geteuid() == 0:
            info = path.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Error(f'Каталог установки должен принадлежать root и запрещать запись другим пользователям: {path}')
    user = original_user()
    for src, _, _ in copies:
        if not src.is_file():
            raise Error(f'Отсутствует файл установки: {src}')
    contents = {dst: (src.read_bytes(), mode) for src, dst, mode in copies
                if dst.parent != root / 'lists' or not dst.exists()}

    # Check new strategies, preserved lists/configuration and the compiled engine
    # without modifying the previous installation.
    with tempfile.TemporaryDirectory(prefix='zapret-install-check-') as temporary:
        stage = Path(temporary)
        atomic_write(stage / 'strategies.json', contents[root / 'strategies.json'][0])
        shutil.copytree(root / 'lists' if (root / 'lists').is_dir() else source / 'lists', stage / 'lists')
        for src, dst, _ in copies:
            if dst.parent == root / 'lists' and not (stage / 'lists' / dst.name).exists():
                shutil.copy2(src, stage / 'lists' / dst.name)
        cfg = dict(DEFAULTS)
        if (root / 'config.json').exists():
            saved = json.loads((root / 'config.json').read_text(encoding='utf-8'))
            if not isinstance(saved, dict):
                raise Error('config.json должен содержать JSON-объект с настройками.')
            cfg.update(saved)
        validate_config(cfg, stage)
        prepare_lists(stage)
        args = engine_args(cfg, stage)
        staged_binary = stage / 'tpws'
        atomic_write(staged_binary, contents[root / 'bin' / 'tpws'][0], 0o755)
        args[0] = str(staged_binary)
        run(args + ['--dry-run'])

    affected = set(contents) | {root / 'config.json', root / 'installation.json'}
    affected.update(root / 'runtime' / (name + '.txt')
                    for name in ('general', 'google', 'excluded_hosts', 'ips', 'excluded_ips', 'excluded4', 'excluded6'))
    previous = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
                for path in affected}
    created_dirs = [path for path in [root, *(root / folder for folder in folders)] if not path.exists()]
    was_running = is_running(root)
    if root.exists():
        stop(root)
    try:
        root.mkdir(mode=0o755, exist_ok=True)
        root.chmod(0o755)
        for folder in folders:
            directory = root / folder
            directory.mkdir(mode=0o755, exist_ok=True)
            directory.chmod(0o755)
        for dst, (content, mode) in contents.items():
            atomic_write(dst, content, mode)
        write_json(root / 'installation.json', dict(user_uid=user.pw_uid))
        if not (root / 'config.json').exists():
            write_json(root / 'config.json', DEFAULTS)
        prepare_lists(root)
        run(engine_args(config(root), root) + ['--dry-run'])
    except BaseException as install_error:
        def restore_file(path, saved):
            if saved is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, saved[0], saved[1])

        try:
            cleanup_steps(*(lambda path=path, saved=saved: restore_file(path, saved)
                            for path, saved in previous.items()))
            for directory in reversed(created_dirs):
                if directory.exists():
                    directory.rmdir()
            if was_running:
                start(root)
        except BaseException as rollback_error:
            raise Error(f'Установка прервана: {install_error}. Восстановление предыдущей установки не завершено: {rollback_error}') from rollback_error
        raise
    print('Установка завершена. Настройки предыдущей установки сохранены.')
    return was_running


def uninstall(root=ROOT):
    require_mac(True)
    stop(root)
    PLIST.unlink(missing_ok=True)
    manage_hosts(False, root)
    from discord_recovery import remove_override
    remove_override(root)
    for path in (root / 'bin' / 'tpws', root / 'zapret.py', root / 'discord_udp.py', root / 'voice_controller.py',
                 root / 'discord_cache.py', root / 'discord_probe.py', root / 'strategy_picker.py',
                 root / 'application_update.py', root / 'discord_recovery.py',
                 root / 'strategies.json', root / 'targets.txt', root / 'VERSION'):
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


def connect(root=ROOT):
    from strategy_picker import complete, select
    from discord_probe import SCHEMA
    cfg = config(root)
    try:
        saved = json.loads((root / 'runtime/strategy-selection.json').read_text())
    except (FileNotFoundError, ValueError):
        saved = {}
    if (isinstance(saved, dict) and saved.get('schema') == SCHEMA
            and saved.get('accepted') is True and saved.get('selected') == cfg['strategy']):
        with control_lock(root):
            restart(root)
            print('Проверяем сохранённую стратегию в текущей сети…', flush=True)
            if complete(network_tests(root, quiet=True)):
                return
        print('Сохранённая стратегия не прошла проверку. Запускаем новый подбор.', flush=True)
        select(root)
    else:
        select(root)


def configure_install(root=ROOT, resume=False):
    from strategy_picker import select
    try:
        select(root)
    except (Error, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print('Автоподбор не завершён:', error)
    if config(root)['autostart']:
        with control_lock(root):
            autostart(True, root)
    else:
        if resume and not is_running(root):
            with control_lock(root):
                start(root)
        print('Сохранено отключение автозапуска.')


def menu(root=ROOT):
    require_mac(True)
    while True:
        print('\nZapretMac ' + version(root))
        status(root)
        print('\n1. Подключить / перезапустить\n2. Остановить\n'
              '3. Автоматически подобрать стратегию\n4. Голос Discord\n'
              '5. Очистить кэш Discord\n6. Проверить подключение\n'
              f'7. Автозапуск [{"включён" if PLIST.exists() else "выключен"}]\n'
              '8. Обновить ZapretMac\n0. Выход')
        try:
            choice = input('Выберите пункт: ').strip()
            if choice == '0':
                return
            if choice == '1':
                connect(root)
            elif choice == '2':
                with control_lock(root):
                    stop(root)
            elif choice == '3':
                from strategy_picker import select
                select(root)
            elif choice == '4':
                from voice_controller import voice_menu
                voice_menu(root)
            elif choice == '5':
                clean_discord_cache(root)
            elif choice == '6':
                status(root)
                network_tests(root)
            elif choice == '7':
                with control_lock(root):
                    autostart(not PLIST.exists(), root)
            elif choice == '8':
                from application_update import update
                if update(root):
                    # All imports must come from the newly installed release.
                    os.execv(sys.executable, [sys.executable, str(root / 'zapret.py'), 'menu'])
            else:
                print('Неизвестный пункт.')
        except (Error, OSError, ValueError, subprocess.TimeoutExpired, urllib.error.URLError) as error:
            print('Ошибка:', error)
        input('Enter — вернуться в меню…')


def main():
    parser = argparse.ArgumentParser(description='ZapretMac: TCP bypass and experimental Discord UDP')
    parser.add_argument('command', choices=['install', 'uninstall', 'menu', 'supervise', 'start', 'stop',
                        'restart', 'status', 'autostart-on', 'autostart-off', 'update-lists',
                        'check-updates', 'hosts-apply', 'hosts-remove', 'diagnostics',
                        'test-sites', 'test-strategies', 'cache-discord', 'plan',
                        'voice-menu', 'voice-status', 'voice-observe', 'auto-strategy', 'choose-strategy',
                        'update-app'])
    parser.add_argument('--engine', type=Path)
    parser.add_argument('--update', action='store_true', help='Install only a newer release (updater)')
    args = parser.parse_args()
    if args.update and args.command != 'install':
        parser.error('--update поддерживается только для install')
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
                'choose-strategy': choose_strategy,
                'hosts-apply': lambda: manage_hosts(True), 'hosts-remove': lambda: manage_hosts(False),
                'autostart-on': lambda: autostart(True), 'autostart-off': lambda: autostart(False)}
    from voice_controller import voice_menu, show_status, observe
    from strategy_picker import select
    commands['auto-strategy'] = select
    from application_update import update
    commands['update-app'] = update
    commands.update({'voice-menu': voice_menu, 'voice-status': show_status, 'voice-observe': observe})
    if args.command == 'install':
        if not args.engine or not args.engine.is_file():
            raise Error('Укажите существующий tpws через --engine.')
        with control_lock(ROOT) if ROOT.exists() else contextlib.nullcontext():
            if args.update:
                from application_update import version_tuple
                if version_tuple(version(ROOT)) >= version_tuple(version(SOURCE)):
                    print('Уже установлена актуальная версия ZapretMac: ' + version(ROOT) + '.')
                    return
            resume = install(args.engine)
        configure_install(resume=resume)
    else:
        read_or_interactive = {'supervise', 'menu', 'voice-menu', 'voice-status', 'voice-observe',
                               'status', 'diagnostics', 'test-sites', 'check-updates', 'auto-strategy', 'update-app'}
        with contextlib.nullcontext() if args.command in read_or_interactive else control_lock(ROOT):
            commands[args.command]()


if __name__ == '__main__':
    # Voice modules import zapret. Reuse this executable module so their Error
    # class and controller state remain identical to the CLI's own objects.
    sys.modules['zapret'] = sys.modules[__name__]
    try:
        main()
    except (Error, OSError, ValueError, subprocess.TimeoutExpired, urllib.error.URLError) as error:
        print('Ошибка:', error, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nОперация прервана.', file=sys.stderr)
        sys.exit(130)
