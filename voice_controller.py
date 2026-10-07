#!/usr/bin/env python3
"""Manage the experimental UDP backend and verify PF before voice traffic."""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import sys
import time

import zapret as z
from discord_udp import PROFILES, TEST4, TEST6, TEST_PORT, UDP_PORT

UDP_ANCHOR = 'com.apple/zapret-macos-udp'


def clear_udp():
    z.pf('-a', UDP_ANCHOR, '-f', '-', input='')


def udp_rules(cfg, root=z.ROOT, linklocal='fe80::1', probe_only=False):
    z.ports(cfg['voice_ports'])
    spec = (cfg['voice_ports'] + ',' + str(TEST_PORT)).replace('-', ':')
    normal = cfg['voice_ports'].replace('-', ':')
    rt = root / 'runtime'
    rows = [f'table <zmac_udp_ex4> persist file "{rt / "excluded4.txt"}"']
    if cfg['ipv6']:
        rows.append(f'table <zmac_udp_ex6> persist file "{rt / "excluded6.txt"}"')
    target4 = f'{TEST4} port {TEST_PORT}' if probe_only else f'any port {{{spec}}}'
    target6 = f'{TEST6} port {TEST_PORT}' if probe_only else f'any port {{{spec}}}'
    rows.append(f'rdr pass on lo0 inet proto udp from !127.0.0.0/8 to {target4} -> 127.0.0.1 port {UDP_PORT}')
    if cfg['ipv6']:
        rows.append(f'rdr pass on lo0 inet6 proto udp from !::1 to {target6} -> {linklocal} port {UDP_PORT}')
    # Explicit probes bypass exclusions and never leave the relay for the WAN.
    # Keep NAT state at the rdr rule only. A second route-to state can reroute replies.
    rows.append(f'pass out route-to (lo0 127.0.0.1) inet proto udp from !127.0.0.0/8 to {TEST4} port {TEST_PORT} user {{ >root }} no state label "zmac-udp-probe"')
    if not probe_only:
        rows.append(f'pass out route-to (lo0 127.0.0.1) inet proto udp from !127.0.0.0/8 to !<zmac_udp_ex4> port {{{normal}}} user {{ >root }} no state label "zmac-udp"')
    if cfg['ipv6']:
        rows.append(f'pass out route-to (lo0 {linklocal}) inet6 proto udp from !::1 to {TEST6} port {TEST_PORT} user {{ >root }} no state label "zmac-udp-probe"')
        if not probe_only:
            rows.append(f'pass out route-to (lo0 {linklocal}) inet6 proto udp from !::1 to !<zmac_udp_ex6> port {{{normal}}} user {{ >root }} no state label "zmac-udp"')
    return '\n'.join(rows) + '\n'


def user_uid(root):
    try:
        return z.original_user().pw_uid
    except z.Error:
        installed = json.loads((root / 'installation.json').read_text())
        uid = installed.get('user_uid') if isinstance(installed, dict) else None
        if type(uid) is not int or not 1 <= uid <= 0xFFFFFFFE:
            raise z.Error('Не сохранён пользователь установки для UDP-самопроверки.')
        import pwd
        try:
            pwd.getpwuid(uid)
        except KeyError as error:
            raise z.Error('Пользователь установки больше не существует; переустановите ZapretMac.') from error
        return uid


class Backend:
    def __init__(self, root=z.ROOT):
        self.root = root
        self.child = None
        self.active = False
        self.error = ''

    def record(self, **extra):
        z.write_json(self.root / 'runtime' / 'udp-mode.json',
                     dict(active=self.active, error=self.error, updated_at=time.time(), **extra))

    def start(self, cfg, probe_only=False, cancelled=lambda: False, probe_debug=False):
        import subprocess
        self.stop()
        if not cfg['voice_udp']:
            return False
        token = secrets.token_hex(16)
        rules_applied = False
        try:
            z.atomic_write(self.root / 'runtime/udp-probe.json', json.dumps(dict(token=token)), 0o600)
            (self.root / 'runtime/udp-status.json').unlink(missing_ok=True)
            with (self.root / 'logs/udp.log').open('ab') as log:
                self.child = subprocess.Popen([sys.executable, '-u', str(self.root / 'discord_udp.py'),
                                               'serve', '--root', str(self.root)], stdout=log, stderr=log)
            for _ in range(100):
                if cancelled():
                    raise z.Error('Запуск UDP отменён при остановке сервиса.')
                if self.child.poll() is not None:
                    raise z.Error('UDP-relay завершился при запуске. Подробности в logs/udp.log.')
                path = self.root / 'runtime/udp-status.json'
                if path.exists():
                    status = json.loads(path.read_text())
                    if not isinstance(status, dict):
                        raise z.Error('Некорректный файл готовности UDP-relay.')
                    if status.get('pid') == self.child.pid and status.get('ready'):
                        break
                time.sleep(0.1)
            else:
                raise z.Error('UDP-relay не сообщил готовность за 10 секунд.')
            ll = 'fe80::1'
            if cfg['ipv6']:
                import re
                found = re.search(r'inet6\s+(fe80:[0-9a-f:]+)', z.run(['/sbin/ifconfig', 'lo0']).stdout)
                if not found:
                    raise z.Error('Не найден IPv6 lo0.')
                ll = found.group(1)
            rules = self.root / 'runtime/udp-anchor.conf'
            text = udp_rules(cfg, self.root, ll, probe_only=probe_only)
            z.atomic_write(rules, text)
            z.pf('-n', '-a', UDP_ANCHOR, '-f', rules)
            if cancelled():
                raise z.Error('Запуск UDP отменён при остановке сервиса.')
            # Until NAT lookup and reverse NAT succeed, redirect only reserved probes.
            if not probe_only:
                z.atomic_write(rules, udp_rules(cfg, self.root, ll, probe_only=True))
                z.pf('-n', '-a', UDP_ANCHOR, '-f', rules)
            z.pf('-a', UDP_ANCHOR, '-f', rules)
            rules_applied = True
            uid = user_uid(self.root)
            command = ['/usr/bin/sudo', '-u', '#' + str(uid), '--', sys.executable,
                       self.root / 'discord_udp.py', 'probe', '--token', token]
            if probe_debug:
                command.append('--debug-probe')
            z.run(command + ['--address', TEST4], timeout=5)
            if cancelled():
                raise z.Error('Запуск UDP отменён при остановке сервиса.')
            ipv6_probe = 'disabled'
            if cfg['ipv6']:
                route = z.run(['/sbin/route', '-n', 'get', '-inet6', 'default'], check=False)
                if route.returncode == 0:
                    z.run(command + ['--address', TEST6], timeout=5)
                    ipv6_probe = 'passed'
                else:
                    ipv6_probe = 'no-default-route'
            if cancelled():
                raise z.Error('Запуск UDP отменён при остановке сервиса.')
            if self.child.poll() is not None:
                raise z.Error('UDP-relay завершился во время самопроверки.')
            if not probe_only:
                z.atomic_write(rules, text)
                z.pf('-a', UDP_ANCHOR, '-f', rules)
            self.active = True
            self.error = ''
            self.record(profile=cfg['voice_profile'], ipv4_probe='passed', ipv6_probe=ipv6_probe)
            print('UDP-самопроверка пройдена. Режим голоса:', cfg['voice_profile'], flush=True)
            return True
        except (z.Error, OSError, ValueError, subprocess.TimeoutExpired) as error:
            self.error = str(error)
            # Read only our failed probe's state; diagnostics must not delay cancellation.
            if rules_applied and not cancelled():
                try:
                    self.capture_failure()
                except (z.Error, OSError, ValueError):
                    pass
            self.stop(preserve_error=True)
            print('UDP-перехват отключён: ' + self.error, flush=True)
            return False

    def capture_failure(self):
        import subprocess
        diagnostic = dict(error=self.error, status=read_status(self.root))
        for name, args in [('pf_info', ['-s', 'info']),
                           ('udp_filter', ['-a', UDP_ANCHOR, '-v', '-s', 'rules']),
                           ('udp_rdr', ['-a', UDP_ANCHOR, '-s', 'nat']),
                           ('pf_interfaces', ['-v', '-s', 'Interfaces']),
                           ('probe_states', ['-s', 'states'])]:
            try:
                result = z.pf(*args, check=False, timeout=2)
                output = result.stdout or ''
                if name == 'probe_states':
                    output = '\n'.join(line for line in output.splitlines()
                                       if TEST4 in line or TEST6 in line or ':989' in line)
                diagnostic[name] = output[:8000]
            except (z.Error, OSError, subprocess.TimeoutExpired):
                diagnostic[name] = 'unavailable'
        z.write_json(self.root / 'logs/udp-start-failure.json', diagnostic)

    def check(self):
        if self.active and self.child and self.child.poll() is not None:
            self.error = 'UDP-relay завершился. Правила сняты; переподключите голос и проверьте udp.log.'
            self.stop(preserve_error=True)
            print(self.error, flush=True)

    def stop(self, preserve_error=False):
        import subprocess
        self.active = False

        def close_child():
            if self.child:
                child = self.child
                if child.poll() is None:
                    try:
                        child.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            child.kill()
                        except ProcessLookupError:
                            pass
                        child.wait(timeout=3)
                self.child = None

        def record_stop():
            if not preserve_error:
                self.error = ''
            self.record()

        # PF and telemetry failures must not orphan the relay process.
        z.cleanup_steps(clear_udp, close_child, record_stop)


def read_status(root=z.ROOT):
    data = {}
    for name in ('udp-mode.json', 'udp-status.json'):
        path = root / 'runtime' / name
        try:
            value = json.loads(path.read_text())
        except FileNotFoundError:
            continue
        if not isinstance(value, dict):
            raise z.Error(f'Некорректный файл состояния UDP: {name}')
        data[name] = value
    return data


def show_status(root=z.ROOT):
    data = read_status(root)
    mode = data.get('udp-mode.json', {})
    status = data.get('udp-status.json', {})
    print('UDP-перехват:', 'АКТИВЕН' if mode.get('active') and status.get('ready') else 'ОТКЛЮЧЁН')
    print('IPv4 PF-проверка:', mode.get('ipv4_probe', 'не пройдена'))
    print('IPv6 PF-проверка:', mode.get('ipv6_probe', 'не пройдена'))
    print('Пакеты к relay / в сеть / обратно:', status.get('received', 0), '/', status.get('forwarded', 0), '/', status.get('replies', 0))
    print('Discovery / STUN / фейки:', status.get('discoveries', 0), '/', status.get('stun', 0), '/', status.get('fakes', 0))
    print('Ошибка:', mode.get('error') or status.get('last_error') or '—')
    print('Ответы UDP подтверждают обмен пакетами; звук проверяется реальным звонком.')


def observe(root=z.ROOT, duration=30):
    initial = read_status(root).get('udp-status.json', {})
    print(f'Наблюдение {duration} секунд. Подключитесь к голосовому каналу Discord.', flush=True)
    end = time.monotonic() + duration
    while time.monotonic() < end:
        time.sleep(min(5, max(0, end - time.monotonic())))
        state = read_status(root).get('udp-status.json', {})
        outgoing = state.get('forwarded', 0) - initial.get('forwarded', 0)
        incoming = state.get('replies', 0) - initial.get('replies', 0)
        print(f'За сеанс: отправлено {outgoing}, ответов {incoming}, '
              f'discovery {state.get("discoveries", 0) - initial.get("discoveries", 0)}', flush=True)
    show_status(root)
    report = root / 'logs' / ('voice-' + z.stamp() + '.json')
    z.write_json(report, dict(initial=initial, final=read_status(root),
                             note='UDP counters only. No audio, tokens, or account information.'))
    print('Отчёт:', report)


def tune(root=z.ROOT):
    """User reconnects for each trial; only their audio confirmation selects a profile."""
    saved = z.config(root)
    was_running = z.is_running(root)
    confirmed = False
    results = []
    report = root / 'logs' / ('voice-trials-' + z.stamp() + '.json')
    try:
        for profile in PROFILES:
            print('\nПрофиль:', profile, flush=True)
            cfg = dict(saved, voice_udp=True, voice_profile=profile)
            z.write_json(root / 'config.json', cfg)
            z.restart(root)
            mode = read_status(root).get('udp-mode.json', {})
            if not mode.get('active'):
                print('PF-самопроверка не пройдена. Подбор прекращён:', mode.get('error', ''))
                break
            print('Отключитесь от голосового канала и подключитесь снова. '
                  'Проверьте, слышите ли вы собеседника и слышит ли он вас.')
            input('Нажмите Enter после переподключения…')
            observe(root, duration=15)
            answer = input('Работает звук В ОБЕ СТОРОНЫ? yes / no / stop: ').strip().lower()
            results.append(dict(profile=profile, user_answer=answer, counters=read_status(root)))
            if answer in ('yes', 'да'):
                confirmed = True
                print('Подтверждённый профиль сохранён:', profile)
                break
            if answer in ('stop', 'стоп'):
                break
    finally:
        try:
            if not confirmed:
                z.write_json(root / 'config.json', saved)
                try:
                    z.stop(root)
                finally:
                    if was_running:
                        z.start(root)
                print('Прежние настройки восстановлены.')
        finally:
            z.write_json(report, dict(trials=results, audio_confirmed_by_user=confirmed))
            print('Отчёт подбора:', report)


def voice_menu(root=z.ROOT):
    z.require_mac(True)
    while True:
        cfg = z.config(root)
        print('\nDiscord Voice — экспериментальный локальный UDP-обход')
        print('Профиль:', cfg['voice_profile'], '| UDP-порты:', cfg['voice_ports'])
        show_status(root)
        print('\n1. Включить режим голоса / перезапустить\n2. Сменить UDP-профиль\n'
              '3. Наблюдать подключение 30 секунд\n4. Отключить UDP-перехват\n'
              '5. Изменить UDP-порты\n6. Выбрать TCP-стратегию для подключения Discord\n'
              '7. Диагностика\n8. Помощник подбора UDP-стратегии\n0. Выход')
        try:
            choice = input('Пункт: ').strip()
            if choice == '0':
                return
            if choice == '1':
                cfg['voice_udp'] = True
                z.write_json(root / 'config.json', cfg)
                z.restart(root)
                show_status(root)
                if read_status(root).get('udp-mode.json', {}).get('active'):
                    print('Отключитесь от голосового канала и подключитесь снова.')
                else:
                    print('UDP не запущен. Сначала проверьте причину в диагностике, пункт 7.')
            elif choice == '2':
                print('relay — без фейков; fake — 6 фейков с обычным TTL; '
                      'ttl3 / ttl5 / ttl7 / ttl9 — 6 фейков с указанным TTL.')
                value = input('Профиль: ').strip()
                if value not in PROFILES:
                    raise z.Error('Неизвестный UDP-профиль.')
                cfg['voice_profile'] = value
                z.write_json(root / 'config.json', cfg)
                if z.is_running(root):
                    z.restart(root)
                print('После смены профиля переподключитесь к голосовому каналу.')
            elif choice == '3':
                observe(root)
            elif choice == '4':
                cfg['voice_udp'] = False
                z.write_json(root / 'config.json', cfg)
                if z.is_running(root):
                    z.restart(root)
                else:
                    clear_udp()
            elif choice == '5':
                print('Стандарт: 3478,5349,19294-19344,50000-65535. Для нестандартных серверов: 1024-65535.')
                cfg['voice_ports'] = input('Порты UDP: ').strip()
                z.validate_config(cfg, root)
                z.write_json(root / 'config.json', cfg)
                if z.is_running(root):
                    z.restart(root)
            elif choice == '6':
                z.choose_strategy(root)
            elif choice == '7':
                z.diagnostics(root)
            elif choice == '8':
                tune(root)
            else:
                print('Неизвестный пункт.')
        except (z.Error, OSError, ValueError) as error:
            print('Ошибка:', error)
        input('Enter — меню…')
