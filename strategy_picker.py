"""Select TCP profiles using Discord-specific results and a confirmation pass."""
from pathlib import Path
import zapret as z
from discord_probe import CHECKS, SCHEMA

REQUIRED = ('DiscordMain', 'DiscordGateway', 'DiscordCDN', 'DiscordUpdates')


def complete(rows):
    by_name = {r['name']: r for r in rows}
    return (all(by_name.get(name, {}).get('tls_reached') is True for name in REQUIRED)
            and all(by_name.get(name, {}).get('application_ok') is True for name in CHECKS))


def rank(rows):
    # Google/Cloudflare alone must never select a broken Discord profile.
    youtube = sum(r['tls_reached'] is True for r in rows if r['name'].startswith('YouTube'))
    total = sum(r['tls_reached'] is True for r in rows)
    return youtube, total


def select(root=z.ROOT):
    z.require_mac(True)
    root = Path(root)
    configured = [name for name, _ in z.targets(root)]
    if len(configured) != len(set(configured)) or not set(REQUIRED).issubset(configured):
        raise z.Error('Для автоподбора нужны четыре уникальных адреса Discord в targets.txt.')
    report = dict(schema=SCHEMA, accepted=False, selected=None, trials=[], confirmation=[])
    path = root / 'logs' / ('auto-strategy-' + z.stamp() + '.json')
    committed = False
    failure = None
    print('Автоподбор перезапускает обход. После завершения переподключите Discord.', flush=True)
    with z.control_lock(root):
        previous = z.config(root)
        was_running = z.is_running(root)
        def accept(name, rows):
            nonlocal committed
            report.update(accepted=True, selected=name)
            try:
                z.write_json(path, report)
                z.write_json(root / 'runtime' / 'strategy-selection.json', report)
            except BaseException:
                report.update(accepted=False, selected=None)
                raise
            committed = True
            print('Сохранена и включена стратегия:', name, flush=True)
            print('Проверены страница, JavaScript, API, WebSocket и доступ к обновлению Discord; '
                  'вход в аккаунт, голос и видео требуют проверки в приложении.')
        try:
            names = list(z.strategies(root))
            # Keep the current profile on ties; prefer a simple baseline next.
            names = [n for n in dict.fromkeys([previous['strategy'], 'passthrough', 'tlsrec'] + names) if n in names]
            candidates = []
            for name in names:
                print('Проверка профиля:', name, flush=True)
                z.stop(root)
                z.write_json(root / 'config.json', dict(previous, strategy=name, voice_udp=False))
                z.start(root)
                rows = z.network_tests(root, quiet=True)
                report['trials'].append(dict(strategy=name, rows=rows))
                discord = sum(r['tls_reached'] is True for r in rows if r['name'] in REQUIRED)
                application = sum(r.get('application_ok') is True for r in rows if r['name'] in CHECKS)
                print(f'{name}: Discord TLS {discord}/4, приложение и обновление {application}/{len(CHECKS)}, '
                      f'всего ответов {rank(rows)[1]}/{len(rows)}', flush=True)
                missing = [r['name'] for r in rows if (r['name'] in REQUIRED and not r['tls_reached'])
                           or (r['name'] in CHECKS and r.get('application_ok') is not True)]
                if missing:
                    print('Не прошли:', ', '.join(missing), flush=True)
                if complete(rows):
                    candidates.append((name, rows))
            # Stable sorting preserves the tie preference above.
            candidates.sort(key=lambda item: rank(item[1]), reverse=True)
            for name, _ in candidates:
                z.stop(root)
                z.write_json(root / 'config.json', dict(previous, strategy=name))
                z.start(root)
                rows = z.network_tests(root, quiet=True)
                report['confirmation'].append(dict(strategy=name, rows=rows))
                if complete(rows):
                    accept(name, rows)
                    return True
            from discord_recovery import recover
            if recover(root, previous, report, accept):
                return True
            print('Ни один профиль не подтвердил все этапы подключения и обновления Discord.')
            return False
        except BaseException as error:
            failure = error
            raise
        finally:
            if not committed:
                report['accepted'] = False
                report['selected'] = None
                if 'endpoint_recovery' in report:
                    report['endpoint_recovery']['accepted'] = False
                def restore():
                    z.write_json(root / 'config.json', previous)
                    if was_running:
                        z.start(root)
                try:
                    z.cleanup_steps(lambda: z.stop(root), restore,
                                    lambda: z.write_json(path, report))
                except BaseException as error:
                    if failure is None:
                        raise
                    print('Дополнительная ошибка восстановления:', error, flush=True)
                else:
                    print('Прежние настройки и состояние сервиса восстановлены.')
            print('Отчёт автоподбора:', path, flush=True)
