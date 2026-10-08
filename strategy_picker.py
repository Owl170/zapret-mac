"""Select TCP profiles using Discord-specific results and a confirmation pass."""
from pathlib import Path
import zapret as z

REQUIRED = ('DiscordMain', 'DiscordGateway', 'DiscordCDN', 'DiscordUpdates')


def complete(rows):
    by_name = {r['name']: r for r in rows}
    return all(by_name.get(name, {}).get('tls_reached') is True for name in REQUIRED)


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
    report = dict(accepted=False, selected=None, trials=[], confirmation=[])
    path = root / 'logs' / ('auto-strategy-' + z.stamp() + '.json')
    committed = False
    failure = None
    print('Автоподбор перезапускает обход. После завершения переподключите Discord.', flush=True)
    with z.control_lock(root):
        previous = z.config(root)
        was_running = z.is_running(root)
        try:
            names = list(z.strategies(root))
            # Keep the current profile on ties; prefer a simple baseline next.
            names = [n for n in dict.fromkeys([previous['strategy'], 'passthrough', 'tlsrec'] + names) if n in names]
            candidates = []
            for name in names:
                z.stop(root)
                z.write_json(root / 'config.json', dict(previous, strategy=name, voice_udp=False))
                z.start(root)
                rows = z.network_tests(root, quiet=True)
                report['trials'].append(dict(strategy=name, rows=rows))
                discord = sum(r['tls_reached'] is True for r in rows if r['name'] in REQUIRED)
                print(f'{name}: Discord {discord}/4, всего TLS {rank(rows)[1]}/{len(rows)}', flush=True)
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
                    report.update(accepted=True, selected=name)
                    z.write_json(path, report)
                    z.write_json(root / 'runtime' / 'strategy-selection.json', report)
                    committed = True
                    print('Сохранена и включена стратегия:', name, flush=True)
                    print('Проверены TCP/TLS-адреса Discord; голос и видео требуют проверки в приложении.')
                    return True
            print('Ни один профиль не подтвердил все четыре адреса Discord.')
            return False
        except BaseException as error:
            failure = error
            raise
        finally:
            if not committed:
                report['accepted'] = False
                report['selected'] = None
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
