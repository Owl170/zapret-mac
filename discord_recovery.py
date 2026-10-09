"""Try current DNS endpoints, retaining only a fully confirmed discord.com override."""
import ipaddress
import json
from pathlib import Path
import re
import ssl
import stat
import urllib.request

import zapret as z

BEGIN = '# BEGIN DISCORD ENDPOINT ZAPRETMAC'
END = '# END DISCORD ENDPOINT ZAPRETMAC'
DNS_URL = 'https://dns.google/resolve?name=discord.com&type=A&edns_client_subnet=0.0.0.0%2F0'


def strip_override(text):
    if BEGIN not in text and END not in text:
        return text
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise z.Error('Повреждён блок адреса Discord в hosts; резервные копии находятся в backups.')
    result, count = re.subn(r'^' + re.escape(BEGIN) + r'\n[^\n]+\n' + re.escape(END) + r'(?:\n|$)',
                            '', text, flags=re.M)
    if count != 1:
        raise z.Error('Некорректные маркеры адреса Discord в hosts.')
    return result


def flush_dns():
    z.run(['/usr/bin/dscacheutil', '-flushcache'], check=False)
    z.run(['/usr/bin/killall', '-HUP', 'mDNSResponder'], check=False)


def remove_override(root=z.ROOT):
    text = z.HOSTS.read_text()
    clean = strip_override(text)
    if clean != text:
        z.atomic_write(Path(root) / 'backups' / ('discord-hosts-' + z.stamp()), text, 0o600)
        z.atomic_write(z.HOSTS, clean, stat.S_IMODE(z.HOSTS.stat().st_mode))
        flush_dns()


class HostsTrial:
    def __init__(self, root, address):
        value = ipaddress.ip_address(address)
        if value.version != 4 or not value.is_global:
            raise z.Error('Адрес восстановления Discord должен быть публичным IPv4.')
        self.address = str(value)
        self.root = Path(root)
        self.committed = False
        self.applied = False

    def __enter__(self):
        if z.HOSTS.is_symlink() or not z.HOSTS.is_file():
            raise z.Error('hosts должен быть обычным файлом.')
        self.original = z.HOSTS.read_text()
        clean = strip_override(self.original)
        domains = {word.lower().rstrip('.') for line in clean.splitlines()
                   for word in line.split('#', 1)[0].split()[1:]}
        if 'discord.com' in domains:
            raise z.Error('В hosts уже есть ваша запись discord.com. Автоматическая замена отменена.')
        self.mode = stat.S_IMODE(z.HOSTS.stat().st_mode)
        self.backup = self.root / 'backups' / ('discord-hosts-' + z.stamp())
        z.atomic_write(self.backup, self.original, 0o600)
        self.block = BEGIN + '\n' + self.address + ' discord.com\n' + END + '\n'
        self.proposed = clean + ('' if clean.endswith('\n') else '\n') + self.block
        if z.HOSTS.read_text() != self.original:
            raise z.Error('hosts изменился во время проверки; повторите подбор.')
        try:
            self.applied = True  # Include a rename interrupted after commit in rollback.
            z.atomic_write(z.HOSTS, self.proposed, self.mode)
            flush_dns()
        except BaseException:
            self.restore()
            raise
        return self

    def restore(self):
        if not self.applied:
            return
        current = z.HOSTS.read_text()
        if current == self.proposed:
            target = self.original
        else:
            # Preserve unrelated edits made by another program during the trial.
            clean = strip_override(current)
            old = ''
            # The old block may have been in the middle, so recover it explicitly.
            if BEGIN in self.original:
                old = self.original[self.original.index(BEGIN):self.original.index(END) + len(END)] + '\n'
            target = clean + ('' if clean.endswith('\n') else '\n') + old
        z.atomic_write(z.HOSTS, target, self.mode)
        self.applied = False
        flush_dns()

    def __exit__(self, kind, error, traceback):
        if not self.committed:
            self.restore()


def candidate_addresses():
    request = urllib.request.Request(DNS_URL, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=8, context=ssl.create_default_context()) as response:
        if response.geturl() != DNS_URL:
            raise z.Error('Неожиданное перенаправление DNS-проверки.')
        data = response.read(16385)
    if len(data) > 16384:
        raise z.Error('Слишком большой ответ DNS-проверки.')
    value = json.loads(data)
    if (not isinstance(value, dict) or type(value.get('Status')) is not int or value['Status'] != 0
            or not isinstance(value.get('Answer'), list)):
        raise z.Error('DNS-over-HTTPS не вернул адресов discord.com.')
    addresses = []
    for record in value['Answer']:
        if (not isinstance(record, dict) or type(record.get('type')) is not int or record['type'] != 1
                or not isinstance(record.get('name'), str)
                or record['name'].lower().rstrip('.') != 'discord.com'
                or not isinstance(record.get('data'), str)):
            continue
        try:
            address = ipaddress.ip_address(record['data'])
        except ValueError:
            continue
        if address.version == 4 and address.is_global and str(address) not in addresses:
            addresses.append(str(address))
    # Never embed Cloudflare IPs or trust addresses for a different DNS name.
    if not addresses:
        raise z.Error('Нет публичных IPv4 адресов Discord для восстановления.')
    return addresses[:6]


def recover(root, previous, report, accept):
    """Called inside the selector's control lock; its finalizer restores config/service."""
    from strategy_picker import REQUIRED, complete, rank
    candidates = [trial for trial in report['trials']
                  if all(any(row['name'] == name and row['tls_reached'] is True
                             for row in trial['rows']) for name in REQUIRED)
                  and any(row['name'] in ('DiscordApp', 'DiscordScript') and row.get('application_ok') is False
                          for row in trial['rows'])]
    if not candidates:
        return False
    recovery = report['endpoint_recovery'] = dict(accepted=False, attempts=[])
    try:
        addresses = candidate_addresses()
    except (z.Error, OSError, ValueError) as error:
        recovery['error'] = str(error)
        print('Проверка других адресов Discord не завершена:', error, flush=True)
        return False
    recovery['addresses'] = addresses
    print('Проверяем загрузку Discord через другие текущие адреса DNS…', flush=True)
    candidates.sort(key=lambda trial: rank(trial['rows']), reverse=True)
    for trial in candidates[:3]:
        strategy = trial['strategy']
        z.stop(root)
        z.write_json(Path(root) / 'config.json', dict(previous, strategy=strategy, voice_udp=False))
        z.start(root)
        for address in addresses:
            print('Страница и JavaScript:', strategy, address, flush=True)
            rows = z.discord_tests(app_ip=address)
            attempt = dict(strategy=strategy, address=address, rows=rows, confirmation=[])
            recovery['attempts'].append(attempt)
            if len(rows) != 2 or not all(row.get('application_ok') is True for row in rows):
                continue
            with HostsTrial(root, address) as hosts:
                z.stop(root)
                z.write_json(Path(root) / 'config.json', dict(previous, strategy=strategy))
                z.start(root)
                for _ in range(2):
                    confirmation = z.network_tests(root, quiet=True)
                    attempt['confirmation'].append(confirmation)
                    if not complete(confirmation):
                        break
                else:
                    recovery.update(accepted=True, address=address, backup=str(hosts.backup))
                    report['confirmation'].append(dict(strategy=strategy, rows=confirmation))
                    try:
                        accept(strategy, confirmation)
                    finally:
                        hosts.committed = report['accepted']
                    print('Загрузка Discord подтверждена. Сохранён адрес discord.com:', address, flush=True)
                    print('Резервная копия hosts:', hosts.backup, flush=True)
                    return True
            # Trial failed: clear the voice mode again for the next isolated IP test.
            z.stop(root)
            z.write_json(Path(root) / 'config.json', dict(previous, strategy=strategy, voice_udp=False))
            z.start(root)
    return False
