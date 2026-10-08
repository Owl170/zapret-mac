"""Install verified stable releases from Owl170/zapret-mac without Git or Homebrew."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile

import zapret as z

REPOSITORY = 'https://github.com/Owl170/zapret-mac'
LATEST = 'https://api.github.com/repos/Owl170/zapret-mac/releases/latest'
MAX_ZIP = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
HOSTS = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com',
         'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,6})\.(0|[1-9][0-9]{0,6})\.(0|[1-9][0-9]{0,6})', value):
        raise z.Error('Некорректная стабильная версия ZapretMac.')
    return tuple(map(int, value.split('.')))


def allowed_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username
            or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
        raise z.Error('Неожиданный адрес загрузки релиза GitHub.')


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        allowed_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def download(url, limit):
    allowed_url(url)
    opener = urllib.request.build_opener(ReleaseRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={'User-Agent': 'ZapretMac-updater',
                                                  'Cache-Control': 'no-cache', 'Accept-Encoding': 'identity'})
    deadline = time.monotonic() + 120
    with opener.open(request, timeout=15) as response:
        allowed_url(response.geturl())
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or int(length) > limit):
            raise z.Error('Файл релиза превышает лимит загрузки.')
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise z.Error('Загрузка релиза заняла слишком много времени.')
            block = response.read1(min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                raise z.Error('Файл релиза превышает лимит загрузки.')
        if length is not None and len(data) != int(length):
            raise z.Error('Файл релиза загружен не полностью.')
        return bytes(data)


def latest_release():
    remote = json.loads(download(LATEST, 2 * 1024 * 1024))
    if (not isinstance(remote, dict) or remote.get('draft') is not False
            or remote.get('prerelease') is not False):
        raise z.Error('GitHub не вернул стабильный опубликованный релиз.')
    tag = remote.get('tag_name')
    if not isinstance(tag, str) or not tag.startswith('v'):
        raise z.Error('Некорректный тег релиза ZapretMac.')
    number = tag[1:]
    version_tuple(number)
    return remote, number


def release_assets(remote, number):
    name = f'ZapretMac-{number}.zip'
    assets = remote.get('assets')
    if not isinstance(assets, list):
        raise z.Error('В релизе нет списка файлов.')
    result = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise z.Error('Некорректное описание файла релиза.')
        filename = asset.get('name')
        if filename not in (name, name + '.sha256'):
            continue
        if filename in result or asset.get('state') != 'uploaded':
            raise z.Error('Файл релиза ещё не готов или повторяется.')
        expected = f'{REPOSITORY}/releases/download/v{number}/{filename}'
        if asset.get('browser_download_url') != expected:
            raise z.Error('Файл релиза принадлежит неожиданному адресу.')
        size = asset.get('size')
        if type(size) is not int or not 0 < size <= (MAX_ZIP if filename == name else 4096):
            raise z.Error('Некорректный размер файла релиза.')
        result[filename] = asset
    if set(result) != {name, name + '.sha256'}:
        raise z.Error('В релизе пока нет ZIP и его контрольной суммы. Повторите позже.')
    return result[name], result[name + '.sha256']


def verified_archive(asset, checksum_asset):
    checksum = download(checksum_asset['browser_download_url'], 4096)
    if len(checksum) != checksum_asset['size']:
        raise z.Error('Размер файла контрольной суммы не совпал.')
    match = re.fullmatch(r'([0-9a-f]{64})  ' + re.escape(asset['name']) + r'\n?', checksum.decode('ascii'))
    if not match:
        raise z.Error('Некорректная контрольная сумма ZIP.')
    data = download(asset['browser_download_url'], MAX_ZIP)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != asset['size'] or digest != match[1]:
        raise z.Error('Проверка SHA-256 или размера ZIP не пройдена; установка отменена.')
    api_digest = asset.get('digest')
    if api_digest is not None and api_digest != 'sha256:' + digest:
        raise z.Error('Контрольная сумма GitHub не совпала; установка отменена.')
    return data


def extract_verified(data, destination, number):
    """Validate the entire archive before writing into a private empty directory."""
    destination = Path(destination)
    if destination.is_symlink() or any(destination.iterdir()):
        raise z.Error('Для обновления нужен пустой временный каталог.')
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        infos = bundle.infolist()
        if not 1 <= len(infos) <= 5000 or sum(i.file_size for i in infos) > MAX_EXPANDED:
            raise z.Error('Архив релиза превышает лимит распаковки.')
        files, names = {}, set()
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = info.external_attr >> 16
            if (name in names or not re.fullmatch(r'[A-Za-z0-9_./-]+', name)
                    or path.parts[:1] != ('ZapretMac',) or '..' in path.parts
                    or name != path.as_posix() + ('/' if info.is_dir() else '')
                    or info.flag_bits & 1 or info.file_size > MAX_ZIP
                    or stat.S_IFMT(mode) not in (0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG)):
                raise z.Error('Архив содержит небезопасный путь или тип файла.')
            names.add(name)
            if not info.is_dir():
                if len(path.parts) < 2:
                    raise z.Error('Некорректный корень архива.')
                files[path.relative_to('ZapretMac').as_posix()] = bundle.read(info)
        manifest = json.loads(files.get('PROVENANCE.json', b'null'))
        if not isinstance(manifest, dict) or manifest.get('version') != number:
            raise z.Error('Версия манифеста не совпала с релизом.')
        hashes = manifest.get('sha256')
        if not isinstance(hashes, dict) or set(hashes) != set(files) - {'PROVENANCE.json'}:
            raise z.Error('Манифест не покрывает все файлы релиза.')
        for name, expected in hashes.items():
            if hashlib.sha256(files[name]).hexdigest() != expected:
                raise z.Error('Не совпала контрольная сумма файла: ' + name)
        if files.get('VERSION', b'').decode('utf-8').strip() != number:
            raise z.Error('Версия внутри ZIP не совпала с релизом.')
        for name in ('zapret.py', 'install.command', 'engine/tpws/Makefile',
                     'native/pf_abi_probe.c', 'discord_udp.py'):
            if name not in files:
                raise z.Error('В архиве отсутствует файл установки: ' + name)
        # Reject file/directory collisions before any extraction.
        for name in files:
            if any(parent.as_posix() in files for parent in PurePosixPath(name).parents if parent != PurePosixPath('.')):
                raise z.Error('В архиве конфликтуют файл и каталог.')
        for name, content in files.items():
            path = destination / 'ZapretMac' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as output:
                output.write(content)
            path.chmod(0o755 if path.suffix == '.command' else 0o644)
    return destination / 'ZapretMac'


def build_engine(source):
    result = subprocess.run(['/usr/bin/xcode-select', '-p'], capture_output=True, text=True)
    if result.returncode:
        raise z.Error('Для обновления нужны Apple Command Line Tools. Выполните xcode-select --install.')
    print('Собираем новую версию для Apple Silicon и Intel…', flush=True)
    command = ['/usr/bin/make', '-C', str(source / 'engine/tpws'), 'mac', 'CC=clang',
               'CFLAGS=-std=gnu99 -Os -ffunction-sections -fdata-sections', 'LDFLAGS=']
    if subprocess.run(command, timeout=300).returncode:
        raise z.Error('Сборка не завершена; установленная версия сохранена.')
    probe = source.parent / 'pf-abi'
    z.run(['/usr/bin/clang', '-I' + str(source / 'engine/tpws/macos'),
           source / 'native/pf_abi_probe.c', '-o', probe], timeout=60)
    native = json.loads(z.run([probe]).stdout)
    python = json.loads(z.run([sys.executable, source / 'discord_udp.py', 'abi']).stdout)
    if native != python:
        raise z.Error('PF ABI новой версии не совпал; установка отменена.')
    return source / 'engine/tpws/tpws'


def update(root=z.ROOT):
    z.require_mac(True)
    z.original_user()  # Preserve the original sudo identity in the child installer.
    print('Проверяем последний стабильный релиз ZapretMac на GitHub…', flush=True)
    remote, number = latest_release()
    current = z.version(root)
    comparison = version_tuple(current)
    if comparison >= version_tuple(number):
        print('Уже установлена актуальная версия ZapretMac: ' + current + '.')
        return False
    asset, checksum = release_assets(remote, number)
    print(f'Обновление ZapretMac: {current} → {number}. Загружаем и проверяем архив…', flush=True)
    data = verified_archive(asset, checksum)
    try:
        with tempfile.TemporaryDirectory(prefix='zapret-update-') as directory:
            source = extract_verified(data, Path(directory), number)
            engine = build_engine(source)
            # Run the new installer without nested sudo: retain SUDO_UID and use
            # the installer's own lock/rollback, never hold the parent control lock.
            print('Устанавливаем обновление. Дождитесь завершения автоподбора…', flush=True)
            result = subprocess.run([sys.executable, str(source / 'zapret.py'), 'install',
                                     '--engine', str(engine), '--update'])
            if result.returncode and version_tuple(z.version(root)) < version_tuple(number):
                raise z.Error('Установщик обновления завершился с ошибкой. Проверьте сообщения выше и повторите попытку.')
    except (zipfile.BadZipFile, UnicodeError) as error:
        raise z.Error('Некорректный архив релиза: ' + str(error)) from None
    installed = z.version(root)
    if version_tuple(installed) < version_tuple(number):
        raise z.Error('Не удалось подтвердить установленную версию после обновления.')
    print('Установлена версия ZapretMac ' + installed + '. Настройки и пользовательские списки сохранены.', flush=True)
    if result.returncode:
        print('Файлы обновлены, но настройка запуска не завершена. После перезапуска меню выберите пункт 1; '
              'ошибка установщика показана выше.', flush=True)
    print('Полностью перезапустите Discord через ⌘Q.', flush=True)
    return True
