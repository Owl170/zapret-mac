#!/usr/bin/env python3
"""Create a portable zip, preserving executable flags for macOS launchers."""
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile

NAMES = ['README.md', 'LICENSE', 'THIRD_PARTY.md', 'VERSION', 'PROVENANCE.json',
         'strategies.json', 'targets.txt', 'zapret.py', 'discord_udp.py', 'voice_controller.py', 'install.command',
         'service.command', 'uninstall.command', 'engine', 'licenses', 'lists',
         'voice.command', 'VOICE.md', 'payloads', 'native', 'scripts', 'tests', '.github', '.gitattributes', '.gitignore']


def package_files(root):
    for name in NAMES:
        path = root / name
        if not path.exists():
            raise FileNotFoundError(path)
        files = sorted(path.rglob('*')) if path.is_dir() else [path]
        for file in files:
            if not file.is_file() or '__pycache__' in file.parts or file.suffix == '.pyc':
                continue
            yield file


def package(root):
    output = root / 'dist'
    output.mkdir(exist_ok=True)
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version):
        raise ValueError('VERSION must contain a stable semantic version.')
    manifest = json.loads((root / 'PROVENANCE.json').read_text(encoding='utf-8'))
    if manifest['version'] != version:
        raise ValueError('PROVENANCE version mismatch. Run scripts/update_version.py.')
    for relative, expected in manifest['sha256'].items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
            raise ValueError(f'Provenance hash mismatch: {relative}. Run scripts/update_version.py.')
    archive = output / f'ZapretMac-{version}.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for file in package_files(root):
            info = zipfile.ZipInfo('ZapretMac/' + file.relative_to(root).as_posix())
            info.create_system = 3
            executable = file.suffix == '.command'
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zipped.writestr(info, file.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / (archive.name + '.sha256')).write_text(digest + '  ' + archive.name + '\n', encoding='utf-8')
    print(archive)
    print('SHA256:', digest)
    return archive


if __name__ == '__main__':
    package(Path(__file__).resolve().parents[1])
