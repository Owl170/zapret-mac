#!/usr/bin/env python3
"""Create a portable zip, preserving executable flags for macOS launchers."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

NAMES = ['README.md', 'AUDIT.md', 'LICENSE', 'THIRD_PARTY.md', 'VERSION', 'PROVENANCE.json',
         'strategies.json', 'targets.txt', 'zapret.py', 'discord_udp.py', 'voice_controller.py',
         'discord_cache.py', 'discord_probe.py', 'strategy_picker.py', 'application_update.py',
         'discord_recovery.py', 'install.command',
         'service.command', 'uninstall.command', 'engine', 'licenses', 'lists',
         'voice.command', 'VOICE.md', 'payloads', 'native', 'scripts', 'tests', '.github', '.gitattributes', '.gitignore']
ENGINE_OUTPUTS = {'engine/tpws/' + name + suffix
                  for name in ('tpws', 'tpwsa', 'tpwsx') for suffix in ('', '.dSYM')}


def package_files(root):
    root = Path(root)
    if root.is_symlink() or getattr(root, 'is_junction', lambda: False)():
        raise ValueError(f'The release root must not be a symbolic link: {root}')
    collected = []

    def collect(path):
        relative = path.relative_to(root)
        if ('__pycache__' in relative.parts or path.suffix == '.pyc' or path.name == '.DS_Store'
                or relative.as_posix() in ENGINE_OUTPUTS
                or (relative.parts[:2] == ('engine', 'tpws') and path.suffix == '.o')):
            return
        if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
            raise ValueError(f'Symbolic links are not allowed in a release: {path}')
        if path.is_dir():
            for child in path.iterdir():
                collect(child)
        elif path.is_file():
            collected.append(path)
        else:
            raise ValueError(f'Release entry is not a regular file: {path}')

    for name in NAMES:
        path = root / name
        if not path.exists() and not path.is_symlink():
            raise FileNotFoundError(path)
        collect(path)
    # Path ordering is case insensitive on Windows. ZIP order must be identical
    # on Windows and macOS/Linux, including mixed-case names.
    yield from sorted(collected, key=lambda path: path.relative_to(root).as_posix())


def replace_files(contents):
    """Stage all writes and restore previous files if a replacement fails."""
    staged, backups, modes = {}, {}, {}
    committed, retained = [], set()
    operation_error = None

    def report_cleanup(path, error):
        try:
            print(f'Temporary file cleanup failed for {path}: {error}', file=sys.stderr)
        except BaseException:
            # Diagnostics must not replace the error that requires recovery.
            pass

    def temporary(path, data, mode):
        fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
        target = Path(name)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
            os.chmod(target, mode)
        except BaseException:
            try:
                target.unlink(missing_ok=True)
            except BaseException as cleanup_error:
                report_cleanup(target, cleanup_error)
            raise
        return target

    try:
        # All originals and staged writes exist before the first replacement.
        for path, data in contents.items():
            if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                raise ValueError(f'Refusing to replace a symbolic link: {path}')
            modes[path] = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
            backups[path] = temporary(path, path.read_bytes(), modes[path]) if path.exists() else None
            staged[path] = temporary(path, data, modes[path])
        for path, temporary_path in staged.items():
            # A signal may interrupt Python after the rename already completed.
            # Include the attempt in rollback before calling into the filesystem.
            committed.append(path)
            os.replace(temporary_path, path)
    except BaseException as error:
        operation_error = error
        for path in reversed(committed):
            try:
                if backups[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    os.replace(backups[path], path)
            except BaseException:
                retained.add(backups[path] or path)
        if retained:
            raise RuntimeError('Rollback failed; recovery files retained: ' +
                               ', '.join(str(path) for path in retained)) from error
        raise
    finally:
        cleanup_errors = []
        for path in [*staged.values(), *backups.values()]:
            if path is not None and path not in retained:
                try:
                    path.unlink(missing_ok=True)
                except BaseException as cleanup_error:
                    cleanup_errors.append((path, cleanup_error))
        for path, cleanup_error in cleanup_errors:
            report_cleanup(path, cleanup_error)
        if cleanup_errors and operation_error is None:
            raise cleanup_errors[0][1]


def package(root):
    root = Path(root)
    # Capture bytes once: files changing after validation must not silently
    # enter the archive with different content from their validated hashes.
    contents = {file.relative_to(root).as_posix(): file.read_bytes() for file in package_files(root)}
    output = root / 'dist'
    if output.is_symlink() or getattr(output, 'is_junction', lambda: False)():
        raise ValueError('The release output directory must not be a symbolic link.')
    output.mkdir(exist_ok=True)
    version = contents['VERSION'].decode('utf-8').strip()
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version):
        raise ValueError('VERSION must contain a stable semantic version.')
    manifest = json.loads(contents['PROVENANCE.json'].decode('utf-8'))
    if manifest['version'] != version:
        raise ValueError('PROVENANCE version mismatch. Run scripts/update_version.py.')
    hashes = manifest.get('sha256')
    expected_names = set(contents) - {'PROVENANCE.json'}
    if not isinstance(hashes, dict) or set(hashes) != expected_names:
        raise ValueError('Provenance must cover exactly every packaged file except PROVENANCE.json.')
    for relative, expected in hashes.items():
        if hashlib.sha256(contents[relative]).hexdigest() != expected:
            raise ValueError(f'Provenance hash mismatch: {relative}. Run scripts/update_version.py.')
    archive = output / f'ZapretMac-{version}.zip'
    fd, temporary_name = tempfile.mkstemp(prefix='.ZapretMac-', suffix='.zip', dir=output)
    os.close(fd)
    temporary_archive = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary_archive, 'w', zipfile.ZIP_DEFLATED) as zipped:
            for relative, data in contents.items():
                info = zipfile.ZipInfo('ZapretMac/' + relative)
                info.create_system = 3
                executable = Path(relative).suffix == '.command'
                info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zipped.writestr(info, data)
        archive_bytes = temporary_archive.read_bytes()
        digest = hashlib.sha256(archive_bytes).hexdigest()
        checksum = (digest + '  ' + archive.name + '\n').encode('utf-8')
        replace_files({archive: archive_bytes, output / (archive.name + '.sha256'): checksum})
    finally:
        temporary_archive.unlink(missing_ok=True)
    print(archive)
    print('SHA256:', digest)
    return archive


if __name__ == '__main__':
    package(Path(__file__).resolve().parents[1])
