"""Move allowlisted cache directories as the user; retain account databases."""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid

APPS = ('discord', 'discordcanary', 'discordptb')
CACHES = ('Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache',
          'DawnWebGPUCache', 'ShaderCache', 'GrShaderCache',
          'Service Worker/CacheStorage', 'Service Worker/ScriptCache')


def backup(home):
    home = Path(home)
    moved, skipped = [], []
    opened = []
    directories = {}
    records = []
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    use_fd = os.name == 'posix'

    def directory(parts):
        if use_fd:
            if () not in directories:
                directories[()] = os.open(home, flags)
                opened.append(directories[()])
            fd = directories[()]
            prefix = ()
            for part in parts:
                prefix += (part,)
                if prefix not in directories:
                    directories[prefix] = os.open(part, flags, dir_fd=fd)
                    opened.append(directories[prefix])
                fd = directories[prefix]
            return fd
        path = home
        for part in parts:
            path /= part
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                raise OSError(errno.ENOTDIR, 'Cache parent is not a physical directory')
        return path

    def exists(parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False) if use_fd else (parent / name).lstat()
        except FileNotFoundError:
            return None

    def rename(parent, source, destination):
        if use_fd:
            os.rename(source, destination, src_dir_fd=parent, dst_dir_fd=parent)
        else:
            os.rename(parent / source, parent / destination)

    def ensure_closed():
        if sys.platform == 'darwin':
            result = subprocess.run(['/usr/bin/pgrep', '-u', str(os.getuid()), '-if',
                                     '/Discord[^/]*/.*MacOS|/Discord[^/]*/.*Helper'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode != 1:
                raise OSError('Discord запущен или его состояние не подтверждено; кэш сохранён.')

    try:
        ensure_closed()
        for app in APPS:
            for cache in CACHES:
                parts = ['Library', 'Application Support', app] + cache.split('/')
                label = app + '/' + cache
                try:
                    parent = directory(parts[:-1])
                except FileNotFoundError:
                    continue
                except OSError as error:
                    if error.errno in (errno.ELOOP, errno.ENOTDIR):
                        skipped.append(label)
                        continue
                    raise
                source = parts[-1]
                info = exists(parent, source)
                if info is None:
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    skipped.append(label)
                    continue
                destination = source + '.zapret-backup-' + uuid.uuid4().hex
                ensure_closed()
                # Record before rename: SIGINT may arrive after the OS moved it
                # but before Python returns from the call.
                records.append((parent, source, destination))
                rename(parent, source, destination)
                moved.append(label)
        ensure_closed()
        return dict(moved=moved, skipped=skipped)
    except BaseException as error:
        failures = []
        for parent, source, destination in reversed(records):
            try:
                if exists(parent, destination) is None:
                    continue  # This rename failed before moving anything.
                if exists(parent, source) is not None:
                    raise OSError('Cache was recreated; backup retained: ' + destination)
                rename(parent, destination, source)
            except OSError as rollback:
                failures.append(str(rollback))
        if failures:
            raise OSError(str(error) + '; rollback: ' + '; '.join(failures)) from error
        raise
    finally:
        active_error = sys.exc_info()[0] is not None
        failures = []
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError as error:
                failures.append(error)
        if failures and not active_error:
            raise failures[0]


if __name__ == '__main__':
    try:
        print(json.dumps(backup(sys.argv[1]), ensure_ascii=False))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
