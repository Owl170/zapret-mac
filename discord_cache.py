"""Close verified Discord processes and back up caches as the invoking user."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from xml.parsers.expat import ExpatError

APPS = ('discord', 'discordcanary', 'discordptb')
CACHES = ('Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache',
          'DawnWebGPUCache', 'ShaderCache', 'GrShaderCache',
          'Service Worker/CacheStorage', 'Service Worker/ScriptCache')
# Bundle names can change when a user renames or copies the app. Match the
# executable in Contents/MacOS, including the supported clients and helpers.
DISCORD_PROCESS_PATTERN = (r'/Contents/MacOS/Discord( ?Canary| ?PTB)?'
                           r'( Helper( \([^/()]*\))?)?([[:space:]]|$)')
DISCORD_CANDIDATE_PATTERN = (DISCORD_PROCESS_PATTERN +
    r'|/Contents/Frameworks/.*chrome_crashpad_handler([[:space:]]|$)')
BUNDLES = {'com.hnc.Discord': {'Discord'},
           'com.hnc.DiscordCanary': {'Discord Canary', 'DiscordCanary'},
           'com.hnc.DiscordPTB': {'Discord PTB', 'DiscordPTB'}}
EXECUTABLE = re.compile(r'Discord( ?Canary| ?PTB)?( Helper( \([A-Za-z0-9 _-]{1,32}\))?)?', re.I)


def _bundle_info(bundle):
    try:
        with (Path(str(bundle)) / 'Contents' / 'Info.plist').open('rb') as source:
            value = plistlib.load(source)
    except (FileNotFoundError, NotADirectoryError, plistlib.InvalidFileException, ValueError, ExpatError):
        return None
    return value if isinstance(value, dict) else None


def is_discord_executable(value):
    """Check the actual executable and its outer app; never match argv text."""
    if not isinstance(value, str) or not value.startswith('/') or any(c in value for c in '\x00\r\n'):
        return False
    path = PurePosixPath(value)
    if path.as_posix() != value or '..' in path.parts:
        return False
    crashpad = path.name == 'chrome_crashpad_handler'
    if not crashpad and (not EXECUTABLE.fullmatch(path.name)
                         or path.parent.name != 'MacOS' or path.parent.parent.name != 'Contents'
                         or not path.parents[2].name.lower().endswith('.app')):
        return False
    bundles = [parent for parent in path.parents
               if parent.name.lower().endswith('.app') and path.relative_to(parent).parts[:2]
               in (('Contents', 'MacOS'), ('Contents', 'Frameworks'))]
    if not bundles:
        return False
    # A helper's own metadata must not authorize a foreign outer application.
    bundle = bundles[-1]
    info = _bundle_info(bundle)
    if not info or not isinstance(info.get('CFBundleIdentifier'), str):
        raise OSError('Не удалось подтвердить пакет процесса Discord; кэш сохранён.')
    if info['CFBundleIdentifier'] not in BUNDLES:
        return False
    names = BUNDLES[info['CFBundleIdentifier']]
    if not isinstance(info.get('CFBundleExecutable'), str) or info['CFBundleExecutable'] not in names:
        raise OSError('Не удалось подтвердить исполняемый файл пакета Discord; кэш сохранён.')
    relative = path.relative_to(bundle).parts
    if crashpad:
        return len(relative) >= 4 and relative[:2] == ('Contents', 'Frameworks')
    if relative[:2] == ('Contents', 'MacOS'):
        return len(relative) == 3 and path.name in names
    return (len(relative) >= 6 and relative[:2] == ('Contents', 'Frameworks')
            and ' Helper' in path.name)


class MacDiscordProcesses:
    """pgrep finds candidates; libproc and UID verification authorize signals."""
    def __init__(self):
        self.uid = os.getuid()
        if self.uid < 1 or os.geteuid() != self.uid:
            raise OSError('Закрытие Discord должно выполняться от имени обычного пользователя.')
        self.library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.library.proc_pidpath.restype = ctypes.c_int

    @staticmethod
    def _timeout(deadline):
        value = 2 if deadline is None else deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('Не удалось подтвердить остановку Discord за отведённое время; кэш сохранён.')
        return min(2, value)

    def _run(self, args, deadline):
        return subprocess.run(args, capture_output=True, text=True, timeout=self._timeout(deadline))

    def _path(self, pid):
        buffer = ctypes.create_string_buffer(4096)  # PROC_PIDPATHINFO_MAXSIZE.
        ctypes.set_errno(0)
        result = self.library.proc_pidpath(pid, buffer, len(buffer))
        if result <= 0:
            code = ctypes.get_errno()
            if code == errno.ESRCH:
                return None
            raise OSError(code, 'Не удалось проверить исполняемый файл процесса Discord; кэш сохранён.')
        return os.fsdecode(buffer.value)

    def identity(self, pid, deadline=None):
        if type(pid) is not int or pid < 2 or pid == os.getpid():
            return None
        path = self._path(pid)
        if path is None or not is_discord_executable(path):
            return None
        result = self._run(['/bin/ps', '-p', str(pid), '-o', 'uid='], deadline)
        if result.returncode == 1 and not result.stdout.strip():
            return None
        if result.returncode or not re.fullmatch(r'\s*[0-9]+\s*', result.stdout):
            raise OSError('Не удалось проверить владельца процесса Discord; кэш сохранён.')
        if int(result.stdout) != self.uid:
            return None
        # A process can disappear or a PID can be reused between native/ps calls.
        return path if self._path(pid) == path else None

    def snapshot(self, deadline=None):
        result = self._run(['/usr/bin/pgrep', '-u', str(self.uid), '-if',
                            DISCORD_CANDIDATE_PATTERN], deadline)
        if result.returncode == 1 and not result.stdout.strip():
            return {}
        if result.returncode or not re.fullmatch(r'(?:\s*[0-9]+)+\s*', result.stdout):
            raise OSError('Не удалось найти процессы Discord; кэш сохранён.')
        found = {}
        for text in result.stdout.split():
            pid = int(text)
            if pid < 2:
                raise OSError('Некорректный PID Discord; кэш сохранён.')
            path = self.identity(pid, deadline)
            if path is not None:
                found[pid] = path
        return found

    def signal_confirmed(self, pid, path, number, deadline):
        if self.identity(pid, deadline) != path:
            return False
        try:
            os.kill(pid, number)
        except ProcessLookupError:
            return False
        return True


def close_discord(grace=5, force=2):
    """Bound TERM/KILL waits; failure leaves all cache directories untouched."""
    if sys.platform != 'darwin':
        return dict(closed_processes=0, forced_processes=0)
    inspector = MacDiscordProcesses()
    begin = time.monotonic()
    hard_deadline = begin + grace + force + 2  # Include bounded process queries.
    terminated, killed = set(), set()
    current = inspector.snapshot(hard_deadline)
    for number, duration, sent in ((signal.SIGTERM, grace, terminated),
                                   (signal.SIGKILL, force, killed)):
        deadline = min(hard_deadline, time.monotonic() + duration)
        while current:
            for pid, path in current.items():
                identity = (pid, path)
                if identity not in sent and inspector.signal_confirmed(pid, path, number, hard_deadline):
                    sent.add(identity)
            current = inspector.snapshot(hard_deadline)
            if not current or time.monotonic() >= deadline:
                break
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        if not current:
            return dict(closed_processes=len(terminated | killed), forced_processes=len(killed))
    raise OSError('Не удалось полностью закрыть Discord; кэш сохранён. PID: '
                  + ', '.join(str(pid) for pid in sorted(current)[:20]))


def backup(home):
    home = Path(home)
    moved, skipped = [], []
    opened = []
    directories = {}
    records = []
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    use_fd = os.name == 'posix'
    inspector = MacDiscordProcesses() if sys.platform == 'darwin' else None

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
        if inspector is not None and inspector.snapshot(time.monotonic() + 2):
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
            except BaseException as rollback:
                # A second interrupt must not skip independent restorations.
                failures.append(f'{destination}: {type(rollback).__name__}: {rollback}')
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('home')
    parser.add_argument('--close', action='store_true', help='Close Discord before moving caches')
    args = parser.parse_args(argv)
    shutdown = close_discord() if args.close else {}
    report = backup(args.home)
    report.update(shutdown)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
