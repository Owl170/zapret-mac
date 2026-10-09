"""Only verified Discord processes may be closed before cache backup."""
import ctypes
import errno
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import discord_cache as cache

MAIN = '/Applications/Chat.app/Contents/MacOS/Discord'
HELPER = '/Applications/Chat.app/Contents/Frameworks/Renamed.app/Contents/MacOS/Discord Helper (Renderer)'
CRASHPAD = '/Applications/Chat.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler'
INFO = dict(CFBundleIdentifier='com.hnc.Discord', CFBundleExecutable='Discord')


class BundleTests(unittest.TestCase):
    def test_main_helper_crashpad_and_channels_allow_renamed_bundles(self):
        for identifier, executable in (('com.hnc.Discord', 'Discord'),
                                       ('com.hnc.DiscordCanary', 'Discord Canary'),
                                       ('com.hnc.DiscordPTB', 'Discord PTB')):
            info = dict(CFBundleIdentifier=identifier, CFBundleExecutable=executable)
            paths = (MAIN.replace('/Discord', '/' + executable),
                     HELPER.replace('/Discord Helper', '/' + executable + ' Helper'), CRASHPAD)
            for path in paths:
                with self.subTest(path=path), patch.object(cache, '_bundle_info', return_value=info):
                    self.assertTrue(cache.is_discord_executable(path))

    def test_other_executables_and_non_bundle_paths_are_rejected(self):
        for path in ('/Applications/Discord.app/Contents/MacOS/Other', MAIN + 'Proxy',
                     '/tmp/Contents/MacOS/Discord', '/tmp/Discord', MAIN + '\n',
                     '/Applications/Chat.app/../Other.app/Contents/MacOS/Discord',
                     '/Applications/Chat.app/Contents/MacOS/chrome_crashpad_handler'):
            with self.subTest(path=path), patch.object(cache, '_bundle_info', return_value=INFO):
                self.assertFalse(cache.is_discord_executable(path))

    def test_foreign_outer_bundle_cannot_be_authorized_by_nested_helper(self):
        foreign = dict(CFBundleIdentifier='org.example.Other', CFBundleExecutable='Other')
        def info(bundle):
            return INFO if bundle.name == 'Renamed.app' else foreign
        with patch.object(cache, '_bundle_info', side_effect=info) as read:
            self.assertFalse(cache.is_discord_executable(HELPER))
        read.assert_called_once_with(PurePosixPath('/Applications/Chat.app'))
        with patch.object(cache, '_bundle_info', return_value=foreign):
            self.assertFalse(cache.is_discord_executable(MAIN))
            self.assertFalse(cache.is_discord_executable(CRASHPAD))

    def test_unknown_or_damaged_discord_bundle_fails_closed(self):
        for info in (None, {}, dict(CFBundleIdentifier='com.hnc.Discord'),
                     dict(INFO, CFBundleExecutable='Other'), dict(INFO, CFBundleExecutable=[]),
                     dict(INFO, CFBundleExecutable={})):
            with self.subTest(info=info), patch.object(cache, '_bundle_info', return_value=info):
                with self.assertRaisesRegex(OSError, 'кэш сохранён'):
                    cache.is_discord_executable(MAIN)
        with patch.object(cache, '_bundle_info', side_effect=PermissionError('bundle unreadable')):
            with self.assertRaises(PermissionError):
                cache.is_discord_executable(MAIN)

    def test_malformed_xml_plist_is_unknown_without_parser_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / 'Contents').mkdir()
            (bundle / 'Contents/Info.plist').write_bytes(b'<?xml version="1.0"?><plist><dict><key>broken</dict>')
            self.assertIsNone(cache._bundle_info(bundle))


class ProcessIdentityTests(unittest.TestCase):
    def setUp(self):
        # Production enters this path only on macOS; keep identity units portable.
        kill = patch.object(signal, 'SIGKILL', 9, create=True)
        kill.start()
        self.addCleanup(kill.stop)

    def inspector(self):
        value = object.__new__(cache.MacDiscordProcesses)
        value.uid = 501
        return value

    def test_root_cannot_load_backend_or_signal_any_process(self):
        with patch.object(cache.os, 'getuid', return_value=0, create=True), patch.object(cache.ctypes, 'CDLL') as load:
            with self.assertRaises(OSError):
                cache.MacDiscordProcesses()
        load.assert_not_called()

    def test_privileged_effective_uid_cannot_load_backend(self):
        with patch.object(cache.os, 'getuid', return_value=501, create=True), \
                patch.object(cache.os, 'geteuid', return_value=0, create=True), patch.object(cache.ctypes, 'CDLL') as load:
            with self.assertRaises(OSError):
                cache.MacDiscordProcesses()
        load.assert_not_called()

    def test_actual_executable_rejects_path_spoofed_in_argv(self):
        inspector = self.inspector()
        result = SimpleNamespace(returncode=0, stdout='101\n')
        with patch.object(inspector, '_run', return_value=result), \
                patch.object(inspector, '_path', return_value='/Applications/Other.app/Contents/MacOS/Other'):
            self.assertEqual(inspector.snapshot(), {})

    def test_uid_and_path_changes_prevent_signal(self):
        for uid, paths in ((0, [MAIN]), (502, [MAIN]),
                           (501, [MAIN, '/Applications/Other.app/Contents/MacOS/Other']),
                           (501, [MAIN, None])):
            inspector = self.inspector()
            with self.subTest(uid=uid, paths=paths), patch.object(cache, 'is_discord_executable', return_value=True), \
                    patch.object(inspector, '_path', side_effect=paths), \
                    patch.object(inspector, '_run', return_value=SimpleNamespace(returncode=0, stdout=str(uid))), \
                    patch.object(cache.os, 'kill') as kill:
                self.assertFalse(inspector.signal_confirmed(101, MAIN, signal.SIGTERM, None))
            kill.assert_not_called()

    def test_matching_identity_is_rechecked_before_each_signal(self):
        inspector = self.inspector()
        with patch.object(cache, 'is_discord_executable', return_value=True), \
                patch.object(inspector, '_path', return_value=MAIN) as path, \
                patch.object(inspector, '_run', return_value=SimpleNamespace(returncode=0, stdout='501')) as query, \
                patch.object(cache.os, 'kill') as kill:
            self.assertTrue(inspector.signal_confirmed(101, MAIN, signal.SIGTERM, None))
            self.assertTrue(inspector.signal_confirmed(101, MAIN, signal.SIGKILL, None))
        self.assertEqual(path.call_count, 4)
        self.assertEqual(query.call_count, 2)
        self.assertEqual([call.args for call in kill.call_args_list], [(101, signal.SIGTERM), (101, signal.SIGKILL)])

    def test_disappeared_pid_is_safe_but_unknown_native_failure_is_not(self):
        inspector = self.inspector()
        inspector.library = Mock()
        inspector.library.proc_pidpath.return_value = 0
        for code in (errno.ESRCH, errno.EPERM, errno.EIO, 0):
            with self.subTest(errno=code), patch.object(cache.ctypes, 'get_errno', return_value=code):
                if code == errno.ESRCH:
                    self.assertIsNone(inspector._path(101))
                else:
                    with self.assertRaises(OSError):
                        inspector._path(101)

    def test_unknown_process_query_and_invalid_pids_refuse(self):
        inspector = self.inspector()
        for code, output in ((2, ''), (0, '1'), (0, '-5'), (0, '101 extra'), (0, ''), (1, '101')):
            with self.subTest(code=code, output=output), \
                    patch.object(inspector, '_run', return_value=SimpleNamespace(returncode=code, stdout=output)):
                with self.assertRaises(OSError):
                    inspector.snapshot()

    def test_vanished_after_identity_check_is_not_an_error(self):
        inspector = self.inspector()
        with patch.object(inspector, 'identity', return_value=MAIN), \
                patch.object(cache.os, 'kill', side_effect=ProcessLookupError):
            self.assertFalse(inspector.signal_confirmed(101, MAIN, signal.SIGTERM, None))


class ShutdownTests(unittest.TestCase):
    def setUp(self):
        kill = patch.object(signal, 'SIGKILL', 9, create=True)
        kill.start()
        self.addCleanup(kill.stop)

    def clock(self):
        value = [0.0]
        def sleep(seconds):
            value[0] += seconds
        return value, patch.object(cache.time, 'monotonic', side_effect=lambda: value[0]), \
            patch.object(cache.time, 'sleep', side_effect=sleep)

    def test_term_then_kill_only_confirmed_remainders(self):
        current = {101: MAIN, 102: HELPER, 103: CRASHPAD}
        inspector = Mock()
        inspector.snapshot.side_effect = lambda *args: dict(current)
        def send(pid, path, number, deadline):
            if pid != 102 or number == signal.SIGKILL:
                current.pop(pid, None)
            return True
        inspector.signal_confirmed.side_effect = send
        clock, now, sleep = self.clock()
        with patch.object(cache.sys, 'platform', 'darwin'), patch.object(cache, 'MacDiscordProcesses', return_value=inspector), now, sleep:
            self.assertEqual(cache.close_discord(.25, .25), dict(closed_processes=3, forced_processes=1))
        self.assertLessEqual(clock[0], .5)
        signals = [(call.args[0], call.args[2]) for call in inspector.signal_confirmed.call_args_list]
        self.assertEqual(signals, [(101, signal.SIGTERM), (102, signal.SIGTERM), (103, signal.SIGTERM), (102, signal.SIGKILL)])

    def test_respawned_process_is_rescanned_and_closed(self):
        inspector = Mock()
        inspector.snapshot.side_effect = [{101: MAIN}, {202: MAIN}, {}]
        inspector.signal_confirmed.return_value = True
        _, now, sleep = self.clock()
        with patch.object(cache.sys, 'platform', 'darwin'), patch.object(cache, 'MacDiscordProcesses', return_value=inspector), now, sleep:
            self.assertEqual(cache.close_discord(.25, .25)['closed_processes'], 2)
        self.assertEqual([call.args[0] for call in inspector.signal_confirmed.call_args_list], [101, 202])

    def test_stubborn_processes_are_bounded_and_prevent_backup(self):
        inspector = Mock()
        inspector.snapshot.return_value = {101: MAIN}
        inspector.signal_confirmed.return_value = True
        clock, now, sleep = self.clock()
        with patch.object(cache.sys, 'platform', 'darwin'), patch.object(cache, 'MacDiscordProcesses', return_value=inspector), now, sleep:
            with self.assertRaisesRegex(OSError, 'кэш сохранён'):
                cache.close_discord(.25, .25)
        self.assertLessEqual(clock[0], .5)
        self.assertEqual(inspector.signal_confirmed.call_count, 2)

    def test_query_failure_or_signal_denial_prevents_backup(self):
        for error in (PermissionError('signal denied'), subprocess.TimeoutExpired('ps', 2), OSError('identity unknown')):
            with self.subTest(error=type(error).__name__), patch.object(cache, 'close_discord', side_effect=error), \
                    patch.object(cache, 'backup') as backup:
                with self.assertRaises(type(error)):
                    cache.main(['/home/test', '--close'])
            backup.assert_not_called()

    def test_cli_prints_one_json_after_shutdown_then_backup(self):
        output = io.StringIO()
        order = []
        def close():
            order.append('close')
            return dict(closed_processes=3, forced_processes=1)
        def backup(home):
            order.append('backup')
            return dict(moved=['discord/Cache'], skipped=[])
        with patch.object(cache, 'close_discord', side_effect=close), patch.object(cache, 'backup', side_effect=backup), patch('sys.stdout', output):
            cache.main(['/home/test', '--close'])
        self.assertEqual(order, ['close', 'backup'])
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())['forced_processes'], 1)

    def test_non_mac_shutdown_is_noop(self):
        with patch.object(cache.sys, 'platform', 'win32'), patch.object(cache, 'MacDiscordProcesses') as backend:
            self.assertEqual(cache.close_discord(), dict(closed_processes=0, forced_processes=0))
        backend.assert_not_called()


@unittest.skipUnless(sys.platform == 'darwin', 'Needs native macOS process identity')
class NativeShutdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='zapret-shutdown-fixture-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        source = cls.root / 'loop.c'
        source.write_text('#include <signal.h>\n#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n'
                          'int main(int argc, char **argv) {\n'
                          'if (argc > 1 && strcmp(argv[1], "ignore") == 0) signal(SIGTERM, SIG_IGN);\n'
                          'puts("ready"); fflush(stdout); for (;;) pause(); }\n')
        cls.binary = cls.root / 'loop'
        subprocess.run(['/usr/bin/clang', '-std=c99', '-Wall', '-Werror', str(source), '-o', str(cls.binary)],
                       capture_output=True, text=True, timeout=30, check=True)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.inspector = cache.MacDiscordProcesses()
        run = self.inspector._run
        def isolated(args, deadline):
            # Never close a developer's real Discord while running this test.
            if args[0] == '/usr/bin/pgrep':
                args = [args[0], '-P', str(os.getpid()), *args[1:]]
            return run(args, deadline)
        self.inspector._run = isolated
        self.backend = patch.object(cache, 'MacDiscordProcesses', return_value=self.inspector)
        self.backend.start()
        self.addCleanup(self.backend.stop)

    def spawn(self, relative, args=(), info=INFO):
        bundle = self.base / 'Renamed.app'
        (bundle / 'Contents').mkdir(parents=True, exist_ok=True)
        if info is not None:
            with (bundle / 'Contents/Info.plist').open('wb') as output:
                plistlib.dump(info, output)
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.binary, path)
        path.chmod(0o755)
        child = subprocess.Popen([str(path), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdout.close()
            child.stderr.close()
        self.addCleanup(cleanup)
        import select
        self.assertTrue(select.select([child.stdout], [], [], 3)[0], 'native fixture did not become ready')
        self.assertEqual(child.stdout.readline().strip(), 'ready')
        self.assertEqual(Path(self.inspector._path(child.pid)).resolve(), path.resolve())
        return child

    def test_renamed_main_helpers_and_crashpad_close_as_current_user(self):
        children = [self.spawn(path) for path in ('Contents/MacOS/Discord',
                    'Contents/Frameworks/Renamed Helper.app/Contents/MacOS/Discord Helper (Renderer)',
                    'Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler')]
        report = cache.close_discord(.2, 1)
        self.assertEqual(report, dict(closed_processes=3, forced_processes=0))
        self.assertTrue(all(child.wait(timeout=2) == -signal.SIGTERM for child in children))

    def test_sigterm_ignoring_native_discord_requires_sigkill(self):
        child = self.spawn('Contents/MacOS/Discord', args=('ignore',))
        self.assertEqual(cache.close_discord(.15, 1), dict(closed_processes=1, forced_processes=1))
        self.assertEqual(child.wait(timeout=2), -signal.SIGKILL)

    def test_foreign_actual_executable_with_discord_path_argument_is_untouched(self):
        child = self.spawn('Contents/MacOS/Other', args=(MAIN,))
        self.assertEqual(cache.close_discord(.1, .1)['closed_processes'], 0)
        self.assertIsNone(child.poll())

    def test_missing_discord_metadata_preserves_running_process_and_cache(self):
        child = self.spawn('Contents/MacOS/Discord', info=None)
        home = self.base / 'home'
        entry = home / 'Library/Application Support/discord/Cache/entry'
        entry.parent.mkdir(parents=True)
        entry.write_bytes(b'preserve')
        with self.assertRaisesRegex(OSError, 'кэш сохранён'):
            cache.main([str(home), '--close'])
        self.assertIsNone(child.poll())
        self.assertEqual(entry.read_bytes(), b'preserve')

    def test_foreign_bundle_crashpad_and_discord_named_executable_are_untouched(self):
        info = dict(CFBundleIdentifier='org.example.Other', CFBundleExecutable='Other')
        children = [self.spawn(path, info=info) for path in ('Contents/MacOS/Discord',
                    'Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler')]
        self.assertEqual(cache.close_discord(.1, .1)['closed_processes'], 0)
        self.assertTrue(all(child.poll() is None for child in children))


if __name__ == '__main__':
    unittest.main()
