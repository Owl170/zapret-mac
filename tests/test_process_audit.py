"""Supervisor identity and shutdown races must not signal unrelated processes."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z


class ProcessAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'runtime').mkdir()
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 555})
        self.command = f'{sys.executable} -u {self.root / "zapret.py"} supervise'
        self.processes = {}
        self.inspect_count = 0
        self.inspect_hook = None

        def ps(args, **kwargs):
            if args[0] != '/bin/ps':
                raise AssertionError('Unexpected subprocess: ' + repr(args))
            pid = int(args[args.index('-p') + 1])
            row = self.processes.get(pid)
            result = SimpleNamespace(returncode=0 if row else 1,
                                     stdout=f'{row[0]} {row[1]}\n' if row else '')
            self.inspect_count += 1
            if self.inspect_hook:
                self.inspect_hook(pid, self.inspect_count)
            return result

        for target, options in [(z, {'attribute': 'require_mac'}),
                                (z, {'attribute': 'launch_loaded', 'return_value': False}),
                                (z, {'attribute': 'run', 'side_effect': ps}),
                                (z.time, {'attribute': 'sleep'})]:
            patcher = patch.object(target, **options)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(z, 'release_pf')
        self.release = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(z, 'recover_stale_children')
        self.recover = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(z.os, 'kill')
        self.kill = patcher.start()
        self.addCleanup(patcher.stop)

    def replacement(self):
        self.processes[444] = (0, self.command)
        z.write_json(self.root / 'runtime/state.json', {'pid': 444, 'engine_pid': 666})

    def assert_replacement_preserved(self):
        self.assertEqual(z.get_state(self.root)['pid'], 444)
        self.assertIn(444, self.processes)

    def test_running_requires_exact_root_supervisor_command(self):
        self.processes[333] = (0, self.command)
        self.assertTrue(z.is_running(self.root))

    def test_foreign_command_containing_supervisor_words_is_not_signalled(self):
        self.processes[333] = (0, f'/usr/bin/grep {self.root / "zapret.py"} supervise')
        self.assertFalse(z.is_running(self.root))
        z.stop(self.root)
        self.kill.assert_not_called()
        self.release.assert_called_once_with(self.root)

    def test_non_root_process_with_exact_command_is_not_signalled(self):
        self.processes[333] = (501, self.command)
        self.assertFalse(z.is_running(self.root))
        z.stop(self.root)
        self.kill.assert_not_called()

    def test_state_removed_during_inspection_does_not_change_signal_target(self):
        self.processes[333] = (0, self.command)

        def remove_state(pid, count):
            if count == 1:
                (self.root / 'runtime/state.json').unlink()

        self.inspect_hook = remove_state
        self.kill.side_effect = lambda pid, sig: self.processes.pop(pid)
        z.stop(self.root)
        self.kill.assert_called_once_with(333, z.signal.SIGTERM)
        self.release.assert_called_once_with(self.root)
        self.recover.assert_called_once_with(self.root)

    def test_exit_between_identity_check_and_signal_still_releases_pf(self):
        self.processes[333] = (0, self.command)

        def already_exited(pid, sig):
            self.processes.pop(pid)
            raise ProcessLookupError('exited before signal')

        self.kill.side_effect = already_exited
        z.stop(self.root)
        self.release.assert_called_once_with(self.root)
        self.recover.assert_called_once_with(self.root)
        self.assertFalse((self.root / 'runtime/state.json').exists())

    def test_replacement_before_signal_preserves_new_service_and_pf(self):
        self.processes[333] = (0, self.command)
        self.inspect_hook = lambda pid, count: self.replacement() if count == 1 else None
        with self.assertRaises(z.Error):
            z.stop(self.root)
        self.kill.assert_not_called()
        self.release.assert_not_called()
        self.recover.assert_not_called()
        self.assert_replacement_preserved()

    def test_replacement_during_shutdown_wait_is_not_signalled_or_cleaned_up(self):
        self.processes[333] = (0, self.command)

        def replace_after_signal(pid, sig):
            self.processes.pop(pid)
            self.replacement()

        self.kill.side_effect = replace_after_signal
        with self.assertRaises(z.Error):
            z.stop(self.root)
        self.kill.assert_called_once_with(333, z.signal.SIGTERM)
        self.release.assert_not_called()
        self.recover.assert_not_called()
        self.assert_replacement_preserved()

    def test_reused_pid_with_foreign_command_is_not_signalled(self):
        self.processes[333] = (0, self.command)

        def reuse_pid(pid, count):
            if count == 1:
                self.processes[333] = (0, '/unrelated/root-program')

        self.inspect_hook = reuse_pid
        z.stop(self.root)
        self.kill.assert_not_called()
        self.release.assert_called_once_with(self.root)

    def test_busy_startup_lock_prevents_pf_cleanup(self):
        busy_fcntl = SimpleNamespace(flock=Mock(side_effect=BlockingIOError('startup owns lock')),
                                     LOCK_EX=1, LOCK_NB=4)
        with patch.object(sys, 'platform', 'darwin'), patch.dict(sys.modules, {'fcntl': busy_fcntl}), \
                patch.object(z.time, 'monotonic', side_effect=[0, 3]):
            with self.assertRaises(z.Error):
                z.stop(self.root)
        self.kill.assert_not_called()
        self.release.assert_not_called()
        self.recover.assert_not_called()
        self.assertEqual(z.get_state(self.root)['pid'], 333)

    def test_old_supervisor_releasing_lock_after_state_removal_is_retried(self):
        lock_attempts = 0

        def release_old_lock(file, flags):
            nonlocal lock_attempts
            lock_attempts += 1
            if lock_attempts == 1:
                (self.root / 'runtime/state.json').unlink()
                raise BlockingIOError('old supervisor is closing')

        old_fcntl = SimpleNamespace(flock=release_old_lock, LOCK_EX=1, LOCK_NB=4)
        with patch.object(sys, 'platform', 'darwin'), patch.dict(sys.modules, {'fcntl': old_fcntl}):
            z.stop(self.root)
        self.assertEqual(lock_attempts, 2)
        self.release.assert_called_once_with(self.root)
        self.recover.assert_called_once_with(self.root)
        self.assertFalse((self.root / 'runtime/state.json').exists())

    def test_new_state_during_lock_retry_preserves_new_service(self):
        def startup(file, flags):
            self.replacement()
            raise BlockingIOError('new supervisor starting')

        startup_fcntl = SimpleNamespace(flock=startup, LOCK_EX=1, LOCK_NB=4)
        with patch.object(sys, 'platform', 'darwin'), patch.dict(sys.modules, {'fcntl': startup_fcntl}):
            with self.assertRaises(z.Error):
                z.stop(self.root)
        self.kill.assert_not_called()
        self.release.assert_not_called()
        self.recover.assert_not_called()
        self.assert_replacement_preserved()

    def test_metadata_replaced_during_cleanup_is_not_unlinked(self):
        self.release.side_effect = lambda root: self.replacement()
        with self.assertRaises(z.Error):
            z.stop(self.root)
        self.kill.assert_not_called()
        self.assert_replacement_preserved()


if __name__ == '__main__':
    unittest.main()
