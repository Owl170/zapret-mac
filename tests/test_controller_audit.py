"""Regression checks for failed cleanup and privileged installation writes."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z
import voice_controller as voice


class ControllerAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'installation'
        self.root.mkdir()
        shutil.copytree(z.SOURCE / 'lists', self.root / 'lists')
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        z.prepare_lists(self.root)
        z.write_json(self.root / 'config.json', z.DEFAULTS)

    def symlink(self, target, link, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (NotImplementedError, OSError) as error:
            self.skipTest('Symbolic links unavailable on this host: ' + str(error))

    def test_release_failure_does_not_skip_other_anchor_or_pf_reference(self):
        token_file = self.root / 'runtime/pf-token.json'
        z.write_json(token_file, {'token': '123'})
        with patch.object(z, 'clear_anchor', side_effect=z.Error('TCP clear failed')), patch.object(voice, 'clear_udp') as udp, patch.object(z, 'pf') as pf:
            with self.assertRaisesRegex(z.Error, 'TCP clear failed'):
                z.release_pf(self.root)
        udp.assert_called_once()
        pf.assert_called_once_with('-X', '123')
        self.assertFalse(token_file.exists())

    def test_failed_pf_release_retains_token_for_retry(self):
        token_file = self.root / 'runtime/pf-token.json'
        z.write_json(token_file, {'token': '123'})
        with patch.object(z, 'clear_anchor'), patch.object(voice, 'clear_udp'), patch.object(z, 'pf', side_effect=z.Error('busy')):
            with self.assertRaises(z.Error):
                z.release_pf(self.root)
        self.assertEqual(json.loads(token_file.read_text()), {'token': '123'})
        with patch.object(z, 'clear_anchor'), patch.object(voice, 'clear_udp'), patch.object(z, 'pf'):
            z.release_pf(self.root)
        self.assertFalse(token_file.exists())

    def test_pf_enable_reference_is_released_if_token_cannot_be_saved(self):
        cfg = dict(z.DEFAULTS, ipv6=False)
        with patch.object(z, 'ensure_pf_hooks'), patch.object(z, 'write_json', side_effect=OSError('disk full')), patch.object(z, 'pf', return_value=SimpleNamespace(stdout='Token : 987', stderr='')) as pf:
            with self.assertRaisesRegex(OSError, 'disk full'):
                z.apply_pf(cfg, self.root)
        self.assertIn((('-X', '987'), {}), [(call.args, call.kwargs) for call in pf.call_args_list])
        self.assertFalse(any(call.args == ('-a', z.ANCHOR, '-f', self.root / 'runtime/anchor.conf') for call in pf.call_args_list))

    def test_failed_udp_cleanup_still_clears_pf_and_terminates_tpws(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        backend = Mock(active=False)
        backend.stop.side_effect = OSError('cannot write UDP status')
        fake_fcntl = SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=4)
        with patch.object(z, 'require_mac'), patch.object(z.signal, 'signal'), patch.dict(sys.modules, {'fcntl': fake_fcntl}), patch.object(z, 'is_running', return_value=False), patch.object(voice, 'Backend', return_value=backend), patch.object(z, 'release_pf') as release, patch.object(z, 'run'), patch.object(z, 'wait_ready', side_effect=z.Error('engine died')), patch.object(z.subprocess, 'Popen', return_value=child):
            with self.assertRaisesRegex(OSError, 'cannot write UDP status'):
                z.supervise(self.root)
        self.assertEqual(release.call_count, 2)
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=5)
        self.assertFalse((self.root / 'runtime/state.json').exists())

    def test_stuck_engine_is_killed_even_when_pf_cleanup_fails(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('tpws', 5), None]
        backend = Mock(active=False)
        fake_fcntl = SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=4)
        with patch.object(z, 'require_mac'), patch.object(z.signal, 'signal'), patch.dict(sys.modules, {'fcntl': fake_fcntl}), patch.object(z, 'is_running', return_value=False), patch.object(voice, 'Backend', return_value=backend), patch.object(z, 'release_pf', side_effect=[None, z.Error('PF cleanup failed')]), patch.object(z, 'run'), patch.object(z, 'wait_ready', side_effect=z.Error('engine died')), patch.object(z.subprocess, 'Popen', return_value=child):
            with self.assertRaisesRegex(z.Error, 'PF cleanup failed'):
                z.supervise(self.root)
        child.kill.assert_called_once()
        self.assertFalse((self.root / 'runtime/state.json').exists())

    def test_cleanup_failure_during_trials_still_attempts_previous_service(self):
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), patch.object(z, 'stop', side_effect=[None, z.Error('cleanup failed')]), patch.object(z, 'start', side_effect=[z.Error('trial failed'), None]) as start:
            with self.assertRaisesRegex(z.Error, 'cleanup failed'):
                z.test_strategies(self.root)
        self.assertEqual(z.config(self.root), z.DEFAULTS)
        self.assertEqual(start.call_count, 2)

    def test_report_failure_occurs_after_previous_service_is_restored(self):
        (self.root / 'logs').mkdir()
        row = dict(name='test', url='https://example.com', tls_reached=True, http='200', seconds='0.1', error='')
        real_open = Path.open

        def failing_report(path, *args, **kwargs):
            if path.suffix == '.csv':
                raise OSError('report unavailable')
            return real_open(path, *args, **kwargs)

        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), patch.object(z, 'strategies', return_value={'passthrough': {}, 'split': {}}), patch.object(z, 'stop'), patch.object(z, 'start') as start, patch.object(z, 'network_tests', return_value=[row]), patch.object(z, 'targets', return_value=[('test', row['url'])]), patch.object(Path, 'open', failing_report):
            with self.assertRaisesRegex(OSError, 'report unavailable'):
                z.test_strategies(self.root)
        self.assertEqual(z.config(self.root), z.DEFAULTS)
        self.assertEqual(start.call_count, 3)

    def test_install_rejects_root_directory_symlink_before_stopping_service(self):
        linked = self.base / 'linked-root'
        self.symlink(self.root, linked, directory=True)
        original = (self.root / 'strategies.json').read_bytes()
        with patch.object(z, 'require_mac'), patch.object(z, 'stop') as stop:
            with self.assertRaises(z.Error):
                z.install(z.SOURCE / 'zapret.py', root=linked)
        stop.assert_not_called()
        self.assertEqual((self.root / 'strategies.json').read_bytes(), original)

    def test_install_rejects_destination_symlink_without_touching_external_file(self):
        external = self.base / 'external.txt'
        external.write_text('preserve me', encoding='utf-8')
        self.symlink(external, self.root / 'zapret.py')
        with patch.object(z, 'require_mac'), patch.object(z, 'stop') as stop:
            with self.assertRaises(z.Error):
                z.install(z.SOURCE / 'zapret.py', root=self.root)
        stop.assert_not_called()
        self.assertEqual(external.read_text(), 'preserve me')

    def test_invalid_new_engine_keeps_previous_installation_and_service(self):
        installed = self.root / 'zapret.py'
        installed.write_text('previous version', encoding='utf-8')
        with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), patch.object(z, 'stop') as stop, patch.object(z, 'run', side_effect=z.Error('engine rejected configuration')):
            with self.assertRaisesRegex(z.Error, 'engine rejected configuration'):
                z.install(z.SOURCE / 'zapret.py', root=self.root)
        stop.assert_not_called()
        self.assertEqual(installed.read_text(), 'previous version')

    def test_mid_install_write_failure_restores_previous_files_before_restart(self):
        old_files = {'zapret.py': b'previous controller', 'discord_udp.py': b'previous relay',
                     'bin/tpws': b'previous engine'}
        for name, content in old_files.items():
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
        original_config = (self.root / 'config.json').read_bytes()
        real_write = z.atomic_write
        failed = False

        def fail_once(path, content, mode=0o644):
            nonlocal failed
            if path == self.root / 'voice_controller.py' and not failed:
                failed = True
                raise OSError('copy interrupted')
            return real_write(path, content, mode)

        def restored_start(root):
            for name, content in old_files.items():
                self.assertEqual((root / name).read_bytes(), content)
            self.assertEqual((root / 'config.json').read_bytes(), original_config)
            self.assertFalse((root / 'voice_controller.py').exists())

        with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), patch.object(z, 'is_running', return_value=True), patch.object(z, 'stop') as stop, patch.object(z, 'run'), patch.object(z, 'atomic_write', side_effect=fail_once), patch.object(z, 'start', side_effect=restored_start) as start:
            with self.assertRaisesRegex(OSError, 'copy interrupted'):
                z.install(z.SOURCE / 'zapret.py', root=self.root)
        stop.assert_called_once_with(self.root)
        start.assert_called_once_with(self.root)
        self.assertFalse((self.root / 'installation.json').exists())

    def test_install_atomically_replaces_destination_hard_link(self):
        import os
        external = self.base / 'external.txt'
        external.write_text('preserve me', encoding='utf-8')
        os.link(external, self.root / 'zapret.py')
        with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), patch.object(z, 'stop'), patch.object(z, 'run'):
            z.install(z.SOURCE / 'zapret.py', root=self.root)
        self.assertEqual(external.read_text(), 'preserve me')
        self.assertEqual((self.root / 'zapret.py').read_bytes(), (z.SOURCE / 'zapret.py').read_bytes())

    def test_non_object_configuration_is_rejected_as_a_controlled_error(self):
        for saved in (None, [], 'split', 42):
            with self.subTest(saved=saved):
                z.write_json(self.root / 'config.json', saved)
                with self.assertRaises(z.Error):
                    z.config(self.root)
        with self.assertRaises(z.Error):
            z.validate_config(dict(z.DEFAULTS, strategy=[]), self.root)

    def test_invalid_or_deleted_sudo_user_is_a_controlled_error(self):
        import os
        fake_pwd = SimpleNamespace(getpwuid=Mock(side_effect=KeyError('deleted user')))
        with patch.dict(sys.modules, {'pwd': fake_pwd}), patch.object(os, 'getuid', return_value=0, create=True):
            for uid in ('invalid', '501', '-1'):
                with self.subTest(uid=uid), patch.dict(os.environ, {'SUDO_UID': uid}):
                    with self.assertRaises(z.Error):
                        z.original_user()

    def test_engine_exit_race_during_termination_still_reaps_child(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        child.terminate.side_effect = ProcessLookupError('already exited')
        backend = Mock(active=False)
        fake_fcntl = SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=4)
        with patch.object(z, 'require_mac'), patch.object(z.signal, 'signal'), patch.dict(sys.modules, {'fcntl': fake_fcntl}), patch.object(z, 'is_running', return_value=False), patch.object(voice, 'Backend', return_value=backend), patch.object(z, 'release_pf'), patch.object(z, 'run'), patch.object(z, 'wait_ready', side_effect=z.Error('engine died')), patch.object(z.subprocess, 'Popen', return_value=child):
            with self.assertRaisesRegex(z.Error, 'engine died'):
                z.supervise(self.root)
        child.wait.assert_called_once_with(timeout=5)
        self.assertFalse((self.root / 'runtime/state.json').exists())


if __name__ == '__main__':
    unittest.main()
