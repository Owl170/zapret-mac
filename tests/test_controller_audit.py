"""Regression checks for failed cleanup and privileged installation writes."""
import json
import os
from pathlib import Path, PurePosixPath
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
        # Recovery executes only on macOS; model its SIGKILL in Windows mocks.
        sigkill = patch.object(z.signal, 'SIGKILL', getattr(z.signal, 'SIGKILL', 9), create=True)
        sigkill.start()
        self.addCleanup(sigkill.stop)
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

    def test_stop_recovers_only_recorded_root_children_after_supervisor_sigkill(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444, 'phase': 'running'})
        z.write_json(self.root / 'runtime/udp-status.json', {'pid': 555, 'ready': True})
        commands = {444: str(self.root / 'bin/tpws') + ' --port=988 --user=root',
                    555: f'{sys.executable} -u {self.root / "discord_udp.py"} serve --root {self.root}'}
        alive = set(commands)

        def ps(args, **kwargs):
            self.assertEqual(args[:2], ['/bin/ps', '-ww'])
            self.assertEqual(args[-2:], ['-o', 'uid=,command='])
            pid = int(args[args.index('-p') + 1])
            return SimpleNamespace(returncode=0 if pid in alive else 1,
                                   stdout='0 ' + commands[pid] + '\n' if pid in alive else '')

        def terminate(pid, sig):
            alive.discard(pid)

        with patch.object(z, 'require_mac'), patch.object(z, 'launch_loaded', return_value=False), patch.object(z, 'is_running', return_value=False), patch.object(z, 'release_pf'), patch.object(z, 'run', side_effect=ps), patch.object(z.os, 'kill', side_effect=terminate) as kill:
            z.stop(self.root)
        self.assertEqual([call.args for call in kill.call_args_list], [(444, z.signal.SIGTERM), (555, z.signal.SIGTERM)])
        self.assertFalse((self.root / 'runtime/state.json').exists())

    def test_reused_pids_and_non_root_processes_are_never_signalled(self):
        engine = str(self.root / 'bin/tpws')
        udp = f'{sys.executable} -u {self.root / "discord_udp.py"} serve --root {self.root}'
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        z.write_json(self.root / 'runtime/udp-status.json', {'pid': 555})
        for engine_line, udp_line in [('501 ' + engine + ' --port=988', '501 ' + udp),
                                      ('0 ' + engine + '-other --port=988', '0 other-process --saved-command=' + udp),
                                      ('0 /unrelated/tpws --port=988', '0 ' + udp + '-other')]:
            with self.subTest(engine=engine_line, udp=udp_line):
                def ps(args, **kwargs):
                    pid = int(args[args.index('-p') + 1])
                    return SimpleNamespace(returncode=0, stdout=(engine_line if pid == 444 else udp_line) + '\n')
                with patch.object(z, 'is_running', return_value=False), patch.object(z, 'run', side_effect=ps), patch.object(z.os, 'kill') as kill:
                    z.recover_stale_children(self.root)
                kill.assert_not_called()

    def test_recovery_never_touches_children_of_live_supervisor(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        z.write_json(self.root / 'runtime/udp-status.json', {'pid': 555})
        with patch.object(z, 'is_running', return_value=True), patch.object(z, 'run') as run, patch.object(z.os, 'kill') as kill:
            z.recover_stale_children(self.root)
        run.assert_not_called()
        kill.assert_not_called()

    def test_old_python_interpreter_does_not_hide_a_recorded_udp_child(self):
        older = self.base / 'Python Tools' / 'python3.9'
        older.parent.mkdir()
        older.write_bytes(b'old interpreter')
        command = f'0 {older} -u {self.root / "discord_udp.py"} serve --root {self.root}\n'
        with patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=command)):
            self.assertTrue(z.matches_stale_child(555, 'udp', self.root))

    def test_deleted_old_python_interpreter_still_identifies_recorded_udp_child(self):
        older = self.base / 'python3.9'
        older.write_bytes(b'old interpreter')
        older.unlink()
        command = f'0 {older} -u {self.root / "discord_udp.py"} serve --root {self.root}\n'
        with patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=command)):
            self.assertTrue(z.matches_stale_child(555, 'udp', self.root))

    def test_supervisor_identity_requires_exact_root_uid_script_and_arguments(self):
        valid = f'{sys.executable} -u {self.root / "zapret.py"} supervise'
        for output, expected in [(f'0 {valid}\n', True), (f'501 {valid}\n', False),
                                 (f'0 unrelated-process --saved-command={valid}\n', False),
                                 (f'0 {valid}-other\n', False),
                                 (f'0 {sys.executable} -u {self.root / "zapret.py"} status --supervise\n', False)]:
            with self.subTest(output=output), patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=output)):
                self.assertEqual(z.matches_stale_child(555, 'supervisor', self.root), expected)

    def test_posix_shell_prefix_cannot_spoof_saved_python_child_identity(self):
        suffixes = {'udp': f' -u {self.root / "discord_udp.py"} serve --root {self.root}',
                    'supervisor': f' -u {self.root / "zapret.py"} supervise'}
        prefixes = ['/bin/sh -c /usr/bin/python3', '/bin/sh -- /usr/bin/python3',
                    '/bin/echo /usr/bin/python3', '/usr/bin/python3 -E /usr/bin/python3']
        # Explicit POSIX semantics make this regression meaningful on Windows.
        for kind, suffix in suffixes.items():
            for prefix in prefixes:
                command = f'0 {prefix}{suffix}\n'
                with self.subTest(kind=kind, prefix=prefix), patch.object(z, 'Path', PurePosixPath), patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=command)):
                    self.assertFalse(z.matches_stale_child(555, kind, self.root))

    def test_deleted_posix_python_path_with_spaces_still_matches_exact_script(self):
        prefix = '/Applications/Old Python Tools/python3.9'
        for kind, suffix in [('udp', f' -u {self.root / "discord_udp.py"} serve --root {self.root}'),
                             ('supervisor', f' -u {self.root / "zapret.py"} supervise')]:
            command = f'0 {prefix}{suffix}\n'
            with self.subTest(kind=kind), patch.object(z, 'Path', PurePosixPath), patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=command)):
                self.assertTrue(z.matches_stale_child(555, kind, self.root))

    def test_bad_udp_metadata_does_not_block_verified_engine_recovery(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        for status in ('{', '[]', 'null', '42'):
            with self.subTest(status=status):
                (self.root / 'runtime/udp-status.json').write_text(status, encoding='utf-8')
                alive = True

                def ps(args, **kwargs):
                    self.assertEqual(int(args[args.index('-p') + 1]), 444)
                    return SimpleNamespace(returncode=0 if alive else 1,
                                           stdout=f'0 {self.root / "bin/tpws"} --port=988\n' if alive else '')

                def terminate(pid, sig):
                    nonlocal alive
                    alive = False

                with patch.object(z, 'is_running', return_value=False), patch.object(z, 'run', side_effect=ps), patch.object(z.os, 'kill', side_effect=terminate) as kill:
                    with self.assertRaisesRegex(z.Error, 'udp-status.json'):
                        z.recover_stale_children(self.root)
                kill.assert_called_once_with(444, z.signal.SIGTERM)

    def test_udp_metadata_disappearing_during_read_does_not_fail_recovery(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        status_path = self.root / 'runtime/udp-status.json'
        z.write_json(status_path, {'pid': 555})
        original_read = Path.read_text

        def read(path, *args, **kwargs):
            if path == status_path:
                raise FileNotFoundError('UDP status removed concurrently')
            return original_read(path, *args, **kwargs)

        with patch.object(z, 'is_running', return_value=False), patch.object(Path, 'read_text', read), patch.object(z, 'matches_stale_child', side_effect=[True, False]), patch.object(z.os, 'kill') as kill:
            z.recover_stale_children(self.root)
        kill.assert_called_once_with(444, z.signal.SIGTERM)

    def test_failed_engine_termination_does_not_skip_verified_udp_recovery(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        z.write_json(self.root / 'runtime/udp-status.json', {'pid': 555})
        udp_alive = True

        def matches(pid, kind, root):
            return pid == 444 or udp_alive

        def terminate(pid, sig):
            nonlocal udp_alive
            if pid == 444:
                raise PermissionError('engine termination denied')
            udp_alive = False

        with patch.object(z, 'is_running', return_value=False), patch.object(z, 'matches_stale_child', side_effect=matches), patch.object(z.os, 'kill', side_effect=terminate) as kill:
            with self.assertRaisesRegex(PermissionError, 'denied'):
                z.recover_stale_children(self.root)
        self.assertEqual([call.args for call in kill.call_args_list], [(444, z.signal.SIGTERM), (555, z.signal.SIGTERM)])

    @unittest.skipIf(os.name == 'nt', 'POSIX directory permissions are unavailable on Windows')
    def test_fresh_install_under_permissive_umask_protects_directories_before_writes(self):
        root = self.base / 'fresh-install'
        folders = ('bin', 'lists', 'runtime', 'logs', 'backups', 'licenses', 'payloads')
        original_write = z.atomic_write

        def protected_write(path, content, mode=0o644):
            if root in Path(path).parents:
                for directory in [root, *(root / folder for folder in folders)]:
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o755, str(directory))
            return original_write(path, content, mode)

        previous_umask = os.umask(0)
        try:
            with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), patch.object(z, 'run'), patch.object(z, 'atomic_write', side_effect=protected_write):
                z.install(z.SOURCE / 'zapret.py', root=root)
        finally:
            os.umask(previous_umask)

    def test_new_live_supervisor_prevents_signal_after_recovery_initial_check(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        with patch.object(z, 'is_running', side_effect=[False, True]), patch.object(z, 'matches_stale_child', return_value=True), patch.object(z.os, 'kill') as kill:
            z.recover_stale_children(self.root)
        kill.assert_not_called()

    def test_state_removed_during_shutdown_is_treated_as_stopped(self):
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError('state removed')):
            self.assertEqual(z.get_state(self.root), {})

    def test_engine_pid_is_persisted_before_waiting_for_listening_port(self):
        child = Mock(pid=444)
        child.poll.return_value = None
        backend = Mock(active=False)
        fake_fcntl = SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=4)

        def readiness(process):
            self.assertEqual(z.get_state(self.root)['engine_pid'], process.pid)
            self.assertEqual(z.get_state(self.root)['phase'], 'starting')
            raise z.Error('engine failed to bind')

        with patch.object(z, 'require_mac'), patch.object(z.signal, 'signal'), patch.dict(sys.modules, {'fcntl': fake_fcntl}), patch.object(z, 'is_running', return_value=False), patch.object(voice, 'Backend', return_value=backend), patch.object(z, 'release_pf'), patch.object(z, 'run'), patch.object(z, 'wait_ready', side_effect=readiness), patch.object(z.subprocess, 'Popen', return_value=child):
            with self.assertRaisesRegex(z.Error, 'failed to bind'):
                z.supervise(self.root)
        child.terminate.assert_called_once()

    def test_pid_reused_during_grace_period_does_not_receive_sigkill(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        with patch.object(z, 'is_running', return_value=False), patch.object(z, 'matches_stale_child', side_effect=[True, True, False]), patch.object(z.time, 'monotonic', side_effect=[0, 4]), patch.object(z.os, 'kill') as kill:
            z.recover_stale_children(self.root)
        kill.assert_called_once_with(444, z.signal.SIGTERM)

    def test_unresponsive_recorded_child_gets_sigkill_after_identity_recheck(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        with patch.object(z, 'is_running', return_value=False), patch.object(z, 'matches_stale_child', side_effect=[True, True, True, False]), patch.object(z.time, 'monotonic', side_effect=[0, 4, 4, 5]), patch.object(z.os, 'kill') as kill:
            z.recover_stale_children(self.root)
        self.assertEqual([call.args for call in kill.call_args_list], [(444, z.signal.SIGTERM), (444, z.signal.SIGKILL)])

    def test_failed_stale_child_recovery_keeps_pid_metadata_for_retry(self):
        z.write_json(self.root / 'runtime/state.json', {'pid': 333, 'engine_pid': 444})
        with patch.object(z, 'require_mac'), patch.object(z, 'launch_loaded', return_value=False), patch.object(z, 'is_running', return_value=False), patch.object(z, 'release_pf'), patch.object(z, 'matches_stale_child', return_value=True), patch.object(z.time, 'monotonic', side_effect=[0, 4, 4, 8]), patch.object(z.os, 'kill'):
            with self.assertRaisesRegex(z.Error, 'Не удалось завершить'):
                z.stop(self.root)
        self.assertEqual(z.get_state(self.root)['engine_pid'], 444)


if __name__ == '__main__':
    unittest.main()
