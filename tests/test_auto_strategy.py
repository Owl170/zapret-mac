import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import strategy_picker as picker
from discord_probe import CHECKS, SCHEMA
import zapret as z


class AutoStrategyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        shutil.copy2(z.SOURCE / 'targets.txt', self.root / 'targets.txt')
        (self.root / 'runtime').mkdir()
        (self.root / 'logs').mkdir()
        self.saved = dict(z.DEFAULTS, voice_udp=True)
        z.write_json(self.root / 'config.json', self.saved)
        self.calls = {}

    def rows(self, good=(), youtube=False):
        rows = [dict(name=name, url=url, tls_reached=name in good or
                     (youtube and name.startswith('YouTube')) or name.startswith('Google'),
                     http='200', seconds='0.1', error='') for name, url in z.targets(self.root)]
        ok = set(picker.REQUIRED).issubset(good)
        return rows + [dict(name=name, url='https://example.invalid', tls_reached=ok,
                            application_ok=ok, http='200', seconds='0.1', error='') for name in CHECKS]

    def run_picker(self, probe):
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'stop'), patch.object(z, 'start'), patch.object(z, 'network_tests', side_effect=probe):
            return picker.select(self.root)

    def test_high_total_with_blocked_updates_is_never_selected(self):
        def probe(*args, **kwargs):
            name = z.config(self.root)['strategy']
            return self.rows(picker.REQUIRED if name == 'tlsrec' else picker.REQUIRED[:-1], youtube=name != 'tlsrec')
        self.assertTrue(self.run_picker(probe))
        self.assertEqual(z.config(self.root), dict(self.saved, strategy='tlsrec'))
        accepted = json.loads((self.root / 'runtime/strategy-selection.json').read_text())
        self.assertTrue(accepted['accepted'])
        self.assertEqual(accepted['schema'], SCHEMA)
        self.assertEqual(len(accepted['confirmation']), 1)

    def test_failed_confirmation_tries_next_complete_candidate(self):
        def probe(*args, **kwargs):
            name = z.config(self.root)['strategy']
            self.calls[name] = self.calls.get(name, 0) + 1
            good = name == 'tlsrec' or (name == 'split-disorder' and self.calls[name] == 1)
            return self.rows(picker.REQUIRED if good else (), youtube=name == 'split-disorder')
        self.assertTrue(self.run_picker(probe))
        self.assertEqual(z.config(self.root)['strategy'], 'tlsrec')
        self.assertEqual(self.calls['split-disorder'], 2)

    def test_failed_search_restores_voice_settings_and_previous_service(self):
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'stop'), patch.object(z, 'start') as start, \
                patch.object(z, 'network_tests', return_value=self.rows()):
            self.assertFalse(picker.select(self.root))
        self.assertEqual(z.config(self.root), self.saved)
        self.assertEqual(start.call_count, len(z.strategies(self.root)) + 1)

    def test_ctrl_c_restores_config_and_running_service(self):
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'stop'), patch.object(z, 'start') as start, \
                patch.object(z, 'network_tests', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                picker.select(self.root)
        self.assertEqual(z.config(self.root), self.saved)
        self.assertEqual(start.call_count, 2)

    def test_report_failure_rolls_back_selected_profile(self):
        write = z.write_json
        def fail(path, data):
            if Path(path).name == 'strategy-selection.json':
                raise OSError('report disk full')
            write(path, data)
        with patch.object(z, 'write_json', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'report disk full'):
                self.run_picker(lambda *a, **k: self.rows(picker.REQUIRED, youtube=True))
        self.assertEqual(z.config(self.root), self.saved)
        reports = list((self.root / 'logs').glob('auto-*.json'))
        self.assertFalse(json.loads(reports[0].read_text())['accepted'])

    def test_missing_discord_targets_refuses_without_stopping(self):
        (self.root / 'targets.txt').write_text('Only = "https://example.invalid"')
        with patch.object(z, 'require_mac'), patch.object(z, 'stop') as stop:
            with self.assertRaises(z.Error):
                picker.select(self.root)
        stop.assert_not_called()

    def test_tls_success_with_broken_websocket_cannot_win(self):
        def probe(*args, **kwargs):
            name = z.config(self.root)['strategy']
            rows = self.rows(picker.REQUIRED, youtube=True)
            if name != 'tlsrec-disorder':
                next(r for r in rows if r['name'] == 'DiscordWebSocket')['application_ok'] = False
            return rows
        self.assertTrue(self.run_picker(probe))
        self.assertEqual(z.config(self.root)['strategy'], 'tlsrec-disorder')

    def test_legacy_confirmation_is_retested(self):
        z.write_json(self.root / 'runtime/strategy-selection.json', dict(accepted=True, selected=self.saved['strategy']))
        with patch.object(picker, 'select') as select, patch.object(z, 'restart') as restart:
            z.connect(self.root)
        select.assert_called_once_with(self.root)
        restart.assert_not_called()

    def test_current_confirmation_is_rechecked_and_bad_network_retunes(self):
        z.write_json(self.root / 'runtime/strategy-selection.json',
                     dict(schema=SCHEMA, accepted=True, selected=self.saved['strategy']))
        with patch.object(picker, 'select') as select, patch.object(z, 'restart') as restart, \
                patch.object(z, 'network_tests', return_value=self.rows()):
            z.connect(self.root)
        restart.assert_called_once_with(self.root)
        select.assert_called_once_with(self.root)

    def test_current_confirmation_that_still_passes_does_not_retune(self):
        z.write_json(self.root / 'runtime/strategy-selection.json',
                     dict(schema=SCHEMA, accepted=True, selected=self.saved['strategy']))
        with patch.object(picker, 'select') as select, patch.object(z, 'restart') as restart, \
                patch.object(z, 'network_tests', return_value=self.rows(picker.REQUIRED)):
            z.connect(self.root)
        restart.assert_called_once_with(self.root)
        select.assert_not_called()

    def test_app_success_with_blocked_update_file_cannot_win(self):
        def probe(*args, **kwargs):
            name = z.config(self.root)['strategy']
            rows = self.rows(picker.REQUIRED)
            if name != 'tlsrec':
                next(r for r in rows if r['name'] == 'DiscordUpdateDownload')['application_ok'] = False
            return rows
        self.assertTrue(self.run_picker(probe))
        self.assertEqual(z.config(self.root)['strategy'], 'tlsrec')

    def test_partial_http_200_is_tls_success_but_incomplete_download(self):
        from types import SimpleNamespace
        result = SimpleNamespace(returncode=28, stdout='200 12.003', stderr='Operation timed out with 17894 bytes received')
        with patch.object(z, 'run', return_value=result):
            row = z.curl_test(('DiscordMain', 'https://discord.com'))
        self.assertTrue(row['tls_reached'])
        self.assertFalse(row['transfer_complete'])

    def test_legacy_csv_report_accepts_application_and_transfer_fields(self):
        import csv
        rows = self.rows(picker.REQUIRED)
        rows[0]['transfer_complete'] = False
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'strategies', return_value={'passthrough': {}, 'split': {}}), \
                patch.object(z, 'stop'), patch.object(z, 'start'), patch.object(z, 'network_tests', return_value=rows):
            z.test_strategies(self.root)
        report = list((self.root / 'logs').glob('tests-*.csv'))[0]
        with report.open(encoding='utf-8', newline='') as stream:
            saved = list(csv.DictReader(stream))
        self.assertEqual(len(saved), 2 * len(rows))
        self.assertEqual(saved[0]['transfer_complete'], 'False')
        self.assertEqual(saved[-1]['application_ok'], 'True')
        self.assertEqual(z.config(self.root), self.saved)

    def test_curl_timeout_is_a_failed_target_not_a_failed_batch(self):
        with patch.object(z, 'run', side_effect=subprocess.TimeoutExpired('curl', 16)):
            self.assertFalse(z.curl_test(('DiscordUpdates', 'https://updates.discord.com'))['tls_reached'])

    def test_malformed_curl_output_cannot_confirm_tls(self):
        from types import SimpleNamespace
        with patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout='garbage', stderr='')):
            self.assertFalse(z.curl_test(('DiscordUpdates', 'https://updates.discord.com'))['tls_reached'])


class AutostartDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        self.plist = self.root / 'daemon.plist'

    def test_install_setup_enables_autostart_by_default(self):
        with patch.object(picker, 'select', return_value=True) as select, patch.object(z, 'autostart') as automatic:
            z.configure_install(self.root)
        select.assert_called_once_with(self.root)
        automatic.assert_called_once_with(True, self.root)

    def test_install_update_preserves_explicit_autostart_off(self):
        z.write_json(self.root / 'config.json', dict(z.DEFAULTS, autostart=False))
        with patch.object(picker, 'select', return_value=False), patch.object(z, 'autostart') as automatic:
            z.configure_install(self.root)
        automatic.assert_not_called()

    def test_disabled_autostart_update_resumes_previous_manual_service(self):
        z.write_json(self.root / 'config.json', dict(z.DEFAULTS, autostart=False))
        with patch.object(picker, 'select', return_value=False), patch.object(z, 'is_running', return_value=False), \
                patch.object(z, 'start') as start:
            z.configure_install(self.root, resume=True)
        start.assert_called_once_with(self.root)

    def test_launch_failure_restores_preference_and_plist(self):
        saved = dict(z.DEFAULTS, autostart=False)
        z.write_json(self.root / 'config.json', saved)
        self.plist.write_bytes(b'old daemon')
        with patch.object(z, 'PLIST', self.plist), patch.object(z, 'require_mac'), \
                patch.object(z, 'stop'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'start', side_effect=[z.Error('launch failed'), None]) as start:
            with self.assertRaisesRegex(z.Error, 'launch failed'):
                z.autostart(True, self.root)
        self.assertEqual(self.plist.read_bytes(), b'old daemon')
        self.assertEqual(z.config(self.root), saved)
        self.assertEqual(start.call_count, 2)

    def test_voice_restart_failure_restores_previous_profile(self):
        import voice_controller as voice
        saved = dict(z.DEFAULTS, voice_udp=True)
        z.write_json(self.root / 'config.json', saved)
        with patch.object(z, 'is_running', return_value=True), patch.object(z, 'stop'), \
                patch.object(z, 'start') as start, patch.object(z, 'restart', side_effect=z.Error('restart failed')):
            with self.assertRaisesRegex(z.Error, 'restart failed'):
                voice.change_voice(self.root, profile='ttl5')
        self.assertEqual(z.config(self.root), saved)
        start.assert_called_once_with(self.root)

    @unittest.skipUnless(sys.platform == 'darwin', 'Needs native flock')
    def test_second_configuration_operation_cannot_enter(self):
        (self.root / 'runtime').mkdir()
        with z.control_lock(self.root):
            with self.assertRaises(z.Error):
                with z.control_lock(self.root):
                    self.fail('Concurrent operation entered')

    @unittest.skipUnless(sys.platform == 'darwin', 'Needs native no-follow open')
    def test_control_lock_rejects_symlink(self):
        (self.root / 'runtime').mkdir()
        outside = self.root / 'outside'
        outside.write_bytes(b'preserve')
        (self.root / 'runtime/control.lock').symlink_to(outside)
        with self.assertRaises(OSError):
            with z.control_lock(self.root):
                self.fail('Symlink lock accepted')
        self.assertEqual(outside.read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
