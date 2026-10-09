import contextlib
import io
import json
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import discord_probe as d
import discord_recovery as r
import strategy_picker as picker
import zapret as z

IP = '162.159.128.233'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hosts = self.root / 'hosts'
        self.original = '127.0.0.1 localhost\n# custom settings\n8.8.8.8 example.com\n'
        self.hosts.write_text(self.original)
        self.hosts_patch = patch.object(z, 'HOSTS', self.hosts)
        self.hosts_patch.start()
        self.addCleanup(self.hosts_patch.stop)
        self.flush = patch.object(r, 'flush_dns')
        self.flush_mock = self.flush.start()
        self.addCleanup(self.flush.stop)

    def test_failed_trial_restores_exact_hosts_and_keeps_backup(self):
        with r.HostsTrial(self.root, IP) as trial:
            self.assertIn(IP + ' discord.com', self.hosts.read_text())
            self.assertEqual(trial.backup.read_text(), self.original)
        self.assertEqual(self.hosts.read_text(), self.original)
        self.assertEqual(self.flush_mock.call_count, 2)

    def test_interrupt_restores_exact_hosts(self):
        with self.assertRaises(KeyboardInterrupt):
            with r.HostsTrial(self.root, IP):
                raise KeyboardInterrupt()
        self.assertEqual(self.hosts.read_text(), self.original)

    def test_committed_trial_is_removed_on_uninstall_without_touching_other_records(self):
        with r.HostsTrial(self.root, IP) as trial:
            trial.committed = True
        self.assertIn(IP + ' discord.com', self.hosts.read_text())
        # New markers cannot be mistaken for the older Flowseal hosts block.
        self.assertEqual(z.strip_hosts_block(self.hosts.read_text()), self.hosts.read_text())
        r.remove_override(self.root)
        self.assertEqual(self.hosts.read_text(), self.original)

    def test_other_programs_unrelated_edits_survive_rollback(self):
        with r.HostsTrial(self.root, IP):
            with self.hosts.open('a') as output:
                output.write('1.1.1.1 other.example\n')
        self.assertEqual(self.hosts.read_text(), self.original + '1.1.1.1 other.example\n')

    def test_user_and_flowseal_discord_records_are_never_replaced(self):
        for original in (self.original + '1.1.1.1 DISCORD.COM.\n',
                         self.original + z.HOST_BEGIN + '\n1.1.1.1 discord.com\n' + z.HOST_END + '\n'):
            self.hosts.write_text(original)
            with self.assertRaises(z.Error):
                with r.HostsTrial(self.root, IP):
                    self.fail('User record overwritten')
            self.assertEqual(self.hosts.read_text(), original)

    def test_existing_owned_override_restores_on_failed_replacement(self):
        with r.HostsTrial(self.root, IP) as trial:
            trial.committed = True
        previous = self.hosts.read_text()
        with r.HostsTrial(self.root, '162.159.137.232'):
            self.assertNotIn(IP + ' discord.com', self.hosts.read_text())
        self.assertEqual(self.hosts.read_text(), previous)

    def test_non_public_addresses_and_damaged_markers_do_not_write(self):
        for address in ('127.0.0.1', '10.0.0.1', '::ffff:162.159.128.233', '::1', 'invalid'):
            with self.subTest(address=address), self.assertRaises((z.Error, ValueError)):
                r.HostsTrial(self.root, address)
        self.hosts.write_text(self.original + r.BEGIN + '\n')
        with self.assertRaises(z.Error):
            with r.HostsTrial(self.root, IP):
                self.fail('Damaged marker accepted')
        self.assertEqual(self.hosts.read_text(), self.original + r.BEGIN + '\n')

    def test_only_dns_a_records_for_discord_and_public_ips_are_candidates(self):
        value = dict(Status=0, Answer=[dict(name='discord.com.', type=1, data=IP),
                    dict(name='discord.com', type=1, data=IP),
                    dict(name='other.com', type=1, data='8.8.8.8'),
                    dict(name='discord.com', type=1, data='127.0.0.1'),
                    dict(name='discord.com', type=28, data='2606:4700::1111'),
                    dict(name=True, type=1, data='8.8.8.8')])
        response = io.BytesIO(json.dumps(value).encode())
        response.geturl = lambda: r.DNS_URL
        with patch.object(r.urllib.request, 'urlopen', return_value=response) as request:
            self.assertEqual(r.candidate_addresses(), [IP])
        self.assertTrue(request.call_args.kwargs['context'].check_hostname)

    def test_dns_failure_or_private_response_is_refused(self):
        for value in ([], {}, dict(Status=False, Answer=[]), dict(Status=2, Answer=[]),
                      dict(Status=0, Answer=[dict(name='discord.com', type=1, data='10.0.0.1')])):
            response = io.BytesIO(json.dumps(value).encode())
            response.geturl = lambda: r.DNS_URL
            with patch.object(r.urllib.request, 'urlopen', return_value=response), self.assertRaises(z.Error):
                r.candidate_addresses()

    def rows(self, complete=False):
        rows = [dict(name=name, tls_reached=True) for name in picker.REQUIRED]
        return rows + [dict(name=name, tls_reached=True, application_ok=complete or name not in d.CHECKS[:2])
                       for name in d.CHECKS]

    def recover(self, app_ok=True, confirmation=None, accept=None):
        report = dict(accepted=False, trials=[dict(strategy='tlsrec', rows=self.rows())], confirmation=[])
        app = [dict(name=n, application_ok=app_ok) for n in d.CHECKS[:2]]
        def accepted(name, rows):
            report.update(accepted=True, selected=name)
        with patch.object(r, 'candidate_addresses', return_value=[IP]), patch.object(z, 'stop'), \
                patch.object(z, 'start'), patch.object(z, 'write_json'), \
                patch.object(z, 'discord_tests', return_value=app), \
                patch.object(z, 'network_tests', side_effect=confirmation or [self.rows(True), self.rows(True)]):
            result = r.recover(self.root, z.DEFAULTS, report, accept or accepted)
        return result, report

    def test_partial_page_never_changes_hosts(self):
        success, report = self.recover(app_ok=False)
        self.assertFalse(success)
        self.assertFalse(report['endpoint_recovery']['accepted'])
        self.assertEqual(self.hosts.read_text(), self.original)
        self.flush_mock.assert_not_called()

    def test_complete_page_but_failed_confirmation_restores_hosts(self):
        success, report = self.recover(confirmation=[self.rows()])
        self.assertFalse(success)
        self.assertEqual(self.hosts.read_text(), self.original)
        self.assertFalse(report['accepted'])

    def test_two_full_confirmations_are_required_before_persisting(self):
        success, report = self.recover()
        self.assertTrue(success)
        self.assertIn(IP + ' discord.com', self.hosts.read_text())
        self.assertTrue(report['accepted'])
        self.assertEqual(len(report['endpoint_recovery']['attempts'][0]['confirmation']), 2)

    def test_report_failure_restores_hosts(self):
        def fail(*args):
            raise OSError('report unavailable')
        with self.assertRaises(OSError):
            self.recover(accept=fail)
        self.assertEqual(self.hosts.read_text(), self.original)

    def test_no_eligible_profiles_never_queries_dns(self):
        report = dict(accepted=False, trials=[dict(strategy='split', rows=[])], confirmation=[])
        with patch.object(r, 'candidate_addresses') as dns:
            self.assertFalse(r.recover(self.root, z.DEFAULTS, report, Mock()))
        dns.assert_not_called()

    def test_completed_page_with_blocked_script_can_recover_another_endpoint(self):
        rows = self.rows(True)
        next(row for row in rows if row['name'] == 'DiscordScript')['application_ok'] = False
        report = dict(accepted=False, trials=[dict(strategy='tlsrec', rows=rows)], confirmation=[])
        app = [dict(name=name, application_ok=True) for name in d.CHECKS[:2]]
        def accept(name, confirmation):
            report.update(accepted=True, selected=name)
        with patch.object(r, 'candidate_addresses', return_value=[IP]) as dns, \
                patch.object(z, 'stop'), patch.object(z, 'start'), patch.object(z, 'write_json'), \
                patch.object(z, 'discord_tests', return_value=app), \
                patch.object(z, 'network_tests', side_effect=[self.rows(True), self.rows(True)]):
            self.assertTrue(r.recover(self.root, z.DEFAULTS, report, accept))
        dns.assert_called_once()
        self.assertIn(IP + ' discord.com', self.hosts.read_text())
        self.assertEqual(len(report['endpoint_recovery']['attempts'][0]['confirmation']), 2)

    def test_ipv4_mapped_results_are_not_counted_as_native_ipv6(self):
        address = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::ffff:' + IP, 443, 0, 0))
        with patch.object(d.socket, 'getaddrinfo', return_value=[address]), patch.object(d.socket, 'socket') as create:
            with self.assertRaises(OSError):
                d.family_socket(('discord.com', 443), 5, None, socket.AF_INET6, [])
        create.assert_not_called()

    def test_endpoint_connection_keeps_discord_sni_and_refuses_bad_certificate(self):
        raw = Mock()
        with patch.object(d.socket, 'create_connection', return_value=raw) as connect, \
                patch.object(ssl.SSLContext, 'wrap_socket', side_effect=ssl.SSLCertVerificationError('bad certificate')) as wrap:
            rows = d.app_checks(app_ip=IP)
        self.assertFalse(rows[0]['application_ok'])
        self.assertEqual(connect.call_args.args[0], (IP, 443))
        self.assertEqual(wrap.call_args.kwargs['server_hostname'], 'discord.com')
        raw.close.assert_called_once()

    def test_partial_http_response_retains_status_but_cannot_pass(self):
        response = SimpleNamespace(status=200, length=100)
        error = d.TransferError('The read operation timed out', response, 16384)
        row = d.row('DiscordApp', d.APP, Mock(side_effect=error))
        self.assertEqual(row['http'], '200')
        self.assertTrue(row['tls_reached'])
        self.assertFalse(row['application_ok'])
        self.assertIn('16384', row['error'])

    def test_endpoint_probe_runs_as_original_user(self):
        rows = [dict(name=n, url=d.APP, http='200', seconds='1', error='',
                     tls_reached=True, application_ok=True) for n in d.CHECKS[:2]]
        with patch.object(z.os, 'geteuid', return_value=0, create=True), \
                patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), \
                patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(rows))) as run:
            self.assertEqual(z.discord_tests(app_ip=IP), rows)
        self.assertEqual(run.call_args.args[0][:4], ['/usr/bin/sudo', '-u', '#501', '--'])
        self.assertEqual(run.call_args.args[0][-2:], ['--app-ip', IP])

    def selection_fixture(self):
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        shutil.copy2(z.SOURCE / 'targets.txt', self.root / 'targets.txt')
        saved = dict(z.DEFAULTS, voice_udp=True, autostart=False)
        z.write_json(self.root / 'config.json', saved)
        (self.root / 'runtime').mkdir()
        return saved

    def test_selector_commits_config_reports_and_hosts_only_after_confirmation(self):
        saved = self.selection_fixture()
        def probe(*args, **kwargs):
            return self.rows(r.BEGIN in self.hosts.read_text())
        app = [dict(name=n, application_ok=True) for n in d.CHECKS[:2]]
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'stop'), patch.object(z, 'start'), \
                patch.object(r, 'candidate_addresses', return_value=[IP]), \
                patch.object(z, 'discord_tests', return_value=app), \
                patch.object(z, 'network_tests', side_effect=probe):
            self.assertTrue(picker.select(self.root))
        selected = json.loads((self.root / 'runtime/strategy-selection.json').read_text())
        self.assertTrue(selected['accepted'])
        self.assertTrue(selected['endpoint_recovery']['accepted'])
        self.assertEqual(z.config(self.root), saved)
        self.assertIn(IP + ' discord.com', self.hosts.read_text())

    def test_selector_runtime_report_failure_restores_hosts_and_all_settings(self):
        saved = self.selection_fixture()
        original_write = z.write_json
        def write(path, data):
            if Path(path).name == 'strategy-selection.json':
                raise OSError('report disk full')
            original_write(path, data)
        def probe(*args, **kwargs):
            return self.rows(r.BEGIN in self.hosts.read_text())
        app = [dict(name=n, application_ok=True) for n in d.CHECKS[:2]]
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'stop'), patch.object(z, 'start'), patch.object(z, 'write_json', side_effect=write), \
                patch.object(r, 'candidate_addresses', return_value=[IP]), \
                patch.object(z, 'discord_tests', return_value=app), \
                patch.object(z, 'network_tests', side_effect=probe):
            with self.assertRaisesRegex(OSError, 'report disk full'):
                picker.select(self.root)
        self.assertEqual(self.hosts.read_text(), self.original)
        self.assertEqual(z.config(self.root), saved)
        report = json.loads(next((self.root / 'logs').glob('auto-strategy-*.json')).read_text())
        self.assertFalse(report['accepted'])

    def test_selector_interrupt_during_recovery_restores_hosts_and_voice_mode(self):
        saved = self.selection_fixture()
        def probe(*args, **kwargs):
            if r.BEGIN in self.hosts.read_text():
                raise KeyboardInterrupt()
            return self.rows()
        app = [dict(name=n, application_ok=True) for n in d.CHECKS[:2]]
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), \
                patch.object(z, 'stop'), patch.object(z, 'start'), \
                patch.object(r, 'candidate_addresses', return_value=[IP]), \
                patch.object(z, 'discord_tests', return_value=app), \
                patch.object(z, 'network_tests', side_effect=probe):
            with self.assertRaises(KeyboardInterrupt):
                picker.select(self.root)
        self.assertEqual(self.hosts.read_text(), self.original)
        self.assertEqual(z.config(self.root), saved)


if __name__ == '__main__':
    unittest.main()
