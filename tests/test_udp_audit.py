"""Failure-path regressions found during the UDP/backend audit."""
import errno
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discord_udp as u
import voice_controller as v
import zapret as z


class RelayFailureTests(unittest.TestCase):
    def test_direct_loopback_datagrams_cannot_terminate_relay(self):
        resolver = Mock(side_effect=OSError(errno.ENOENT, 'no PF state'))
        relay = u.Relay(resolver, profile='relay')
        self.addCleanup(relay.close)
        listener = relay.listen(('127.0.0.1', 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(3):
                client.sendto(b'direct local packet', listener)
                relay.step(timeout=1)
        self.assertEqual(relay.stats['received'], 3)
        self.assertTrue(relay.running)
        self.assertEqual(relay.stats['forwarded'], 0)
        resolver.assert_not_called()

    def test_missing_nat_states_are_dropped_without_stopping_relay(self):
        resolver = Mock(side_effect=OSError(errno.ENOENT, 'no PF state'))
        relay = u.Relay(resolver, profile='relay')
        self.addCleanup(relay.close)
        listener = Mock(family=socket.AF_INET)
        listener.getsockname.return_value = ('127.0.0.1', u.UDP_PORT)
        listener.recvfrom.return_value = (b'direct packet', ('192.0.2.1', 50001))
        for _ in range(3):
            relay.receive_client(listener)
        self.assertEqual(resolver.call_count, 3)
        self.assertEqual(relay.stats['lookup_errors'], 3)
        self.assertEqual(relay.lookup_streak, 0)
        self.assertTrue(relay.running)
        self.assertEqual(relay.stats['forwarded'], 0)
        self.assertEqual(relay.sessions, {})

    def test_ipv6_loopback_and_direct_listener_source_are_not_resolved(self):
        resolver = Mock(side_effect=OSError(errno.ENOENT, 'no PF state'))
        relay = u.Relay(resolver, profile='relay')
        self.addCleanup(relay.close)
        listener = Mock(family=socket.AF_INET6)
        listener.getsockname.return_value = ('fe80::1', u.UDP_PORT, 0, 1)
        for source in ('::1', 'fe80::1%lo0'):
            listener.recvfrom.return_value = (b'local packet', (source, 50001, 0, 1))
            relay.receive_client(listener)
        resolver.assert_not_called()
        self.assertEqual(relay.stats['forwarded'], 0)

    def test_repeated_structural_nat_errors_still_disable_relay(self):
        resolver = Mock(side_effect=OSError(errno.EIO, 'PF I/O failure'))
        relay = u.Relay(resolver, profile='relay')
        self.addCleanup(relay.close)
        listener = Mock(family=socket.AF_INET)
        listener.getsockname.return_value = ('127.0.0.1', u.UDP_PORT)
        listener.recvfrom.return_value = (b'voice', ('192.0.2.1', 50001))
        relay.receive_client(listener)
        relay.receive_client(listener)
        with self.assertRaises(z.Error):
            relay.receive_client(listener)
        self.assertEqual(relay.stats['forwarded'], 0)

    def test_unavailable_ttl_skips_fakes_but_delivers_real_packet(self):
        sock = Mock(family=socket.AF_INET)
        sock.getsockopt.side_effect = OSError(errno.ENOPROTOOPT, 'TTL unavailable')
        self.assertEqual(u.transmit(sock, b'voice', b'fake', u.PROFILES['ttl3'], True), 0)
        sock.send.assert_called_once_with(b'voice')
        sock.setsockopt.assert_not_called()

    def test_initial_status_write_failure_closes_listener(self):
        relay = u.Relay(Mock(), profile='relay')
        relay.listen(('127.0.0.1', 0))
        listener = relay.listeners[0]
        with patch.object(relay, 'snapshot', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                relay.serve()
        self.assertEqual(listener.fileno(), -1)
        self.assertFalse(relay.stats['ready'])
        relay.close()

    def test_final_status_write_failure_closes_listener(self):
        relay = u.Relay(Mock(), profile='relay')
        relay.listen(('127.0.0.1', 0))
        listener = relay.listeners[0]
        relay.running = False
        with patch.object(relay, 'snapshot', side_effect=[None, OSError('disk full')]):
            with self.assertRaises(OSError):
                relay.serve()
        self.assertEqual(listener.fileno(), -1)
        self.assertFalse(relay.stats['ready'])

    def test_close_handles_listener_already_unregistered(self):
        relay = u.Relay(Mock(), profile='relay')
        relay.listen(('127.0.0.1', 0))
        listener = relay.listeners[0]
        relay.selector.unregister(listener)
        relay.close()
        relay.close()
        self.assertEqual(listener.fileno(), -1)

    def test_probe_connect_failure_reports_stage(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.connect.side_effect = OSError(errno.EHOSTUNREACH, 'no route')
        with patch.object(socket, 'socket', return_value=client):
            with self.assertRaisesRegex(z.Error, r'connect, errno='):
                u.probe(u.TEST4, '01' * 16)
        client.send.assert_not_called()

    def test_debug_probe_still_rejects_wrong_echo_and_never_prints_token(self):
        token = 'ae01' * 16
        client = MagicMock()
        client.__enter__.return_value = client
        client.getsockname.return_value = ('192.0.2.1', 50001)
        client.getpeername.return_value = (u.TEST4, u.TEST_PORT)
        client.recv.return_value = b'wrong echo'
        output = io.StringIO()
        with patch.object(socket, 'socket', return_value=client), patch('sys.stderr', output):
            with self.assertRaisesRegex(z.Error, 'неправильный ответ'):
                u.probe(u.TEST4, token, debug=True)
        client.connect.assert_called_once_with((u.TEST4, u.TEST_PORT))
        client.send.assert_called_once_with(u.TEST_PREFIX + bytes.fromhex(token))
        self.assertIn('before_connect', output.getvalue())
        self.assertIn('after_recv', output.getvalue())
        self.assertNotIn(token, output.getvalue())
        self.assertNotIn('wrong echo', output.getvalue())

    def test_debug_connect_error_has_original_traceback_without_sending(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.connect.side_effect = OSError(errno.EHOSTUNREACH, 'no route')
        output = io.StringIO()
        with patch.object(socket, 'socket', return_value=client), patch('sys.stderr', output):
            with self.assertRaisesRegex(z.Error, r'connect, errno='):
                u.probe(u.TEST4, 'ae01' * 16, debug=True)
        client.send.assert_not_called()
        self.assertIn('Traceback', output.getvalue())
        self.assertIn('discord_udp.py', output.getvalue())
        self.assertIn('OSError', output.getvalue())
        self.assertIn('before_connect', output.getvalue())
        self.assertNotIn('after_connect', output.getvalue())
        self.assertNotIn('ae01' * 16, output.getvalue())


class BackendFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(z.SOURCE / 'lists', self.root / 'lists')
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        (self.root / 'logs').mkdir()
        z.prepare_lists(self.root)

    def backend_with_child(self):
        backend = v.Backend(self.root)
        backend.active = True
        backend.child = Mock()
        backend.child.poll.return_value = None
        return backend, backend.child

    def start_with_family_probes(self, *, ipv6_failure=None, route_code=0, child_crashes=False):
        child = Mock(pid=123)
        crashed = False
        child.poll.side_effect = lambda: 1 if crashed else None
        applied = []
        probes = []

        def spawn(*args, **kwargs):
            z.write_json(self.root / 'runtime/udp-status.json', dict(pid=123, ready=True))
            return child

        def pf(*args, **kwargs):
            if args[0] == '-a':
                applied.append(Path(args[-1]).read_text())
            return types.SimpleNamespace(returncode=0, stdout='', stderr='')

        def run(args, **kwargs):
            nonlocal crashed
            if args[0] == '/sbin/ifconfig':
                return types.SimpleNamespace(returncode=0, stdout='inet6 fe80::1%lo0', stderr='')
            if args[0] == '/sbin/route':
                return types.SimpleNamespace(returncode=route_code, stdout='', stderr='')
            if args[-1] in (u.TEST4, u.TEST6):
                probes.append(args[-1])
                if args[-1] == u.TEST6 and ipv6_failure:
                    crashed = child_crashes
                    raise ipv6_failure
                return types.SimpleNamespace(returncode=0, stdout='', stderr='')
            raise AssertionError('Unexpected command: ' + repr(args))

        backend = v.Backend(self.root)
        with patch.object(v, 'clear_udp'), patch('subprocess.Popen', side_effect=spawn), \
                patch.object(z, 'pf', side_effect=pf), patch.object(z, 'run', side_effect=run), \
                patch.object(v, 'user_uid', return_value=501):
            try:
                started = backend.start(dict(z.DEFAULTS, voice_udp=True))
                mode = v.read_status(self.root)['udp-mode.json']
            finally:
                backend.stop()
        return started, mode, applied, probes

    def test_failed_ipv6_probe_preserves_verified_ipv4_and_removes_ipv6_rules(self):
        started, mode, applied, probes = self.start_with_family_probes(ipv6_failure=z.Error('no IPv6 route'))
        self.assertTrue(started)
        self.assertEqual(probes, [u.TEST4, u.TEST6])
        self.assertTrue(mode['ipv4_active'])
        self.assertFalse(mode['ipv6_active'])
        self.assertEqual(mode['ipv6_probe'], 'failed')
        self.assertEqual(mode['ipv6_error'], 'no IPv6 route')
        self.assertIn('inet6', applied[0])
        self.assertNotIn('label "zmac-udp"', applied[1])
        self.assertNotIn('inet6', applied[1])
        self.assertIn('label "zmac-udp"', applied[-1])
        self.assertNotIn('inet6', applied[-1])

    def test_successful_ipv6_probe_enables_both_verified_families(self):
        started, mode, applied, probes = self.start_with_family_probes()
        self.assertTrue(started)
        self.assertEqual(probes, [u.TEST4, u.TEST6])
        self.assertTrue(mode['ipv4_active'])
        self.assertTrue(mode['ipv6_active'])
        self.assertEqual(mode['ipv6_probe'], 'passed')
        self.assertIn('inet6', applied[-1])
        self.assertIn('label "zmac-udp"', applied[-1])

    def test_unverified_ipv6_without_default_route_is_never_enabled(self):
        started, mode, applied, probes = self.start_with_family_probes(route_code=1)
        self.assertTrue(started)
        self.assertEqual(probes, [u.TEST4])
        self.assertFalse(mode['ipv6_active'])
        self.assertEqual(mode['ipv6_probe'], 'no-default-route')
        self.assertTrue(all('inet6' not in text for text in applied[1:]))

    def test_ipv6_probe_timeout_keeps_only_verified_ipv4(self):
        started, mode, applied, probes = self.start_with_family_probes(
            ipv6_failure=subprocess.TimeoutExpired('IPv6 probe', 5))
        self.assertTrue(started)
        self.assertEqual(mode['ipv6_probe'], 'failed')
        self.assertFalse(mode['ipv6_active'])
        self.assertNotIn('inet6', applied[-1])

    def test_ipv6_probe_launch_failure_keeps_only_verified_ipv4(self):
        started, mode, applied, probes = self.start_with_family_probes(
            ipv6_failure=OSError(errno.EAGAIN, 'fork temporarily unavailable'))
        self.assertTrue(started)
        self.assertTrue(mode['ipv4_active'])
        self.assertEqual(mode['ipv6_probe'], 'failed')
        self.assertFalse(mode['ipv6_active'])
        self.assertIn('fork temporarily unavailable', mode['ipv6_error'])
        self.assertNotIn('inet6', applied[-1])

    def test_relay_crash_during_ipv6_probe_still_disables_every_family(self):
        started, mode, applied, probes = self.start_with_family_probes(
            ipv6_failure=z.Error('IPv6 probe failed'), child_crashes=True)
        self.assertFalse(started)
        self.assertFalse(mode['active'])
        self.assertEqual(len(applied), 1)
        self.assertNotIn('label "zmac-udp"', applied[0])

    def test_pf_cleanup_failure_still_terminates_relay(self):
        backend, child = self.backend_with_child()
        with patch.object(v, 'clear_udp', side_effect=z.Error('PF unavailable')):
            with self.assertRaisesRegex(z.Error, 'PF unavailable'):
                backend.stop()
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=3)
        self.assertIsNone(backend.child)
        self.assertFalse(backend.active)
        self.assertFalse(v.read_status(self.root)['udp-mode.json']['active'])

    def test_pf_error_is_preserved_when_status_write_also_fails(self):
        backend, child = self.backend_with_child()
        with patch.object(v, 'clear_udp', side_effect=z.Error('PF unavailable')), \
                patch.object(backend, 'record', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(z.Error, 'PF unavailable'):
                backend.stop()
        child.terminate.assert_called_once()
        self.assertIsNone(backend.child)

    def test_status_write_failure_does_not_orphan_relay(self):
        backend, child = self.backend_with_child()
        with patch.object(v, 'clear_udp'), patch.object(backend, 'record', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                backend.stop()
        child.terminate.assert_called_once()
        self.assertIsNone(backend.child)

    def test_child_exiting_between_poll_and_terminate_is_reaped(self):
        backend, child = self.backend_with_child()
        child.terminate.side_effect = ProcessLookupError('already exited')
        with patch.object(v, 'clear_udp'):
            backend.stop()
        child.wait.assert_called_once_with(timeout=3)
        self.assertIsNone(backend.child)

    def test_kill_is_waited_with_a_deadline(self):
        backend, child = self.backend_with_child()
        child.wait.side_effect = [subprocess.TimeoutExpired('relay', 3), None]
        with patch.object(v, 'clear_udp'):
            backend.stop()
        child.kill.assert_called_once()
        self.assertEqual([call.kwargs for call in child.wait.call_args_list], [{'timeout': 3}] * 2)

    def test_report_failure_during_tuning_still_restores_configuration(self):
        saved = dict(z.DEFAULTS, voice_profile='ttl7')
        z.write_json(self.root / 'config.json', saved)
        original_write = z.write_json

        def write(path, data):
            if Path(path).name.startswith('voice-trials-'):
                raise OSError('report disk full')
            return original_write(path, data)

        with patch.object(z, 'is_running', return_value=True), patch.object(z, 'restart'), \
                patch.object(v, 'read_status', return_value={'udp-mode.json': {'active': False}}), \
                patch.object(z, 'write_json', side_effect=write), patch.object(z, 'stop') as stop, \
                patch.object(z, 'start') as start:
            with self.assertRaisesRegex(OSError, 'report disk full'):
                v.tune(self.root)
        self.assertEqual(z.config(self.root), saved)
        stop.assert_called_once_with(self.root)
        start.assert_called_once_with(self.root)

    def test_unknown_installation_user_is_a_managed_error(self):
        z.write_json(self.root / 'installation.json', {'user_uid': 501})
        fake_pwd = types.SimpleNamespace(getpwuid=Mock(side_effect=KeyError(501)))
        with patch.object(z, 'original_user', side_effect=z.Error('not sudo')), \
                patch.dict(sys.modules, {'pwd': fake_pwd}):
            with self.assertRaisesRegex(z.Error, 'больше не существует'):
                v.user_uid(self.root)

    def test_boolean_installation_uid_is_rejected(self):
        z.write_json(self.root / 'installation.json', {'user_uid': True})
        with patch.object(z, 'original_user', side_effect=z.Error('not sudo')):
            with self.assertRaisesRegex(z.Error, 'пользователь установки'):
                v.user_uid(self.root)

    def test_overflowing_installation_uid_is_rejected(self):
        z.write_json(self.root / 'installation.json', {'user_uid': 10 ** 80})
        with patch.object(z, 'original_user', side_effect=z.Error('not sudo')):
            with self.assertRaisesRegex(z.Error, 'пользователь установки'):
                v.user_uid(self.root)

    def test_non_object_status_is_a_managed_error(self):
        z.write_json(self.root / 'runtime/udp-status.json', [])
        with self.assertRaisesRegex(z.Error, 'файл состояния UDP'):
            v.read_status(self.root)


if __name__ == '__main__':
    unittest.main()
