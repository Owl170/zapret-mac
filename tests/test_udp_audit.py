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
    def failed_real_packets(self, times):
        relay = u.Relay(Mock(return_value=('8.8.8.8', 50001)), profile='fake', payload=b'fake')
        self.addCleanup(relay.close)
        relay.selector.close()
        relay.selector = Mock()
        listener = Mock(family=socket.AF_INET)
        listener.getsockname.return_value = ('127.0.0.1', u.UDP_PORT)
        listener.fileno.return_value = 15
        packet = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + bytes(12)
        listener.recvfrom.return_value = (packet, ('192.0.2.1', 50001))
        upstream = Mock(family=socket.AF_INET)
        fake_packets = []

        def send(data):
            if data == b'fake':
                fake_packets.append(data)
                return len(data)
            raise OSError(errno.EHOSTUNREACH, 'pending ICMP error')

        upstream.send.side_effect = send
        # The first clock sample records creation; each following sample is a
        # discovery retry. Failed real sends must still consume the fake budget.
        with patch.object(u.socket, 'socket', return_value=upstream), \
                patch.object(u.time, 'monotonic', side_effect=[times[0], *times]):
            for _ in times:
                with self.assertRaises(OSError):
                    relay.receive_client(listener)
        self.assertEqual(relay.stats['fakes'], len(fake_packets))
        return fake_packets

    def test_failed_real_send_does_not_bypass_two_fake_groups(self):
        self.assertEqual(len(self.failed_real_packets([2, 3, 4])), 12)

    def test_failed_real_send_does_not_bypass_fake_interval(self):
        self.assertEqual(len(self.failed_real_packets([2, 2.1])), 6)

    def test_failed_real_send_keeps_successfully_sent_fake_count(self):
        self.assertEqual(len(self.failed_real_packets([2])), 6)

    def test_successful_real_send_does_not_double_count_fakes(self):
        relay = u.Relay(Mock(return_value=('8.8.8.8', 50001)), profile='fake', payload=b'fake')
        self.addCleanup(relay.close)
        relay.selector.close()
        relay.selector = Mock()
        listener = Mock(family=socket.AF_INET)
        listener.getsockname.return_value = ('127.0.0.1', u.UDP_PORT)
        listener.fileno.return_value = 15
        packet = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + bytes(12)
        listener.recvfrom.return_value = (packet, ('192.0.2.1', 50001))
        upstream = Mock(family=socket.AF_INET)
        with patch.object(u.socket, 'socket', return_value=upstream), \
                patch.object(u.time, 'monotonic', return_value=2):
            relay.receive_client(listener)
        packets = [call.args[0] for call in upstream.send.call_args_list]
        self.assertEqual(packets, [b'fake'] * 6 + [packet])
        self.assertEqual(relay.stats['fakes'], 6)
        self.assertEqual(relay.stats['forwarded'], 1)

    def test_partial_fake_failure_counts_only_successful_fakes_and_keeps_return_value(self):
        sock = Mock(family=socket.AF_INET)
        sock.send.side_effect = [4, OSError(errno.EHOSTUNREACH, 'fake ICMP'), 4]
        record = Mock()
        self.assertEqual(u.transmit(sock, b'voice', b'fake', u.PROFILES['fake'], True,
                                    on_fake=record), 1)
        record.assert_called_once_with()
        self.assertEqual([call.args[0] for call in sock.send.call_args_list], [b'fake', b'fake', b'voice'])

    def test_late_fake_icmp_does_not_drop_following_plain_audio(self):
        sock = Mock(family=socket.AF_INET)
        sock.send.side_effect = [OSError(errno.EHOSTUNREACH, 'late fake ICMP'), None]
        self.assertEqual(u.transmit(sock, b'plain audio', b'fake', u.PROFILES['ttl3'], False), 0)
        self.assertEqual([call.args for call in sock.send.call_args_list], [(b'plain audio',)] * 2)
        sock.setsockopt.assert_not_called()

    def test_listener_close_error_still_closes_remaining_sockets(self):
        relay = u.Relay(Mock(), profile='relay')
        self.addCleanup(relay.close)
        relay.listen(('127.0.0.1', 0))
        relay.listen(('127.0.0.1', 0))
        first, second = relay.listeners

        class BrokenClose:
            def fileno(self):
                return first.fileno()

            def close(self):
                first.close()
                raise OSError('close failed')

        relay.listeners[0] = BrokenClose()
        with self.assertRaisesRegex(OSError, 'close failed'):
            relay.close()
        self.assertEqual(first.fileno(), -1)
        self.assertEqual(second.fileno(), -1)
        self.assertIsNone(relay.selector.get_map())
        self.assertEqual(relay.listeners, [])

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


class ResolverLifecycleTests(unittest.TestCase):
    def test_blank_natlook_einval_keeps_resolver_open_for_real_requests(self):
        ioctl = Mock(side_effect=OSError(errno.EINVAL, 'blank lookup'))
        with patch.object(u.sys, 'platform', 'darwin'), \
                patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(ioctl=ioctl)}), \
                patch.object(u.os, 'open', return_value=91), patch.object(u.os, 'close') as close:
            resolver = u.PFResolver()
            close.assert_not_called()
            resolver.close()
            resolver.close()
        close.assert_called_once_with(91)

    def test_unexpected_blank_natlook_success_closes_descriptor_and_rejects_abi(self):
        with patch.object(u.sys, 'platform', 'darwin'), \
                patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(ioctl=Mock())}), \
                patch.object(u.os, 'open', return_value=91), patch.object(u.os, 'close') as close:
            with self.assertRaisesRegex(z.Error, 'ABI'):
                u.PFResolver()
        close.assert_called_once_with(91)

    def test_interrupted_natlook_initialization_closes_descriptor(self):
        ioctl = Mock(side_effect=KeyboardInterrupt())
        with patch.object(u.sys, 'platform', 'darwin'), \
                patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(ioctl=ioctl)}), \
                patch.object(u.os, 'open', return_value=91), patch.object(u.os, 'close') as close:
            with self.assertRaises(KeyboardInterrupt):
                u.PFResolver()
        close.assert_called_once_with(91)

    def main_root(self, directory):
        root = Path(directory)
        (root / 'payloads').mkdir()
        (root / 'payloads/discord-fake.bin').write_bytes(b'fake')
        (root / 'runtime').mkdir()
        (root / 'runtime/udp-probe.json').write_text(json.dumps({'token': '01' * 16}))
        (root / 'runtime/excluded_ips.txt').write_text('')
        return root

    def test_invalid_exclusions_after_opening_pf_still_close_resolver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.main_root(directory)
            resolver = Mock()
            with patch.object(u.sys, 'argv', ['discord_udp.py', 'serve', '--root', str(root)]), \
                    patch.object(u, 'config', return_value=dict(z.DEFAULTS, ipv6=False)), \
                    patch.object(u, 'PFResolver', return_value=resolver), \
                    patch.object(z, 'load_entries', side_effect=z.Error('invalid exclusion')):
                with self.assertRaisesRegex(z.Error, 'invalid exclusion'):
                    u.main()
            resolver.close.assert_called_once()

    def test_relay_close_error_does_not_leak_pf_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.main_root(directory)
            resolver, relay = Mock(), Mock()
            relay.close.side_effect = OSError('socket close failed')
            with patch.object(u.sys, 'argv', ['discord_udp.py', 'serve', '--root', str(root)]), \
                    patch.object(u, 'config', return_value=dict(z.DEFAULTS, ipv6=False)), \
                    patch.object(u, 'PFResolver', return_value=resolver), \
                    patch.object(u, 'Relay', return_value=relay), patch.object(u.signal, 'signal'):
                with self.assertRaisesRegex(OSError, 'socket close failed'):
                    u.main()
            relay.serve.assert_called_once()
            resolver.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
