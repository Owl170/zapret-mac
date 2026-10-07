import errno
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discord_udp as u
import voice_controller as v
import zapret as z


class PacketTests(unittest.TestCase):
    def test_probe_requires_exact_echo_even_after_pending_icmp(self):
        token = '01' * 16
        client = MagicMock()
        client.__enter__.return_value = client
        packet = u.TEST_PREFIX + bytes.fromhex(token)
        client.recv.side_effect = [OSError(errno.EHOSTUNREACH, 'pending ICMP'), packet]
        with patch.object(socket, 'socket', return_value=client):
            u.probe(u.TEST4, token)
        self.assertEqual(client.recv.call_count, 2)
        client.send.assert_called_once_with(packet)

    def test_discovery_and_stun_detection(self):
        discovery = b'\x00\x01\x00\x46' + struct.pack('!I', 123) + bytes(66)
        self.assertEqual(u.classify(discovery), 'discord-discovery')
        self.assertEqual(u.classify(struct.pack('!I', 123) + bytes(66)), 'discord-discovery-legacy')
        stun = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + bytes(12)
        self.assertEqual(u.classify(stun), 'stun')
        self.assertEqual(u.classify(stun + b'extra'), 'other')
        self.assertEqual(u.classify(b'\x80\x78' + bytes(200)), 'other')

    def test_natlook_abi_and_network_order(self):
        raw = u.natlook_buffer(('192.168.1.5', 53000), ('127.0.0.1', 989), socket.AF_INET)
        self.assertEqual(len(raw), 84)
        self.assertEqual(raw[:4], socket.inet_aton('192.168.1.5'))
        self.assertEqual(struct.unpack_from('!H', raw, 64)[0], 53000)
        self.assertEqual(raw[80:], bytes((2, 17, 1, 2)))
        raw[48:52] = socket.inet_aton('8.8.8.8')
        struct.pack_into('!H', raw, 76, 50001)
        self.assertEqual(u.natlook_result(raw, socket.AF_INET), ('8.8.8.8', 50001))
        raw6 = u.natlook_buffer(('2001:db8::1', 53000, 0, 0), ('fe80::1', 989, 0, 1), socket.AF_INET6)
        self.assertEqual(raw6[80:], bytes((30, 17, 1, 2)))

    def test_fakes_precede_real_and_original_ttl_is_restored(self):
        sock = Mock(family=socket.AF_INET)
        sock.getsockopt.return_value = 64
        self.assertEqual(u.transmit(sock, b'real', b'fake', u.PROFILES['ttl5'], True), 6)
        self.assertEqual([call.args[0] for call in sock.send.call_args_list], [b'fake'] * 6 + [b'real'])
        self.assertEqual([call.args[-1] for call in sock.setsockopt.call_args_list], [5, 64])

    def test_normal_ttl_profile_matches_original_fake_order(self):
        sock = Mock(family=socket.AF_INET)
        self.assertEqual(u.transmit(sock, b'real', b'fake', u.PROFILES['fake'], True), 6)
        self.assertEqual([call.args[0] for call in sock.send.call_args_list], [b'fake'] * 6 + [b'real'])
        sock.getsockopt.assert_not_called()
        sock.setsockopt.assert_not_called()

    def test_ttl_restore_failure_stops_before_real_data(self):
        sock = Mock(family=socket.AF_INET)
        sock.getsockopt.return_value = 64
        sock.setsockopt.side_effect = [None, OSError(errno.EINVAL, 'cannot restore')]
        with self.assertRaises(z.Error):
            u.transmit(sock, b'real', b'fake', u.PROFILES['ttl5'], True)
        self.assertNotIn(b'real', [call.args[0] for call in sock.send.call_args_list])

    def test_pending_icmp_error_retries_real_packet_once(self):
        sock = Mock(family=socket.AF_INET)
        sock.send.side_effect = [4] * 6 + [OSError(errno.ECONNREFUSED, 'ICMP'), 4]
        self.assertEqual(u.transmit(sock, b'real', b'fake', u.PROFILES['fake'], True), 6)
        self.assertEqual([call.args[0] for call in sock.send.call_args_list][-2:], [b'real', b'real'])

    def test_fake_failure_does_not_swallow_real(self):
        sock = Mock(family=socket.AF_INET)
        sock.getsockopt.return_value = 64
        sock.send.side_effect = [OSError(errno.EHOSTUNREACH, 'expired fake'), 4]
        self.assertEqual(u.transmit(sock, b'real', b'fake', u.PROFILES['ttl3'], True), 0)
        self.assertEqual(sock.send.call_args_list[-1].args, (b'real',))
        self.assertEqual(sock.setsockopt.call_args_list[-1].args[-1], 64)

    def test_no_injection_into_audio(self):
        sock = Mock(family=socket.AF_INET)
        u.transmit(sock, b'encrypted-audio', b'fake', u.PROFILES['ttl5'], False)
        sock.send.assert_called_once_with(b'encrypted-audio')
        sock.setsockopt.assert_not_called()

    def test_ipv6_hop_limit_restored(self):
        sock = Mock(family=socket.AF_INET6)
        sock.getsockopt.return_value = 64
        u.transmit(sock, b'real', b'fake', u.PROFILES['ttl7'], True)
        self.assertEqual(sock.setsockopt.call_args_list[0].args, (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 7))
        self.assertEqual(sock.setsockopt.call_args_list[-1].args[-1], 64)


class RealDatagramTests(unittest.TestCase):
    def setUp(self):
        self.echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.echo.bind(('127.0.0.1', 0))
        self.echo.settimeout(0.1)
        self.dest = self.echo.getsockname()
        self.peers = []
        self.echo_running = True

        def echo_loop():
            while self.echo_running:
                try:
                    data, peer = self.echo.recvfrom(65535)
                    self.peers.append(peer)
                    self.echo.sendto(data, peer)
                except socket.timeout:
                    continue
                except OSError:
                    return

        self.echo_thread = threading.Thread(target=echo_loop, daemon=True)
        self.echo_thread.start()
        self.relay = u.Relay(lambda *args: self.dest, profile='relay', allow_local_test=True, idle=0.2)
        self.listen = self.relay.listen(('127.0.0.1', 0))
        self.errors = []

        def relay_loop():
            try:
                self.relay.serve()
            except Exception as error:
                self.errors.append(error)

        self.thread = threading.Thread(target=relay_loop, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.relay.running = False
        self.thread.join(2)
        self.echo_running = False
        self.echo.close()
        self.echo_thread.join(1)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_bidirectional_bytes_and_stable_nat_mapping(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            for data in [b'\x80\x78encrypted-voice', bytes(range(256)) * 4, b'']:
                client.sendto(data, self.listen)
                self.assertEqual(client.recvfrom(65535)[0], data)
        self.assertEqual(len(set(self.peers)), 1)
        self.assertEqual(self.relay.stats['forwarded'], 3)
        self.assertEqual(self.relay.stats['replies'], 3)
        self.assertEqual(self.relay.stats['fakes'], 0)

    def test_idle_sessions_are_reclaimed(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(b'hello', self.listen)
            client.recvfrom(4096)
        end = time.monotonic() + 2
        while self.relay.sessions and time.monotonic() < end:
            time.sleep(0.05)
        self.assertEqual(len(self.relay.sessions), 0)

    def test_reserved_probe_is_local_and_requires_correct_token(self):
        self.relay.resolver = lambda *args: (u.TEST4, u.TEST_PORT)
        self.relay.probe_token = bytes(range(16))
        packet = u.TEST_PREFIX + self.relay.probe_token
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(b'wrong-token', self.listen)
            client.sendto(packet, self.listen)
            self.assertEqual(client.recvfrom(4096)[0], packet)
        self.assertEqual(self.relay.stats['probes4'], 1)
        self.assertEqual(self.relay.stats['forwarded'], 0)
        self.assertEqual(self.peers, [])

    def test_destination_change_does_not_reuse_old_mapping(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as next_server:
            client.settimeout(2)
            next_server.settimeout(2)
            next_server.bind(('127.0.0.1', 0))
            client.sendto(b'first', self.listen)
            self.assertEqual(client.recvfrom(4096)[0], b'first')
            self.dest = next_server.getsockname()
            client.sendto(b'second', self.listen)
            packet, peer = next_server.recvfrom(4096)
            self.assertEqual(packet, b'second')
            next_server.sendto(b'second-response', peer)
            self.assertEqual(client.recvfrom(4096)[0], b'second-response')
        self.assertEqual(len(self.peers), 1)
        self.assertEqual(len(self.relay.sessions), 1)


class DestinationLookupTests(unittest.TestCase):
    def test_missing_out_state_tries_in_direction(self):
        resolver = u.PFResolver.__new__(u.PFResolver)
        resolver.fd = 100
        directions = []
        def ioctl(fd, request, raw, mutate):
            directions.append(raw[83])
            if len(directions) == 1:
                raise OSError(errno.ENOENT, 'no out state')
            raw[48:52] = socket.inet_aton('8.8.8.8')
            struct.pack_into('!H', raw, 76, 50001)
        resolver.ioctl = ioctl
        self.assertEqual(resolver(('192.168.1.5', 53000), ('127.0.0.1', 989), socket.AF_INET),
                         ('8.8.8.8', 50001))
        self.assertEqual(directions, [2, 1])

    def test_ambiguous_state_never_falls_back_or_guesses(self):
        resolver = u.PFResolver.__new__(u.PFResolver)
        resolver.fd = 100
        resolver.ioctl = Mock(side_effect=OSError(errno.E2BIG, 'two matching states'))
        with self.assertRaises(OSError) as error:
            resolver(('192.168.1.5', 53000), ('127.0.0.1', 989), socket.AF_INET)
        self.assertEqual(error.exception.errno, errno.E2BIG)
        resolver.ioctl.assert_called_once()

    def test_relay_fails_closed_on_ambiguous_destination(self):
        relay = u.Relay(Mock(side_effect=OSError(errno.E2BIG, 'two matching states')), profile='relay')
        self.addCleanup(relay.close)
        address = relay.listen(('127.0.0.1', 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b'voice', address)
            with self.assertRaises(z.Error):
                relay.step(timeout=2)
        self.assertEqual(relay.stats['forwarded'], 0)
        self.assertEqual(relay.stats['lookup_errors'], 1)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(z.SOURCE / 'lists', self.root / 'lists')
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        (self.root / 'logs').mkdir()
        z.prepare_lists(self.root)

    def test_udp_uses_separate_anchor_and_does_not_block_packets(self):
        rules = v.udp_rules(dict(z.DEFAULTS, voice_udp=True), self.root)
        self.assertIn('proto udp', rules)
        self.assertNotIn('proto tcp', rules)
        self.assertNotIn('block ', rules)
        self.assertNotEqual(v.UDP_ANCHOR, z.ANCHOR)
        self.assertIn('user { >root }', rules)
        self.assertIn(u.TEST4, rules)
        self.assertTrue(all('no state' in line for line in rules.splitlines() if 'route-to' in line))

    def test_voice_control_tcp_accepts_dynamic_ports(self):
        cfg = dict(z.DEFAULTS, voice_udp=True)
        args = z.engine_args(cfg, self.root)
        self.assertIn('--filter-tcp=1024-65535', args)
        self.assertIn('--hostlist-domains=discord.media,discord.gg', args)
        self.assertIn('1024:65535', z.pf_rules(cfg, self.root))

    def test_old_configuration_migrates_with_udp_disabled(self):
        old = {k: val for k, val in z.DEFAULTS.items() if not k.startswith('voice_')}
        z.write_json(self.root / 'config.json', old)
        self.assertFalse(z.config(self.root)['voice_udp'])

    def test_udp_crash_clears_only_udp_rules(self):
        backend = v.Backend(self.root)
        backend.active = True
        backend.child = Mock()
        backend.child.poll.return_value = 1
        with patch.object(v, 'clear_udp') as clear:
            backend.check()
        clear.assert_called_once()
        self.assertFalse(backend.active)
        self.assertTrue(backend.error)

    def test_startup_error_releases_udp_and_records_reason(self):
        child = Mock(pid=123)
        child.poll.return_value = 1
        backend = v.Backend(self.root)
        with patch.object(v, 'clear_udp') as clear, patch('subprocess.Popen', return_value=child):
            self.assertFalse(backend.start(dict(z.DEFAULTS, voice_udp=True)))
        self.assertFalse(backend.active)
        self.assertEqual(clear.call_count, 2)
        self.assertIn('завершился', backend.error)

    def test_traffic_rules_loaded_only_after_pf_loop_is_verified(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        applied = []
        verified = []
        def spawn(*args, **kwargs):
            z.write_json(self.root / 'runtime/udp-status.json', dict(pid=123, ready=True))
            return child
        def pf(*args, **kwargs):
            if args[0] == '-a':
                applied.append((Path(args[-1]).read_text(), bool(verified)))
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        def probe(*args, **kwargs):
            verified.append(True)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        backend = v.Backend(self.root)
        with patch.object(v, 'clear_udp'), patch('subprocess.Popen', side_effect=spawn), \
                patch.object(z, 'pf', side_effect=pf), patch.object(z, 'run', side_effect=probe), \
                patch.object(v, 'user_uid', return_value=501):
            try:
                self.assertTrue(backend.start(dict(z.DEFAULTS, voice_udp=True, ipv6=False)))
                self.assertEqual(len(applied), 2)
                self.assertNotIn('label "zmac-udp"', applied[0][0])
                self.assertIn('to ' + u.TEST4, applied[0][0])
                self.assertFalse(applied[0][1])
                self.assertIn('label "zmac-udp"', applied[1][0])
                self.assertTrue(applied[1][1])
            finally:
                backend.stop()

    def test_pf_probe_failure_cleans_up_and_never_applies_traffic_rules(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        applied = []
        def spawn(*args, **kwargs):
            z.write_json(self.root / 'runtime/udp-status.json', dict(pid=123, ready=True))
            return child
        def pf(*args, **kwargs):
            if args[0] == '-a':
                applied.append(Path(args[-1]).read_text())
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        backend = v.Backend(self.root)
        with patch.object(v, 'clear_udp') as clear, patch('subprocess.Popen', side_effect=spawn), \
                patch.object(z, 'pf', side_effect=pf), patch.object(v, 'user_uid', return_value=501), \
                patch.object(z, 'run', side_effect=z.Error('probe timed out')):
            self.assertFalse(backend.start(dict(z.DEFAULTS, voice_udp=True, ipv6=False)))
        child.terminate.assert_called_once()
        self.assertEqual(clear.call_count, 2)
        self.assertEqual(len(applied), 1)
        self.assertNotIn('label "zmac-udp"', applied[0])
        self.assertEqual(v.read_status(self.root)['udp-mode.json']['error'], 'probe timed out')

    def test_probe_only_rules_capture_only_reserved_addresses(self):
        rules = v.udp_rules(dict(z.DEFAULTS, voice_udp=True), self.root, probe_only=True)
        self.assertNotIn('label "zmac-udp"', rules)
        for line in rules.splitlines():
            if 'proto udp' in line:
                self.assertTrue(u.TEST4 in line or u.TEST6 in line)
                self.assertNotIn('to any', line)

    def test_stop_request_cancels_startup_and_closes_child(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        backend = v.Backend(self.root)
        with patch.object(v, 'clear_udp'), patch('subprocess.Popen', return_value=child), \
                patch.object(z, 'pf') as pf:
            self.assertFalse(backend.start(dict(z.DEFAULTS, voice_udp=True), cancelled=lambda: True))
        self.assertFalse(any('-f' in call.args for call in pf.call_args_list))
        child.terminate.assert_called_once()
        self.assertIn('отменён', backend.error)

    def test_interrupted_tuning_restores_config_and_running_state(self):
        saved = dict(z.DEFAULTS, strategy='tlsrec', voice_profile='ttl7')
        z.write_json(self.root / 'config.json', saved)
        with patch.object(z, 'is_running', return_value=True), patch.object(z, 'restart'), \
                patch.object(v, 'read_status', return_value={'udp-mode.json': {'active': True}}), \
                patch('builtins.input', side_effect=KeyboardInterrupt), patch.object(z, 'stop') as stop, \
                patch.object(z, 'start') as start:
            with self.assertRaises(KeyboardInterrupt):
                v.tune(self.root)
        self.assertEqual(z.config(self.root), saved)
        stop.assert_called_once_with(self.root)
        start.assert_called_once_with(self.root)
        report = next((self.root / 'logs').glob('voice-trials-*.json'))
        self.assertFalse(json.loads(report.read_text())['audio_confirmed_by_user'])

    def test_tuning_saves_profile_only_after_user_confirms_audio(self):
        with patch.object(z, 'is_running', return_value=False), patch.object(z, 'restart'), \
                patch.object(v, 'read_status', return_value={'udp-mode.json': {'active': True}}), \
                patch('builtins.input', side_effect=['', 'no', '', 'yes']), \
                patch.object(v, 'observe'), patch.object(z, 'stop') as stop:
            v.tune(self.root)
        stop.assert_not_called()
        self.assertTrue(z.config(self.root)['voice_udp'])
        self.assertEqual(z.config(self.root)['voice_profile'], 'fake')
        report = json.loads(next((self.root / 'logs').glob('voice-trials-*.json')).read_text())
        self.assertTrue(report['audio_confirmed_by_user'])
        self.assertEqual([trial['user_answer'] for trial in report['trials']], ['no', 'yes'])

    def test_quic_fallback_cannot_conflict_with_voice_udp443(self):
        cfg = dict(z.DEFAULTS, voice_udp=True, voice_ports='443,19294-19344', quic_fallback=True)
        with self.assertRaises(z.Error):
            z.validate_config(cfg, self.root)


if __name__ == '__main__':
    unittest.main()
