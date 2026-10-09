"""A failed new UDP flow must not displace a negotiated voice socket."""
import errno
from pathlib import Path
import select
import socket
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discord_udp as u


class _RelayFixture(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.server.close)
        self.server.bind(('127.0.0.1', 0))
        self.destination = self.server.getsockname()
        self.relay = u.Relay(lambda *args: self.destination, profile='relay',
                             allow_local_test=True, max_sessions=1)
        self.addCleanup(self.relay.close)
        self.address = self.relay.listen(('127.0.0.1', 0))
        self.listener = self.relay.listeners[0]
        for name in ('voice_client', 'new_client'):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.addCleanup(client.close)
            setattr(self, name, client)
        self.voice_client.sendto(b'\x00\x01\x00\x46' + bytes(70), self.address)
        self.wait_for_client_packet()
        self.relay.receive_client(self.listener)
        self.voice_key = next(iter(self.relay.sessions))
        self.voice_socket = self.relay.sessions[self.voice_key]['socket']
        self.assertTrue(self.relay.sessions[self.voice_key]['preserve_port'])
        self.registered = set(self.relay.selector.get_map())

    def assert_voice_survived(self):
        self.assertEqual(list(self.relay.sessions), [self.voice_key])
        self.assertIs(self.relay.sessions[self.voice_key]['socket'], self.voice_socket)
        self.assertGreaterEqual(self.voice_socket.fileno(), 0)
        self.assertEqual(set(self.relay.selector.get_map()), self.registered)
        self.assertEqual(self.relay.stats['capacity_closed'], 0)
        self.assertEqual(self.relay.stats['session_created'], 1)

    def wait_for_client_packet(self):
        ready, _, _ = select.select([self.listener], [], [], 2)
        self.assertIn(self.listener, ready, 'UDP test packet was not ready within 2 seconds')

    def new_packet(self):
        self.new_client.sendto(b'new flow', self.address)
        self.wait_for_client_packet()


class CapacitySetupErrorTests(_RelayFixture):
    def test_failed_initial_real_send_keeps_actual_fake_counter(self):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(new_socket.close)
        wrapped = Mock(wraps=new_socket, family=socket.AF_INET)

        def send(data):
            if data == b'fake':
                return new_socket.send(data)
            raise BlockingIOError(errno.EWOULDBLOCK, 'real packet would block')

        wrapped.send.side_effect = send
        self.relay.profile = u.PROFILES['fake']
        self.relay.payload = b'fake'
        self.new_client.sendto(b'\x00\x01\x00\x46' + bytes(70), self.address)
        self.wait_for_client_packet()
        with patch.object(u.socket, 'socket', return_value=wrapped):
            with self.assertRaises(BlockingIOError):
                self.relay.receive_client(self.listener)
        self.assertEqual(new_socket.fileno(), -1)
        self.assert_voice_survived()
        self.assertEqual(self.relay.stats['fakes'], 6)
        self.assertEqual(self.relay.stats['forwarded'], 1)
        self.server.settimeout(0.05)
        self.server.recvfrom(4096)  # Original voice discovery.
        for _ in range(6):
            self.assertEqual(self.server.recvfrom(4096)[0], b'fake')
        with self.assertRaises(socket.timeout):
            self.server.recvfrom(4096)

    def test_initial_send_errors_keep_voice_and_close_temporary_socket(self):
        for failure in (BlockingIOError(errno.EWOULDBLOCK, 'would block'),
                        OSError(errno.ENETUNREACH, 'no route')):
            with self.subTest(error=type(failure).__name__):
                new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.addCleanup(new_socket.close)
                self.new_packet()
                with patch.object(u.socket, 'socket', return_value=new_socket), \
                        patch.object(u, 'transmit', side_effect=failure) as transmit:
                    with self.assertRaises(OSError):
                        self.relay.receive_client(self.listener)
                transmit.assert_called_once()
                self.assertEqual(new_socket.fileno(), -1)
                self.assert_voice_survived()
                self.assertEqual(self.relay.stats['forwarded'], 1)

    def test_creation_failure_keeps_negotiated_voice(self):
        self.new_packet()
        with patch.object(u.socket, 'socket', side_effect=OSError(errno.EMFILE, 'no descriptors')):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        self.assert_voice_survived()

    def test_connect_failure_keeps_negotiated_voice_and_closes_new_socket(self):
        new_socket = Mock(family=socket.AF_INET)
        new_socket.connect.side_effect = OSError(errno.EHOSTUNREACH, 'no route')
        self.new_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        new_socket.close.assert_called_once()
        self.assert_voice_survived()

    def test_registration_failure_keeps_voice_and_closes_new_socket(self):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(new_socket.close)
        self.new_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket), \
                patch.object(self.relay.selector, 'register', side_effect=OSError('register failed')):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        self.assertEqual(new_socket.fileno(), -1)
        self.assert_voice_survived()

    def test_partial_registration_failure_removes_new_selector_entry(self):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(new_socket.close)
        register = self.relay.selector.register

        def partial_register(*args, **kwargs):
            register(*args, **kwargs)
            raise OSError('registration interrupted')

        self.new_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket), \
                patch.object(self.relay.selector, 'register', side_effect=partial_register):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        self.assertEqual(new_socket.fileno(), -1)
        self.assert_voice_survived()

    def test_successful_new_flow_still_respects_capacity(self):
        self.server.settimeout(0.05)
        self.server.recvfrom(4096)
        self.new_packet()
        with patch.object(u, 'transmit', wraps=u.transmit) as transmit:
            self.relay.receive_client(self.listener)
        transmit.assert_called_once()
        self.assertEqual(self.server.recvfrom(4096)[0], b'new flow')
        with self.assertRaises(socket.timeout):
            self.server.recvfrom(4096)
        self.assertEqual(len(self.relay.sessions), 1)
        self.assertNotIn(self.voice_key, self.relay.sessions)
        self.assertEqual(self.voice_socket.fileno(), -1)
        self.assertEqual(len(self.relay.selector.get_map()), 2)
        self.assertEqual(self.relay.stats['capacity_closed'], 1)
        self.assertEqual(self.relay.stats['session_created'], 2)

    def test_eviction_failure_unregisters_and_closes_new_socket(self):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(new_socket.close)
        self.new_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket), \
                patch.object(self.relay, 'close_session', side_effect=OSError('eviction failed')):
            with self.assertRaisesRegex(OSError, 'eviction failed'):
                self.relay.receive_client(self.listener)
        self.assertEqual(new_socket.fileno(), -1)
        self.assert_voice_survived()
        self.assertEqual(self.relay.stats['forwarded'], 2)


class EndpointSetupErrorTests(_RelayFixture):
    def setUp(self):
        super().setUp()
        self.next_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.next_server.close)
        self.next_server.bind(('127.0.0.1', 0))
        self.next_server.settimeout(1)
        self.old_destination = self.destination
        self.destination = self.next_server.getsockname()
        self.server.settimeout(0.05)
        self.server.recvfrom(4096)  # Consume the initial discovery packet.

    def changed_packet(self):
        self.voice_client.sendto(b'new endpoint audio', self.address)
        self.wait_for_client_packet()

    def test_initial_send_errors_keep_old_endpoint_without_misrouting(self):
        for failure in (BlockingIOError(errno.EWOULDBLOCK, 'would block'),
                        OSError(errno.ENETUNREACH, 'no route')):
            with self.subTest(error=type(failure).__name__):
                new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.addCleanup(new_socket.close)
                self.changed_packet()
                with patch.object(u.socket, 'socket', return_value=new_socket), \
                        patch.object(u, 'transmit', side_effect=failure) as transmit:
                    with self.assertRaises(OSError):
                        self.relay.receive_client(self.listener)
                transmit.assert_called_once()
                self.assertEqual(new_socket.fileno(), -1)
                self.assert_old_endpoint_survived()

    def assert_old_endpoint_survived(self, forwarded=1):
        self.assert_voice_survived()
        self.assertEqual(self.relay.sessions[self.voice_key]['destination'], self.old_destination)
        self.assertEqual(self.relay.stats['endpoint_closed'], 0)
        self.assertEqual(self.relay.stats['forwarded'], forwarded)
        with self.assertRaises(socket.timeout):
            self.server.recvfrom(4096)  # Never send the new packet to the old peer.

    def test_creation_failure_keeps_old_endpoint_without_misrouting(self):
        self.changed_packet()
        with patch.object(u.socket, 'socket', side_effect=OSError(errno.EMFILE, 'no descriptors')):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        self.assert_old_endpoint_survived()

    def test_connect_failure_keeps_old_endpoint_without_misrouting(self):
        new_socket = Mock(family=socket.AF_INET)
        new_socket.connect.side_effect = OSError(errno.EHOSTUNREACH, 'no route')
        self.changed_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        new_socket.close.assert_called_once()
        self.assert_old_endpoint_survived()

    def test_registration_failure_keeps_old_endpoint_without_misrouting(self):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(new_socket.close)
        self.changed_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket), \
                patch.object(self.relay.selector, 'register', side_effect=OSError('register failed')):
            with self.assertRaises(OSError):
                self.relay.receive_client(self.listener)
        self.assertEqual(new_socket.fileno(), -1)
        self.assert_old_endpoint_survived()

    def test_successful_endpoint_change_sends_only_to_new_peer(self):
        self.changed_packet()
        with patch.object(u, 'transmit', wraps=u.transmit) as transmit:
            self.relay.receive_client(self.listener)
        transmit.assert_called_once()
        self.assertEqual(self.next_server.recvfrom(4096)[0], b'new endpoint audio')
        self.assertEqual(len(self.relay.sessions), 1)
        self.assertEqual(self.voice_socket.fileno(), -1)
        self.assertEqual(self.relay.sessions[self.voice_key]['destination'], self.destination)
        self.assertEqual(self.relay.stats['endpoint_closed'], 1)
        self.assertEqual(self.relay.stats['capacity_closed'], 0)
        self.assertEqual(len(self.relay.selector.get_map()), 2)
        with self.assertRaises(socket.timeout):
            self.server.recvfrom(4096)

    def test_old_endpoint_close_failure_cleans_new_socket_without_misrouting(self):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(new_socket.close)
        self.changed_packet()
        with patch.object(u.socket, 'socket', return_value=new_socket), \
                patch.object(self.relay, 'close_session', side_effect=OSError('endpoint close failed')):
            with self.assertRaisesRegex(OSError, 'endpoint close failed'):
                self.relay.receive_client(self.listener)
        self.assertEqual(new_socket.fileno(), -1)
        self.assert_old_endpoint_survived(forwarded=2)
        self.assertEqual(self.next_server.recvfrom(4096)[0], b'new endpoint audio')


if __name__ == '__main__':
    unittest.main()
