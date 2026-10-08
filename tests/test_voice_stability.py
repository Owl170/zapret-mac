"""Negotiated UDP ports must survive silence without unbounded socket growth."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

import discord_udp as u


DISCOVERY = b'\x00\x01\x00\x46' + struct.pack('!I', 123) + bytes(66)


class VoiceStabilityTests(unittest.TestCase):
    @unittest.skipIf(sys.platform == 'win32', 'Needs a real POSIX descriptor limit')
    def test_low_descriptor_limit_still_accepts_new_voice_sessions(self):
        code = '''
import resource, socket
import discord_udp as u
resource.setrlimit(resource.RLIMIT_NOFILE, (64, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(('127.0.0.1', 0)); server.settimeout(2)
    relay = u.Relay(lambda *args: server.getsockname(), profile='relay', allow_local_test=True)
    try:
        address = relay.listen(('127.0.0.1', 0))
        for _ in range(48):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b'\\x00\\x01\\x00\\x46' + bytes(70), address)
                relay.step(timeout=1)
                server.recvfrom(4096)
        assert relay.stats['forwarded'] == 48
        assert relay.stats['socket_errors'] == 0
        assert len(relay.sessions) < 48
        assert relay.stats['capacity_closed'] > 0
    finally:
        relay.close()
'''
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def setUp(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.server.close)
        self.server.bind(('127.0.0.1', 0))
        self.server.settimeout(2)
        self.destination = self.server.getsockname()
        self.relay = u.Relay(lambda *args: self.destination, profile='relay',
                             allow_local_test=True, max_sessions=2)
        self.addCleanup(self.relay.close)
        self.address = self.relay.listen(('127.0.0.1', 0))

    def send(self, data):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        client.sendto(data, self.address)
        self.relay.step(timeout=1)
        packet, peer = self.server.recvfrom(4096)
        self.assertEqual(packet, data)
        key = (self.relay.listeners[0].fileno(), client.getsockname())
        # An unbound client's getsockname uses 0.0.0.0; PF/listener sees loopback.
        key = (key[0], ('127.0.0.1', key[1][1]))
        return client, key, peer

    def test_capacity_preserves_older_voice_before_ordinary_udp(self):
        _, voice_key, _ = self.send(DISCOVERY)
        voice = self.relay.sessions[voice_key]['socket']
        self.relay.sessions[voice_key]['last'] -= 10
        _, ordinary_key, _ = self.send(b'ordinary-1')
        ordinary = self.relay.sessions[ordinary_key]['socket']
        self.send(b'ordinary-2')
        self.assertIs(self.relay.sessions[voice_key]['socket'], voice)
        self.assertGreaterEqual(voice.fileno(), 0)
        self.assertEqual(ordinary.fileno(), -1)
        self.assertEqual(len(self.relay.sessions), 2)
        self.assertEqual(self.relay.stats['capacity_closed'], 1)
        self.assertFalse(self.relay.stats['last_session_close']['preserve_port'])

    def test_all_preserved_sessions_still_obey_capacity_and_report_eviction(self):
        _, oldest_key, _ = self.send(DISCOVERY)
        oldest = self.relay.sessions[oldest_key]['socket']
        self.relay.sessions[oldest_key]['last'] -= 10
        self.send(DISCOVERY)
        self.send(DISCOVERY)
        self.assertEqual(oldest.fileno(), -1)
        self.assertEqual(len(self.relay.sessions), 2)
        self.assertEqual(self.relay.stats['session_created'], 3)
        self.assertEqual(self.relay.stats['capacity_closed'], 1)
        self.assertTrue(self.relay.stats['last_session_close']['preserve_port'])

    def test_endpoint_change_replaces_preserved_socket(self):
        client, key, _ = self.send(DISCOVERY)
        old = self.relay.sessions[key]['socket']
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as next_server:
            next_server.bind(('127.0.0.1', 0))
            next_server.settimeout(2)
            self.destination = next_server.getsockname()
            client.sendto(b'audio', self.address)
            self.relay.step(timeout=1)
            self.assertEqual(next_server.recvfrom(4096)[0], b'audio')
        self.assertEqual(old.fileno(), -1)
        self.assertEqual(self.relay.sessions[key]['destination'], self.destination)
        self.assertFalse(self.relay.sessions[key]['preserve_port'])
        self.assertEqual(self.relay.stats['endpoint_closed'], 1)

    def test_snapshot_exposes_port_and_reply_age_without_packet_content(self):
        _, _, peer = self.send(DISCOVERY)
        with tempfile.TemporaryDirectory() as directory:
            self.relay.status_path = Path(directory) / 'status.json'
            self.relay.snapshot(force=True)
            state = json.loads(self.relay.status_path.read_text())
        self.assertEqual(state['preserved_sessions'], 1)
        self.assertEqual(state['session_limit'], 2)
        detail = state['session_details'][0]
        self.assertEqual(detail['local_port'], peer[1])
        self.assertEqual(detail['sent'], 1)
        self.assertEqual(detail['replies'], 0)
        self.assertIsNone(detail['reply_age_seconds'])
        self.assertNotIn('data', detail)
        self.assertNotIn('payload', detail)


if __name__ == '__main__':
    unittest.main()
