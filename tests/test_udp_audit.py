"""Failure-path regressions found during the UDP/backend audit."""
import errno
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
