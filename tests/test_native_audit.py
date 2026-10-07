"""Regression checks for native validation safeguards."""
import contextlib
import io
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import check_pf_udp as check


class NativeAuditTests(unittest.TestCase):
    def test_installer_rejects_abi_mismatch_even_with_python_optimization(self):
        root = Path(__file__).resolve().parents[1]
        line = next(line for line in (root / 'install.command').read_text().splitlines()
                    if 'PF ABI mismatch' in line)
        code = re.search(r"-c '([^']+)'", line).group(1)
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / 'native.json', Path(directory) / 'python.json'
            first.write_text('{"size":84}')
            second.write_text('{"size":80}')
            result = subprocess.run([sys.executable, '-O', '-c', code, str(first), str(second)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('PF ABI mismatch', result.stderr)
            second.write_text(first.read_text())
            result = subprocess.run([sys.executable, '-O', '-c', code, str(first), str(second)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_probe_still_stops_both_packet_traces(self):
        children = [Mock(), Mock()]
        for child in children:
            child.poll.return_value = None
        outputs = []
        def spawn(*args, **kwargs):
            outputs.append(kwargs['stdout'])
            return children[len(outputs) - 1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'logs').mkdir()
            with patch.object(check.z, 'run', return_value=SimpleNamespace(stdout='interface: en0\n')), \
                    patch.object(check.subprocess, 'Popen', side_effect=spawn), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'probe failed'):
                    with check.packet_trace(root, True):
                        raise RuntimeError('probe failed')
            for child, output in zip(children, outputs):
                child.send_signal.assert_called_once_with(signal.SIGINT)
                child.wait.assert_called_once_with(timeout=3)
                self.assertTrue(output.closed)

    def test_trace_launch_failure_closes_previous_capture(self):
        child = Mock()
        child.poll.return_value = None
        outputs = []
        def spawn(*args, **kwargs):
            outputs.append(kwargs['stdout'])
            if len(outputs) == 2:
                raise OSError('capture launch failed')
            return child
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'logs').mkdir()
            with patch.object(check.z, 'run', return_value=SimpleNamespace(stdout='interface: en0\n')), \
                    patch.object(check.subprocess, 'Popen', side_effect=spawn), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(OSError, 'capture launch failed'):
                    with check.packet_trace(root, True):
                        self.fail('Probe must not run if trace launch failed')
            child.wait.assert_called_once_with(timeout=3)
            self.assertTrue(all(output.closed for output in outputs))


if __name__ == '__main__':
    unittest.main()
