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

    def test_trace_read_failure_does_not_orphan_another_capture(self):
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
                    patch.object(Path, 'read_text', side_effect=OSError('trace unavailable')), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with check.packet_trace(root, True):
                    pass
            for child, output in zip(children, outputs):
                child.wait.assert_called_once_with(timeout=3)
                self.assertTrue(output.closed)

    def test_trace_output_close_failure_does_not_orphan_another_capture(self):
        children = [Mock(), Mock()]
        for child in children:
            child.poll.return_value = None
        real_open = Path.open
        outputs = []

        class BrokenClose:
            def __init__(self, output):
                self.output = output

            def close(self):
                self.output.close()
                raise OSError('trace close failed')

        def open_output(path, *args, **kwargs):
            output = real_open(path, *args, **kwargs)
            outputs.append(output)
            return BrokenClose(output) if len(outputs) == 1 else output

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'logs').mkdir()
            with patch.object(check.z, 'run', return_value=SimpleNamespace(stdout='interface: en0\n')), \
                    patch.object(check.subprocess, 'Popen', side_effect=children), \
                    patch.object(Path, 'open', side_effect=open_output, autospec=True), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with check.packet_trace(root, True):
                    pass
            for child in children:
                child.wait.assert_called_once_with(timeout=3)
            self.assertTrue(all(output.closed for output in outputs))


if __name__ == '__main__':
    unittest.main()
