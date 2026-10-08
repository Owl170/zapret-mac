"""Interrupted list updates must restore the complete previous file set."""
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z


class UpdateRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'lists').mkdir()
        self.previous = {}
        for name in z.LIST_FILES:
            value = (b'1.1.1.1/32\n' if name.startswith('ipset')
                     else ('old-' + name.removesuffix('.txt') + '.example\n').encode())
            self.previous[name] = value
            (self.root / 'lists' / name).write_bytes(value)

    @staticmethod
    def download(url):
        return '198.51.100.7/32\n' if 'ipset' in url else 'test-updated.invalid\n'

    def assert_previous_files(self):
        self.assertEqual({name: (self.root / 'lists' / name).read_bytes()
                          for name in z.LIST_FILES}, self.previous)

    def interrupt_update(self, *, committed, exception):
        real_write = z.atomic_write
        calls = 0

        def write(path, text, mode=0o644):
            nonlocal calls
            calls += 1
            if calls == 2:
                if committed:
                    real_write(path, text, mode)
                raise exception
            return real_write(path, text, mode)

        with patch.object(z, 'require_mac'), patch.object(z, 'download', side_effect=self.download), \
                patch.object(z, 'atomic_write', side_effect=write), patch.object(z, 'restart') as restart:
            with self.assertRaises(type(exception)) as raised:
                z.update_lists(self.root)
        self.assertIs(raised.exception, exception)
        restart.assert_not_called()
        self.assert_previous_files()

    def test_ctrl_c_before_second_write_restores_first_file(self):
        self.interrupt_update(committed=False, exception=KeyboardInterrupt())

    def test_ctrl_c_after_second_atomic_commit_restores_both_files(self):
        self.interrupt_update(committed=True, exception=KeyboardInterrupt())

    def test_io_error_after_second_atomic_commit_restores_both_files(self):
        self.interrupt_update(committed=True, exception=OSError('error after commit'))

    def test_failed_rollback_does_not_skip_other_files_or_replace_original_error(self):
        real_write = z.atomic_write
        update_error = OSError('update failed after commit')
        calls = 0
        restored = []

        def write(path, text, mode=0o644):
            nonlocal calls
            calls += 1
            if calls == 2:
                real_write(path, text, mode)
                raise update_error
            if isinstance(text, bytes):
                restored.append(path.name)
                if path.name == z.LIST_FILES[0]:
                    raise OSError('first rollback unavailable')
            return real_write(path, text, mode)

        output = io.StringIO()
        with patch.object(z, 'require_mac'), patch.object(z, 'download', side_effect=self.download), \
                patch.object(z, 'atomic_write', side_effect=write), patch('sys.stderr', output):
            with self.assertRaises(OSError) as raised:
                z.update_lists(self.root)
        self.assertIs(raised.exception, update_error)
        self.assertEqual(restored, z.LIST_FILES[:2])
        self.assertEqual((self.root / 'lists' / z.LIST_FILES[1]).read_bytes(), self.previous[z.LIST_FILES[1]])
        self.assertIn('first rollback unavailable', output.getvalue())
        self.assertIn(z.LIST_FILES[0], output.getvalue())
        backup = next((self.root / 'backups').glob('lists-*'))
        self.assertEqual((backup / z.LIST_FILES[0]).read_bytes(), self.previous[z.LIST_FILES[0]])


if __name__ == '__main__':
    unittest.main()
