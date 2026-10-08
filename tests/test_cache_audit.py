"""Cache moves must run as the invoking user, including through parent links."""
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z


class CacheAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.app = self.home / 'Library' / 'Application Support' / 'discord'
        (self.app / 'Cache').mkdir(parents=True)
        (self.app / 'Cache' / 'entry').write_bytes(b'cached data')
        self.user = SimpleNamespace(pw_uid=501, pw_dir=str(self.home))

    def cache_run(self, args, **kwargs):
        if args[0] == '/usr/bin/pgrep':
            return SimpleNamespace(returncode=1)
        # This boundary is essential: root must never rename directly inside
        # the user-controlled directory tree. Execute the child in isolation.
        self.assertEqual(args[:5], ['/usr/bin/sudo', '-u', '#501', '--', sys.executable])
        self.assertIsNone(kwargs['timeout'], 'The parent must let the child finish its rollback')
        return subprocess.run([str(a) for a in args[4:]], check=True,
                              capture_output=True, text=True)

    def test_cache_backup_preserves_contents_without_privileged_rename(self):
        with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=self.user), \
                patch.object(z, 'run', side_effect=self.cache_run), \
                patch.object(Path, 'rename', side_effect=AssertionError('privileged rename')):
            z.clean_discord_cache()
        self.assertFalse((self.app / 'Cache').exists())
        backups = list(self.app.glob('Cache.zapret-backup-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / 'entry').read_bytes(), b'cached data')

    def test_user_permission_failure_leaves_original_cache_intact(self):
        def denied(args, **kwargs):
            if args[0] == '/usr/bin/pgrep':
                return SimpleNamespace(returncode=1)
            self.assertEqual(args[:4], ['/usr/bin/sudo', '-u', '#501', '--'])
            raise z.Error('Permission denied for invoking user')

        with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=self.user), \
                patch.object(z, 'run', side_effect=denied):
            with self.assertRaisesRegex(z.Error, 'Permission denied'):
                z.clean_discord_cache()
        self.assertEqual((self.app / 'Cache' / 'entry').read_bytes(), b'cached data')
        self.assertEqual(list(self.app.glob('Cache.zapret-backup-*')), [])


if __name__ == '__main__':
    unittest.main()
