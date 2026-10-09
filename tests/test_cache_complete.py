import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import discord_cache as cache


class CompleteCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.app = self.home / 'Library/Application Support/discord'
        self.app.mkdir(parents=True)

    def entry(self, name, value=b'cache'):
        path = self.app / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def test_all_allowlisted_caches_move_and_account_data_stays(self):
        for app in cache.APPS:
            for name in cache.CACHES:
                path = self.app.parent / app / name / 'entry'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'cache')
        account = [self.entry(name, b'account') for name in (
            'Local Storage/leveldb/token', 'IndexedDB/login', 'Cookies',
            'Network/Cookies', 'settings.json', 'Local State')]
        result = cache.backup(self.home)
        self.assertEqual(len(result['moved']), len(cache.APPS) * len(cache.CACHES))
        for app in cache.APPS:
            for name in cache.CACHES:
                old = self.app.parent / app / name
                self.assertFalse(old.exists())
                copies = list(old.parent.glob(old.name + '.zapret-backup-*'))
                self.assertEqual((copies[0] / 'entry').read_bytes(), b'cache')
        for path in account:
            self.assertEqual(path.read_bytes(), b'account')

    def test_midway_rename_failure_restores_all_originals(self):
        self.entry('Cache/entry')
        self.entry('Code Cache/entry')
        rename = os.rename
        calls = 0
        def fail(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PermissionError(errno.EACCES, 'denied')
            return rename(*args, **kwargs)
        with patch.object(cache.os, 'rename', side_effect=fail):
            with self.assertRaises(PermissionError):
                cache.backup(self.home)
        self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'cache')
        self.assertEqual((self.app / 'Code Cache/entry').read_bytes(), b'cache')
        self.assertEqual(list(self.app.glob('*.zapret-backup-*')), [])

    def test_missing_cache_is_reported_as_zero(self):
        self.assertEqual(cache.backup(self.home)['moved'], [])

    def test_interrupt_restores_already_moved_cache(self):
        self.entry('Cache/entry')
        self.entry('Code Cache/entry')
        rename = os.rename
        calls = 0
        def interrupt(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return rename(*args, **kwargs)
        with patch.object(cache.os, 'rename', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                cache.backup(self.home)
        self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'cache')
        self.assertEqual(list(self.app.glob('*.zapret-backup-*')), [])

    def test_discord_starting_during_cleanup_rolls_back(self):
        self.entry('Cache/entry')
        self.entry('Code Cache/entry')
        inspector = Mock()
        inspector.snapshot.side_effect = [{}, {}, {101: '/Applications/Chat.app/Contents/MacOS/Discord'}]
        with patch.object(cache.sys, 'platform', 'darwin'), \
                patch.object(cache, 'MacDiscordProcesses', return_value=inspector):
            with self.assertRaisesRegex(OSError, 'Discord'):
                cache.backup(self.home)
        self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'cache')
        self.assertEqual(list(self.app.glob('*.zapret-backup-*')), [])

    def test_interrupt_after_committed_rename_restores_that_cache(self):
        self.entry('Cache/entry')
        rename = os.rename
        interrupted = False
        def interrupt(*args, **kwargs):
            nonlocal interrupted
            result = rename(*args, **kwargs)
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            return result
        with patch.object(cache.os, 'rename', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                cache.backup(self.home)
        self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'cache')
        self.assertEqual(list(self.app.glob('*.zapret-backup-*')), [])

    def test_running_or_unknown_process_state_refuses_before_move(self):
        self.entry('Cache/entry')
        for failure in ('running', 'unknown'):
            inspector = Mock()
            if failure == 'running':
                inspector.snapshot.return_value = {101: '/Applications/Chat.app/Contents/MacOS/Discord'}
            else:
                inspector.snapshot.side_effect = OSError('Process state unknown')
            with self.subTest(failure=failure), patch.object(cache.sys, 'platform', 'darwin'), \
                    patch.object(cache, 'MacDiscordProcesses', return_value=inspector):
                with self.assertRaises(OSError):
                    cache.backup(self.home)
            self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'cache')
            self.assertEqual(list(self.app.glob('*.zapret-backup-*')), [])

    @unittest.skipUnless(os.name == 'posix', 'Needs POSIX descriptor limits')
    def test_all_clients_can_be_cleaned_under_low_descriptor_limit(self):
        import resource
        for app in cache.APPS:
            for name in cache.CACHES:
                path = self.app.parent / app / name / 'entry'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'cache')
        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(48, before[0]), before[1]))
            result = cache.backup(self.home)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, before)
        self.assertEqual(len(result['moved']), 30)

    def test_recreated_cache_is_not_overwritten_by_rollback(self):
        self.entry('Cache/entry', b'old')
        self.entry('Code Cache/entry')
        rename = os.rename
        calls = 0
        def fail(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.entry('Cache/new', b'new')
                raise PermissionError(errno.EACCES, 'failed')
            return rename(*args, **kwargs)
        with patch.object(cache.os, 'rename', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'backup retained'):
                cache.backup(self.home)
        self.assertEqual((self.app / 'Cache/new').read_bytes(), b'new')
        backup = list(self.app.glob('Cache.zapret-backup-*'))[0]
        self.assertEqual((backup / 'entry').read_bytes(), b'old')

    def test_ancestor_link_cannot_move_external_cache(self):
        external = self.home / 'external'
        (external / 'Cache').mkdir(parents=True)
        (external / 'Cache/entry').write_bytes(b'keep')
        self.app.rmdir()
        try:
            self.app.symlink_to(external, target_is_directory=True)
        except OSError:
            self.skipTest('Symlink unavailable')
        result = cache.backup(self.home)
        self.assertEqual(result['moved'], [])
        self.assertEqual((external / 'Cache/entry').read_bytes(), b'keep')

    def test_leaf_link_is_preserved(self):
        external = self.home / 'external'
        external.mkdir()
        try:
            (self.app / 'Cache').symlink_to(external, target_is_directory=True)
        except OSError:
            self.skipTest('Symlink unavailable')
        result = cache.backup(self.home)
        self.assertEqual(result['moved'], [])
        self.assertTrue((self.app / 'Cache').is_symlink())


if __name__ == '__main__':
    unittest.main()
