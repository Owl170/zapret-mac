"""Regression coverage for renamed app bundles and interrupted cache rollback."""
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import discord_cache as cache
import zapret as z


class DiscordCacheRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.app = self.home / 'Library/Application Support/discord'
        self.app.mkdir(parents=True)

    def entry(self, folder, value=b'cache'):
        path = self.app / folder / 'entry'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def process_result(self, executable):
        def run(args, **kwargs):
            self.assertEqual(args[0], '/usr/bin/pgrep')
            # pgrep uses POSIX ERE; Python needs an equivalent whitespace class.
            pattern = args[-1].replace('[[:space:]]', r'\s')
            return SimpleNamespace(returncode=0 if re.search(pattern, executable, re.I) else 1)
        return run

    def test_renamed_running_discord_and_helpers_refuse_cleanup(self):
        executables = (
            '/Applications/Chat.app/Contents/MacOS/Discord',
            '/Applications/Preview.app/Contents/MacOS/Discord Canary --type=browser',
            '/Applications/Preview.app/Contents/MacOS/Discord PTB',
            '/Applications/Chat.app/Contents/Frameworks/Chat Helper.app/Contents/MacOS/Discord Helper (Renderer) --type=renderer',
            '/Applications/Chat.app/Contents/Frameworks/Chat Helper.app/Contents/MacOS/Discord Canary Helper (GPU)',
            '/Applications/Chat.app/Contents/Frameworks/Chat Helper.app/Contents/MacOS/Discord PTB Helper',
        )
        for executable in executables:
            self.entry('Cache', b'preserve')
            with self.subTest(executable=executable), patch.object(cache.sys, 'platform', 'darwin'), \
                    patch.object(cache.os, 'getuid', return_value=501, create=True), \
                    patch.object(cache.subprocess, 'run', side_effect=self.process_result(executable)):
                with self.assertRaisesRegex(OSError, 'Discord'):
                    cache.backup(self.home)
                self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'preserve')
                self.assertEqual(list(self.app.glob('*.zapret-backup-*')), [])

    def test_unrelated_executable_in_discord_named_bundle_does_not_block(self):
        for executable in ('/Applications/Discord.app/Contents/MacOS/Other',
                           '/Applications/Chat.app/Contents/MacOS/DiscordProxy'):
            self.entry('Cache')
            with self.subTest(executable=executable), patch.object(cache.sys, 'platform', 'darwin'), \
                    patch.object(cache.os, 'getuid', return_value=501, create=True), \
                    patch.object(cache.subprocess, 'run', side_effect=self.process_result(executable)):
                result = cache.backup(self.home)
                self.assertFalse((self.app / 'Cache').exists())
                self.assertEqual(result['moved'], ['discord/Cache'])

    def test_parent_refuses_renamed_discord_before_starting_cache_child(self):
        executable = '/Applications/Chat.app/Contents/MacOS/Discord'
        user = SimpleNamespace(pw_uid=501, pw_dir=str(self.home))
        self.entry('Cache', b'preserve')
        with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=user), \
                patch.object(z, 'run', side_effect=self.process_result(executable)) as run:
            with self.assertRaisesRegex(z.Error, 'Discord'):
                z.clean_discord_cache()
        self.assertEqual(run.call_count, 1)
        self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'preserve')

    def test_repeat_interrupt_during_rollback_does_not_skip_other_caches(self):
        for folder in ('Cache', 'Code Cache', 'GPUCache'):
            self.entry(folder, folder.encode())
        rename = os.rename
        calls = 0

        def interrupt(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls in (3, 4):
                raise KeyboardInterrupt('repeat interrupt')
            return rename(*args, **kwargs)

        failure = None
        with patch.object(cache.os, 'rename', side_effect=interrupt):
            try:
                cache.backup(self.home)
            except BaseException as error:
                failure = error
        self.assertIsInstance(failure, OSError)
        self.assertRegex(str(failure), 'rollback.*KeyboardInterrupt')
        self.assertEqual((self.app / 'Cache/entry').read_bytes(), b'Cache')
        self.assertEqual((self.app / 'GPUCache/entry').read_bytes(), b'GPUCache')
        self.assertFalse((self.app / 'Code Cache').exists())
        backups = list(self.app.glob('*.zapret-backup-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / 'entry').read_bytes(), b'Code Cache')
        self.assertEqual(calls, 5)


if __name__ == '__main__':
    unittest.main()
