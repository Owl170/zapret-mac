import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
import zipfile

import scripts.package as packaging
from scripts.update_version import sync
import zapret


class PackagingAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for source in packaging.package_files(zapret.SOURCE):
            target = self.root / source.relative_to(zapret.SOURCE)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        (self.root / 'VERSION').write_text('0.2.0\n', encoding='utf-8')
        sync(self.root, '0.3.0')

    def metadata(self):
        return {name: (self.root / name).read_bytes()
                for name in ['VERSION', 'README.md', 'VOICE.md', 'PROVENANCE.json']}

    def test_unsigned_new_file_cannot_enter_archive(self):
        (self.root / 'scripts' / 'extra.py').write_text('print("unsigned")\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'exactly every packaged file'):
            packaging.package(self.root)

    def test_manifest_cannot_reference_a_file_outside_the_package(self):
        path = self.root / 'PROVENANCE.json'
        manifest = json.loads(path.read_text(encoding='utf-8'))
        # An unsafe entry must be rejected before any attempt to read it.
        manifest['sha256']['../not-present-secret'] = '0' * 64
        path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'exactly every packaged file'):
            packaging.package(self.root)

    def test_missing_manifest_entry_cannot_enter_archive(self):
        path = self.root / 'PROVENANCE.json'
        manifest = json.loads(path.read_text(encoding='utf-8'))
        del manifest['sha256']['discord_udp.py']
        path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'exactly every packaged file'):
            packaging.package(self.root)

    def test_symlink_files_and_directories_are_rejected(self):
        original = Path.is_symlink
        for target in [self.root / 'discord_udp.py', self.root / 'lists']:
            with self.subTest(target=target):
                with patch.object(Path, 'is_symlink', lambda path: path == target or original(path)):
                    with self.assertRaisesRegex(ValueError, 'Symbolic links'):
                        list(packaging.package_files(self.root))

    def test_symlink_output_directory_is_rejected(self):
        original = Path.is_symlink
        target = self.root / 'dist'
        with patch.object(Path, 'is_symlink', lambda path: path == target or original(path)):
            with self.assertRaisesRegex(ValueError, 'output directory'):
                packaging.package(self.root)

    def test_symlink_release_root_is_rejected_before_traversal(self):
        original = Path.is_symlink
        with patch.object(Path, 'is_symlink', lambda path: path == self.root or original(path)):
            with self.assertRaisesRegex(ValueError, 'release root'):
                list(packaging.package_files(self.root))

    def test_junction_release_root_is_rejected_before_traversal(self):
        original = getattr(Path, 'is_junction', lambda path: False)
        with patch.object(Path, 'is_junction', lambda path: path == self.root or original(path), create=True):
            with self.assertRaisesRegex(ValueError, 'release root'):
                list(packaging.package_files(self.root))

    def test_local_engine_build_outputs_do_not_change_source_release(self):
        before = [path.relative_to(self.root).as_posix() for path in packaging.package_files(self.root)]
        engine = self.root / 'engine' / 'tpws'
        for name in ('tpws', 'tpwsa', 'tpwsx', 'tpws.o'):
            (engine / name).write_bytes(b'local compiled object')
        for name in ('tpws', 'tpwsa', 'tpwsx'):
            symbols = engine / (name + '.dSYM') / 'Contents' / 'Resources'
            symbols.mkdir(parents=True)
            (symbols / 'symbols').write_bytes(b'local debug symbols')
        (engine / 'epoll-shim' / 'src' / 'epoll.o').write_bytes(b'local object')
        after = [path.relative_to(self.root).as_posix() for path in packaging.package_files(self.root)]
        self.assertEqual(after, before)
        # The original source manifest remains valid after a local compilation.
        sync(self.root, '0.3.0', check=True)
        archive = packaging.package(self.root)
        with zipfile.ZipFile(archive) as bundle:
            self.assertFalse(any(name.endswith(('.o', '/tpws', '/tpwsa', '/tpwsx'))
                                 or '.dSYM/' in name for name in bundle.namelist()))

    def test_unknown_binary_names_are_not_silently_excluded(self):
        (self.root / 'engine' / 'tpws' / 'unrecognized-binary').write_bytes(b'unsigned binary')
        with self.assertRaisesRegex(ValueError, 'exactly every packaged file'):
            packaging.package(self.root)

    def test_object_suffix_outside_engine_is_not_silently_excluded(self):
        (self.root / 'scripts' / 'unexpected.o').write_bytes(b'unsigned object')
        with self.assertRaisesRegex(ValueError, 'exactly every packaged file'):
            packaging.package(self.root)

    def test_package_order_is_posix_lexical_on_every_platform(self):
        for name in ['a.py', 'Z.py']:
            (self.root / 'scripts' / name).write_text('# ordering\n', encoding='utf-8')
        names = [path.relative_to(self.root).as_posix() for path in packaging.package_files(self.root)]
        self.assertEqual(names, sorted(names))

    def test_macos_metadata_is_not_shipped(self):
        (self.root / 'scripts' / '.DS_Store').write_bytes(b'finder metadata')
        self.assertFalse(any(path.name == '.DS_Store' for path in packaging.package_files(self.root)))

    def test_missing_source_does_not_partially_update_version(self):
        before = self.metadata()
        (self.root / 'voice.command').unlink()
        with self.assertRaises(FileNotFoundError):
            sync(self.root, '0.4.0')
        self.assertEqual(self.metadata(), before)

    def test_failed_hash_read_does_not_partially_update_version(self):
        before = self.metadata()
        original = Path.read_bytes
        target = self.root / 'discord_udp.py'

        def fail_source(path):
            if path == target:
                raise OSError('simulated source read failure')
            return original(path)

        with patch.object(Path, 'read_bytes', fail_source):
            with self.assertRaises(OSError):
                sync(self.root, '0.4.0')
        self.assertEqual(self.metadata(), before)

    def test_failed_version_replacement_rolls_back_all_metadata(self):
        before = self.metadata()
        original = packaging.os.replace
        calls = 0

        def fail_once(source, target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('simulated replacement failure')
            return original(source, target)

        with patch.object(packaging.os, 'replace', fail_once):
            with self.assertRaises(OSError):
                sync(self.root, '0.4.0')
        self.assertEqual(self.metadata(), before)

    def test_interrupt_after_completed_rename_restores_previous_metadata(self):
        before = self.metadata()
        original = packaging.os.replace
        interrupted = False

        def interrupt_after_replace(source, target):
            nonlocal interrupted
            result = original(source, target)
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt('interrupted after rename')
            return result

        with patch.object(packaging.os, 'replace', interrupt_after_replace):
            with self.assertRaises(KeyboardInterrupt):
                sync(self.root, '0.4.0')
        self.assertEqual(self.metadata(), before)

    def test_interrupt_during_rollback_preserves_rescue_and_restores_other_files(self):
        before = self.metadata()
        original = packaging.os.replace
        calls = 0

        def fail_and_interrupt_rollback(source, target):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise KeyboardInterrupt('interrupted rollback')
            result = original(source, target)
            if calls == 2:
                raise OSError('write failed after rename')
            return result

        with patch.object(packaging.os, 'replace', fail_and_interrupt_rollback):
            with self.assertRaisesRegex(RuntimeError, 'recovery files retained') as raised:
                sync(self.root, '0.4.0')
        self.assertIsInstance(raised.exception.__cause__, OSError)
        self.assertEqual((self.root / 'VERSION').read_bytes(), before['VERSION'])
        backups = list(self.root.glob('.README.md.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before['README.md'])
        self.assertNotEqual((self.root / 'README.md').read_bytes(), before['README.md'])

    def test_cleanup_interrupt_does_not_mask_write_error_or_skip_other_cleanup(self):
        before = self.metadata()
        original_unlink = Path.unlink
        interrupted = False

        def interrupt_cleanup_once(path, *args, **kwargs):
            nonlocal interrupted
            if path.name.startswith('.VERSION.') and not interrupted:
                interrupted = True
                raise KeyboardInterrupt('interrupted cleanup')
            return original_unlink(path, *args, **kwargs)

        original_replace = packaging.os.replace
        failed = False

        def fail_write_once(source, target):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError('original write failure')
            return original_replace(source, target)

        with patch.object(packaging.os, 'replace', fail_write_once), \
                patch.object(Path, 'unlink', interrupt_cleanup_once), redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(OSError, 'original write failure'):
                sync(self.root, '0.4.0')
        self.assertEqual(self.metadata(), before)
        leftovers = [path for path in self.root.iterdir() if path.name.startswith(('.VERSION.', '.README.md.', '.VOICE.md.', '.PROVENANCE.json.'))]
        self.assertEqual(len(leftovers), 1)
        self.assertTrue(leftovers[0].name.startswith('.VERSION.'))

    def test_failed_zip_write_preserves_previous_archive_and_checksum(self):
        archive = packaging.package(self.root)
        checksum = Path(str(archive) + '.sha256')
        before = (archive.read_bytes(), checksum.read_bytes())
        with patch.object(zipfile.ZipFile, 'writestr', side_effect=OSError('simulated disk failure')):
            with self.assertRaises(OSError):
                packaging.package(self.root)
        self.assertEqual((archive.read_bytes(), checksum.read_bytes()), before)
        self.assertEqual(sorted(path.name for path in archive.parent.iterdir()),
                         sorted([archive.name, checksum.name]))

    def test_failed_checksum_replacement_restores_archive_pair(self):
        archive = packaging.package(self.root)
        checksum = Path(str(archive) + '.sha256')
        before = (archive.read_bytes(), checksum.read_bytes())
        (self.root / 'scripts' / 'new.py').write_text('# new package\n', encoding='utf-8')
        sync(self.root, '0.3.0')
        original = packaging.os.replace
        failed = False

        def fail_checksum_once(source, target):
            nonlocal failed
            if target == checksum and not failed:
                failed = True
                raise OSError('simulated checksum replacement failure')
            return original(source, target)

        with patch.object(packaging.os, 'replace', fail_checksum_once):
            with self.assertRaises(OSError):
                packaging.package(self.root)
        self.assertEqual((archive.read_bytes(), checksum.read_bytes()), before)

    def test_archive_uses_the_same_bytes_that_were_validated(self):
        target = self.root / 'discord_udp.py'
        before = target.read_bytes()
        original = Path.read_bytes
        calls = 0

        def mutate_after_read(path):
            nonlocal calls
            data = original(path)
            if path == target:
                calls += 1
                if calls == 1:
                    path.write_bytes(data + b'\n# concurrent edit\n')
            return data

        with patch.object(Path, 'read_bytes', mutate_after_read):
            archive = packaging.package(self.root)
        with zipfile.ZipFile(archive) as bundle:
            payload = bundle.read('ZapretMac/discord_udp.py')
            manifest = json.loads(bundle.read('ZapretMac/PROVENANCE.json'))
        self.assertEqual(payload, before)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest['sha256']['discord_udp.py'])
        self.assertEqual(calls, 1)


if __name__ == '__main__':
    unittest.main()
