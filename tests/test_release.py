import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
import zipfile

from scripts.package import package, package_files
from scripts.update_version import sync
import zapret as z


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for source in package_files(z.SOURCE):
            target = self.root / source.relative_to(z.SOURCE)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        # Keep fixtures stable when the real project's automatic version advances.
        with (self.root / 'VERSION').open('w', encoding='utf-8', newline='\n') as output:
            output.write('0.2.0\n')

    def test_version_sync_updates_documents_manifest_and_runtime(self):
        sync(self.root, '0.3.0', test_count=49, platform='test fixture')
        self.assertEqual(z.version(self.root), '0.3.0')
        self.assertIn('Текущая версия: **0.3.0**.', (self.root / 'README.md').read_text(encoding='utf-8'))
        self.assertTrue((self.root / 'VOICE.md').read_text(encoding='utf-8').startswith('# Голос Discord на Mac: версия 0.3.0'))
        manifest = json.loads((self.root / 'PROVENANCE.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['version'], '0.3.0')
        self.assertEqual(manifest['flowseal_tag'], '1.10.3')
        self.assertFalse(manifest['discord_voice_tested'])
        self.assertEqual(manifest['validation']['python_tests_passed'], 49)
        self.assertEqual(manifest['sha256']['VERSION'], hashlib.sha256(b'0.3.0\n').hexdigest())
        sync(self.root, '0.3.0', check=True)

    def test_invalid_or_lower_versions_do_not_modify_files(self):
        before = (self.root / 'VERSION').read_bytes()
        for value in ['v0.3.0', '0.03.0', '0.3.0-beta', '0.1.0', '../other']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                sync(self.root, value)
        self.assertEqual((self.root / 'VERSION').read_bytes(), before)

    def test_missing_document_marker_is_rejected_before_writing(self):
        (self.root / 'README.md').write_text('No version line\n', encoding='utf-8')
        before = (self.root / 'VERSION').read_bytes()
        with self.assertRaises(ValueError):
            sync(self.root, '0.3.0')
        self.assertEqual((self.root / 'VERSION').read_bytes(), before)

    def test_modified_files_fail_manifest_check_and_packaging(self):
        sync(self.root, '0.3.0')
        path = self.root / 'discord_udp.py'
        with path.open('ab') as output:
            output.write(b'\n# change after checksums\n')
        with self.assertRaises(ValueError):
            sync(self.root, '0.3.0', check=True)
        with self.assertRaises(ValueError):
            package(self.root)

    def test_archive_has_verified_hashes_and_executable_launchers(self):
        sync(self.root, '0.3.0')
        archive = package(self.root)
        with zipfile.ZipFile(archive) as bundle:
            self.assertIsNone(bundle.testzip())
            for name in ['install', 'service', 'voice', 'uninstall']:
                self.assertEqual(stat.S_IMODE(bundle.getinfo(f'ZapretMac/{name}.command').external_attr >> 16), 0o755)
            self.assertEqual(bundle.read('ZapretMac/payloads/discord-fake.bin'), (z.SOURCE / 'payloads/discord-fake.bin').read_bytes())
            self.assertFalse(any('/upstream/' in name or name.endswith('.pyc') for name in bundle.namelist()))
        expected = Path(str(archive) + '.sha256').read_text().split()[0]
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), expected)

    def test_archive_rejects_unsynchronized_version(self):
        sync(self.root, '0.3.0')
        (self.root / 'VERSION').write_text('0.4.0\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            package(self.root)


if __name__ == '__main__':
    unittest.main()
