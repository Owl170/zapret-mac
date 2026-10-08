import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

import application_update as u
import zapret as z


def archive(number='1.1.99', mutate=None, extra=None):
    files = {'VERSION': (number + '\n').encode(), 'zapret.py': b'controller',
             'install.command': b'installer', 'engine/tpws/Makefile': b'make',
             'native/pf_abi_probe.c': b'probe', 'discord_udp.py': b'udp'}
    manifest = dict(version=number, sha256={name: hashlib.sha256(data).hexdigest()
                                         for name, data in files.items()})
    files['PROVENANCE.json'] = json.dumps(manifest).encode()
    if mutate:
        mutate(files)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            info = zipfile.ZipInfo('ZapretMac/' + name)
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(info, data)
        if extra:
            bundle.writestr(*extra)
    return buffer.getvalue()


def release(number='1.1.99', data=b'zip'):
    name = 'ZapretMac-' + number + '.zip'
    digest = hashlib.sha256(data).hexdigest()
    checksum = (digest + '  ' + name + '\n').encode()
    assets = [dict(name=n, state='uploaded', size=len(content),
                   browser_download_url=f'{u.REPOSITORY}/releases/download/v{number}/{n}')
              for n, content in ((name, data), (name + '.sha256', checksum))]
    assets[0]['digest'] = 'sha256:' + digest
    return dict(tag_name='v' + number, draft=False, prerelease=False, assets=assets), checksum


class UpdateValidationTests(unittest.TestCase):
    def test_numeric_version_comparison_and_invalid_versions(self):
        self.assertGreater(u.version_tuple('1.1.10'), u.version_tuple('1.1.9'))
        for value in ('v1.1.5', '1.01.5', '1.1.5-beta', '../5', None, '١.١.٥'):
            with self.subTest(value=value), self.assertRaises(z.Error):
                u.version_tuple(value)

    def test_already_current_or_newer_does_not_download_or_build(self):
        for installed in ('1.1.99', '1.2.0'):
            output = io.StringIO()
            with patch.object(z, 'require_mac'), patch.object(z, 'original_user'), \
                    patch.object(z, 'version', return_value=installed), \
                    patch.object(u, 'latest_release', return_value=(release()[0], '1.1.99')), \
                    patch.object(u, 'verified_archive') as download, patch.object(u, 'build_engine') as build, \
                    contextlib.redirect_stdout(output):
                self.assertFalse(u.update())
            download.assert_not_called()
            build.assert_not_called()
            self.assertIn('Уже установлена актуальная версия', output.getvalue())

    def test_draft_prerelease_and_malformed_api_never_install(self):
        for value in ([], {}, dict(release()[0], draft=True),
                      dict(release()[0], prerelease=True), dict(release()[0], tag_name='v1.1.5-beta')):
            with patch.object(u, 'download', return_value=json.dumps(value).encode()), self.assertRaises(z.Error):
                u.latest_release()

    def test_assets_require_exact_repository_tag_names_and_uploaded_state(self):
        remote, _ = release()
        u.release_assets(remote, '1.1.99')
        for changes in ({'browser_download_url': 'https://outside.invalid/zip'},
                        {'state': 'new'}, {'size': True}, {'size': u.MAX_ZIP + 1}):
            altered = dict(remote, assets=[dict(remote['assets'][0], **changes), remote['assets'][1]])
            with self.subTest(changes=changes), self.assertRaises(z.Error):
                u.release_assets(altered, '1.1.99')
        for assets in (remote['assets'][:1], remote['assets'] + remote['assets'][:1]):
            with self.assertRaises(z.Error):
                u.release_assets(dict(remote, assets=assets), '1.1.99')

    def test_zip_requires_checksum_size_and_optional_github_digest(self):
        data = b'correct ZIP bytes'
        remote, checksum = release(data=data)
        asset, sums = u.release_assets(remote, '1.1.99')
        with patch.object(u, 'download', side_effect=[checksum, data]):
            self.assertEqual(u.verified_archive(asset, sums), data)
        for corrupt in (b'changed ZIP bytes', data + b'x'):
            with patch.object(u, 'download', side_effect=[checksum, corrupt]), self.assertRaises(z.Error):
                u.verified_archive(asset, sums)
        with patch.object(u, 'download', side_effect=[checksum, data]), self.assertRaises(z.Error):
            u.verified_archive(dict(asset, digest='sha256:' + '0' * 64), sums)

    def test_checksum_for_another_filename_is_refused(self):
        remote, checksum = release()
        asset, sums = u.release_assets(remote, '1.1.99')
        wrong = checksum.replace(b'ZapretMac', b'Different')
        with patch.object(u, 'download', return_value=wrong), self.assertRaises(z.Error):
            u.verified_archive(asset, dict(sums, size=len(wrong)))

    def test_plain_http_credentials_and_untrusted_redirect_hosts_are_refused(self):
        for url in ('http://github.com/file', 'https://outside.invalid/file',
                    'https://github.com@outside.invalid/file', 'https://user:pass@github.com/file',
                    'https://github.com:444/file'):
            with self.subTest(url=url), self.assertRaises(z.Error):
                u.allowed_url(url)
            with self.assertRaises(z.Error):
                u.ReleaseRedirect().redirect_request(urllib_request(), None, 302, '', {}, url)

    def test_bounded_download_rejects_large_or_truncated_transfer(self):
        for payload, length, limit in ((b'abcdef', '6', 4), (b'ab', '3', 4), (b'abcde', None, 4)):
            response = io.BytesIO(payload)
            response.headers = {'Content-Length': length} if length else {}
            response.geturl = lambda: u.LATEST
            opener = Mock()
            opener.open.return_value = response
            with patch.object(u.urllib.request, 'build_opener', return_value=opener), self.assertRaises(z.Error):
                u.download(u.LATEST, limit)
            request = opener.open.call_args.args[0]
            self.assertFalse(request.has_header('Authorization'))

    def test_valid_archive_is_verified_and_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = u.extract_verified(archive(), Path(directory), '1.1.99')
            self.assertEqual((source / 'VERSION').read_text().strip(), '1.1.99')
            self.assertEqual((source / 'zapret.py').read_bytes(), b'controller')
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE((source / 'install.command').stat().st_mode), 0o755)

    def test_corrupt_manifest_or_version_writes_nothing(self):
        mutations = [lambda files: files.update({'zapret.py': b'tampered'}),
                     lambda files: files.update({'PROVENANCE.json': b'null'}),
                     lambda files: files.update({'PROVENANCE.json': json.dumps(dict(version='1.1.99', sha256={})).encode()})]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(z.Error):
                    u.extract_verified(archive(mutate=mutate), Path(directory), '1.1.99')
                self.assertEqual(list(Path(directory).iterdir()), [])
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(z.Error):
            u.extract_verified(archive(), Path(directory), '1.1.98')

    def test_traversal_absolute_path_duplicate_symlink_and_device_are_refused(self):
        names = ('ZapretMac/../escape', '/absolute', 'ZapretMac/a\\b', 'ZapretMac//a',
                 'Other/zapret.py', 'ZapretMac/zapret.py')
        extras = [(name, b'x') for name in names]
        for kind in (stat.S_IFLNK, stat.S_IFCHR):
            info = zipfile.ZipInfo('ZapretMac/link')
            info.external_attr = (kind | 0o777) << 16
            extras.append((info, b'/etc/hosts'))
        for extra in extras:
            with self.subTest(extra=extra[0]), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(z.Error):
                    u.extract_verified(archive(extra=extra), Path(directory), '1.1.99')
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_file_directory_collision_is_refused_before_writing(self):
        data = archive(mutate=lambda files: files.update({'engine': b'collision'}))
        # Include the collision in the manifest, so this reaches path validation.
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            files = {info.filename.removeprefix('ZapretMac/'): bundle.read(info) for info in bundle.infolist()}
        manifest = json.loads(files['PROVENANCE.json'])
        manifest['sha256']['engine'] = hashlib.sha256(b'collision').hexdigest()
        data = archive(mutate=lambda values: values.update({'engine': b'collision', 'PROVENANCE.json': json.dumps(manifest).encode()}))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(z.Error):
                u.extract_verified(data, Path(directory), '1.1.99')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_build_failure_does_not_run_installer_or_change_installed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'VERSION').write_text('1.1.4')
            (root / 'config.json').write_bytes(b'preserve settings')
            data = archive()
            remote, _ = release(data=data)
            with patch.object(z, 'require_mac'), patch.object(z, 'original_user'), \
                    patch.object(u, 'latest_release', return_value=(remote, '1.1.99')), \
                    patch.object(u, 'verified_archive', return_value=data), \
                    patch.object(u, 'build_engine', side_effect=z.Error('build failed')), \
                    patch.object(u.subprocess, 'run') as install:
                with self.assertRaisesRegex(z.Error, 'build failed'):
                    u.update(root)
            install.assert_not_called()
            self.assertEqual((root / 'VERSION').read_text(), '1.1.4')
            self.assertEqual((root / 'config.json').read_bytes(), b'preserve settings')

    def test_successful_update_inherits_sudo_identity_and_checks_installed_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'VERSION').write_text('1.1.4')
            data = archive()
            remote, _ = release(data=data)
            paths = []
            def install(args):
                self.assertEqual(args[0], sys.executable)
                self.assertEqual(args[2], 'install')
                self.assertEqual(args[-1], '--update')
                self.assertNotIn('/usr/bin/sudo', args)
                self.assertEqual(os.environ['SUDO_UID'], '501')
                paths.append(Path(args[1]).parent)
                (root / 'VERSION').write_text('1.1.99')
                return SimpleNamespace(returncode=0)
            with patch.object(z, 'require_mac'), patch.object(z, 'original_user'), \
                    patch.object(u, 'latest_release', return_value=(remote, '1.1.99')), \
                    patch.object(u, 'verified_archive', return_value=data), \
                    patch.object(u, 'build_engine', side_effect=lambda source: source / 'engine/tpws/tpws'), \
                    patch.object(u.subprocess, 'run', side_effect=install), patch.dict(os.environ, SUDO_UID='501'):
                self.assertTrue(u.update(root))
            self.assertFalse(paths[0].exists())

    def test_update_installer_under_lock_refuses_equal_or_lower_source_version(self):
        for installed, available in (('1.1.5', '1.1.5'), ('1.2.0', '1.1.5')):
            with patch.object(z, 'require_mac'), patch.object(z, 'control_lock', return_value=contextlib.nullcontext()), \
                    patch.object(z, 'version', side_effect=lambda root: available if root == z.SOURCE else installed), \
                    patch.object(z, 'install') as install, patch.object(z, 'configure_install') as configure, \
                    patch.object(sys, 'argv', ['zapret.py', 'install', '--engine', str(z.SOURCE / 'zapret.py'), '--update']):
                z.main()
            install.assert_not_called()
            configure.assert_not_called()

    def test_installed_update_still_reloads_if_post_install_setup_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'VERSION').write_text('1.1.4')
            data = archive()
            remote, _ = release(data=data)
            def install(args):
                (root / 'VERSION').write_text('1.1.99')
                return SimpleNamespace(returncode=1)
            output = io.StringIO()
            with patch.object(z, 'require_mac'), patch.object(z, 'original_user'), \
                    patch.object(u, 'latest_release', return_value=(remote, '1.1.99')), \
                    patch.object(u, 'verified_archive', return_value=data), \
                    patch.object(u, 'build_engine', side_effect=lambda source: source / 'engine/tpws/tpws'), \
                    patch.object(u.subprocess, 'run', side_effect=install), contextlib.redirect_stdout(output):
                self.assertTrue(u.update(root))
            self.assertIn('настройка запуска не завершена', output.getvalue())

    def test_menu_reloads_installed_code_after_update(self):
        with patch.object(z, 'require_mac'), patch.object(z, 'status'), patch.object(z, 'version', return_value='1.1.4'), \
                patch('builtins.input', side_effect=['8', '0']), patch.object(u, 'update', return_value=True), \
                patch.object(z.os, 'execv', side_effect=SystemExit(0)) as reload:
            with self.assertRaises(SystemExit):
                z.menu()
        self.assertEqual(reload.call_args.args[1], [sys.executable, str(z.ROOT / 'zapret.py'), 'menu'])


def urllib_request():
    return u.urllib.request.Request(u.LATEST)


if __name__ == '__main__':
    unittest.main()
