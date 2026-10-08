"""Controller regressions found while preparing the first stable release."""
import contextlib
import io
import ipaddress
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z


class StableControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(z.SOURCE / 'lists', self.root / 'lists')
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')

    def test_non_ascii_ports_are_rejected_before_writing_unusable_config(self):
        for field, value in [('game_tcp', '１０２４-６５５３５'),
                             ('voice_ports', '٣٤٧٨,٥٣٤٩')]:
            with self.subTest(field=field), self.assertRaises(z.Error):
                z.validate_config(dict(z.DEFAULTS, **{field: value}), self.root)
        self.assertEqual(z.ports('1024-1934,1936-65535'), '1024-1934,1936-65535')

    def test_shared_address_space_is_excluded_from_tcp_and_udp_interception(self):
        # Default local exclusions must not depend on the downloaded/user list.
        for name in ('ipset-exclude.txt', 'ipset-exclude-user.txt'):
            (self.root / 'lists' / name).write_text('', encoding='utf-8')
        z.prepare_lists(self.root)
        for name in ('excluded_ips.txt', 'excluded4.txt'):
            excluded = [ipaddress.ip_network(line)
                        for line in (self.root / 'runtime' / name).read_text().splitlines()]
            for address in ('100.64.0.1', '100.100.100.100', '100.127.255.254'):
                with self.subTest(file=name, address=address):
                    self.assertTrue(any(ipaddress.ip_address(address) in network
                                        for network in excluded if network.version == 4))
            self.assertFalse(any(ipaddress.ip_address('100.128.0.1') in network
                                 for network in excluded if network.version == 4))

    def test_active_pf_loopback_skip_is_rejected_without_mutating_global_rules(self):
        def pf(*args, **kwargs):
            if args == ('-sr',):
                return SimpleNamespace(stdout='anchor "com.apple/*" all\n')
            if args == ('-sn',):
                return SimpleNamespace(stdout='rdr-anchor "com.apple/*" all\n')
            if args == ('-v', '-s', 'Interfaces'):
                return SimpleNamespace(stdout='ALL\nen0\nlo0 (skip)\n')
            raise AssertionError('PF mutation during rejected startup: ' + repr(args))

        with patch.object(z, 'pf', side_effect=pf), self.assertRaisesRegex(z.Error, 'lo0'):
            z.ensure_pf_hooks()

    def test_standard_pf_hooks_allow_unskipped_loopback(self):
        responses = [SimpleNamespace(stdout='anchor "com.apple/*" all\n'),
                     SimpleNamespace(stdout='rdr-anchor "com.apple/*" all\n'),
                     SimpleNamespace(stdout='lo0\nen0 (skip)\n')]
        with patch.object(z, 'pf', side_effect=responses) as pf:
            z.ensure_pf_hooks()
        self.assertFalse(any('-f' in call.args for call in pf.call_args_list))

    def test_pf_rule_label_cannot_impersonate_the_required_filter_anchor(self):
        responses = [SimpleNamespace(stdout='pass all label "com.apple/*"\n'),
                     SimpleNamespace(stdout='rdr-anchor "com.apple/*" all\n'),
                     SimpleNamespace(stdout='lo0\n')]
        with patch.object(z, 'pf', side_effect=responses) as pf, self.assertRaises(z.Error):
            z.ensure_pf_hooks()
        self.assertFalse(any('-f' in call.args for call in pf.call_args_list))

    def test_scoped_pf_anchors_cannot_claim_to_cover_the_transparent_backend(self):
        for filter_rule, rdr_rule in [
                ('anchor "com.apple/*" on en0 inet proto udp all', 'rdr-anchor "com.apple/*" all'),
                ('anchor "com.apple/*" all', 'rdr-anchor "com.apple/*" on en0 all')]:
            responses = [SimpleNamespace(stdout=filter_rule + '\n'),
                         SimpleNamespace(stdout=rdr_rule + '\n'),
                         SimpleNamespace(stdout='lo0\n')]
            with self.subTest(filter=filter_rule, rdr=rdr_rule), \
                    patch.object(z, 'pf', side_effect=responses) as pf, self.assertRaises(z.Error):
                z.ensure_pf_hooks()
            self.assertFalse(any('-f' in call.args for call in pf.call_args_list))

    def test_scoped_pf_conf_is_not_loaded_when_active_rules_are_empty(self):
        source = 'rdr-anchor "com.apple/*"\nanchor "com.apple/*" on en0 proto udp\n'
        responses = [SimpleNamespace(stdout=''), SimpleNamespace(stdout='')]
        with patch.object(z, 'pf', side_effect=responses) as pf, \
                patch.object(Path, 'read_text', return_value=source), self.assertRaises(z.Error):
            z.ensure_pf_hooks()
        self.assertFalse(any('-f' in call.args for call in pf.call_args_list))

    def test_default_pf_conf_load_checks_the_resulting_loopback_flags(self):
        source = 'rdr-anchor\t"com.apple/*" # Apple hook\nanchor "com.apple/*"\n'
        for flags, success in [('lo0\nen0\n', True), ('lo0 (skip)\n', False)]:
            responses = [SimpleNamespace(stdout=''), SimpleNamespace(stdout=''),
                         SimpleNamespace(stdout=''), SimpleNamespace(stdout=''),
                         SimpleNamespace(stdout=flags)]
            with self.subTest(flags=flags), patch.object(z, 'pf', side_effect=responses), \
                    patch.object(Path, 'read_text', return_value=source):
                if success:
                    z.ensure_pf_hooks()
                else:
                    with self.assertRaisesRegex(z.Error, 'lo0'):
                        z.ensure_pf_hooks()

    def test_cache_cleanup_aborts_when_process_inventory_is_unavailable(self):
        home = self.root / 'home'
        cache = home / 'Library' / 'Application Support' / 'discord' / 'Cache'
        cache.mkdir(parents=True)
        (cache / 'entry').write_bytes(b'preserve active cache')
        user = SimpleNamespace(pw_uid=501, pw_dir=str(home))
        for code in (2, 3):
            with self.subTest(returncode=code):
                def failed_inventory(args, **kwargs):
                    if args[0] == '/usr/bin/pgrep':
                        return SimpleNamespace(returncode=code, stderr='process inventory failed')
                    raise AssertionError('Cache moved without a reliable Discord process check')

                with patch.object(z, 'require_mac'), patch.object(z, 'original_user', return_value=user), \
                        patch.object(z, 'run', side_effect=failed_inventory), self.assertRaises(z.Error):
                    z.clean_discord_cache(self.root)
                self.assertEqual((cache / 'entry').read_bytes(), b'preserve active cache')
                self.assertEqual(list(cache.parent.glob('Cache.zapret-backup-*')), [])

    def test_open_foreign_listener_cannot_make_engine_ready(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        foreign = SimpleNamespace(returncode=0, stdout='p999\nf3\nn127.0.0.1:988\n')
        # Port 988 needs root on macOS. Model an accepted connection here;
        # sudo check_native.py covers the actual socket and lsof integration.
        with patch.object(z.socket, 'create_connection', return_value=contextlib.nullcontext()), \
                patch.object(z, 'run', return_value=foreign), \
                patch.object(z.time, 'monotonic', side_effect=[0, 0, 1]), patch.object(z.time, 'sleep'):
            with self.assertRaises(z.Error):
                z.wait_ready(child, timeout=0.5)

    def test_engine_readiness_requires_its_exact_local_listener(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        owned = SimpleNamespace(returncode=0, stdout='p123\nf4\nn127.0.0.1:988\n')
        with patch.object(z.socket, 'create_connection', return_value=contextlib.nullcontext()), \
                patch.object(z, 'run', return_value=owned):
            z.wait_ready(child, timeout=0.5)

    def test_child_exit_during_listener_inventory_cannot_make_engine_ready(self):
        child = Mock(pid=123)
        child.poll.side_effect = [None, 1]
        owned = SimpleNamespace(returncode=0, stdout='p123\nf4\nn127.0.0.1:988\n')
        with patch.object(z.socket, 'create_connection', return_value=contextlib.nullcontext()), \
                patch.object(z, 'run', return_value=owned), self.assertRaises(z.Error):
            z.wait_ready(child, timeout=0.5)

    @unittest.skipUnless(os.name == 'posix', 'Needs POSIX directory permission bits')
    def test_list_backups_stay_private_with_permissive_umask(self):
        def downloaded(url):
            return '1.1.1.1/32\n' if 'ipset' in url else 'updated.invalid\n'

        previous_umask = os.umask(0)
        try:
            with patch.object(z, 'require_mac'), patch.object(z, 'download', side_effect=downloaded), \
                    patch.object(z, 'is_running', return_value=False), contextlib.redirect_stdout(io.StringIO()):
                z.update_lists(self.root)
        finally:
            os.umask(previous_umask)
        backup = next((self.root / 'backups').glob('lists-*'))
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
