import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z


class NativeControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(z.SOURCE / 'lists', self.root / 'lists')
        shutil.copy2(z.SOURCE / 'strategies.json', self.root / 'strategies.json')
        self.cfg = dict(z.DEFAULTS)
        z.prepare_lists(self.root)

    def test_all_bundled_lists_accept_real_upstream_format(self):
        for path in (self.root / 'lists').iterdir():
            z.load_entries(path, 'ip' if path.name.startswith('ipset') else 'host')
        self.assertIn('^dns.google', z.load_entries(self.root / 'lists/list-general.txt', 'host'))

    def test_domains_and_ipsets_reject_injected_options(self):
        for text, kind in [('--new', 'host'), ('a.com\"; pass all', 'host'), ('0.0.0.0/0; pass all', 'ip')]:
            with self.assertRaises(z.Error):
                z.entries(text, kind)
        self.assertEqual(z.entries('^EXAMPLE.COM\nexample.org # ok', 'host'), ['^example.com', 'example.org'])

    def test_exclusions_apply_to_every_active_profile(self):
        for mode in ('none', 'loaded', 'any'):
            cfg = dict(self.cfg, ipset=mode, game_filter=True)
            args = z.engine_args(cfg, self.root)
            groups = []
            group = []
            for arg in args[args.index('--filter-tcp=443'):]:
                if arg == '--new':
                    groups.append(group)
                    group = []
                else:
                    group.append(arg)
            for group in groups:
                self.assertTrue(any(a.startswith('--hostlist-exclude=') for a in group))
                self.assertTrue(any(a.startswith('--ipset-exclude=') for a in group))
            self.assertEqual(any(a.startswith('--ipset=') for a in args), mode == 'loaded')

    def test_game_off_and_ipset_none_do_not_capture_game_ports(self):
        for cfg in (self.cfg, dict(self.cfg, game_filter=True, ipset='none')):
            self.assertNotIn('1024:65535', z.pf_rules(cfg, self.root))
            self.assertNotIn('--split-any-protocol', z.engine_args(cfg, self.root))
        cfg = dict(self.cfg, game_filter=True, game_tcp='1024-1934,1936-65535')
        self.assertIn('1024:1934,1936:65535', z.pf_rules(cfg, self.root))
        self.assertIn('--split-any-protocol', z.engine_args(cfg, self.root))

    def test_no_udp_desync_is_advertised_or_generated(self):
        for name in z.strategies(self.root):
            cfg = dict(self.cfg, strategy=name)
            args = z.engine_args(cfg, self.root)
            self.assertFalse(any('dpi-desync' in a or 'filter-udp' in a or 'fake' in a for a in args))
        self.assertNotIn('proto udp', z.pf_rules(self.cfg, self.root))
        self.assertIn('block return out quick inet proto udp', z.pf_rules(dict(self.cfg, quic_fallback=True), self.root))

    def test_ipv6_is_present_unless_explicitly_disabled(self):
        self.assertIn('inet6', z.pf_rules(self.cfg, self.root))
        self.assertIn('--bind-iface6=lo0', z.engine_args(self.cfg, self.root))
        cfg = dict(self.cfg, ipv6=False)
        self.assertNotIn('inet6', z.pf_rules(cfg, self.root))
        self.assertNotIn('--bind-iface6=lo0', z.engine_args(cfg, self.root))

    def test_no_oob_disorder_combination_on_macos(self):
        for value in z.strategies(self.root).values():
            self.assertFalse('--oob' in value['args'] and '--disorder' in value['args'])

    def test_hosts_block_preserves_unrelated_records(self):
        original = '127.0.0.1 localhost\n192.168.1.2 private.local\n'
        combined = original + z.HOST_BEGIN + '\n1.1.1.1 example.com\n' + z.HOST_END + '\n'
        self.assertEqual(z.strip_hosts_block(combined), original)
        with self.assertRaises(z.Error):
            z.strip_hosts_block(original + z.HOST_BEGIN + '\n')
        with self.assertRaises(z.Error):
            z.hosts_entries('127.0.0.1 discord.com')

    def test_download_failure_leaves_all_original_lists(self):
        original = {p.name: p.read_bytes() for p in (self.root / 'lists').iterdir()}
        with patch.object(z, 'require_mac'), patch.object(z, 'download', side_effect=['example.com', z.Error('offline')]):
            with self.assertRaises(z.Error):
                z.update_lists(self.root)
        self.assertEqual(original, {p.name: p.read_bytes() for p in (self.root / 'lists').iterdir()})

    def test_update_write_failure_rolls_back_written_files(self):
        original = {p.name: p.read_bytes() for p in (self.root / 'lists').iterdir()}
        real_write = z.atomic_write

        def failing_write(path, text, mode=0o644):
            if path.name == 'list-google.txt':
                raise OSError('disk error')
            real_write(path, text, mode)

        downloads = ['example.com', 'google.com', 'exclude.com', '1.1.1.0/24', '8.8.8.0/24']
        with patch.object(z, 'require_mac'), patch.object(z, 'download', side_effect=downloads), patch.object(z, 'atomic_write', side_effect=failing_write):
            with self.assertRaises(OSError):
                z.update_lists(self.root)
        self.assertEqual(original, {p.name: p.read_bytes() for p in (self.root / 'lists').iterdir()})

    def test_pf_cleanup_only_replaces_our_anchor(self):
        with patch.object(z, 'pf') as pf:
            z.clear_anchor()
        pf.assert_called_once_with('-a', z.ANCHOR, '-f', '-', input='', check=False)

    def test_custom_active_pf_is_not_overwritten(self):
        with patch.object(z, 'pf', side_effect=[SimpleNamespace(stdout='block all'), SimpleNamespace(stdout='')]) as pf:
            with self.assertRaises(z.Error):
                z.ensure_pf_hooks()
        self.assertEqual(pf.call_count, 2)

    def test_strategy_failure_restores_config_and_running_state(self):
        (self.root / 'logs').mkdir()
        z.write_json(self.root / 'config.json', self.cfg)
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=True), patch.object(z, 'stop') as stop, patch.object(z, 'start', side_effect=[z.Error('engine failed'), None]) as start:
            with self.assertRaises(z.Error):
                z.test_strategies(self.root)
        self.assertEqual(z.config(self.root), self.cfg)
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(start.call_count, 2)

    def test_engine_crash_removes_anchor_and_terminates_child(self):
        child = SimpleNamespace(pid=123, poll=lambda: None, terminate=lambda: None, wait=lambda timeout=None: None)
        with patch.object(z, 'require_mac'), patch.object(z.signal, 'signal'), patch.dict(sys.modules, {'fcntl': SimpleNamespace(flock=lambda *a: None, LOCK_EX=1, LOCK_NB=4)}), patch.object(z, 'is_running', return_value=False), patch.object(z, 'release_pf') as release, patch.object(z, 'run'), patch.object(z, 'wait_ready', side_effect=z.Error('child died')), patch.object(z.subprocess, 'Popen', return_value=child):
            with self.assertRaises(z.Error):
                z.supervise(self.root)
        self.assertEqual(release.call_count, 2)
        self.assertFalse((self.root / 'runtime/state.json').exists())

    def test_stopping_error_during_tests_still_restores_configuration(self):
        (self.root / 'logs').mkdir()
        z.write_json(self.root / 'config.json', self.cfg)
        with patch.object(z, 'require_mac'), patch.object(z, 'is_running', return_value=False), patch.object(z, 'stop', side_effect=[None, z.Error('cannot stop')]), patch.object(z, 'start', side_effect=z.Error('cannot start')):
            with self.assertRaises(z.Error):
                z.test_strategies(self.root)
        self.assertEqual(z.config(self.root), self.cfg)


if __name__ == '__main__':
    unittest.main()
