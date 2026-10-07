#!/usr/bin/env python3
"""On macOS validate generated options with the actual engine and PF parser."""
import itertools
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z
from voice_controller import udp_rules, UDP_ANCHOR

if sys.platform != 'darwin':
    raise SystemExit('Run this check on macOS.')
binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='zapret-native-check-') as temp:
    root = Path(temp)
    shutil.copytree(z.SOURCE / 'lists', root / 'lists')
    shutil.copy2(z.SOURCE / 'strategies.json', root / 'strategies.json')
    (root / 'bin').mkdir()
    shutil.copy2(binary, root / 'bin/tpws')
    z.prepare_lists(root)
    count = 0
    for name, ipset, game, ipv6 in itertools.product(z.strategies(root), ['none', 'loaded', 'any'], [False, True], [False, True]):
        cfg = dict(z.DEFAULTS, strategy=name, ipset=ipset, game_filter=game, ipv6=ipv6)
        z.run(z.engine_args(cfg, root) + ['--dry-run'])
        count += 1
    for ipv6, game, quic in itertools.product([False, True], repeat=3):
        cfg = dict(z.DEFAULTS, ipv6=ipv6, game_filter=game, quic_fallback=quic)
        anchor = root / 'runtime/anchor.conf'
        z.atomic_write(anchor, z.pf_rules(cfg, root))
        z.pf('-n', '-a', z.ANCHOR, '-f', anchor)
    for ipv6, ports in itertools.product([False, True], ['19294-19344,50000-50100', '1024-65535']):
        cfg = dict(z.DEFAULTS, ipv6=ipv6, voice_udp=True, voice_ports=ports)
        anchor = root / 'runtime/udp-anchor.conf'
        z.atomic_write(anchor, udp_rules(cfg, root))
        z.pf('-n', '-a', UDP_ANCHOR, '-f', anchor)
        z.run(z.engine_args(cfg, root) + ['--dry-run'])
        tcp_anchor = root / 'runtime/voice-tcp-anchor.conf'
        z.atomic_write(tcp_anchor, z.pf_rules(cfg, root))
        z.pf('-n', '-a', z.ANCHOR, '-f', tcp_anchor)
    print(f'PASS: {count + 4} engine configurations and 16 PF syntax checks. No rules applied.')
