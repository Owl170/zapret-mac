#!/usr/bin/env python3
"""On macOS validate generated options with the actual engine and PF parser."""
import itertools
from pathlib import Path
import shutil
import socket
import subprocess
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
    # Exercise production readiness with the actual macOS lsof field format.
    # Refuse to disturb a pre-existing listener; only this child is terminated.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        # Match tpws so TIME_WAIT from preceding transport checks is reusable.
        # An active listener still prevents this bind.
        reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            reserved.bind(('127.0.0.1', 988))
        except OSError as error:
            raise z.Error('Native readiness check needs free TCP 127.0.0.1:988.') from error
    ready_log = root / 'runtime/readiness.log'
    with ready_log.open('wb') as log:
        child = subprocess.Popen(z.engine_args(dict(z.DEFAULTS, ipv6=False), root),
                                 stdout=log, stderr=log)
        try:
            z.wait_ready(child)
        except BaseException:
            log.flush()
            print(ready_log.read_text(encoding='utf-8', errors='replace'), file=sys.stderr)
            raise
        finally:
            if child.poll() is None:
                try:
                    child.terminate()
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                child.wait(timeout=5)
    print('PASS: production TCP readiness verified the engine PID owns 127.0.0.1:988.')
    print(f'PASS: {count + 4} engine configurations and 16 PF syntax checks. No rules applied.')
