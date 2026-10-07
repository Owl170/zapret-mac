#!/usr/bin/env python3
"""macOS-only end-to-end UDP PF test, scoped to reserved probe destinations."""
from pathlib import Path
import argparse
import contextlib
import json
import re
import shutil
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z
import voice_controller as v


@contextlib.contextmanager
def packet_trace(root, enabled):
    """Bounded packet headers for reserved selftest traffic; never dump payloads."""
    captures = []
    try:
        if enabled:
            interfaces = ['lo0']
            route = z.run(['/sbin/route', '-n', 'get', v.TEST4], check=False)
            found = re.search(r'^\s*interface:\s*([a-zA-Z][a-zA-Z0-9]*)\s*$', route.stdout, re.M)
            if found and found.group(1) not in interfaces:
                interfaces.append(found.group(1))
            expression = (f'udp and (port {v.UDP_PORT} or '
                          f'((host {v.TEST4} or host {v.TEST6}) and port {v.TEST_PORT}))')
            for interface in interfaces:
                path = root / 'logs' / ('probe-headers-' + interface + '.txt')
                output = path.open('wb')
                try:
                    child = subprocess.Popen(['/usr/sbin/tcpdump', '-n', '-q', '-l', '-c', '100',
                                              '-i', interface, expression], stdout=output,
                                             stderr=subprocess.STDOUT)
                except OSError:
                    output.close()
                    raise
                captures.append((child, output, path))
        yield
    finally:
        failures = []
        for child, output, path in captures:
            try:
                if child.poll() is None:
                    child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
            finally:
                output.close()
                print(path.name + ':\n' + path.read_text(errors='replace')[:16000])
        if failures:
            print('Trace cleanup: ' + '; '.join(failures), file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', action='store_true', help='Print bounded reserved-probe packet headers.')
    args = parser.parse_args(argv)
    z.require_mac(True)
    if z.ROOT.exists() and z.is_running():
        raise SystemExit('Сначала остановите ZapretMac. Проверка не меняет активную установку.')
    if z.pf('-a', v.UDP_ANCHOR, '-sr').stdout.strip() or z.pf('-a', v.UDP_ANCHOR, '-sn').stdout.strip():
        raise SystemExit('UDP-anchor уже занят. Проверка прекращена.')
    z.ensure_pf_hooks()
    enabled = z.pf('-E')
    token = re.search(r'Token\s*:\s*(\d+)', enabled.stdout + enabled.stderr)
    if not token:
        raise SystemExit('PF enable token missing.')
    try:
        with tempfile.TemporaryDirectory(prefix='zmac-pf-udp-test-') as directory:
            root = Path(directory)
            # The non-root probe must be able to read Python modules and this directory.
            root.chmod(0o755)
            shutil.copytree(z.SOURCE / 'lists', root / 'lists')
            shutil.copytree(z.SOURCE / 'payloads', root / 'payloads')
            shutil.copy2(z.SOURCE / 'strategies.json', root / 'strategies.json')
            for name in ('zapret.py', 'discord_udp.py', 'voice_controller.py'):
                shutil.copy2(z.SOURCE / name, root / name)
            (root / 'logs').mkdir()
            cfg = dict(z.DEFAULTS, voice_udp=True, voice_profile='relay')
            z.write_json(root / 'config.json', cfg)
            z.write_json(root / 'installation.json', dict(user_uid=z.original_user().pw_uid))
            z.prepare_lists(root)
            backend = v.Backend(root)
            with packet_trace(root, args.trace):
                try:
                    if not backend.start(cfg, probe_only=True):
                        path = root / 'logs' / 'udp.log'
                        if path.exists():
                            print(path.read_text())
                        diagnostic = root / 'logs/udp-start-failure.json'
                        if diagnostic.exists():
                            print(diagnostic.read_text())
                        print('Relay final counters:', json.dumps(v.read_status(root), ensure_ascii=False, indent=2))
                        print('lo0:', z.run(['/sbin/ifconfig', 'lo0'], check=False).stdout)
                        print('probe route:', z.run(['/sbin/route', '-n', 'get', v.TEST4], check=False).stdout)
                        raise SystemExit('FAIL: ' + backend.error)
                    print(json.dumps(v.read_status(root), indent=2, ensure_ascii=False))
                    print('PASS: non-root UDP → PF redirect → original destination lookup → reverse NAT reply.')
                    print('Only reserved probe destinations were redirected. This does not test Discord audio.')
                finally:
                    backend.stop()
    finally:
        z.pf('-X', token.group(1))


if __name__ == '__main__':
    main()
