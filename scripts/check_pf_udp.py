#!/usr/bin/env python3
"""macOS-only end-to-end UDP PF test, scoped to reserved probe destinations."""
from pathlib import Path
import json
import re
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zapret as z
import voice_controller as v

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
        try:
            if not backend.start(cfg, probe_only=True):
                path = root / 'logs' / 'udp.log'
                if path.exists():
                    print(path.read_text())
                raise SystemExit('FAIL: ' + backend.error)
            print(json.dumps(v.read_status(root), indent=2, ensure_ascii=False))
            print('PASS: non-root UDP → PF redirect → original destination lookup → reverse NAT reply.')
            print('Only reserved probe destinations were redirected. This does not test Discord audio.')
        finally:
            backend.stop()
finally:
    z.pf('-X', token.group(1))
