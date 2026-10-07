#!/bin/bash
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then echo 'Требуется macOS.'; exit 1; fi
TASK_ROOT='/Library/Application Support/ZapretMac'
if [[ ! -f "$TASK_ROOT/discord_udp.py" ]]; then
  echo 'Сначала установите эту версию через install.command.'
  read -r -p 'Нажмите Enter…' _ || true
  exit 1
fi
sudo /usr/bin/python3 "$TASK_ROOT/zapret.py" voice-menu
