#!/bin/bash
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then echo 'Требуется macOS.'; exit 1; fi
TASK_ROOT='/Library/Application Support/ZapretMac'
if [[ -f "$TASK_ROOT/zapret.py" ]]; then
  sudo /usr/bin/python3 "$TASK_ROOT/zapret.py" uninstall
else
  echo 'ZapretMac не установлен.'
fi
read -r -p 'Нажмите Enter…' _ || true
