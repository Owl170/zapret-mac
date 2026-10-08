#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
finish() { echo; read -r -p 'Нажмите Enter, чтобы закрыть окно…' _ || true; }
trap finish EXIT
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'Этот установщик предназначен для macOS.'; exit 1
fi
if ! xcode-select -p >/dev/null 2>&1; then
  echo 'Нужны Apple Command Line Tools. Подтвердите установку в окне Apple,'
  echo 'дождитесь её завершения и снова откройте install.command.'
  xcode-select --install || true
  exit 1
fi
/usr/bin/python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else "Нужен Python 3.9+. Обновите Apple Command Line Tools.")'
TASK_BUILD=$(mktemp -d /tmp/zapret-macos-build.XXXXXXXX)
trap 'rm -rf -- "$TASK_BUILD"; finish' EXIT
cp -R engine/tpws "$TASK_BUILD/tpws"
echo 'Сборка официального tpws для Apple Silicon и Intel…'
make -C "$TASK_BUILD/tpws" mac CC=clang CFLAGS='-std=gnu99 -Os -ffunction-sections -fdata-sections' LDFLAGS=''
"$TASK_BUILD/tpws/tpws" --dry-run --port=988 --bind-addr=127.0.0.1 --split-pos=1,midsld
echo 'Проверка интерфейса UDP NAT lookup…'
clang -Iengine/tpws/macos native/pf_abi_probe.c -o "$TASK_BUILD/pf_abi_probe"
"$TASK_BUILD/pf_abi_probe" > "$TASK_BUILD/abi-native.json"
/usr/bin/python3 discord_udp.py abi > "$TASK_BUILD/abi-python.json"
/usr/bin/python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])) == json.load(open(sys.argv[2])) else "PF ABI mismatch")' "$TASK_BUILD/abi-native.json" "$TASK_BUILD/abi-python.json"
echo 'Установка в /Library/Application Support/ZapretMac.'
sudo /usr/bin/python3 zapret.py install --engine "$TASK_BUILD/tpws/tpws"
echo 'Готово. Автозапуск включается по умолчанию; выбранные настройки сохранены.'
echo 'Для голоса откройте voice.command и выберите пункт 1.'
