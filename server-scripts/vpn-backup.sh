#!/usr/bin/env bash
# vpn-backup.sh — снимает бэкап входного сервера (3X-UI + AmneziaWG + sysctl + fail2ban)
# Запуск на основном входе:  bash vpn-backup.sh
# Результат: /root/vpn-backup-<дата>.tar.gz (внутри ключи и пароли — храните как секрет)

set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }

TS=$(date +%F_%H%M)
NAME="vpn-backup-$(hostname -s)-$TS"
WORK="/root/$NAME"
DST="$WORK/files"
mkdir -p "$DST"

say() { printf '\n== %s\n' "$*"; }

copy() {
  for p in "$@"; do
    if [ -e "$p" ]; then
      mkdir -p "$DST$(dirname "$p")"
      cp -a "$p" "$DST$(dirname "$p")/"
      echo "  + $p"
    else
      echo "  - нет $p (пропущено)"
    fi
  done
}

say "3X-UI: база (снимок без остановки панели)"
if [ -f /etc/x-ui/x-ui.db ]; then
  mkdir -p "$DST/etc/x-ui"
  python3 - "$DST/etc/x-ui/x-ui.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
dst.close(); src.close()
print('  + /etc/x-ui/x-ui.db')
PY
else
  echo "  ! /etc/x-ui/x-ui.db не найден — 3X-UI не будет в бэкапе"
fi

say "3X-UI: сертификаты панели и подписки (пути берутся из базы)"
CERTS=$(python3 - <<'PY' || true
import sqlite3
try:
    c = sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
    rows = c.execute("select key, value from settings where key in "
                     "('webCertFile','webKeyFile','subCertFile','subKeyFile')").fetchall()
    for k, v in rows:
        if v: print(v)
except Exception as e:
    pass
PY
)
if [ -n "$CERTS" ]; then
  # shellcheck disable=SC2046
  copy $(echo "$CERTS" | sort -u)
else
  echo "  (в базе пути к сертификатам не заданы)"
fi

say "AmneziaWG: конфиги (только для справки — на новом сервере нужны НОВЫЕ клиенты)"
copy /etc/amnezia/amneziawg

say "Ядро: sysctl (BBR, буферы)"
copy /etc/sysctl.conf /etc/sysctl.d

say "fail2ban"
copy /etc/fail2ban/jail.local /etc/fail2ban/jail.d

say "Версии компонентов"
{
  echo "date=$(date -Is)"
  echo "host=$(hostname)"
  echo "ip=$(hostname -I | awk '{print $1}')"
  echo "kernel=$(uname -r)"
  echo "os=$(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "xui=$( { /usr/local/x-ui/x-ui -v 2>/dev/null || x-ui -v 2>/dev/null; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  XRAY_BIN=$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -n1 || true)
  # sed -n 1p вместо head -1: head закрывает канал раньше времени, и с pipefail
  # вместе с версией печаталось ещё и «unknown»
  echo "xray=$( { [ -n "$XRAY_BIN" ] && "$XRAY_BIN" version 2>/dev/null; } | sed -n 1p)"
  echo "awg_tools=$(awg --version 2>/dev/null | sed -n 1p)"
  echo "awg_module=$(modinfo -F version amneziawg 2>/dev/null || echo unknown)"
} | tee "$WORK/versions.txt"

say "Упаковка"
ARCH="/root/$NAME.tar.gz"
tar -czf "$ARCH" -C /root "$NAME"
chmod 600 "$ARCH"
rm -rf "$WORK"

SIZE=$(du -h "$ARCH" | cut -f1)
IP=$(hostname -I | awk '{print $1}')
cat <<EOF

Готово: $ARCH ($SIZE)
В архиве UUID, ключи REALITY и AWG — храните как пароль.

Скачать на компьютер (PowerShell, в папку, где вы сейчас):
  scp root@$IP:$ARCH .

Или сразу на новый сервер (выполнить здесь, на этом сервере):
  scp $ARCH root@НОВЫЙ_IP:/root/
EOF
