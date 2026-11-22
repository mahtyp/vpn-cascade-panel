#!/usr/bin/env bash
# Изолированный стенд реальной add_sudoku() со службой/Mihomo/SOCKS-заглушками.
# Не вызывает SSH, systemctl, curl, apt или файловую систему VPS.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../server-scripts/vpn-add-exit.sh
source "$ROOT/server-scripts/vpn-add-exit.sh"

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
MIHOMO_CONF="$TMPD/config.yaml"
MIHOMO_BIN="$TMPD/mihomo"
NAME="NewExit"
IP="203.0.113.55"
FORCE=0
LOG="$TMPD/restarts.log"
BASE="$TMPD/original.yaml"

cat > "$BASE" <<'YAML'
listeners: []
proxies: []
rules:
  - MATCH,DIRECT
YAML
cat > "$MIHOMO_BIN" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$MIHOMO_BIN"

rssh() {
  cat <<'REMOTE'
=====/etc/sudoku/subscription.yaml
proxies:
  - type: sudoku
    name: stand-node
    port: 8443
    key: stand-only-key
=====/etc/sudoku/config.json
{}
=====/etc/sudoku/export-state.env
REMOTE
}
systemctl() {
  if [ "$1" = restart ] && [ "$2" = mihomo ]; then
    echo restarted >> "$LOG"
    if [ "${SERVICE_FAIL_FIRST:-0}" = 1 ] && [ "$(wc -l < "$LOG")" -eq 1 ]; then
      return 1
    fi
  fi
  return 0
}
curl() {
  [[ "$*" == *"--socks5-hostname 127.0.0.1:1080 "* ]] || return 8
  case "${VIA_MODE:-good}" in
    good) echo "$IP" ;;
    dual-stack)
      case "${!#}" in
        https://ifconfig.me) echo 2001:db8::55 ;;
        https://api.ipify.org) echo "$IP" ;;
        *) return 8 ;;
      esac
      ;;
    bad) return 7 ;;
    wrong) echo 198.51.100.1 ;;
    *) return 8 ;;
  esac
}
sleep() { :; }

reset_fixture() {
  cp "$BASE" "$MIHOMO_CONF"
  : > "$LOG"
  SERVICE_FAIL_FIRST=0
  VIA_MODE=good
}
expect_restarts() {
  local count
  count=$(wc -l < "$LOG")
  [ "$count" = "$1" ] || { echo "ожидал $1 перезапусков, было $count" >&2; exit 1; }
}

# 1. Новый выход: конфигурация должна измениться; только один перезапуск.
reset_fixture
(add_sudoku) > "$TMPD/success.log" 2>&1 || { cat "$TMPD/success.log"; exit 1; }
grep -q 'EU-Sudoku-NewExit' "$MIHOMO_CONF"
grep -q 'SOCKS 1080' "$TMPD/success.log"
expect_restarts 1
cp "$MIHOMO_CONF" "$TMPD/installed.yaml"
echo "PASS: новый канал работает"

# 2. Канал пропал: обязан вернуться исходный файл и состояться второй перезапуск.
reset_fixture
VIA_MODE=bad
if (add_sudoku) > "$TMPD/no-channel.log" 2>&1; then
  echo "ошибка: недоступный новый SOCKS принят за рабочий" >&2; exit 1
fi
cmp -s "$BASE" "$MIHOMO_CONF" || { echo "новый конфиг не откатился" >&2; exit 1; }
expect_restarts 2
grep -q 'прежний конфиг Mihomo восстановлен' "$TMPD/no-channel.log"
echo "PASS: SOCKS не работает → конфиг и служба восстановлены"

# 3. systemctl restart не прошёл: откат должен работать и без HTTP.
reset_fixture
SERVICE_FAIL_FIRST=1
if (add_sudoku) > "$TMPD/restart-fail.log" 2>&1; then
  echo "ошибка: отказ перезапуска скрыт" >&2; exit 1
fi
cmp -s "$BASE" "$MIHOMO_CONF" || { echo "не откатился после отказа systemctl" >&2; exit 1; }
expect_restarts 2
echo "PASS: отказ systemctl → прежний конфиг восстановлен"

# 4. Уже существующий, но упавший путь: не менять конфиг, не перезапускать, сообщить сбой.
cp "$TMPD/installed.yaml" "$MIHOMO_CONF"
: > "$LOG"
VIA_MODE=wrong
if (add_sudoku) > "$TMPD/already-bad.log" 2>&1; then
  echo "ошибка: нерабочий существующий путь принят" >&2; exit 1
fi
cmp -s "$TMPD/installed.yaml" "$MIHOMO_CONF" || { echo "исправный конфиг изменён" >&2; exit 1; }
expect_restarts 0
echo "PASS: существующий недоступный SOCKS не помечен рабочим"

# 5. Dual stack: для настроенного IPv4 нужен контрольный сайт с IPv4.
reset_fixture
VIA_MODE=dual-stack
(add_sudoku) > "$TMPD/dual-stack.log" 2>&1 || { cat "$TMPD/dual-stack.log"; exit 1; }
expect_restarts 1
echo "PASS: проверка нового канала с IPv4 на выходе с двумя стеками"
