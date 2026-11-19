#!/usr/bin/env bash
# vpn-sw-update.sh — обновить Sudoku (выход) или Mihomo (вход) с GitHub. Кнопкой из панели каскада.
# Конфиги не меняются. Новая версия сначала проверяет конфиг; не подошла — ничего не трогаю. Не поднялась
# после перезапуска — сразу возвращаю старую. Каналы со входов панель проверяет сама и при сбое зовёт *-rollback.
#
#   bash vpn-sw-update.sh sudoku   <ссылка на sudoku-linux-*.tar.gz> <тег>
#   bash vpn-sw-update.sh mihomo   <ссылка на mihomo-linux-*.gz> <путь к mihomo>
#   bash vpn-sw-update.sh sudoku-rollback
#   bash vpn-sw-update.sh mihomo-rollback <путь к mihomo>
#
# Старая программа — в /root/.vpn-dash-sw-backup/ (sudoku.bin, mihomo.bin).
set -uo pipefail

BK=/root/.vpn-dash-sw-backup
SUDOKU=/usr/local/bin/sudoku
SCONF=/etc/sudoku/config.json
VERS=/etc/sudoku/versions.env
MDIR=/etc/mihomo

say() { echo "== $*"; }
ok()  { echo "  ✓ $*"; }
die() { echo "  ✗ $*" >&2; exit 1; }
listening() { ss -Htln "sport = :$1" 2>/dev/null | grep -q .; }
wait_port() { for _ in $(seq 1 "${2:-15}"); do listening "$1" && return 0; sleep 1; done; return 1; }
ver_set() {
  local tmp; tmp=$(mktemp)
  [ -f "$VERS" ] && grep -v "^$1=" "$VERS" > "$tmp" || true
  echo "$1=$2" >> "$tmp"; mv "$tmp" "$VERS"; chmod 600 "$VERS"
}
fetch() {   # <url> <файл>
  case "$1" in https://github.com/*/releases/download/*) ;; *) die "ссылка не на релиз GitHub: $1" ;; esac
  curl -fsSL --connect-timeout 15 --max-time 300 "$1" -o "$2" || die "не скачалось: $1"
}
mihomo_ports() {   # порты, которые слушает mihomo сейчас (SOCKS-входы для Sudoku)
  ss -Htlnp 2>/dev/null | awk '/"mihomo"/ {n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' '
}

mkdir -p "$BK" && chmod 700 "$BK"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

case "${1:-}" in
sudoku)
  URL=${2:?ссылка}; TAG=${3:?тег}
  say "Sudoku: проверка"
  systemctl is-active --quiet sudoku || die "служба sudoku не работает — обновлять нечего"
  P=$(python3 -c "import json; print(json.load(open('$SCONF'))['local_port'])" 2>/dev/null) || die "нет local_port в $SCONF"
  OLD=$(sed -n 's/^SUDOKU_VERSION=//p' "$VERS" 2>/dev/null | tail -n1)
  ok "сейчас ${OLD:-версия неизвестна}, TCP $P"
  say "Sudoku $TAG: скачать и проверить конфиг"
  fetch "$URL" "$TMP/s.tgz"
  tar -xzf "$TMP/s.tgz" -C "$TMP" || die "архив повреждён"
  NB=$(find "$TMP" -type f -name sudoku | head -n1); [ -n "$NB" ] || die "в архиве нет sudoku"
  chmod 755 "$NB"
  OUT=$("$NB" -c "$SCONF" -test 2>&1) || { echo "$OUT" | tail -5; die "sudoku $TAG не принимает конфиг — ничего не менял"; }
  ok "конфиг подходит"
  say "Замена и перезапуск"
  cp -p "$SUDOKU" "$BK/sudoku.bin"; echo "${OLD:-}" > "$BK/sudoku.ver"
  cp "$NB" "$SUDOKU.new" && chmod 755 "$SUDOKU.new" && mv -f "$SUDOKU.new" "$SUDOKU"
  ver_set SUDOKU_VERSION "$TAG"
  systemctl restart sudoku
  if wait_port "$P" 15 && systemctl is-active --quiet sudoku; then
    ok "sudoku $TAG работает, TCP $P"
  else
    journalctl -u sudoku -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
    cp -p "$BK/sudoku.bin" "$SUDOKU"; [ -n "$OLD" ] && ver_set SUDOKU_VERSION "$OLD"
    systemctl restart sudoku
    die "sudoku $TAG не поднялся — вернул ${OLD:-старую версию}"
  fi
  ;;
sudoku-rollback)
  say "Sudoku: возврат старой версии"
  [ -f "$BK/sudoku.bin" ] || die "нет копии старого sudoku"
  cp -p "$BK/sudoku.bin" "$SUDOKU"
  OLD=$(cat "$BK/sudoku.ver" 2>/dev/null); [ -n "$OLD" ] && ver_set SUDOKU_VERSION "$OLD"
  systemctl restart sudoku
  P=$(python3 -c "import json; print(json.load(open('$SCONF'))['local_port'])" 2>/dev/null)
  wait_port "$P" 15 && ok "вернул ${OLD:-старую версию}, TCP $P" || die "старый sudoku не слушает TCP $P — проверьте вручную"
  ;;
mihomo)
  URL=${2:?ссылка}; BIN=${3:-/usr/local/bin/mihomo}
  say "Mihomo: проверка"
  systemctl is-active --quiet mihomo || die "служба mihomo не работает — обновлять нечего"
  [ -x "$BIN" ] || die "нет $BIN"
  PORTS=$(mihomo_ports)
  ok "сейчас $("$BIN" -v 2>/dev/null | head -n1 | cut -c1-60); слушает: ${PORTS:-ничего}"
  say "Mihomo: скачать и проверить конфиг"
  fetch "$URL" "$TMP/m.gz"
  gunzip -c "$TMP/m.gz" > "$TMP/mihomo" 2>/dev/null || die "архив повреждён"
  chmod 755 "$TMP/mihomo"
  NV=$("$TMP/mihomo" -v 2>/dev/null | head -n1) || true
  [ -n "$NV" ] || die "новый mihomo не запускается на этом сервере — ничего не менял"
  OUT=$("$TMP/mihomo" -d "$MDIR" -t 2>&1) || { echo "$OUT" | tail -5; die "новый mihomo не принимает конфиг — ничего не менял"; }
  ok "$(echo "$NV" | cut -c1-60), конфиг подходит"
  say "Замена и перезапуск (каналы Sudoku с этого входа моргнут на пару секунд)"
  cp -p "$BIN" "$BK/mihomo.bin"
  cp "$TMP/mihomo" "$BIN.new" && chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN"
  systemctl restart mihomo
  okp=1
  for p in $PORTS; do wait_port "$p" 15 || { okp=0; echo "  порт $p не поднялся"; }; done
  if [ "$okp" = 1 ] && systemctl is-active --quiet mihomo; then
    ok "mihomo работает, слушает: ${PORTS:-—}"
  else
    journalctl -u mihomo -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
    cp -p "$BK/mihomo.bin" "$BIN"; systemctl restart mihomo
    die "новый mihomo не поднялся — вернул старый"
  fi
  ;;
mihomo-rollback)
  BIN=${2:-/usr/local/bin/mihomo}
  say "Mihomo: возврат старой версии"
  [ -f "$BK/mihomo.bin" ] || die "нет копии старого mihomo"
  cp -p "$BK/mihomo.bin" "$BIN"; systemctl restart mihomo; sleep 2
  systemctl is-active --quiet mihomo && ok "вернул $("$BIN" -v 2>/dev/null | head -n1 | cut -c1-60)" || die "mihomo не запустился — проверьте вручную"
  ;;
*)
  echo "использование: $0 sudoku <url> <tag> | mihomo <url> <bin> | sudoku-rollback | mihomo-rollback <bin>" >&2; exit 2 ;;
esac
