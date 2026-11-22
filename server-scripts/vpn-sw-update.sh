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
  local tmp; tmp=$(mktemp "$VERS.XXXXXX") || return 1
  if { [ ! -f "$VERS" ] || awk -v key="$1" 'index($0, key "=") != 1' "$VERS"; } > "$tmp" \
      && printf '%s=%s\n' "$1" "$2" >> "$tmp" && mv -f "$tmp" "$VERS"; then return 0; fi
  rm -f "$tmp"
  return 1
}
restore_sudoku() {
  cp -p "$BK/sudoku.bin" "$SUDOKU" || return 1
  if [ -f "$BK/sudoku.versions" ]; then
    cp -p "$BK/sudoku.versions" "$VERS" || return 1
  elif [ -f "$BK/sudoku.no-versions" ]; then
    rm -f "$VERS" || return 1
  else
    local old; old=$(cat "$BK/sudoku.ver" 2>/dev/null)
    if [ -n "$old" ]; then ver_set SUDOKU_VERSION "$old" || return 1; fi
  fi
  systemctl restart sudoku
}
fetch() {   # <url> <файл>
  case "$1" in https://github.com/*/releases/download/*) ;; *) die "ссылка не на релиз GitHub: $1" ;; esac
  curl -fsSL --connect-timeout 15 --max-time 300 "$1" -o "$2" || die "не скачалось: $1"
}
mihomo_ports() {   # порты, которые слушает mihomo сейчас (SOCKS-входы для Sudoku)
  local comm=${1##*/}
  ss -Htlnp 2>/dev/null | awk -v comm="${comm:0:15}" 'index($0, "(\"" comm "\",") {n=split($4,a,":"); print a[n]}' | sort -un
}
expected_mihomo_ports() {
  python3 - "$MDIR/config.yaml" <<'PY'
import pathlib, re, sys

text = pathlib.Path(sys.argv[1]).read_text()
keys = ("port", "socks-port", "mixed-port", "redir-port", "tproxy-port")
try:
    import yaml
except ImportError:
    # На новом входе без PyYAML панель создаёт именно пустой список.
    listeners = re.search(r"(?m)^listeners:[ \t]*(.*)", text)
    if not listeners or listeners[1].split("#", 1)[0].strip() != "[]":
        sys.exit("для чтения непустого списка listeners нужен PyYAML")
    values = [p for k, p in re.findall(r"(?m)^([\w-]+):[ \t]*(\d+)[ \t]*(?:#.*)?$", text) if k in keys]
else:
    y = yaml.safe_load(text) or {}
    values = [y.get(key) for key in keys]
    values.extend(l.get("port") for l in y.get("listeners") or []
                  if l.get("network") != "udp" and l.get("type") not in ("tuic", "hysteria", "hysteria2"))
print(*sorted({int(p) for p in values if p and 1 <= int(p) <= 65535}))
PY
}
wait_mihomo_ports() {
  local actual p missing
  for _ in $(seq 1 15); do
    if actual=$(mihomo_ports "$2"); then
      actual=$(echo "$actual" | tr '\n' ' ')
      missing=""
      for p in $1; do
        case " $actual " in *" $p "*) ;; *) missing="$missing $p" ;; esac
      done
      [ -n "$missing" ] || return 0
    fi
    sleep 1
  done
  say "Mihomo не подтвердил слушающие порты"
  return 1
}

mkdir -p "$BK" && chmod 700 "$BK" || die "не удалось создать папку с копиями"
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
  cp -p "$SUDOKU" "$BK/sudoku.bin" && rm -f "$BK/sudoku.versions" "$BK/sudoku.no-versions" || die "не удалось сохранить прежний Sudoku"
  if [ -f "$VERS" ]; then
    cp -p "$VERS" "$BK/sudoku.versions" || die "не удалось сохранить versions.env"
  else
    touch "$BK/sudoku.no-versions" || die "не удалось записать отсутствие versions.env"
  fi
  if cp "$NB" "$SUDOKU.new" && chmod 755 "$SUDOKU.new" && mv -f "$SUDOKU.new" "$SUDOKU" \
      && ver_set SUDOKU_VERSION "$TAG" && systemctl restart sudoku && wait_port "$P" 15 && systemctl is-active --quiet sudoku; then
    ok "sudoku $TAG работает, TCP $P"
  else
    journalctl -u sudoku -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
    if restore_sudoku && wait_port "$P" 15 && systemctl is-active --quiet sudoku; then
      die "sudoku $TAG не поднялся — вернул ${OLD:-старую версию}"
    fi
    die "sudoku $TAG не поднялся, возврат прежней версии не подтверждён"
  fi
  ;;
sudoku-rollback)
  say "Sudoku: возврат старой версии"
  [ -f "$BK/sudoku.bin" ] || die "нет копии старого sudoku"
  P=$(python3 -c "import json; print(json.load(open('$SCONF'))['local_port'])" 2>/dev/null) || die "нет local_port в $SCONF"
  restore_sudoku && wait_port "$P" 15 && systemctl is-active --quiet sudoku \
    && ok "вернул старую версию, TCP $P" || die "возврат прежней версии Sudoku не подтверждён"
  ;;
mihomo)
  URL=${2:?ссылка}; BIN=${3:-/usr/local/bin/mihomo}
  say "Mihomo: проверка"
  systemctl is-active --quiet mihomo || die "служба mihomo не работает — обновлять нечего"
  [ -x "$BIN" ] || die "нет $BIN"
  PORTS=$(mihomo_ports "$BIN") || die "не удалось прочитать слушающие порты Mihomo"
  EXPECTED=$(expected_mihomo_ports) || die "не удалось прочитать порты из конфига Mihomo"
  PORTS=$(printf '%s\n%s\n' "$PORTS" "$EXPECTED" | tr ' ' '\n' | awk 'NF' | sort -un | paste -sd' ' -)
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
  cp -p "$BIN" "$BK/mihomo.bin" || die "не удалось сохранить прежний Mihomo"
  if cp "$TMP/mihomo" "$BIN.new" && chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN" \
      && systemctl restart mihomo && wait_mihomo_ports "$PORTS" "$BIN" && systemctl is-active --quiet mihomo; then
    ok "mihomo работает, слушает: ${PORTS:-—}"
  else
    journalctl -u mihomo -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
    if cp -p "$BK/mihomo.bin" "$BIN" && systemctl restart mihomo && systemctl is-active --quiet mihomo; then
      die "новый mihomo не поднялся — вернул старый"
    fi
    die "новый Mihomo не поднялся, возврат прежней версии не подтверждён"
  fi
  ;;
mihomo-rollback)
  BIN=${2:-/usr/local/bin/mihomo}
  say "Mihomo: возврат старой версии"
  [ -f "$BK/mihomo.bin" ] || die "нет копии старого mihomo"
  cp -p "$BK/mihomo.bin" "$BIN" && systemctl restart mihomo || die "не удалось вернуть прежний Mihomo"
  sleep 2
  systemctl is-active --quiet mihomo && ok "вернул $("$BIN" -v 2>/dev/null | head -n1 | cut -c1-60)" || die "mihomo не запустился — проверьте вручную"
  ;;
*)
  echo "использование: $0 sudoku <url> <tag> | mihomo <url> <bin> | sudoku-rollback | mihomo-rollback <bin>" >&2; exit 2 ;;
esac
