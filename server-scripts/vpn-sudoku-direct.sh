#!/usr/bin/env bash
# vpn-sudoku-direct.sh — выход: Sudoku внутри sudoku-sing-box (режим WARP установщика) → обычный sudoku,
# как на выходах, поставленных панелью. Конфиг /etc/sudoku/config.json (ключ, порт, заглушка) не меняется,
# поэтому входам ничего перенастраивать не надо. Повторяет то, что делает переключатель WARP в sudoku-dash.
#
#   bash vpn-sudoku-direct.sh switch    свежий sudoku с GitHub, проверка конфига, sing-box → sudoku (при сбое — назад)
#   bash vpn-sudoku-direct.sh rollback  вернуть sudoku-sing-box (если каналы со входов не заработали)
#   bash vpn-sudoku-direct.sh finish    sudoku в автозапуск, sudoku-sing-box убрать из автозапуска (копии остаются)
#
# Копии всего, что меняется, — в /root/.vpn-dash-sudoku-backup/. Вернуть вручную:
#   systemctl stop sudoku; systemctl disable sudoku
#   cp /root/.vpn-dash-sudoku-backup/sudoku-sing-box.service /etc/systemd/system/ && systemctl daemon-reload
#   systemctl enable --now sudoku-sing-box
set -uo pipefail

BIN=/usr/local/bin/sudoku
CONF=/etc/sudoku/config.json
VERS=/etc/sudoku/versions.env
UNIT=/etc/systemd/system/sudoku.service
SB_UNIT=/etc/systemd/system/sudoku-sing-box.service
BK=/root/.vpn-dash-sudoku-backup
REPO=SUDOKU-ASCII/sudoku

say()  { echo "== $*"; }
ok()   { echo "  ✓ $*"; }
die()  { echo "  ✗ $*" >&2; exit 1; }

port() { python3 -c "import json; print(json.load(open('$CONF'))['local_port'])" 2>/dev/null; }
listening() { ss -Htln "sport = :$1" 2>/dev/null | grep -q .; }
wait_port() { for _ in $(seq 1 "${2:-15}"); do listening "$1" && return 0; sleep 1; done; return 1; }
ver_set() {   # как ver_set установщика: KEY=value, остальное в файле сохраняется
  local tmp; tmp=$(mktemp)
  [ -f "$VERS" ] && grep -v "^$1=" "$VERS" > "$tmp" || true
  echo "$1=$2" >> "$tmp"; mv "$tmp" "$VERS"; chmod 600 "$VERS"
}
latest_tag() {
  local t
  t=$(curl -fsSL --connect-timeout 8 --max-time 25 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null)
  if [ -z "$t" ]; then   # без API: по переадресации страницы релиза
    t=$(curl -fsSL --connect-timeout 8 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null)
    t=${t##*/}; [ "$t" = latest ] && t=""
  fi
  echo "$t"
}
unit_text() {   # тот же юнит, что пишет установщик Sudoku в прямом режиме
cat <<EOF
[Unit]
Description=Sudoku Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=$BIN -c $CONF
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

back_to_singbox() {
  systemctl stop sudoku >/dev/null 2>&1 || true
  systemctl disable sudoku >/dev/null 2>&1 || true
  [ -f "$BK/sudoku.bin" ] && cp -p "$BK/sudoku.bin" "$BIN"
  # юнита sudoku и versions.env до переключения не было — убрать, иначе панель решит, что «Sudoku не работает»
  [ -f "$BK/no-unit" ] && rm -f "$UNIT"
  [ -f "$BK/no-versions" ] && rm -f "$VERS"
  [ -f "$BK/sudoku-sing-box.service" ] && [ ! -f "$SB_UNIT" ] && cp "$BK/sudoku-sing-box.service" "$SB_UNIT"
  systemctl daemon-reload
  systemctl enable sudoku-sing-box >/dev/null 2>&1 || true
  systemctl start sudoku-sing-box
}

case "${1:-}" in
switch)
  say "Проверка"
  systemctl is-active --quiet sudoku-sing-box || die "sudoku-sing-box не работает — переключать нечего"
  [ -f "$CONF" ] || die "нет $CONF"
  P=$(port); [ -n "$P" ] || die "в $CONF нет local_port"
  listening "$P" || die "на порту $P никто не слушает — сначала разберёмся, почему"
  ok "sudoku-sing-box работает, TCP $P; конфиг $CONF"
  case "$(uname -m)" in x86_64|amd64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) die "архитектура $(uname -m) не поддерживается" ;; esac

  say "Копии"
  mkdir -p "$BK" && chmod 700 "$BK"
  [ -f "$BK/sudoku-sing-box.service" ] || cp "$SB_UNIT" "$BK/sudoku-sing-box.service" 2>/dev/null || true
  [ -f "$BIN" ] && cp -p "$BIN" "$BK/sudoku.bin"
  rm -f "$BK/no-unit" "$BK/no-versions"
  [ -f "$UNIT" ] || touch "$BK/no-unit"
  [ -f "$VERS" ] || touch "$BK/no-versions"
  cp -p "$CONF" "$BK/config.json"
  [ -d /etc/sing-box ] && cp -rp /etc/sing-box "$BK/" 2>/dev/null
  ok "$BK"

  say "Свежий sudoku"
  T=$(latest_tag); [ -n "$T" ] || die "не удалось узнать последнюю версию на GitHub"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  curl -fsSL --connect-timeout 10 --max-time 120 "https://github.com/$REPO/releases/download/$T/sudoku-linux-$A.tar.gz" -o "$TMP/s.tgz" \
    || die "не скачался sudoku $T"
  tar -xzf "$TMP/s.tgz" -C "$TMP" || die "архив sudoku $T повреждён"
  NB=$(find "$TMP" -type f -name sudoku | head -n1); [ -n "$NB" ] || die "в архиве нет sudoku"
  chmod 755 "$NB"
  OUT=$("$NB" -c "$CONF" -test 2>&1) || { echo "$OUT" | tail -5; die "sudoku $T не принимает конфиг — ничего не менял, sing-box работает"; }
  ok "sudoku $T, конфиг проверен"

  say "Переключение"
  cp "$NB" "$BIN.new" && chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN"
  ver_set SUDOKU_VERSION "$T"
  unit_text > "$UNIT"
  systemctl daemon-reload
  systemctl stop sudoku-sing-box
  for _ in 1 2 3 4 5; do listening "$P" || break; sleep 1; done
  systemctl start sudoku
  if wait_port "$P" 15 && systemctl is-active --quiet sudoku; then
    ok "sudoku слушает TCP $P, sudoku-sing-box остановлен"
  else
    journalctl -u sudoku -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
    back_to_singbox
    wait_port "$P" 15 && die "sudoku не поднялся — вернул sudoku-sing-box, всё как было" \
                      || die "sudoku не поднялся, и sudoku-sing-box после возврата не слушает порт — проверьте вручную"
  fi
  ;;
rollback)
  say "Возврат к sudoku-sing-box"
  back_to_singbox
  P=$(port)
  wait_port "$P" 15 && ok "sudoku-sing-box снова слушает TCP $P" || die "sudoku-sing-box не слушает TCP $P — проверьте вручную"
  ;;
finish)
  say "Автозапуск"
  systemctl enable sudoku >/dev/null 2>&1 && ok "sudoku включён в автозапуск"
  systemctl disable sudoku-sing-box >/dev/null 2>&1 || true
  # без юнита sing-box установщик (sudoku-dash, --upgrade) тоже считает режим прямым; копия юнита — в $BK
  [ -f "$SB_UNIT" ] && rm -f "$SB_UNIT"
  systemctl daemon-reload
  ok "sudoku-sing-box убран из автозапуска (программа и /etc/sing-box остались, копия юнита — $BK)"
  ;;
*)
  echo "использование: $0 switch | rollback | finish" >&2; exit 2 ;;
esac
