#!/usr/bin/env bash
# Имитация vpn-exit-setup.sh для стенда: то же, что настоящий, оставляет на сервере
# (awg0.conf, файлы Sudoku), но без apt, сборки модуля и установщика Sudoku. Только для dev/testbed.sh.
set -euo pipefail
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
D=/etc/amnezia/amneziawg; CONF=$D/awg0.conf; NET=${AWG_SUBNET:-10.9.0}
if [ "${1:-}" = status ]; then ok "awg-quick@awg0 работает"; ok "Sudoku: TCP 8443"; exit 0; fi
if [ "${ONLY_SUDOKU:-0}" = 1 ]; then
  say "Пакеты (имитация)"; for p in curl jq; do sleep 0.3; ok "$p"; done
  say "Sudoku"; mkdir -p /etc/sudoku
  [ -f /etc/sudoku/config.json ] || echo '{"local_port": 8443, "aead": "chacha20-poly1305", "ascii": "up_ascii_down_entropy"}' > /etc/sudoku/config.json
  [ -f /etc/sudoku/export-state.env ] || echo 'AVAILABLE_PRIVATE_KEY="stand-key-123"' > /etc/sudoku/export-state.env
  ok "Sudoku работает, TCP $(jq -r .local_port /etc/sudoku/config.json)"
  ok "Готово: только Sudoku (ONLY_SUDOKU=1). AmneziaWG, ядро, sysctl, fail2ban и остальное на сервере не трогал"
  exit 0
fi
say "Пакеты (имитация)"; for p in curl jq fail2ban amneziawg; do sleep 0.3; ok "$p"; done
say "AmneziaWG: сервер awg0"
mkdir -p $D
[ -f $CONF ] || printf '[Interface]\nPrivateKey = %s\nAddress = %s.1/24\nListenPort = %s\nMTU = 1280\nJc = 4\nS1 = 40\nS2 = 77\nH1 = 1\n' \
  "$(awg genkey)" "$NET" "${AWG_PORT:-41234}" > $CONF
ok "awg0 работает, UDP $(awg show awg0 listen-port)"
if [ "${ONLY_AWG:-0}" = 1 ]; then ok "AmneziaWG без Docker готов: UDP $(awg show awg0 listen-port). Sudoku и fail2ban не трогал (ONLY_AWG=1)"; exit 0; fi
say "Sudoku"
mkdir -p /etc/sudoku
echo '{"local_port": 8443, "aead": "chacha20-poly1305", "ascii": "up_ascii_down_entropy"}' > /etc/sudoku/config.json
echo 'AVAILABLE_PRIVATE_KEY="stand-key-123"' > /etc/sudoku/export-state.env
ok "Sudoku работает, TCP 8443"
if [ "${SKIP_FAIL2BAN:-0}" = 1 ]; then echo "  ! fail2ban пропущен"; else say "fail2ban (SSH)"; ok "fail2ban: active"; fi
say "Готово"
