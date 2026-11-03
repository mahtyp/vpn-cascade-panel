#!/usr/bin/env bash
# Имитация vpn-exit-setup.sh для стенда: оставляет на сервере то же, что настоящий (awg0.conf),
# но без apt и сборки модуля. Только для dev/testbed.sh.
set -euo pipefail
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
D=/etc/amnezia/amneziawg; CONF=$D/awg0.conf; NET=${AWG_SUBNET:-10.9.0}
if [ "${1:-}" = status ]; then ok "awg-quick@awg0 работает"; ok "AWG: UDP $(awg show awg0 listen-port)"; exit 0; fi
say "Пакеты (имитация)"; for p in curl jq fail2ban amneziawg; do sleep 0.3; ok "$p"; done
say "AmneziaWG: сервер awg0"
mkdir -p $D
[ -f $CONF ] || printf '[Interface]\nPrivateKey = %s\nAddress = %s.1/24\nListenPort = %s\nMTU = 1280\nJc = 4\nS1 = 40\nS2 = 77\nH1 = 1\n' \
  "$(awg genkey)" "$NET" "${AWG_PORT:-41234}" > $CONF
ok "awg0 работает, UDP $(awg show awg0 listen-port)"
if [ "${ONLY_AWG:-0}" = 1 ]; then ok "AmneziaWG без Docker готов: UDP $(awg show awg0 listen-port). fail2ban не трогал (ONLY_AWG=1)"; exit 0; fi
if [ "${SKIP_FAIL2BAN:-0}" = 1 ]; then echo "  ! fail2ban пропущен"; else say "fail2ban (SSH)"; ok "fail2ban: active"; fi
say "Готово"
