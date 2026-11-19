#!/usr/bin/env bash
# Имитация vpn-entry-new.sh для стенда: все «серверы» стенда — одна машина с общей базой 3X-UI, поэтому
# ничего не ставит и базу не трогает — только шаги в журнал и итог (логин панели, подписки). Только для dev/testbed.sh.
set -euo pipefail
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
[[ "${MASK:-}" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "MASK — домен" >&2; exit 1; }
say "Сайт маскировки $MASK"; ok "$MASK отвечает: HTTP 200, HTTP/2 (имитация)"
say "sysctl: BBR и буферы"; ok "bbr включён"
say "Пакеты (имитация)"; for p in curl fail2ban amneziawg; do sleep 0.3; ok "$p"; done
say "Mihomo (клиент Sudoku)"; ok "Mihomo Meta (имитация), ссылка: ${MIHOMO_URL:-нет}"
say "3X-UI"; ok "3X-UI ${XUI_VERSION:-?} (имитация), Xray ${XRAY_VERSION:-?}"
python3 - <<'PY'
import json, os, secrets
cl = os.environ["CLIENTS"].split(",")
subs = [{"name": c, "url": "https://127.0.0.8:2096/standsub/%s" % secrets.token_hex(8)} for c in cl]
res = {"user": "stand" + secrets.token_hex(3), "password": secrets.token_hex(10), "port": 34567, "path": "/standpath/",
       "listen": "127.0.0.1", "vless_port": int(os.environ.get("VLESS_PORT", "443")), "mask": os.environ["MASK"], "subs": subs}
p = os.environ["RESULT"]; os.makedirs(os.path.dirname(p), exist_ok=True)
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(res, f)
for s in subs:
    print("  Подписка %-14s %s" % (s["name"], s["url"]))
PY
ok "вход VLESS Reality на порту ${VLESS_PORT:-443}, маскировка $MASK, клиенты: ${CLIENTS//,/, }"
say "fail2ban"; ok "fail2ban: active"
say "Готово"
