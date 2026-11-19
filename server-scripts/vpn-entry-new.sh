#!/usr/bin/env bash
# vpn-entry-new.sh — новый вход «с нуля», без бэкапа: своя связка (например, для друга), не копия ваших входов.
#
# Этапы:
#   sysctl    BBR и сетевые буферы
#   packages  AmneziaWG (модуль ядра), fail2ban, утилиты — туннели к выходам потом ставит vpn-add-exit.sh
#   mihomo    клиент Sudoku: свежий бинарник с GitHub, пустой конфиг, служба (прокси к выходам добавит vpn-add-exit.sh)
#   xui       3X-UI официальным установщиком; свой логин, пароль, порт и путь; панель — только на 127.0.0.1;
#             шаблон Xray: российское — напрямую, IPv6/частные/торренты — в блок, DNS, наблюдатель для цепочки резервов;
#             вход VLESS Reality (Vision) со своими ключами, клиентами и подпиской
#   fail2ban  стандартная защита SSH
#
# Переменные (их задаёт панель):
#   MASK        домен сайта маскировки Reality (TLS 1.3), например www.example.com
#   CLIENTS     имена клиентов через запятую (латиница, цифры, - _), например anna-phone,anna-pc
#   VLESS_PORT  порт входа (по умолчанию 443)
#   MIHOMO_URL  ссылка на mihomo-linux-*.gz из релиза MetaCubeX на GitHub
#   XUI_VERSION версия 3X-UI (например 3.8.5); XRAY_VERSION — версия Xray (как на ваших входах)
#   RESULT      куда записать итог (логин и пароль панели, ссылки подписки) — файл 600, панель забирает и удаляет
#
# Повторный запуск пропускает уже сделанное. Сначала — выход: после этого скрипта вход ещё никуда
# не выпускает (весь трафик напрямую с него), цепочку создаст первый подключённый выход.

set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# общие этапы (sysctl, packages, fail2ban, xray_match) — из vpn-restore.sh, без запуска его main
# shellcheck source=vpn-restore.sh
source "$HERE/vpn-restore.sh"
SRC=/nonexistent                 # бэкапа нет: этапы из vpn-restore.sh берут только свои значения по умолчанию

MASK=${MASK:-}; CLIENTS=${CLIENTS:-}; VLESS_PORT=${VLESS_PORT:-443}
RESULT=${RESULT:-/root/.vpn-dash-job/entry-result.json}
XUI_DIR=${XUI_DIR:-/usr/local/x-ui}
XUI_DB=${XUI_DB:-/etc/x-ui/x-ui.db}
NEW_IP=$(curl -4 -s -m 10 https://ifconfig.me || hostname -I | awk '{print $1}')
rnd() { echo $(( $1 + $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % ($2 - $1 + 1) )); }
rstr() { python3 -c 'import secrets, string, sys; print("".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(int(sys.argv[1]))))' "$1"; }

preflight() {
  [ "$(id -u)" -eq 0 ] || die "запустите от root"
  [[ "$MASK" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "MASK — домен сайта маскировки, например www.example.com"
  [[ "$CLIENTS" =~ ^[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$ ]] || die "CLIENTS — имена клиентов через запятую (латиница, цифры, - _)"
  [[ "$VLESS_PORT" =~ ^[0-9]+$ ]] || die "VLESS_PORT — число"
  if ! grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null; then
    warn "скрипт проверялся на Ubuntu 24.04, у вас: $(. /etc/os-release; echo "$PRETTY_NAME")"
  fi
  say "Сайт маскировки $MASK"
  # Reality ходит на этот сайт при каждом подключении: он должен открываться с сервера по TLS 1.3
  local r
  r=$(curl -s -o /dev/null -m 12 --tlsv1.3 --http2 -w '%{http_code} %{http_version}' "https://$MASK/" || true)
  case "$r" in
    000*|"") die "$MASK не открывается с этого сервера по TLS 1.3 — выберите другой сайт (лучше в той же подсети, что сервер)";;
  esac
  ok "$MASK отвечает: HTTP ${r% *}, HTTP/${r#* }"
}

# ---------------------------------------------------------------- Mihomo
stage_mihomo_new() {
  say "Mihomo (клиент Sudoku)"
  if [ -x /usr/local/bin/mihomo ] && [ -f /etc/mihomo/config.yaml ]; then
    ok "уже стоит: $(/usr/local/bin/mihomo -v 2>/dev/null | head -n1)"
  else
    [ -n "${MIHOMO_URL:-}" ] || die "панель не передала ссылку на Mihomo (MIHOMO_URL)"
    [[ "$MIHOMO_URL" =~ ^https://github\.com/MetaCubeX/mihomo/releases/download/[A-Za-z0-9._/-]+\.gz$ ]] || die "странная ссылка на Mihomo: $MIHOMO_URL"
    local t; t=$(mktemp -d)
    curl -fsSL -m 180 -o "$t/m.gz" "$MIHOMO_URL" || die "не скачался Mihomo с GitHub"
    gunzip -c "$t/m.gz" > "$t/mihomo" || die "архив Mihomo повреждён"
    chmod 755 "$t/mihomo"
    "$t/mihomo" -v >/dev/null 2>&1 || die "Mihomo не запускается на этом сервере"
    install -m 755 "$t/mihomo" /usr/local/bin/mihomo
    rm -rf "$t"
    mkdir -p /etc/mihomo; chmod 700 /etc/mihomo
    cat > /etc/mihomo/config.yaml <<'EOF'
# SOCKS-входы к выходам (Sudoku) добавляет vpn-add-exit.sh: по слушателю и прокси на каждый выход
log-level: warning
ipv6: false
mode: rule
listeners: []
proxies: []
rules:
  - MATCH,DIRECT
EOF
    chmod 600 /etc/mihomo/config.yaml
    /usr/local/bin/mihomo -t -d /etc/mihomo >/dev/null 2>&1 || die "Mihomo не принял начальный конфиг"
    ok "$(/usr/local/bin/mihomo -v | head -n1)"
  fi
  [ -f /etc/systemd/system/mihomo.service ] || cat > /etc/systemd/system/mihomo.service <<'EOF'
[Unit]
Description=mihomo (клиент Sudoku для выходов)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  # ночной перезапуск — как на остальных входах
  [ -f /etc/systemd/system/mihomo-restart.service ] || printf '[Unit]\nDescription=Ночной перезапуск mihomo\n\n[Service]\nType=oneshot\nExecStart=/bin/systemctl restart mihomo\n' > /etc/systemd/system/mihomo-restart.service
  [ -f /etc/systemd/system/mihomo.timer ] || printf '[Unit]\nDescription=Ночной перезапуск mihomo\n\n[Timer]\nOnCalendar=*-*-* 04:30\nUnit=mihomo-restart.service\n\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/mihomo.timer
  systemctl daemon-reload
  systemctl enable --now mihomo >/dev/null 2>&1
  systemctl enable --now mihomo.timer >/dev/null 2>&1 || true
  systemctl restart mihomo; sleep 2
  systemctl is-active --quiet mihomo && ok "mihomo работает" || die "mihomo не запустился: journalctl -u mihomo -n 30"
}

# ---------------------------------------------------------------- 3X-UI
xui_wait() {   # ждём, пока x-ui поднимет Xray (config.json) и, если задан порт, — свою веб-панель на нём
  local i
  sleep 2
  for i in $(seq 60); do
    if [ -s "$XUI_DIR/bin/config.json" ] && pgrep -f "bin/xray-linux" >/dev/null \
       && { [ -z "${1:-}" ] || ss -Htln "sport = :$1" | grep -q .; }; then
      return 0
    fi
    sleep 1
  done
  return 1
}

stage_xui_new() {
  say "3X-UI"
  if [ ! -x "$XUI_DIR/x-ui" ]; then
    echo "  Ставлю 3X-UI${XUI_VERSION:+ v${XUI_VERSION#v}} официальным установщиком (без вопросов; сертификат Let's Encrypt на IP — нужен порт 80)."
    XUI_SSL_MODE="${XUI_SSL_MODE:-ip}" XUI_SERVER_IP="${XUI_SERVER_IP:-$NEW_IP}" \
      bash <(curl -fsSL https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh) ${XUI_VERSION:+"v${XUI_VERSION#v}"} 2>&1 \
      | sed -u -E 's/^([[:space:]]*(Username|Password|Port|WebBasePath|Access URL|API Token)[^:]*:).*/\1 (скрыто — ниже панель задаст свои)/'
    # установщик печатает свои логин, пароль и токен API — в журнал они не попадают (выше), а токен ниже перевыпускается
  else
    ok "3X-UI уже установлена: $( { "$XUI_DIR/x-ui" -v 2>/dev/null || true; } | head -n1)"
  fi
  systemctl enable x-ui >/dev/null 2>&1 || true
  systemctl restart x-ui
  xui_wait || die "x-ui не запустилась: journalctl -u x-ui -n 50"

  local have; have=$(python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("select count(*) from inbounds").fetchone()[0])' "$XUI_DB")
  if [ "$have" != 0 ] && [ -s "$RESULT.keep" ]; then
    ok "вход уже настроен этим скриптом — пропускаю"; cp "$RESULT.keep" "$RESULT"; return 0
  fi
  [ "$have" = 0 ] || die "в 3X-UI уже есть входящие ($have) — это не чистый сервер; «вход с нуля» ставится только на чистый"

  # своя учётная запись и путь панели; панель — только на 127.0.0.1 (открывается кнопкой «3X-UI» в панели каскада)
  local U P WP WB
  U=$(rstr 10); P=$(rstr 20); WP=$(rnd 20000 59999); WB="/$(rstr 14)/"
  "$XUI_DIR/x-ui" setting -username "$U" -password "$P" -port "$WP" -webBasePath "$WB" >/dev/null
  "$XUI_DIR/x-ui" setting -listenIP 127.0.0.1 >/dev/null
  ok "логин и пароль панели — новые, порт $WP, путь скрытый, панель закрыта из интернета"

  # шаблон Xray: берём то, что 3X-UI собрала без входящих (её шаблон по умолчанию), и дописываем своё
  cp "$XUI_DIR/bin/config.json" ${XUI_TMP:-/root}/.vpn-dash-xui-default.json
  systemctl stop x-ui; sleep 1
  python3 - ${XUI_TMP:-/root}/.vpn-dash-xui-default.json "$XUI_DB" <<'PY' || die "не удалось записать шаблон Xray"
import json, sqlite3, sys
t = json.load(open(sys.argv[1]))
t["dns"] = {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"}
rules = t.setdefault("routing", {}).setdefault("rules", [])
api = [r for r in rules if "api" in (r.get("inboundTag") or [])]
rest = [r for r in rules if r not in api]
rules[:] = api + [
    {"type": "field", "ip": ["::/0"], "outboundTag": "blocked"},          # IPv6 через выходы не ходит — пусть клиент сразу берёт IPv4
    {"type": "field", "domain": ["domain:ru", "domain:su", "domain:xn--p1ai", "geosite:category-ru"], "outboundTag": "direct"},
    {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
] + rest
# цепочку резервов (балансировщики Bal-N) и общее правило создаст первый выход (vpn-add-exit.sh)
t["routing"].setdefault("balancers", [])
t["burstObservatory"] = {"subjectSelector": [], "pingConfig": {"destination": "https://www.gstatic.com/generate_204",
                         "connectivity": "", "interval": "1m", "sampling": 2, "timeout": "10s"}}
db = sqlite3.connect(sys.argv[2])
db.execute("delete from settings where key='xrayTemplateConfig'")
db.execute("insert into settings(key, value) values('xrayTemplateConfig', ?)", (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit()
PY
  rm -f ${XUI_TMP:-/root}/.vpn-dash-xui-default.json
  if [ -n "${XRAY_VERSION:-}" ]; then        # Xray той же версии, что на ваших входах (xray_match из vpn-restore.sh)
    VERS=$(mktemp); echo "xray=Xray $XRAY_VERSION" > "$VERS"; xray_match; rm -f "$VERS"
  fi
  systemctl start x-ui
  xui_wait "$WP" || die "x-ui не запустилась с новым шаблоном: journalctl -u x-ui -n 50"
  grep -q burstObservatory "$XUI_DIR/bin/config.json" || die "3X-UI не взяла шаблон Xray"
  ok "шаблон Xray: российское напрямую, наблюдатель для цепочки резервов"

  # вход VLESS Reality — через API 3X-UI (токен для командной строки), чтобы клиенты легли в её таблицы как положено
  local TOK XB KP
  TOK=$("$XUI_DIR/x-ui" setting -getApiToken 2>/dev/null | sed -n 's/^apiToken: *//p' | tail -n1)
  [ -n "$TOK" ] || die "3X-UI не выдала токен API"
  XB=$(ls "$XUI_DIR"/bin/xray-linux-* | grep -v '\.before' | head -n1)
  KP=$("$XB" x25519)
  PRIV=$(printf '%s\n' "$KP" | sed -n 's/^Private[ ]*[Kk]ey: *//p' | head -n1)
  PUB=$(printf '%s\n' "$KP" | sed -n -E 's/^(Public key|Password[^:]*): *//p' | head -n1)
  [ -n "$PRIV" ] && [ -n "$PUB" ] || die "не удалось сгенерировать ключи Reality"
  local SCHEME=http
  [ -n "$(sqlite3_get webCertFile)" ] && SCHEME=https
  BASE="$SCHEME://127.0.0.1:$WP$WB" PRIV="$PRIV" PUB="$PUB" TOK="$TOK" U="$U" P="$P" WP="$WP" WB="$WB" python3 - <<'PY' || die "3X-UI не создала вход"
import json, os, secrets, ssl, sqlite3, urllib.request, uuid
E = os.environ
clients = [{"id": str(uuid.uuid4()), "flow": "xtls-rprx-vision", "email": n, "limitIp": 0, "totalGB": 0, "expiryTime": 0,
            "enable": True, "tgId": 0, "subId": secrets.token_hex(8), "reset": 0} for n in E["CLIENTS"].split(",")]
inb = {"up": 0, "down": 0, "total": 0, "remark": "vless-reality", "enable": True, "expiryTime": 0, "listen": "",
       "port": int(E["VLESS_PORT"]), "protocol": "vless",
       "settings": json.dumps({"clients": clients, "decryption": "none", "fallbacks": []}),
       "streamSettings": json.dumps({"network": "tcp", "security": "reality", "externalProxy": [],
           "realitySettings": {"show": False, "xver": 0, "target": E["MASK"] + ":443", "serverNames": [E["MASK"]],
                               "privateKey": E["PRIV"], "minClientVer": "", "maxClientVer": "", "maxTimediff": 0,
                               "shortIds": [secrets.token_hex(4), secrets.token_hex(8)],
                               "settings": {"publicKey": E["PUB"], "fingerprint": "firefox", "serverName": "", "spiderX": "/"}},
           "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}),
       "sniffing": json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}),
       "allocate": json.dumps({"strategy": "always", "refresh": 5, "concurrency": 3})}
ctx = ssl._create_unverified_context()        # своя панель на 127.0.0.1, сертификат выпущен на внешний IP
req = urllib.request.Request(E["BASE"] + "panel/api/inbounds/add", data=json.dumps(inb).encode(),
                             headers={"Authorization": "Bearer " + E["TOK"], "Content-Type": "application/json"})
op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
r = json.loads(op.open(req, timeout=30).read())
if not r.get("success"):
    raise SystemExit("3X-UI: " + str(r.get("msg")))
st = dict(sqlite3.connect("file:%s?mode=ro" % E["XUI_DB"], uri=True).execute("select key, value from settings").fetchall())
sub_scheme = "https" if st.get("subCertFile") else "http"
base = (st.get("subURI") or "%s://%s:%s%s" % (sub_scheme, E["NEW_IP"], st.get("subPort", "2096"), st.get("subPath", "/sub/")))
base = base if base.endswith("/") else base + "/"
res = {"user": E["U"], "password": E["P"], "port": int(E["WP"]), "path": E["WB"], "listen": "127.0.0.1",
       "vless_port": int(E["VLESS_PORT"]), "mask": E["MASK"], "subs": [{"name": c["email"], "url": base + c["subId"]} for c in clients]}
fd = os.open(E["RESULT"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(res, f, ensure_ascii=False)
for c in clients:
    print("  Подписка %-14s %s" % (c["email"], base + c["subId"]))
PY
  cp -a "$RESULT" "$RESULT.keep"       # повторный запуск не создаёт второй вход; панель удалит после установки
  # токены API: и тот, что показал установщик, и наш — перевыпускаем (старые перестают действовать), новые нигде не печатаются
  "$XUI_DIR/x-ui" setting -getApiToken -tokenName install >/dev/null 2>&1 || true
  "$XUI_DIR/x-ui" setting -getApiToken >/dev/null 2>&1 || true
  rm -f /etc/x-ui/install-result.env
  systemctl restart x-ui
  xui_wait "$WP" || die "x-ui не запустилась после создания входа"
  sleep 2
  ss -Htln "sport = :$VLESS_PORT" | grep -q . || die "Xray не слушает порт $VLESS_PORT"
  ok "вход VLESS Reality на порту $VLESS_PORT, маскировка $MASK, клиенты: ${CLIENTS//,/, }"
}

sqlite3_get() { python3 -c 'import sqlite3,sys; r=sqlite3.connect("file:%s?mode=ro" % sys.argv[2], uri=True).execute("select value from settings where key=?", (sys.argv[1],)).fetchone(); print(r[0] if r else "")' "$1" "$XUI_DB"; }

entry_new_main() {
  export MASK CLIENTS VLESS_PORT RESULT NEW_IP XUI_DB
  preflight
  mkdir -p "$(dirname "$RESULT")"
  stage_sysctl
  stage_packages
  stage_mihomo_new
  stage_xui_new
  stage_fail2ban
  say "Готово"
  echo "  Вход поставлен. Пока к нему не подключён выход, весь трафик идёт напрямую с этого сервера —"
  echo "  следующий шаг: мастер «Новый сервер» → «Выход», галочка только у этого входа."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then entry_new_main "$@"; fi
