#!/usr/bin/env bash
# vpn-add-exit.sh — подключает новый выходной сервер к ЭТОМУ входу (вход-1, вход-2, ...).
#
# Выход должен быть подготовлен vpn-exit-setup.sh (или это Amnezia в Docker + Sudoku).
# Запуск на входе от root, рядом должен лежать vpn-restore.sh (из него берутся общие функции):
#   bash vpn-add-exit.sh ИМЯ IP              например: bash vpn-add-exit.sh ExitA IP_ВЫХОДА
#   bash vpn-add-exit.sh ИМЯ IP --force      пересоздать AWG-клиента и обновить параметры Sudoku
#
# Что делает:
#   1. AWG     создаёт на выходе клиента <этот сервер>-wgN и поднимает здесь туннель wgN
#   2. Sudoku  забирает с выхода параметры клиента и добавляет прокси + SOCKS-порт в Mihomo
#   3. 3X-UI   добавляет исходящие AWG-ИМЯ и Sudoku-ИМЯ и ставит их В КОНЕЦ цепочки
#              балансировщиков (последний резерв); база панели бэкапится, при ошибке — откат
# Пароль root выхода спрашивается один раз и никуда не сохраняется.
#
# Место в цепочке (по умолчанию — в конец, последний резерв):
#   POSITION=first bash vpn-add-exit.sh ...              первым, основной выход
#   POSITION=after:Sudoku-ExitB bash vpn-add-exit.sh ...  сразу после звена с этим исходящим
# Отдельные цепочки правил (например DC5TG от vpn-pin-chain.sh) не затрагиваются.
#
# Замена выхода (новый сервер вместо старого, например умершего):
#   REPLACE=IP_СТАРОГО bash vpn-add-exit.sh ИМЯ IP
#   Новый выход встаёт ровно на места старого во ВСЕХ цепочках (основной и DC5TG): исходящие старого
#   переводятся на новый туннель и новый SOCKS-порт и переименовываются в AWG-ИМЯ / Sudoku-ИМЯ.
#   Потом со входа убираются туннель и прокси Mihomo старого выхода. Сам старый сервер не трогается.
#   Если старого выхода на этом входе нет — новый просто добавляется на место POSITION.
#
# Только Sudoku — запасной канал к выходу, где AmneziaWG нет (на выходе — vpn-exit-setup.sh с ONLY_SUDOKU=1):
#   SUDOKU_ONLY=1 bash vpn-add-exit.sh ИМЯ IP
#   Туннель не создаётся, в 3X-UI добавляется только Sudoku-ИМЯ. Если цепочки ещё нет, а общее правило
#   («всё остальное») ведёт прямо на исходящее (например, из подписки 3X-UI), это исходящее оборачивается
#   в цепочку: сначала оно, при его отказе — Sudoku-ИМЯ. Есть цепочка — Sudoku встаёт в неё на место POSITION.
#
# Только AmneziaWG — туннель к выходу без Sudoku (связать уже настроенные серверы одним протоколом):
#   AWG_ONLY=1 bash vpn-add-exit.sh ИМЯ IP
#   Mihomo не трогается, в 3X-UI добавляется только AWG-ИМЯ; с цепочкой — как у SUDOKU_ONLY.
#
# Только VLESS — путь до сервера с 3X-UI через его входящий VLESS Reality (клиента там заводит панель):
#   VLESS_ONLY=1 VLESS_FILE=/root/.vpn-dash-job/vless.json bash vpn-add-exit.sh ИМЯ IP
#   В файле (JSON, только для root) — port, uuid, flow, pbk, sid, sni, fp того входящего. Туннель и Mihomo не трогаются,
#   в 3X-UI добавляется исходящее VLESS-ИМЯ; с цепочкой — как у SUDOKU_ONLY. Файл удаляется сразу после чтения.
#
# Перевод выхода с Amnezia в Docker на AmneziaWG без Docker (на самом выходе уже поднят awg0):
#   MIGRATE=1 bash vpn-add-exit.sh ИМЯ IP
#   Туннель до этого выхода (тот же wgN) переводится на новый awg0: новые ключи, порт, адрес.
#   Sudoku, Mihomo и 3X-UI не меняются — исходящие по-прежнему смотрят в тот же wgN. Нет выхода через
#   новый туннель — старый конфиг возвращается.

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ -f "$HERE/vpn-restore.sh" ] || { echo "Рядом с этим скриптом должен лежать vpn-restore.sh" >&2; exit 1; }
# shellcheck source=vpn-restore.sh
source "$HERE/vpn-restore.sh"

DB=/etc/x-ui/x-ui.db
MIHOMO_CONF=/etc/mihomo/config.yaml
MIHOMO_BIN=${MIHOMO_BIN:-/usr/local/bin/mihomo}

usage() { echo "Использование: bash $0 ИМЯ IP [--force]   (ИМЯ латиницей, например ExitA)"; exit 1; }

# ---------------------------------------------------------------- 1. AWG

add_awg() {
  say "1. AmneziaWG: туннель до $NAME"
  local f ep
  IFACE=""
  for f in "$AWG_DIR"/wg*.conf; do
    [ -e "$f" ] || continue
    ep=$(awk -F'=' '/^[[:space:]]*Endpoint/ {gsub(/[[:space:]]/, "", $2); print $2}' "$f")
    if [ "${ep%:*}" = "$IP" ]; then IFACE=$(basename "$f" .conf); break; fi
  done
  if [ -n "$IFACE" ] && [ "$FORCE" != 1 ]; then
    ok "туннель до $IP уже есть: $IFACE (пересоздать: --force)"
    return
  fi
  local force_awg=$FORCE
  if [ -z "$IFACE" ]; then
    local n=0
    while [ -e "$AWG_DIR/wg$n.conf" ]; do n=$((n + 1)); done
    IFACE="wg$n"
    # туннеля здесь нет, а клиент с нашим именем на выходе остался от прошлой попытки —
    # его ключ всё равно потерян, так что заменяем
    force_awg=1
  fi
  FORCE_AWG=$force_awg awg_add_exit "$IFACE" "$IP"
}

# ---------------------------------------------------------------- 2. Sudoku / Mihomo

add_sudoku() {
  say "2. Sudoku: прокси в Mihomo"
  [ -f "$MIHOMO_CONF" ] || die "нет $MIHOMO_CONF — на этом сервере не настроен Mihomo"
  python3 -c 'import yaml' 2>/dev/null || apt-get install -y -q python3-yaml >/dev/null
  local T="$TMPD"
  rssh "$IP" 'for f in /etc/sudoku/subscription.yaml /etc/sudoku/config.json /etc/sudoku/export-state.env; do
                echo; echo "=====$f"; cat "$f" 2>/dev/null || true; done' > "$T/remote" \
    || die "не удалось забрать параметры Sudoku с $IP"

  # параметры клиента: из готового subscription.yaml, иначе собираем из config.json + export-state.env
  python3 - "$T/remote" "$T/node.json" <<'PY' || die "на $IP не нашлось параметров клиента Sudoku"
import json, re, shlex, sys, yaml
blob = open(sys.argv[1]).read()
chunks = re.split(r"^=====(\S+)\n?", blob, flags=re.M)   # пустой файл не «съедает» следующий
parts = {chunks[i]: chunks[i + 1] for i in range(1, len(chunks) - 1, 2)}
node = None
sub = parts.get("/etc/sudoku/subscription.yaml", "")
if sub.strip():
    try:
        y = yaml.safe_load(sub)
        cand = y.get("proxies", []) if isinstance(y, dict) else (y if isinstance(y, list) else [])
        node = next((p for p in cand if isinstance(p, dict) and p.get("type") == "sudoku"), None)
    except Exception:
        node = None
if node is None:
    cfg = json.loads(parts["/etc/sudoku/config.json"])
    env = {}
    for line in parts.get("/etc/sudoku/export-state.env", "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = (shlex.split(v) or [""])[0]
    key = env.get("AVAILABLE_PRIVATE_KEY", "")
    if not key:
        sys.exit("нет AVAILABLE_PRIVATE_KEY")
    hm = cfg.get("httpmask") or {}
    node = {"type": "sudoku", "port": cfg["local_port"], "key": key,
            "aead-method": cfg.get("aead", "chacha20-poly1305"),
            "padding-min": cfg.get("padding_min", 2), "padding-max": cfg.get("padding_max", 7),
            "table-type": cfg.get("ascii", "up_ascii_down_entropy"),
            "custom-table": cfg.get("custom_table"),
            "httpmask": {"disable": hm.get("disable", False), "mode": hm.get("mode", "auto"),
                         "tls": hm.get("tls", False), "host": hm.get("host", ""),
                         "multiplex": hm.get("multiplex", "on"), "path-root": hm.get("path_root", "")},
            "enable-pure-downlink": cfg.get("enable_pure_downlink", False)}
    node = {k: v for k, v in node.items() if v is not None}
if not node.get("key") or not node.get("port"):
    sys.exit("в параметрах нет key или port")
json.dump(node, open(sys.argv[2], "w"))
PY

  python3 - "$MIHOMO_CONF" "$T/config.new" "$NAME" "$IP" "$T/node.json" "$FORCE" > "$T/out" <<'PY' || die "не удалось обновить конфиг Mihomo"
import json, socket, sys, yaml
src, dst, name, ip, node_path, force = sys.argv[1:7]
cfg = yaml.safe_load(open(src)) or {}
node = json.load(open(node_path))
pname, lname = "EU-Sudoku-" + name, "socks-" + name.lower()
proxies = cfg.setdefault("proxies", []) or []
listeners = cfg.setdefault("listeners", []) or []
rules = cfg.setdefault("rules", []) or []

other = next((p for p in proxies if p.get("type") == "sudoku" and str(p.get("server")) == ip
              and p.get("name") != pname), None)
if other:
    sys.exit("в Mihomo уже есть прокси на %s под именем %s" % (ip, other.get("name")))

new = {"name": pname, "type": "sudoku", "server": ip}
new.update({k: v for k, v in node.items() if k not in ("name", "type", "server")})
cur = next((p for p in proxies if p.get("name") == pname), None)
if cur is None:
    proxies.append(new); state = "добавлен"
elif force == "1":
    proxies[proxies.index(cur)] = new; state = "обновлён"
else:
    state = "уже был"

def busy(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port)); return False
    except OSError:
        return True
    finally:
        s.close()

lst = next((l for l in listeners if l.get("name") == lname), None)
if lst is None:
    used = {int(l["port"]) for l in listeners if l.get("port")}
    port = max(used | {1079}) + 1
    while port in used or busy(port):
        port += 1
    listeners.append({"name": lname, "type": "socks", "port": port, "listen": "127.0.0.1"})
else:
    port = int(lst["port"])

rule = "IN-NAME,%s,%s" % (lname, pname)
if rule not in rules:
    i = next((i for i, r in enumerate(rules) if str(r).startswith("MATCH")), len(rules))
    rules.insert(i, rule)
for g in cfg.get("proxy-groups") or []:
    if pname not in (g.get("proxies") or []):
        g.setdefault("proxies", []).append(pname)   # в конец группы — последний резерв

cfg["proxies"], cfg["listeners"], cfg["rules"] = proxies, listeners, rules
with open(dst, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
print("PORT=%d" % port)
print("STATE=%s" % state)
PY
  SOCKS_PORT=$(sed -n 's/^PORT=//p' "$T/out")
  local state; state=$(sed -n 's/^STATE=//p' "$T/out")

  if [ "$state" = "уже был" ] && cmp -s "$MIHOMO_CONF" "$T/config.new"; then
    ok "прокси EU-Sudoku-$NAME уже есть, SOCKS $SOCKS_PORT"
  else
    "$MIHOMO_BIN" -t -d "$(dirname "$MIHOMO_CONF")" -f "$T/config.new" >"$T/test" 2>&1 \
      || { cat "$T/test" >&2; die "Mihomo не принял новый конфиг — ничего не меняю"; }
    cp "$MIHOMO_CONF" "$MIHOMO_CONF.bak-$(date +%F_%H%M%S)"
    install -m 600 "$T/config.new" "$MIHOMO_CONF"
    systemctl restart mihomo
    sleep 3
    ok "прокси EU-Sudoku-$NAME $state, SOCKS 127.0.0.1:$SOCKS_PORT (старый конфиг: $MIHOMO_CONF.bak-*)"
  fi
  local via; via=$(curl -s -m 15 --socks5 "127.0.0.1:$SOCKS_PORT" https://ifconfig.me || true)
  if [ "$via" = "$IP" ]; then ok "SOCKS $SOCKS_PORT → $via"; else warn "SOCKS $SOCKS_PORT → ${via:-нет ответа} (ожидался $IP)"; fi
}

# ---------------------------------------------------------------- замена: что осталось от старого выхода

find_old() {   # OLD_IFACE — туннель до старого выхода, OLD_SPORT/OLD_PROXY — его SOCKS-порт и прокси в Mihomo
  OLD_IFACE=""; OLD_SPORT=""; OLD_PROXY=""
  [ -n "${REPLACE:-}" ] || return 0
  [ "$REPLACE" != "$IP" ] || die "REPLACE совпадает с IP нового выхода"
  local f ep
  for f in "$AWG_DIR"/wg*.conf; do
    [ -e "$f" ] || continue
    ep=$(awk -F'=' '/^[[:space:]]*Endpoint/ {gsub(/[[:space:]]/, "", $2); print $2}' "$f")
    if [ "${ep%:*}" = "$REPLACE" ]; then OLD_IFACE=$(basename "$f" .conf); break; fi
  done
  if [ -f "$MIHOMO_CONF" ]; then
    local out
    out=$(python3 - "$MIHOMO_CONF" "$REPLACE" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
p = next((p for p in cfg.get("proxies") or [] if str(p.get("server")) == sys.argv[2]), None)
if p:
    lname = next((str(r).split(",")[1] for r in cfg.get("rules") or []
                  if str(r).startswith("IN-NAME,") and str(r).split(",")[2:3] == [p["name"]]), "")
    port = next((l.get("port") for l in cfg.get("listeners") or [] if l.get("name") == lname), "")
    print(p["name"], port or "")
PY
)
    OLD_PROXY=$(echo "$out" | awk '{print $1}'); OLD_SPORT=$(echo "$out" | awk '{print $2}')
  fi
  if [ -n "$OLD_IFACE$OLD_PROXY" ]; then
    ok "старый выход $REPLACE на этом входе: туннель ${OLD_IFACE:-нет}, Sudoku ${OLD_PROXY:-нет}${OLD_SPORT:+ (SOCKS $OLD_SPORT)}"
  else
    ok "старого выхода $REPLACE на этом входе нет — новый просто добавляется"
  fi
}

drop_old() {   # после переключения 3X-UI: убрать туннель и прокси старого выхода
  [ -n "${REPLACE:-}" ] && [ -n "$OLD_IFACE$OLD_PROXY" ] || return 0
  say "${DROP_TITLE:-4. Старый выход $REPLACE: убираю с этого входа}"
  local TS; TS=$(date +%F_%H%M%S)
  if [ -n "$OLD_IFACE" ] && [ -f "$AWG_DIR/$OLD_IFACE.conf" ]; then
    systemctl disable --now "awg-quick@$OLD_IFACE" >/dev/null 2>&1 || true
    ip link show "$OLD_IFACE" >/dev/null 2>&1 && { awg-quick down "$OLD_IFACE" >/dev/null 2>&1 || ip link del "$OLD_IFACE" 2>/dev/null || true; }
    mv "$AWG_DIR/$OLD_IFACE.conf" "$AWG_DIR/$OLD_IFACE.conf.removed-$TS"
    ok "туннель $OLD_IFACE выключен (конфиг сохранён: $AWG_DIR/$OLD_IFACE.conf.removed-$TS)"
  fi
  if [ -n "$OLD_PROXY" ]; then
    python3 - "$MIHOMO_CONF" "$TMPD/mihomo.drop" "$OLD_PROXY" <<'PY' || die "не удалось убрать старый прокси из Mihomo"
import sys, yaml
src, dst, pname = sys.argv[1:4]
cfg = yaml.safe_load(open(src)) or {}
rules = cfg.get("rules") or []
lnames = {str(r).split(",")[1] for r in rules if str(r).startswith("IN-NAME,") and str(r).split(",")[2:3] == [pname]}
cfg["proxies"] = [p for p in cfg.get("proxies") or [] if p.get("name") != pname]
cfg["listeners"] = [l for l in cfg.get("listeners") or [] if l.get("name") not in lnames]
cfg["rules"] = [r for r in rules if not (str(r).startswith("IN-NAME,") and str(r).split(",")[2:3] == [pname])]
for g in cfg.get("proxy-groups") or []:
    g["proxies"] = [x for x in g.get("proxies") or [] if x != pname]
with open(dst, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
PY
    "$MIHOMO_BIN" -t -d "$(dirname "$MIHOMO_CONF")" -f "$TMPD/mihomo.drop" >"$TMPD/test" 2>&1 \
      || { cat "$TMPD/test" >&2; die "Mihomo не принял конфиг без старого прокси — оставляю как было"; }
    cp "$MIHOMO_CONF" "$MIHOMO_CONF.bak-$TS"
    install -m 600 "$TMPD/mihomo.drop" "$MIHOMO_CONF"
    systemctl restart mihomo
    ok "прокси $OLD_PROXY${OLD_SPORT:+ и SOCKS $OLD_SPORT} убраны из Mihomo (старый конфиг: $MIHOMO_CONF.bak-$TS)"
  fi
}

# ---------------------------------------------------------------- 3. 3X-UI

xui_inbound_ports() {
  python3 - "$DB" <<'PY'
import sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
for (p,) in db.execute("select port from inbounds where enable=1"):
    print(p)
PY
}

xray_up() {   # ждём, пока процесс Xray (bin/xray-linux-*) снова слушает порты входящих
  local p ports; ports=$(xui_inbound_ports)
  [ -n "$ports" ] || ports=none
  for _ in $(seq 1 30); do
    sleep 1
    pgrep -f 'xray-linux' >/dev/null || continue
    [ "$ports" = none ] && return 0
    for p in $ports; do
      ss -Hltnp "sport = :$p" | grep -q xray || continue 2
    done
    return 0
  done
  return 1
}

xui_db_backup() {   # $1 — метка: копия базы 3X-UI в $DB.before-<метка>-<время>; задаёт TS и BAK вызывающей функции
  TS=$(date +%F_%H%M%S); BAK="$DB.before-$1-$TS"
  python3 - "$DB" "$BAK" <<'PY'
import sqlite3, sys
src = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
dst = sqlite3.connect(sys.argv[2]); src.backup(dst); dst.close(); src.close()
PY
  chmod 600 "$BAK"
  ok "бэкап базы: $BAK"
}

xui_start_or_rollback() {   # $1 — что сказать, если Xray поднялся; иначе база возвращается из $BAK (нужны TS и BAK)
  systemctl start x-ui
  if xray_up; then
    ok "$1"
  else
    warn "Xray не поднялся с новым шаблоном — откатываю базу"
    systemctl stop x-ui
    local f
    for f in x-ui.db-wal x-ui.db-shm; do [ -f "/etc/x-ui/$f" ] && mv "/etc/x-ui/$f" "/etc/x-ui/$f.failed-$TS"; done
    mv "$DB" "$DB.failed-$TS"
    install -m 600 "$BAK" "$DB"
    systemctl start x-ui
    xray_up && die "изменения в 3X-UI откатил, всё работает как раньше. Пришлите вывод: journalctl -u x-ui -n 50" \
            || die "после отката Xray тоже не поднялся! Проверьте: journalctl -u x-ui -n 50"
  fi
}

add_xui() {
  say "3. 3X-UI: исходящие и цепочка балансировщиков"
  [ -f "$DB" ] || die "нет $DB"
  local TS BAK
  xui_db_backup add-exit

  systemctl stop x-ui
  local rc=0
  REPLACE_IFACE="${OLD_IFACE:-}" REPLACE_PORT="${OLD_SPORT:-}" SUDOKU_ONLY="${SUDOKU_ONLY:-0}" AWG_ONLY="${AWG_ONLY:-0}" \
  VLESS_ONLY="${VLESS_ONLY:-0}" VLESS_FILE="${VLESS_FILE:-}" VLESS_ADDR="$IP" \
  python3 - "$DB" "$NAME" "$IFACE" "${SOCKS_PORT:-0}" <<'PY' || rc=$?
import copy, json, os, re, sqlite3, sys
path, name, iface, sport = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
db = sqlite3.connect(path)
row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
if not row:
    sys.exit("в базе нет xrayTemplateConfig")
t = json.loads(row[0])
obs = t.setdefault("outbounds", [])
tags = {o.get("tag") for o in obs}
awg, sdk = "AWG-" + name, "Sudoku-" + name
only_sdk = os.environ.get("SUDOKU_ONLY") == "1"
only_awg = os.environ.get("AWG_ONLY") == "1"
only_vl, vls = os.environ.get("VLESS_ONLY") == "1", "VLESS-" + name
only = sdk if only_sdk else awg if only_awg else vls if only_vl else ""   # режим «один протокол»: тег единственного нового исходящего
if only_vl:
    if vls in tags:
        sys.exit(10)
elif (sdk in tags and not only_awg) or (awg in tags and not only_sdk):
    sys.exit(10)

# Замена: исходящие старого выхода переводим на новый туннель / SOCKS-порт и переименовываем.
# Так новый выход оказывается ровно на местах старого во всех цепочках (основной, DC5TG и любых других).
rep_iface, rep_port = os.environ.get("REPLACE_IFACE", ""), os.environ.get("REPLACE_PORT", "")
if rep_iface or rep_port:
    olds = []
    for o in obs:
        so = (o.get("streamSettings") or {}).get("sockopt") or {}
        srvs = (o.get("settings") or {}).get("servers") or []
        if rep_iface and o.get("protocol") == "freedom" and so.get("interface") == rep_iface:
            so["interface"] = iface
            olds.append((o.get("tag", ""), awg))
        elif rep_port and o.get("protocol") == "socks" and any(str(x.get("port")) == rep_port for x in srvs):
            for x in srvs:
                if str(x.get("port")) == rep_port:
                    x["port"] = sport
            olds.append((o.get("tag", ""), sdk))
    if olds:
        ren = {}
        for old, new in olds:
            if old.split("-", 1)[0] == new.split("-", 1)[0] and new not in ren.values() and old != new:
                ren[old] = new
        txt = json.dumps(t, ensure_ascii=False)
        for old, new in ren.items():          # тег целиком или в конце имени звена: "Bal-1-AWG-Old", "_bl_DC5TG-2-AWG-Old"
            txt = re.sub(r'(?<=["\-])%s(?=")' % re.escape(old), new, txt)
        t = json.loads(txt)
        db.execute("update settings set value=? where key='xrayTemplateConfig'",
                   (json.dumps(t, indent=2, ensure_ascii=False),))
        db.commit()
        print("  на месте старого: " + ", ".join("%s → %s" % kv for kv in ren.items()) if ren else
              "  исходящие старого выхода переведены на новый")
        sys.exit(0)
    print("  в 3X-UI исходящих старого выхода нет — добавляю как новый")

r = t.setdefault("routing", {})
bals, rules = r.setdefault("balancers", []), r.setdefault("rules", [])
bal_by = {b["tag"]: b for b in bals}

def is_bl(rule):
    return any(str(x).startswith("_bl_") for x in rule.get("inboundTag", []) or [])

# Основная цепочка — та, на которую ведёт общее правило (без ip/domain/служебных петель).
# Отдельные цепочки вроде DC5TG-* (vpn-pin-chain.sh) не трогаем.
main_rule = next((x for x in reversed(rules) if x.get("balancerTag") in bal_by and not is_bl(x)
                  and not x.get("ip") and not x.get("domain")), None)
head = bal_by.get(main_rule["balancerTag"]) if main_rule else None
if head is None:
    referenced = {b.get("fallbackTag") for b in bals}
    head = next((b for b in bals if "_bl_" + b["tag"] not in referenced), None)
if head is None and bals:
    sys.exit("не нашёл цепочку балансировщиков")
# пустой вход (vpn-entry-new.sh): цепочки ещё нет — этот выход её создаёт
chain, b, seen = [], head, set()
while b is not None and b["tag"] not in seen:
    seen.add(b["tag"]); chain.append(b)
    b = bal_by.get((b.get("fallbackTag") or "")[4:])

def observe(tag):           # наблюдатель должен следить за звеном, у которого есть запасное
    ob = t.get("burstObservatory") or t.get("observatory")
    if ob is None:
        ob = t["burstObservatory"] = {"subjectSelector": [], "pingConfig": {
            "destination": "https://www.gstatic.com/generate_204", "connectivity": "", "interval": "1m", "sampling": 2, "timeout": "10s"}}
        print("  наблюдателя не было — добавил (проверка раз в минуту)")
    sel = ob.setdefault("subjectSelector", [])
    if tag not in sel:
        sel.append(tag)

o_sdk = {"tag": sdk, "protocol": "socks",
         "settings": {"servers": [{"address": "127.0.0.1", "port": sport, "users": []}]}}
n = len(bals) + 1
pos = max([i for i, x in enumerate(rules) if is_bl(x)] or
          [i for i, x in enumerate(rules) if "api" in (x.get("inboundTag") or [])] or [-1]) + 1

def make_awg():
    tpl = next((o for o in obs if o.get("protocol") == "freedom"
                and (o.get("streamSettings") or {}).get("sockopt", {}).get("interface")), None)
    if tpl:
        o = copy.deepcopy(tpl)
        o["tag"] = awg
        o["streamSettings"]["sockopt"]["interface"] = iface
        return o
    return {"tag": awg, "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {
        "domainStrategy": "UseIPv4", "interface": iface, "tcpMaxSeg": 1240, "tcpcongestion": "bbr"}}}

def make_vless():
    v = json.load(open(os.environ["VLESS_FILE"]))
    fp = v.get("fp") if v.get("fp") in ("firefox", "safari", "ios") else "firefox"   # большое приветствие chrome ТСПУ рвёт
    return {"tag": vls, "protocol": "vless",
            "settings": {"vnext": [{"address": os.environ["VLESS_ADDR"], "port": int(v["port"]),
                                    "users": [{"id": v["uuid"], "encryption": "none", "flow": v.get("flow") or ""}]}]},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverName": v.get("sni") or "", "fingerprint": fp, "publicKey": v["pbk"],
                                                   "shortId": v.get("sid") or "", "spiderX": "/"}}}

o_one = o_sdk if only_sdk else make_awg() if only_awg else make_vless() if only_vl else None

if only and main_rule is None and not chain:
    # цепочки нет: общее правило ведёт прямо на исходящее (например, из подписки 3X-UI) — оборачиваем его:
    # сначала оно, при отказе — новое. Все правила, что вели на это исходящее, теперь ведут на цепочку.
    plain = {o.get("tag") for o in obs if o.get("protocol") in ("freedom", "blackhole", "dns", "loopback")}
    MATCH = ("ip", "domain", "port", "sourcePort", "source", "protocol", "user", "attrs")
    gen = next((x for x in reversed(rules) if x.get("outboundTag") and not is_bl(x) and not any(x.get(k) for k in MATCH)
                and x["outboundTag"] not in plain and x["outboundTag"] not in ("direct", "blocked", "block", "api")), None)
    if gen is None:
        sys.exit("не нашёл общего правила «всё остальное» на исходящее и цепочки — некуда ставить запасной канал")
    main = gen["outboundTag"]
    bm, bs = "Bal-%d-%s" % (n, main), "Bal-%d-%s" % (n + 1, only)
    obs += [o_one, {"tag": "_bl_" + bs, "protocol": "loopback", "settings": {"inboundTag": "_bl_" + bs}}]
    rules.insert(pos, {"type": "field", "inboundTag": ["_bl_" + bs], "balancerTag": bs})
    moved = 0
    for x in rules:
        if x.get("outboundTag") == main and not is_bl(x):
            del x["outboundTag"]
            x["balancerTag"] = bm
            moved += 1
    bals += [{"tag": bm, "selector": [main], "fallbackTag": "_bl_" + bs}, {"tag": bs, "selector": [only], "fallbackTag": ""}]
    observe(main)
    db.execute("update settings set value=? where key='xrayTemplateConfig'", (json.dumps(t, indent=2, ensure_ascii=False),))
    db.commit()
    print("  цепочка: %s → запасной %s (правил переведено на цепочку: %d)" % (main, only, moved))
    sys.exit(0)

if only:
    obs.append(o_one)
    new_b = [{"tag": "Bal-%d-%s" % (n, only), "selector": [only], "fallbackTag": ""}]
else:
    o_awg = make_awg()
    b1, b2 = "Bal-%d-%s" % (n, awg), "Bal-%d-%s" % (n + 1, sdk)
    l1, l2 = "_bl_" + b1, "_bl_" + b2
    obs += [o_awg, o_sdk,
            {"tag": l1, "protocol": "loopback", "settings": {"inboundTag": l1}},
            {"tag": l2, "protocol": "loopback", "settings": {"inboundTag": l2}}]
    rules[pos:pos] = [{"type": "field", "inboundTag": [l1], "balancerTag": b1},
                      {"type": "field", "inboundTag": [l2], "balancerTag": b2}]
    new_b = [{"tag": b1, "selector": [awg], "fallbackTag": l2}, {"tag": b2, "selector": [sdk], "fallbackTag": ""}]
bals += new_b

# место в цепочке: end (по умолчанию) | first | after:ТЕГ_ИСХОДЯЩЕГО
position = os.environ.get("POSITION", "end")
order = list(chain)
if position == "first":
    at = 0
elif position.startswith("after:"):
    want = position[6:]
    idx = [i for i, x in enumerate(order) if want in (x.get("selector") or [])]
    if not idx:
        sys.exit("нет звена с исходящим %s для POSITION" % want)
    at = idx[-1] + 1
else:
    at = len(order)
order[at:at] = new_b
for i, x in enumerate(order):
    x["fallbackTag"] = "_bl_" + order[i + 1]["tag"] if i + 1 < len(order) else ""
    if i > 0 and not any(o.get("tag") == "_bl_" + x["tag"] for o in obs):
        obs.append({"tag": "_bl_" + x["tag"], "protocol": "loopback", "settings": {"inboundTag": "_bl_" + x["tag"]}})
        rules.insert(pos, {"type": "field", "inboundTag": ["_bl_" + x["tag"]], "balancerTag": x["tag"]})
if order[0] is not head and main_rule is not None:
    DNS_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}      # правило «DNS Xray — через цепочку» идёт за её началом
    for x in rules:
        if (head is not None and x.get("balancerTag") == head["tag"] and not is_bl(x) and x.get("ip") and not x.get("domain")
                and all(str(i).split("/")[0] in DNS_IPS for i in x["ip"])):
            x["balancerTag"] = order[0]["tag"]
    main_rule["balancerTag"] = order[0]["tag"]
if main_rule is None:
    # первая цепочка на входе: всё, что не ушло напрямую/в блок по правилам выше, — в неё; DNS-запросы Xray
    # к 1.1.1.1 и 8.8.8.8 тоже через неё (на российских серверах их часто подменяют по дороге)
    rules.insert(pos + len([x for x in rules[pos:] if is_bl(x)]),
                 {"type": "field", "ip": ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"], "balancerTag": order[0]["tag"]})
    rules.append({"type": "field", "network": "tcp,udp", "balancerTag": order[0]["tag"]})
    print("  создана цепочка выходов: всё, что не напрямую, идёт через %s" % name)

# здоровье проверяется для всех, у кого теперь есть следующий в цепочке
if not (t.get("burstObservatory") or t.get("observatory")) and not only:
    print("WARN: нет observatory — переключение на резерв работать не будет")
elif len(order) > 1:
    for x in order[:-1]:                     # у кого есть следующее звено
        for s in x.get("selector") or []:
            observe(s)

db.execute("update settings set value=? where key='xrayTemplateConfig'",
           (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit()

PY
  if [ "$rc" = 10 ]; then
    systemctl start x-ui
    ok "исходящее для $NAME уже есть в 3X-UI — ничего не меняю"
    XUI_ALREADY=1
    rm -f "$BAK"
    return
  fi
  if [ "$rc" != 0 ]; then
    systemctl start x-ui
    die "3X-UI не изменена (ошибка выше), база осталась прежней"
  fi
  xui_start_or_rollback "Xray перезапущен с новой цепочкой"
  python3 - "$DB" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
bals = t["routing"]["balancers"]
byl = {"_bl_" + b["tag"]: b for b in bals}
head = next((b for b in bals if not any(x.get("fallbackTag") == "_bl_" + b["tag"] for x in bals)), bals[0])
chain, b = [], head
while b is not None and len(chain) <= len(bals):
    chain.append(",".join(b.get("selector", []))); b = byl.get(b.get("fallbackTag") or "")
print("  Цепочка: " + "  →  ".join(chain))
PY
}

# ---------------------------------------------------------------- перевод выхода на AmneziaWG без Docker

migrate_awg() {
  say "Перевожу туннель до $NAME ($IP) на AmneziaWG без Docker"
  local f ep IFACE="" BAK v i
  for f in "$AWG_DIR"/wg*.conf; do
    [ -e "$f" ] || continue
    ep=$(awk -F'=' '/^[[:space:]]*Endpoint/ {gsub(/[[:space:]]/, "", $2); print $2}' "$f")
    if [ "${ep%:*}" = "$IP" ]; then IFACE=$(basename "$f" .conf); break; fi
  done
  [ -n "$IFACE" ] || die "на этом входе нет туннеля до $IP — переводить нечего"
  BAK="$AWG_DIR/$IFACE.conf.before-migrate-$(date +%F_%H%M%S)"
  cp "$AWG_DIR/$IFACE.conf" "$BAK"
  ok "$IFACE сейчас: ${ep}; копия конфига: $BAK"
  AWG_MODE=native FORCE_AWG=1 awg_add_exit "$IFACE" "$IP"
  for i in 1 2 3; do
    v=$(curl -s -m 10 --interface "$IFACE" https://ifconfig.me || true)
    [ "$v" = "$IP" ] && break
    sleep 5
  done
  if [ "$v" != "$IP" ]; then
    install -m 600 "$BAK" "$AWG_DIR/$IFACE.conf"
    systemctl restart "awg-quick@$IFACE" || true
    die "через новый туннель $IFACE нет выхода (${v:-нет ответа}) — вернул старый конфиг (Amnezia в Docker)"
  fi
  ok "$IFACE → $v: туннель идёт на AmneziaWG без Docker (новый порт $(awk -F'[:[:space:]]+' '/^[[:space:]]*Endpoint/ {print $NF}' "$AWG_DIR/$IFACE.conf"))"
  echo
  echo "  Готово. Sudoku, Mihomo и 3X-UI не менялись: исходящие AWG-$NAME по-прежнему идут в $IFACE."
}

# ---------------------------------------------------------------- main

add_exit_main() {
  NAME=${1:-}; IP=${2:-}; FORCE=0
  [ -n "$NAME" ] && [ -n "$IP" ] || usage
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      --force) FORCE=1 ;;
      *) usage ;;
    esac
    shift
  done
  [[ "$NAME" =~ ^[A-Za-z][A-Za-z0-9]{0,19}$ ]] || die "ИМЯ — латиница и цифры, до 20 символов (например ExitA)"
  [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "IP выхода в виде 203.0.113.10"
  [ "$(id -u)" -eq 0 ] || die "запустите от root"
  [ "${SUDOKU_ONLY:-0}" = 1 ] || [ "${VLESS_ONLY:-0}" = 1 ] || command -v awg >/dev/null || die "нет awg — это точно вход с AmneziaWG?"

  TMPD=$(mktemp -d); chmod 700 "$TMPD"
  trap 'rm -rf "$TMPD"' EXIT
  if [ "${MIGRATE:-0}" = 1 ]; then migrate_awg; return 0; fi
  say "Подключаю выход $NAME ($IP) к $(hostname -s)"
  [ -n "${VPN_PWDIR:-}" ] || [ "${VLESS_ONLY:-0}" = 1 ] || echo "  Пароль root выхода спросят один раз."
  echo "  Во время шага 3 панель и VPN на этом входе перезапустятся (5–10 секунд)."
  XUI_ALREADY=0
  find_old
  if [ "${VLESS_ONLY:-0}" = 1 ]; then
    [ -z "${REPLACE:-}" ] || die "VLESS_ONLY и REPLACE вместе не бывают"
    [ -r "${VLESS_FILE:-}" ] || die "нет файла с параметрами VLESS (VLESS_FILE)"
    IFACE=""; SOCKS_PORT=""; ok "только VLESS: туннель и Mihomo не трогаю"
    add_xui; rm -f "$VLESS_FILE"
  elif [ "${SUDOKU_ONLY:-0}" = 1 ]; then
    [ -z "${REPLACE:-}" ] || die "SUDOKU_ONLY и REPLACE вместе не бывают"
    [ "${AWG_ONLY:-0}" != 1 ] || die "SUDOKU_ONLY и AWG_ONLY вместе не бывают"
    IFACE=""; ok "только Sudoku: туннель AmneziaWG не создаю"
  else
    add_awg
  fi
  if [ "${VLESS_ONLY:-0}" = 1 ]; then
    :
  elif [ "${AWG_ONLY:-0}" = 1 ]; then
    [ -z "${REPLACE:-}" ] || die "AWG_ONLY и REPLACE вместе не бывают"
    SOCKS_PORT=""; ok "только AmneziaWG: Mihomo и Sudoku не трогаю"
  else
    add_sudoku
  fi
  [ "${VLESS_ONLY:-0}" = 1 ] || add_xui
  drop_old

  say "Проверка"
  if [ -n "$IFACE" ]; then
    v=$(curl -s -m 10 --interface "$IFACE" https://ifconfig.me || true)
    if [ "$v" = "$IP" ]; then ok "$IFACE → $v"; else warn "$IFACE → ${v:-нет ответа} (ожидался $IP)"; fi
  fi
  if [ -n "${SOCKS_PORT:-}" ]; then
    v=$(curl -s -m 15 --socks5 "127.0.0.1:$SOCKS_PORT" https://ifconfig.me || true)
    if [ "$v" = "$IP" ]; then ok "SOCKS $SOCKS_PORT → $v"; else warn "SOCKS $SOCKS_PORT → ${v:-нет ответа} (ожидался $IP)"; fi
  fi
  if [ "${SUDOKU_ONLY:-0}${AWG_ONLY:-0}${VLESS_ONLY:-0}" != 000 ] && [ "$XUI_ALREADY" != 1 ]; then
    case "${POSITION:-end}" in
      end) where="в конец цепочки, запасным" ;; first) where="первым, основным путём" ;; after:*) where="сразу после ${POSITION#after:}" ;; *) where="$POSITION" ;;
    esac
    echo; echo "  Готово. Новый путь до $NAME добавлен в цепочку: $where."
  elif [ "$XUI_ALREADY" = 1 ]; then
    echo; echo "  Готово. $NAME уже был подключён к этому входу (повторный запуск) — цепочки не менялись."
  elif [ -n "${REPLACE:-}" ] && [ -n "$OLD_IFACE$OLD_PROXY" ]; then
    echo; echo "  Готово. $NAME стоит на месте старого выхода $REPLACE во всех цепочках."
  elif [ "${POSITION:-end}" = end ]; then
    echo; echo "  Готово. $NAME — последний резерв: трафик пойдёт туда, только если все выходы перед ним недоступны."
  else
    echo; echo "  Готово. $NAME стоит в цепочке на выбранном месте (${POSITION})."
  fi
  [ -n "${VPN_PWDIR:-}" ] || [ "${VLESS_ONLY:-0}" = 1 ] || echo "  Повторите то же на втором входе."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then add_exit_main "$@"; fi
