#!/usr/bin/env bash
# vpn-add-exit.sh — подключает новый выходной сервер к ЭТОМУ входу.
#
# Выход должен быть подготовлен vpn-exit-setup.sh (или это AmneziaWG в Docker от приложения Amnezia).
# Запуск на входе от root, рядом должен лежать vpn-restore.sh (из него берутся общие функции):
#   bash vpn-add-exit.sh ИМЯ IP              например: bash vpn-add-exit.sh ИМЯ_ЛАТИНИЦЕЙ IP_ВЫХОДА
#   bash vpn-add-exit.sh ИМЯ IP --force      пересоздать AWG-клиента на выходе и туннель здесь
#
# Что делает:
#   1. AWG     создаёт на выходе клиента <этот сервер>-wgN и поднимает здесь туннель wgN
#   2. 3X-UI   добавляет исходящее AWG-ИМЯ и ставит его В КОНЕЦ цепочки
#              балансировщиков (последний резерв); база панели бэкапится, при ошибке — откат
# Пароль root выхода спрашивается один раз и никуда не сохраняется.
#
# Место в цепочке (по умолчанию — в конец, последний резерв):
#   POSITION=first bash vpn-add-exit.sh ...              первым, основной выход
#   POSITION=after:AWG-Warsaw bash vpn-add-exit.sh ...     сразу после звена с этим исходящим
# Отдельные цепочки правил (например DC5TG от vpn-pin-chain.sh) не затрагиваются.
#
# Замена выхода (новый сервер вместо старого, например умершего):
#   REPLACE=IP_СТАРОГО bash vpn-add-exit.sh ИМЯ IP
#   Новый выход встаёт ровно на места старого во ВСЕХ цепочках (основной и DC5TG): исходящие старого
#   переводятся на новый туннель и переименовываются в AWG-ИМЯ.
#   Потом со входа убирается туннель до старого выхода. Сам старый сервер не трогается.
#   Если старого выхода на этом входе нет — новый просто добавляется на место POSITION.
#
# Перевод выхода с Amnezia в Docker на AmneziaWG без Docker (на самом выходе уже поднят awg0):
#   MIGRATE=1 bash vpn-add-exit.sh ИМЯ IP
#   Туннель до этого выхода (тот же wgN) переводится на новый awg0: новые ключи, порт, адрес.
#   3X-UI не меняется — исходящие по-прежнему смотрят в тот же wgN. Нет выхода через
#   новый туннель — старый конфиг возвращается.

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ -f "$HERE/vpn-restore.sh" ] || { echo "Рядом с этим скриптом должен лежать vpn-restore.sh" >&2; exit 1; }
# shellcheck source=vpn-restore.sh
source "$HERE/vpn-restore.sh"

DB=/etc/x-ui/x-ui.db

usage() { echo "Использование: bash $0 ИМЯ IP [--force]   (ИМЯ латиницей, например Frankfurt)"; exit 1; }

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

# ---------------------------------------------------------------- замена: что осталось от старого выхода

find_old() {   # OLD_IFACE — туннель до старого выхода
  OLD_IFACE=""
  [ -n "${REPLACE:-}" ] || return 0
  [ "$REPLACE" != "$IP" ] || die "REPLACE совпадает с IP нового выхода"
  local f ep
  for f in "$AWG_DIR"/wg*.conf; do
    [ -e "$f" ] || continue
    ep=$(awk -F'=' '/^[[:space:]]*Endpoint/ {gsub(/[[:space:]]/, "", $2); print $2}' "$f")
    if [ "${ep%:*}" = "$REPLACE" ]; then OLD_IFACE=$(basename "$f" .conf); break; fi
  done
  if [ -n "$OLD_IFACE" ]; then
    ok "старый выход $REPLACE на этом входе: туннель $OLD_IFACE"
  else
    ok "старого выхода $REPLACE на этом входе нет — новый просто добавляется"
  fi
}

drop_old() {   # после переключения 3X-UI: убрать туннель до старого выхода
  [ -n "${REPLACE:-}" ] && [ -n "$OLD_IFACE" ] || return 0
  say "3. Старый выход $REPLACE: убираю с этого входа"
  local TS; TS=$(date +%F_%H%M%S)
  if [ -f "$AWG_DIR/$OLD_IFACE.conf" ]; then
    systemctl disable --now "awg-quick@$OLD_IFACE" >/dev/null 2>&1 || true
    ip link show "$OLD_IFACE" >/dev/null 2>&1 && { awg-quick down "$OLD_IFACE" >/dev/null 2>&1 || ip link del "$OLD_IFACE" 2>/dev/null || true; }
    mv "$AWG_DIR/$OLD_IFACE.conf" "$AWG_DIR/$OLD_IFACE.conf.removed-$TS"
    ok "туннель $OLD_IFACE выключен (конфиг сохранён: $AWG_DIR/$OLD_IFACE.conf.removed-$TS)"
  fi
}

# ---------------------------------------------------------------- 2. 3X-UI

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
  say "2. 3X-UI: исходящее и цепочка балансировщиков"
  [ -f "$DB" ] || die "нет $DB"
  local TS BAK
  xui_db_backup add-exit

  systemctl stop x-ui
  local rc=0
  REPLACE_IFACE="${OLD_IFACE:-}" \
  python3 - "$DB" "$NAME" "$IFACE" <<'PY' || rc=$?
import copy, json, os, re, sqlite3, sys
path, name, iface = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(path)
row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
if not row:
    sys.exit("в базе нет xrayTemplateConfig")
t = json.loads(row[0])
obs = t.setdefault("outbounds", [])
tags = {o.get("tag") for o in obs}
awg = "AWG-" + name
if awg in tags:
    sys.exit(10)

# Замена: исходящие старого выхода переводим на новый туннель и переименовываем.
# Так новый выход оказывается ровно на местах старого во всех цепочках (основной, DC5TG и любых других).
rep_iface = os.environ.get("REPLACE_IFACE", "")
if rep_iface:
    olds = []
    for o in obs:
        so = (o.get("streamSettings") or {}).get("sockopt") or {}
        if o.get("protocol") == "freedom" and so.get("interface") == rep_iface:
            so["interface"] = iface
            olds.append(o.get("tag", ""))
    if olds:
        ren = {}
        for old in olds:
            if old.startswith("AWG-") and awg not in ren.values() and old != awg:
                ren[old] = awg
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
if head is None:
    sys.exit("не нашёл цепочку балансировщиков")
chain, b, seen = [], head, set()
while b is not None and b["tag"] not in seen:
    seen.add(b["tag"]); chain.append(b)
    b = bal_by.get((b.get("fallbackTag") or "")[4:])
tail = chain[-1]

tpl = next((o for o in obs if o.get("protocol") == "freedom"
            and (o.get("streamSettings") or {}).get("sockopt", {}).get("interface")), None)
if tpl:
    o_awg = copy.deepcopy(tpl)
    o_awg["tag"] = awg
    o_awg["streamSettings"]["sockopt"]["interface"] = iface
else:
    o_awg = {"tag": awg, "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {
        "domainStrategy": "UseIPv4", "interface": iface, "tcpMaxSeg": 1240, "tcpcongestion": "bbr"}}}

n = len(bals) + 1
while any(x["tag"].startswith("Bal-%d-" % n) for x in bals):
    n += 1
b1 = "Bal-%d-%s" % (n, awg)
l1 = "_bl_" + b1
obs += [o_awg, {"tag": l1, "protocol": "loopback", "settings": {"inboundTag": l1}}]

pos = max([i for i, x in enumerate(rules) if is_bl(x)] or
          [i for i, x in enumerate(rules) if "api" in (x.get("inboundTag") or [])] or [-1]) + 1
rules[pos:pos] = [{"type": "field", "inboundTag": [l1], "balancerTag": b1}]

new_b = [{"tag": b1, "selector": [awg], "fallbackTag": ""}]
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
    main_rule["balancerTag"] = order[0]["tag"]

# здоровье проверяется для всех, у кого теперь есть следующий в цепочке
ob = t.get("burstObservatory") or t.get("observatory")
if ob is None:
    print("WARN: нет observatory — переключение на резерв работать не будет")
else:
    sel = ob.setdefault("subjectSelector", [])
    for x in order[:-1]:                     # у кого есть следующее звено
        for s in x.get("selector") or []:
            if s not in sel:
                sel.append(s)

db.execute("update settings set value=? where key='xrayTemplateConfig'",
           (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit()

PY
  if [ "$rc" = 10 ]; then
    systemctl start x-ui
    ok "исходящее AWG-$NAME уже есть в 3X-UI — ничего не меняю"
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
  echo "  Готово. 3X-UI не менялась: исходящие AWG-$NAME по-прежнему идут в $IFACE."
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
  [[ "$NAME" =~ ^[A-Za-z][A-Za-z0-9]{0,19}$ ]] || die "ИМЯ — латиница и цифры, до 20 символов (например Frankfurt)"
  [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "IP выхода в виде 1.2.3.4"
  [ "$(id -u)" -eq 0 ] || die "запустите от root"
  command -v awg >/dev/null || die "нет awg — это точно вход с AmneziaWG?"

  TMPD=$(mktemp -d); chmod 700 "$TMPD"
  trap 'rm -rf "$TMPD"' EXIT
  if [ "${MIGRATE:-0}" = 1 ]; then migrate_awg; return 0; fi
  say "Подключаю выход $NAME ($IP) к $(hostname -s)"
  [ -n "${VPN_PWDIR:-}" ] || echo "  Пароль root выхода спросят один раз."
  echo "  Во время шага 2 панель и VPN на этом входе перезапустятся (5–10 секунд)."
  XUI_ALREADY=0
  find_old
  add_awg
  add_xui
  drop_old

  say "Проверка"
  v=$(curl -s -m 10 --interface "$IFACE" https://ifconfig.me || true)
  if [ "$v" = "$IP" ]; then ok "$IFACE → $v"; else warn "$IFACE → ${v:-нет ответа} (ожидался $IP)"; fi
  if [ "$XUI_ALREADY" = 1 ]; then
    echo; echo "  Готово. $NAME уже был подключён к этому входу (повторный запуск) — цепочки не менялись."
  elif [ -n "${REPLACE:-}" ] && [ -n "$OLD_IFACE" ]; then
    echo; echo "  Готово. $NAME стоит на месте старого выхода $REPLACE во всех цепочках."
  elif [ "${POSITION:-end}" = end ]; then
    echo; echo "  Готово. $NAME — последний резерв: трафик пойдёт туда, только если все выходы перед ним недоступны."
  else
    echo; echo "  Готово. $NAME стоит в цепочке на выбранном месте (${POSITION})."
  fi
  [ -n "${VPN_PWDIR:-}" ] || echo "  Повторите то же на втором входе."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then add_exit_main "$@"; fi
