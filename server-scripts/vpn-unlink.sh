#!/usr/bin/env bash
# Отвязать выход от этого входа одним протоколом — обратное к «Связать» («Протоколы» → «Настройка»).
#
# Запуск на входе от root, рядом должны лежать vpn-add-exit.sh и vpn-restore.sh:
#   bash vpn-unlink.sh AWG ИМЯ        — убрать путь AWG-ИМЯ: звено цепочки, исходящее, туннель wgN
#   bash vpn-unlink.sh Sudoku ИМЯ     — убрать путь Sudoku-ИМЯ: звено цепочки, исходящее, прокси и SOCKS в Mihomo
#   bash vpn-unlink.sh VLESS ИМЯ      — убрать путь VLESS-ИМЯ: звено цепочки и исходящее (клиента на той стороне убирает панель)
#   bash vpn-unlink.sh AWG @wg3 / Sudoku @1083 — найти путь по туннелю / SOCKS-порту (если имя исходящего неизвестно;
#                                       исходящего нет вовсе — убирается только туннель или прокси)
#   CHECK=1 bash vpn-unlink.sh …      — только проверить, можно ли (ничего не меняет)
#
# В цепочке звено вынимается, соседи сшиваются: тот, кто передавал ему трафик при отказе, передаёт следующему;
# было первым — правила, что вели на цепочку, ведут на следующее звено. Не убирает и ничего не меняет, если:
#   • путь — единственный в цепочке (трафику некуда будет идти);
#   • исходящее используется где-то ещё: в обходах «Сайтов и обходов», DC5TG, прямо в правилах.
# Перед изменением — копия базы 3X-UI; Xray не поднялся — база возвращается. Туннель и прокси убираются только после.
# В конце строка UNLINK-PEER=<публичный ключ туннеля> — по ней панель убирает этот вход из awg0 на выходе.

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ -f "$HERE/vpn-add-exit.sh" ] && [ -f "$HERE/vpn-restore.sh" ] \
  || { echo "Рядом должны лежать vpn-add-exit.sh и vpn-restore.sh" >&2; exit 1; }
# shellcheck source=vpn-add-exit.sh
source "$HERE/vpn-add-exit.sh"

unlink_main() {
  local KIND=${1:-} NAME=${2:-}
  { [ "$KIND" = AWG ] || [ "$KIND" = Sudoku ] || [ "$KIND" = VLESS ]; } && [[ "$NAME" =~ ^([A-Za-z][A-Za-z0-9_-]{0,39}|@wg[0-9]{1,3}|@[0-9]{2,5})$ ]] \
    || die "Использование: bash $0 AWG|Sudoku|VLESS ИМЯ  (или @wgN / @порт_SOCKS)"
  [ "$KIND" != VLESS ] || [[ "$NAME" != @* ]] || die "VLESS — только по имени"
  [ "$(id -u)" = 0 ] || die "нужен root"
  [ -f "$DB" ] || die "нет 3X-UI ($DB)"
  local TAG="$KIND-$NAME"
  TMPD=$(mktemp -d); chmod 700 "$TMPD"
  trap 'rm -rf "$TMPD"' EXIT

  say "1. Что убрать: $TAG"
  local out
  out=$(python3 - "$DB" "$TAG" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
tag = sys.argv[2]
kind, _, sel = tag.partition("-")
if sel.startswith("@"):                  # по туннелю / SOCKS-порту
    want = sel[1:]
    def key(o):
        if o.get("protocol") == "freedom":
            return ((o.get("streamSettings") or {}).get("sockopt") or {}).get("interface")
        if o.get("protocol") == "socks":
            s = ((o.get("settings") or {}).get("servers") or [{}])[0]
            return str(s.get("port")) if s.get("address") in ("127.0.0.1", "localhost") else None
    o = next((o for o in t.get("outbounds") or [] if key(o) == want), None)
    if not o:
        print("none", want if want.startswith("wg") else "", want if want.isdigit() else "")
        sys.exit(0)
    print("tag", o["tag"])
o = next((o for o in t.get("outbounds") or [] if o.get("tag") == tag), None) if not sel.startswith("@") else o
if not o:
    sys.exit("в 3X-UI нет исходящего %s — этот путь уже убран или назывался иначе" % tag)
if o.get("protocol") == "freedom":
    print("iface", ((o.get("streamSettings") or {}).get("sockopt") or {}).get("interface") or "")
else:
    print("port", ((o.get("settings") or {}).get("servers") or [{}])[0].get("port") or "")
PY
) || die "$out"
  local IFACE="" SPORT="" NOXUI=0
  if [[ "$out" == none\ * ]]; then          # исходящего в 3X-UI нет — только туннель / прокси
    NOXUI=1; read -r _ IFACE SPORT <<<"$out"; ok "в 3X-UI исходящего на ${NAME#@} нет — уберу только $([ "$KIND" = AWG ] && echo туннель || echo прокси)"
  else
    [[ "$out" == tag\ * ]] && { TAG=$(head -n1 <<<"$out"); TAG=${TAG#tag }; out=$(tail -n +2 <<<"$out"); ok "исходящее: $TAG"; }
    case "$out" in iface\ *) IFACE=${out#iface } ;; port\ *) SPORT=${out#port } ;; esac
  fi
  OLD_IFACE=""; OLD_PROXY=""; OLD_SPORT=""
  if [ "$KIND" = AWG ]; then
    [ -n "$IFACE" ] && [ -f "$AWG_DIR/$IFACE.conf" ] && OLD_IFACE=$IFACE
    ok "туннель: ${OLD_IFACE:-не найден (уберу только из 3X-UI)}"
  elif [ "$KIND" = Sudoku ]; then
    if [ -n "$SPORT" ] && [ -f "$MIHOMO_CONF" ]; then
      OLD_PROXY=$(python3 - "$MIHOMO_CONF" "$SPORT" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
ln = next((l.get("name") for l in cfg.get("listeners") or [] if str(l.get("port")) == sys.argv[2]), None)
print(next((str(r).split(",")[2] for r in cfg.get("rules") or [] if ln and str(r).startswith("IN-NAME,%s," % ln)), ""))
PY
)
      OLD_SPORT=$SPORT
    fi
    ok "Mihomo: прокси ${OLD_PROXY:-не найден (уберу только из 3X-UI)}${OLD_SPORT:+, SOCKS $OLD_SPORT}"
    # прокси нужен ещё кому-то (другому SOCKS) — его не трогаем, убираем только этот SOCKS
  fi

  local rc=0
  if [ "$NOXUI" = 1 ]; then
    [ "${CHECK:-0}" = 1 ] && { ok "проверка пройдена, ничего не менял (CHECK=1)"; return 0; }
  else
  say "2. 3X-UI: звено цепочки и исходящее"
  [ "${CHECK:-0}" = 1 ] || { xui_db_backup unlink; systemctl stop x-ui; }
  CHECK="${CHECK:-0}" python3 - "$DB" "$TAG" <<'PY' || rc=$?
import json, os, sqlite3, sys
path, tag = sys.argv[1], sys.argv[2]
check = os.environ.get("CHECK") == "1"
db = sqlite3.connect(path)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
r = t.setdefault("routing", {})
rules, bals, obs = r.setdefault("rules", []), r.setdefault("balancers", []), t.setdefault("outbounds", [])
is_bl = lambda x: any(str(i).startswith("_bl_") for i in x.get("inboundTag") or [])
own = [b for b in bals if (b.get("selector") or []) == [tag] and str(b.get("tag", "")).startswith("Bal-")]
other = [b["tag"] for b in bals if tag in (b.get("selector") or []) and b not in own]
direct = [x.get("comment") or x.get("ruleTag") or ", ".join(map(str, (x.get("domain") or x.get("ip") or [])[:2])) or "без имени"
          for x in rules if x.get("outboundTag") == tag]
if other or direct:
    why = []
    if other:
        why.append("цепочках %s (обходы «Сайтов и обходов», DC5TG и т. п.)" % ", ".join(other))
    if direct:
        why.append("правилах: %s" % "; ".join(direct))
    sys.exit("%s используется ещё в %s — сначала уберите его оттуда, тогда отвяжу" % (tag, " и ".join(why)))
byl = {"_bl_" + b["tag"]: b for b in bals}
b = own[0] if own else None
if b:
    succ = byl.get(b.get("fallbackTag") or "")
    pred = next((x for x in bals if x.get("fallbackTag") == "_bl_" + b["tag"]), None)
    users = [x for x in rules if x.get("balancerTag") == b["tag"] and not is_bl(x)]
    if users and not succ:
        sys.exit("%s — единственный путь в своей цепочке: без него трафику некуда идти. Сначала свяжите вход с другим выходом" % tag)
    if check:
        print("  можно: звено %s, %s" % (b["tag"], ("правил на него: %d → перейдут на %s" % (len(users), succ["tag"])) if users else
                                            "до него доходят при отказе %s" % (pred["tag"] if pred else "—")))
        sys.exit(0)
    for x in users:
        x["balancerTag"] = succ["tag"]
    if pred:
        pred["fallbackTag"] = b.get("fallbackTag") or ""
    bals.remove(b)
    rules[:] = [x for x in rules if not (x.get("inboundTag") == ["_bl_" + b["tag"]])]
    obs[:] = [o for o in obs if o.get("tag") != "_bl_" + b["tag"]]
    print("  звено %s вынуто из цепочки%s" % (b["tag"], ", правила перешли на %s" % succ["tag"] if users else ""))
elif check:
    print("  можно: %s не в цепочке" % tag)
    sys.exit(0)
obs[:] = [o for o in obs if o.get("tag") != tag]
for k in ("burstObservatory", "observatory"):
    ob = t.get(k)
    if ob and tag in (ob.get("subjectSelector") or []):
        ob["subjectSelector"] = [s for s in ob["subjectSelector"] if s != tag]
db.execute("update settings set value=? where key='xrayTemplateConfig'", (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit()
print("  исходящее %s убрано" % tag)
PY
  if [ "$rc" != 0 ]; then
    [ "${CHECK:-0}" = 1 ] || { systemctl start x-ui; rm -f "$BAK"; }
    die "ничего не менял"
  fi
  if [ "${CHECK:-0}" = 1 ]; then ok "проверка пройдена, ничего не менял (CHECK=1)"; return 0; fi
  xui_start_or_rollback "Xray перезапущен без $TAG"
  fi

  local PUB=""
  if [ -n "$OLD_IFACE" ]; then
    # ключ кончается на «=» — режем только по первому «=» строки
    PUB=$(sed -n 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//p' "$AWG_DIR/$OLD_IFACE.conf" | head -n1 | tr -d ' \r' | awg pubkey 2>/dev/null || true)
  fi
  if [ -n "$OLD_PROXY" ]; then             # тот же прокси через другой SOCKS кому-то ещё нужен — оставляем
    local more
    more=$(python3 - "$MIHOMO_CONF" "$OLD_PROXY" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
print(sum(1 for r in cfg.get("rules") or [] if str(r).startswith("IN-NAME,") and str(r).split(",")[2:3] == [sys.argv[2]]))
PY
)
    [ "${more:-1}" -le 1 ] || { warn "прокси $OLD_PROXY нужен ещё другому SOCKS — оставляю его"; OLD_PROXY=""; }
  fi
  [ "$KIND" = VLESS ] || REPLACE="$TAG" DROP_TITLE="3. Убираю $([ "$KIND" = AWG ] && echo "туннель ${OLD_IFACE:-}" || echo "прокси Mihomo ${OLD_PROXY:-}")" drop_old
  [ -n "$PUB" ] && echo "UNLINK-PEER=$PUB"
  echo; echo "  Готово. Путь $TAG убран с этого входа."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then unlink_main "$@"; fi
