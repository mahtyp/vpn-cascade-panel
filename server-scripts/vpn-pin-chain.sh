#!/usr/bin/env bash
# vpn-pin-chain.sh — даёт отдельному правилу маршрутизации 3X-UI (например, DC5 Telegram → AWG-Warsaw)
# свою резервную цепочку: если первый выход недоступен, трафик этого правила идёт на следующий.
#
# Запуск на входе от root, рядом должны лежать vpn-add-exit.sh и vpn-restore.sh:
#   bash vpn-pin-chain.sh DC5TG AWG-Warsaw AWG-Frankfurt
#     DC5TG — комментарий правила в 3X-UI (поле comment), дальше — исходящие по порядку.
# Повторный запуск с другим списком пересобирает цепочку. Вернуть как было (правило снова
# ведёт прямо в первый выход):
#   bash vpn-pin-chain.sh DC5TG --off AWG-Warsaw
# Дописать выход в конец уже существующей цепочки правила:
#   bash vpn-pin-chain.sh DC5TG --append AWG-Amsterdam
#
# Перед правкой база панели бэкапится; если Xray с новым шаблоном не поднимется — откат.

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ -f "$HERE/vpn-add-exit.sh" ] && [ -f "$HERE/vpn-restore.sh" ] \
  || { echo "Рядом должны лежать vpn-add-exit.sh и vpn-restore.sh" >&2; exit 1; }
# shellcheck source=vpn-add-exit.sh
source "$HERE/vpn-add-exit.sh"

pin_main() {
  local COMMENT=${1:-}
  shift || true
  local OFF=0
  if [ "${1:-}" = "--off" ]; then OFF=1; shift; fi
  if [ "${1:-}" = "--append" ]; then
    [ $# -eq 2 ] || die "с --append укажите ровно один выход"
    local cur
    cur=$(python3 - "$DB" "$COMMENT" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
r = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])["routing"]
rule = next((x for x in r.get("rules", []) if x.get("comment") == sys.argv[2]), None)
if rule is None:
    sys.exit("в 3X-UI нет правила «%s»" % sys.argv[2])
if rule.get("outboundTag"):
    print(rule["outboundTag"]); sys.exit()
bals = {b["tag"]: b for b in r.get("balancers", [])}
b, out = bals.get(rule.get("balancerTag")), []
while b is not None and len(out) < 20:
    out += b.get("selector") or []
    b = bals.get((b.get("fallbackTag") or "")[4:])
print(" ".join(out))
PY
) || die "не удалось прочитать цепочку правила"
    local add=$2
    if [[ " $cur " == *" $add "* ]]; then ok "$add уже в цепочке «$COMMENT»: $cur"; return 0; fi
    # shellcheck disable=SC2086
    set -- $cur "$add"
  fi
  [ -n "$COMMENT" ] && [ $# -ge 1 ] || {
    echo "Использование: bash $0 КОММЕНТАРИЙ_ПРАВИЛА ВЫХОД1 [ВЫХОД2 ...]"
    echo "          или: bash $0 КОММЕНТАРИЙ_ПРАВИЛА --off ВЫХОД"
    exit 1; }
  [ "$OFF" = 1 ] && [ $# -ne 1 ] && die "с --off укажите ровно один выход"
  [[ "$COMMENT" =~ ^[A-Za-z0-9_-]{1,20}$ ]] || die "комментарий правила — латиница, цифры, - и _"
  [ "$(id -u)" -eq 0 ] || die "запустите от root"
  [ -f "$DB" ] || die "нет $DB"

  say "Правило «$COMMENT» в 3X-UI на $(hostname -s)"
  local TS BAK rc=0
  xui_db_backup pin

  systemctl stop x-ui
  python3 - "$DB" "$COMMENT" "$OFF" "$@" <<'PY' || rc=$?
import json, sqlite3, sys
path, comment, off, tags = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4:]
db = sqlite3.connect(path)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
obs = t.setdefault("outbounds", [])
r = t.setdefault("routing", {})
rules, bals = r.setdefault("rules", []), r.setdefault("balancers", [])

rule = next((x for x in rules if x.get("comment") == comment), None)
if rule is None:
    sys.exit("в 3X-UI нет правила с комментарием «%s» (есть: %s)" % (
        comment, ", ".join(x["comment"] for x in rules if x.get("comment")) or "ни одного"))
have = {o.get("tag") for o in obs}
miss = [x for x in tags if x not in have]
if miss:
    sys.exit("нет исходящих: %s (есть: %s)" % (", ".join(miss), ", ".join(
        sorted(x for x in have if x and not x.startswith("_bl_")))))

# убрать прежнюю цепочку этого правила
pre = comment + "-"
old_b = {b["tag"] for b in bals if b["tag"].startswith(pre)}
bals[:] = [b for b in bals if b["tag"] not in old_b]
obs[:] = [o for o in obs if not (o.get("protocol") == "loopback" and o.get("tag", "")[4:] in old_b)]
rules[:] = [x for x in rules if not any(str(i)[4:] in old_b for i in x.get("inboundTag") or [])]
rule.pop("balancerTag", None)

if off:
    rule["outboundTag"] = tags[0]
    print("CHAIN=" + tags[0] + " (напрямую, без резерва)")
else:
    names = ["%s%d-%s" % (pre, i, tag) for i, tag in enumerate(tags, 1)]
    for i, (name, tag) in enumerate(zip(names, tags)):
        nxt = "_bl_" + names[i + 1] if i + 1 < len(names) else ""
        bals.append({"tag": name, "selector": [tag], "fallbackTag": nxt})
    for name in names[1:]:
        obs.append({"tag": "_bl_" + name, "protocol": "loopback", "settings": {"inboundTag": "_bl_" + name}})
    # служебные правила петель — СТРОГО выше самого правила, иначе трафик зациклится
    def is_bl(x):
        return any(str(i).startswith("_bl_") for i in x.get("inboundTag") or [])
    rpos = rules.index(rule)
    after = [i for i, x in enumerate(rules) if is_bl(x) and i < rpos]
    pos = (max(after) + 1) if after else rpos
    rules[pos:pos] = [{"type": "field", "inboundTag": ["_bl_" + n], "balancerTag": n} for n in names[1:]]
    rule.pop("outboundTag", None)
    rule["balancerTag"] = names[0]
    # без проверки здоровья переключения не будет
    ob = t.get("burstObservatory") or t.get("observatory")
    if ob is None:
        print("WARN: нет observatory — резерв работать не будет")
    else:
        sel = ob.setdefault("subjectSelector", [])
        for tag in tags[:-1]:
            if tag not in sel:
                sel.append(tag)
    print("CHAIN=" + "  →  ".join(tags))
    assert rules.index(rule) > max(i for i, x in enumerate(rules) if is_bl(x) and (x.get("inboundTag") or [""])[0][4:] in names)

db.execute("update settings set value=? where key='xrayTemplateConfig'", (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit()
PY
  if [ "$rc" != 0 ]; then
    systemctl start x-ui
    die "3X-UI не изменена (ошибка выше)"
  fi
  xui_start_or_rollback "Xray перезапущен"
  python3 - "$DB" "$COMMENT" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
r = t["routing"]
rule = next(x for x in r["rules"] if x.get("comment") == sys.argv[2])
if rule.get("outboundTag"):
    print("  «%s» → %s (без резерва)" % (sys.argv[2], rule["outboundTag"])); sys.exit()
bals = {b["tag"]: b for b in r["balancers"]}
b, chain = bals.get(rule.get("balancerTag")), []
while b is not None and len(chain) < 20:
    chain.append(",".join(b["selector"]))
    b = bals.get((b.get("fallbackTag") or "")[4:])
print("  «%s»: %s" % (sys.argv[2], "  →  ".join(chain)))
PY
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then pin_main "$@"; fi
