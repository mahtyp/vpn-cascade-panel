#!/usr/bin/env bash
# Новый порядок основной цепочки резерва на входе («Протоколы» → «Схема», перетаскивание звеньев).
#
# Запуск на входе от root, рядом должны лежать vpn-add-exit.sh и vpn-restore.sh:
#   bash vpn-reorder.sh AWG-ExitA,Sudoku-ExitA,AWG-ExitB   — исходящие основной цепочки в новом порядке
#   CHECK=1 bash vpn-reorder.sh …                                     — только проверить, можно ли (ничего не меняет)
#
# Список — те же звенья, что сейчас, в другом порядке (ни добавить, ни убрать так нельзя — для этого «Связать»/«Отвязать»).
# Балансировщики остаются те же (Bal-N-…), меняется только кто за кем: fallbackTag и петли _bl_; общее правило
# и правило «DNS Xray через цепочку» ведут на новое первое звено. Отдельные цепочки (DC5TG, обходы) не трогаются.
# Не меняет ничего, если на средние звенья основной цепочки ссылаются свои правила (порядок поменял бы и их смысл).
# Перед изменением — копия базы 3X-UI; Xray не поднялся — база возвращается.

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ -f "$HERE/vpn-add-exit.sh" ] && [ -f "$HERE/vpn-restore.sh" ] \
  || { echo "Рядом должны лежать vpn-add-exit.sh и vpn-restore.sh" >&2; exit 1; }
# shellcheck source=vpn-add-exit.sh
source "$HERE/vpn-add-exit.sh"

reorder_main() {
  local ORDER=${1:-}
  [[ "$ORDER" =~ ^[A-Za-z0-9_.@:+-]{1,60}(,[A-Za-z0-9_.@:+-]{1,60}){1,39}$ ]] \
    || die "Использование: bash $0 ТЕГ1,ТЕГ2,…  (исходящие основной цепочки в новом порядке, не меньше двух)"
  [ "$(id -u)" = 0 ] || die "нужен root"
  [ -f "$DB" ] || die "нет 3X-UI ($DB)"
  local TS BAK rc=0
  say "1. Новый порядок цепочки: ${ORDER//,/ → }"
  [ "${CHECK:-0}" = 1 ] || { xui_db_backup reorder; systemctl stop x-ui; }
  CHECK="${CHECK:-0}" python3 - "$DB" "$ORDER" <<'PY' || rc=$?
import json, os, sqlite3, sys
path, want = sys.argv[1], sys.argv[2].split(",")
check = os.environ.get("CHECK") == "1"
db = sqlite3.connect(path)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
r = t.setdefault("routing", {})
rules, bals, obs = r.setdefault("rules", []), r.setdefault("balancers", []), t.setdefault("outbounds", [])
is_bl = lambda x: any(str(i).startswith("_bl_") for i in x.get("inboundTag") or [])
bal_by = {b["tag"]: b for b in bals}
main_rule = next((x for x in reversed(rules) if x.get("balancerTag") in bal_by and not is_bl(x)
                  and not x.get("ip") and not x.get("domain")), None)
if main_rule is None:
    sys.exit("нет основной цепочки (общее правило «всё остальное» не ведёт на балансировщик) — менять нечего")
head = bal_by[main_rule["balancerTag"]]
chain, b, seen = [], head, set()
while b is not None and b["tag"] not in seen:
    seen.add(b["tag"]); chain.append(b)
    b = bal_by.get((b.get("fallbackTag") or "")[4:])
cur = [(x.get("selector") or [""])[0] for x in chain]
if any(len(x.get("selector") or []) != 1 for x in chain):
    sys.exit("в цепочке есть звено с несколькими исходящими сразу — такой порядок панель не меняет")
if sorted(cur) != sorted(want) or len(set(want)) != len(want):
    sys.exit("список не совпадает с нынешней цепочкой (сейчас: %s) — обновите схему и попробуйте снова" % " → ".join(cur))
if cur == want:
    print("  порядок и так такой — ничего не меняю")
    sys.exit(0)
# правила (не петли _bl_) на средние звенья: при новом порядке их смысл поменяется — не трогаем
mid = {x["tag"] for x in chain[1:]}
odd = [x.get("comment") or x.get("balancerTag") for x in rules if not is_bl(x) and x.get("balancerTag") in mid]
if odd:
    sys.exit("на середину цепочки ведут свои правила (%s) — порядок не меняю" % ", ".join(map(str, odd)))
by_sel = {(x.get("selector") or [""])[0]: x for x in chain}
order = [by_sel[s] for s in want]
if check:
    print("  можно: было %s" % " → ".join(cur))
    sys.exit(0)
for i, x in enumerate(order):
    x["fallbackTag"] = "_bl_" + order[i + 1]["tag"] if i + 1 < len(order) else ""
    lb = "_bl_" + x["tag"]
    if i > 0 and not any(o.get("tag") == lb for o in obs):          # петля нужна каждому, кроме первого
        obs.append({"tag": lb, "protocol": "loopback", "settings": {"inboundTag": lb}})
        pos = max([k for k, y in enumerate(rules) if is_bl(y)] or [-1]) + 1
        rules.insert(pos, {"type": "field", "inboundTag": [lb], "balancerTag": x["tag"]})
new_head = order[0]
lb = "_bl_" + new_head["tag"]                                      # первому петля не нужна — убрать, чтобы не путала
rules[:] = [x for x in rules if x.get("inboundTag") != [lb]]
obs[:] = [o for o in obs if o.get("tag") != lb]
moved = 0
for x in rules:                                                   # общее правило, DNS Xray и всё, что вело на старое начало
    if not is_bl(x) and x.get("balancerTag") == head["tag"]:
        x["balancerTag"] = new_head["tag"]
        moved += 1
ob = t.get("burstObservatory") or t.get("observatory")
if ob is not None:                                                # наблюдатель — за всеми, у кого есть запасной
    sel = ob.setdefault("subjectSelector", [])
    for s in want[:-1]:
        if s not in sel:
            sel.append(s)
db.execute("update settings set value=? where key='xrayTemplateConfig'", (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit()
print("  было: %s" % " → ".join(cur))
print("  стало: %s (правил переведено на новое начало: %d)" % (" → ".join(want), moved))
PY
  if [ "$rc" != 0 ]; then
    [ "${CHECK:-0}" = 1 ] || { systemctl start x-ui; rm -f "$BAK"; }
    die "ничего не менял"
  fi
  if [ "${CHECK:-0}" = 1 ]; then ok "проверка пройдена, ничего не менял (CHECK=1)"; return 0; fi
  xui_start_or_rollback "Xray перезапущен с новым порядком цепочки"
  echo; echo "  Готово."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then reorder_main "$@"; fi
