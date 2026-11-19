#!/usr/bin/env python3
"""Проверка реальной перестановки AWG/Sudoku в ТОЛЬКО фиктивной 3X-UI на CI-стенде."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "server-scripts" / "vpn-reorder.sh"
DB = Path("/etc/x-ui/x-ui.db")

def template():
    with sqlite3.connect(DB) as db:
        row = db.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
    return json.loads(row[0])

def order(t):
    routing = t["routing"]
    bals = {b["tag"]: b for b in routing["balancers"]}
    rule = next((x for x in reversed(routing["rules"])
                 if x.get("balancerTag") in bals
                 and not x.get("domain") and not x.get("ip")
                 and not any(str(i).startswith("_bl_") for i in (x.get("inboundTag") or []))), None)
    assert rule is not None, "Не найдено основное правило"
    seen, cur, tag = set(), [], rule["balancerTag"]
    while tag and tag not in seen:
        seen.add(tag)
        b = bals[tag]
        cur.append(b["selector"][0])
        tag = (b.get("fallbackTag") or "")[4:]
    return cur

def canonical(t):
    """Служебные _bl_ правила и loopback-исходящие независимы и могут менять порядок."""
    import copy
    x = copy.deepcopy(t)
    obs = x.get("outbounds", [])
    loops = [o for o in obs if o.get("protocol") == "loopback"
             and str(o.get("tag") or "").startswith("_bl_")]
    x["outbounds"] = [o for o in obs if o not in loops] + sorted(
        loops, key=lambda o: o.get("tag") or "")
    rules = x["routing"].get("rules") or []
    is_service = lambda r: bool(r.get("inboundTag")) and all(
        str(i).startswith("_bl_") for i in r["inboundTag"])
    svc = [r for r in rules if is_service(r)]
    x["routing"]["rules"] = sorted(svc, key=lambda r: json.dumps(r, sort_keys=True)) + [
        r for r in rules if not is_service(r)]
    return x


def cmd(new_order, dry=False):
    env = dict(os.environ, CHECK="1" if dry else "0")
    p = subprocess.run(["bash", str(SCRIPT), ",".join(new_order)],
                       env=env, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120)
    if p.returncode:
        raise AssertionError("reorder failed (%s): %s" % (
            "dry" if dry else "apply", (p.stdout + p.stderr)[-1300:]))

def main():
    if os.geteuid() != 0 or not Path("/etc/x-ui/.testbed").exists():
        raise SystemExit("Этот тест разрешён только от root на фиктивном dev/testbed.sh")
    original = template()
    old = order(original)
    assert old == ["AWG-ExitA", "Sudoku-ExitA", "AWG-ExitB",
                   "Sudoku-ExitB", "AWG-ExitC", "Sudoku-ExitC"], "Неожиданная исходная схема"
    changed = [old[1], old[0]] + old[2:]

    cmd(changed, dry=True)
    assert template() == original, "CHECK=1 изменил базу!"
    print("PASS: CHECK=1 не изменяет SQL-конфигурацию")

    try:
        cmd(changed)
        assert order(template()) == changed, "Новый порядок не применён"
        print("PASS: применена перестановка основного AWG/Sudoku")
    finally:
        if order(template()) != old:
            cmd(old)
    assert order(template()) == old, "Исходный порядок не восстановлен"
    assert canonical(template()) == canonical(original), (
        "После возврата изменились содержимое правил или пользовательский порядок маршрутов")
    print("PASS: исходный порядок и маршрутизация восстановлены (порядок независимых _bl_ записей несущественен)")

if __name__ == "__main__":
    main()
