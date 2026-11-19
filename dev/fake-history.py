#!/usr/bin/env python3
"""Стенд: история проверок каналов за сутки — чтобы «Перемотке» на схеме было что показать.
Запуск при работающей панели стенда: python3 dev/fake-history.py [порт]. Пишет в history.db панели стенда.
Сценарий: у Вход-A ночью падает AWG Выход-A, потом и Sudoku Выход-A (трафик уходит на Выход-B);
у «дополнительного входа» днём на полчаса нет ни одного пути; остальное работает."""
import json, re, sqlite3, sys, time, urllib.request
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8790
base = "http://127.0.0.1:%d/" % port
tok = re.search(r'const TOKEN = "([^"]+)"', urllib.request.urlopen(base).read().decode()).group(1)
req = urllib.request.Request(base + "api/state", headers={"X-Dash": tok})
st = json.loads(urllib.request.urlopen(req).read())
import os
db = sqlite3.connect(sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "stand", "app", "history.db"))
now = time.time()
def bad(eid, c, t):
    h = (t - (now - 86400)) / 3600          # часов от начала суток
    if eid == "en1" and c.get("tag") == "AWG-ExitA" and 3 <= h < 6:
        return True
    if eid == "en1" and c.get("tag") == "Sudoku-ExitA" and 4 <= h < 5:
        return True
    if eid == "aux1" and 10 <= h < 10.5:
        return True
    return False
db.execute("delete from samples where kind='ch' and ts >= ?", (now - 86400,))
n = 0
for eid, chans in (st.get("channels") or {}).items():
    for c in chans:
        t = now - 86400 + 60
        while t < now - 120:
            b = bad(eid, c, t)
            db.execute("insert into samples values(?,?,?,?,?)", (t, "ch", "%s:%s" % (eid, c["key"]), "bad" if b else "ok", None if b else 0.4 + (hash((eid, c["key"])) % 50) / 100))
            t += 300; n += 1
db.commit()
print("записано проверок:", n)
