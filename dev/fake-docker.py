#!/usr/bin/python3
"""Стенд: «docker» с контейнером Amnezia (amnezia-awg2) — чтобы проверить перевод выхода на AmneziaWG без Docker.
Включается вручную: sudo cp dev/fake-docker.py /usr/local/sbin/docker && sudo chmod +x /usr/local/sbin/docker.
Контейнер «живёт», пока есть /etc/testbed-docker.json; docker rm -f его убирает."""
import json
import os
import sys
import time

F = "/etc/testbed-docker.json"
a = sys.argv[1:]
st = json.load(open(F)) if os.path.exists(F) else {"containers": {}}
cs = st["containers"]

if a[:1] == ["ps"]:
    fmt = a[a.index("--format") + 1] if "--format" in a else "{{.Names}}"
    for n, c in cs.items():
        print(fmt.replace("{{.Names}}", n).replace("\\t", "\t").replace("{{.Ports}}", "0.0.0.0:%d->%d/udp" % (c["port"], c["port"])))
elif a[:1] == ["port"] and len(a) > 1 and a[1] in cs:
    print("%d/udp -> 0.0.0.0:%d" % (cs[a[1]]["port"], cs[a[1]]["port"]))
elif a[:1] == ["exec"] and len(a) > 2 and a[1] in cs:
    cmd = " ".join(a[2:])
    if "show all dump" in cmd:
        now = int(time.time())
        print("wg0\tPRIV\tPUB\t%d\toff" % cs[a[1]]["port"])
        print("wg0\tPHONE\t(none)\t10.20.30.40:5555\t10.8.1.2/32\t%d\t1000\t9000\t0" % (now - 3600))
    elif "clientsTable" in cmd:
        print('[{"clientId": "PHONE", "userData": {"clientName": "мой телефон"}}]')
elif a[:2] == ["rm", "-f"] and len(a) > 2:
    for n in a[2:]:
        if cs.pop(n, None) is not None:
            print(n)
    json.dump(st, open(F, "w"))
elif a[:1] == ["--version"]:
    print("Docker version 27.0.0 (стенд)")
else:
    sys.exit(0)
