#!/usr/bin/python3
"""Стенд: «ufw». Запоминает правила и включён ли в /etc/testbed-ufw.json, по-настоящему ничего не блокирует.
Если есть /etc/testbed-ufw-break — при включении «ломает» вход (останавливает фейковый Xray на 1935),
при выключении чинит: так проверяется откат."""
import json
import os
import subprocess
import sys

F = "/etc/testbed-ufw.json"
st = json.load(open(F)) if os.path.exists(F) else {"active": False, "added": []}
a = [x for x in sys.argv[1:] if x != "--force"]
XRAY = ("nohup /usr/local/x-ui/bin/xray-linux-srv -c 'import socket,time; s=socket.socket(); "
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"0.0.0.0\", 1935)); s.listen(); time.sleep(10**9)' "
        "</dev/null >/dev/null 2>&1 &")


def save():
    json.dump(st, open(F, "w"))


if a[:1] == ["status"]:
    print("Status: active\n\nTo                         Action      From\n--                         ------      ----" if st["active"] else "Status: inactive")
    for r in st["added"] if st["active"] else []:
        print(r[4:])
elif a[:2] == ["show", "added"]:
    print("Added user rules (see 'ufw status' for running firewall):")
    print("\n".join(st["added"]) if st["added"] else "(None)")
elif a[:1] == ["default"]:
    print("Default %s policy changed to '%s'" % (a[2], a[1]))
elif a[:1] == ["allow"] or a[:2] == ["route", "allow"]:
    r = "ufw " + " ".join(a)
    if r not in st["added"]:
        st["added"].append(r)
    save()
    print("Rules updated")
elif a[:1] == ["delete"]:
    r = "ufw " + " ".join(a[1:])
    if r in st["added"]:
        st["added"].remove(r)
        save()
        print("Rule deleted")
    else:
        print("Could not delete non-existent rule")
elif a[:1] == ["enable"]:
    st["active"] = True
    save()
    if os.path.exists("/etc/testbed-ufw-break"):
        subprocess.run(["pkill", "-x", "xray-linux-srv"])
    print("Firewall is active and enabled on system startup")
elif a[:1] == ["disable"]:
    st["active"] = False
    save()
    if subprocess.run(["pgrep", "-x", "xray-linux-srv"], stdout=subprocess.DEVNULL).returncode:
        subprocess.run(XRAY, shell=True)
    print("Firewall stopped and disabled on system startup")
else:
    print("ufw (стенд): не знаю «%s»" % " ".join(a))
    sys.exit(1)
