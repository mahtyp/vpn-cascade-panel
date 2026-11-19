#!/usr/bin/env python3
"""Стенд: «sudoku» и «sudoku-sing-box» (по имени файла). Только слушают TCP-порт из конфига — по-настоящему
ничего не проксируют (каналы на стенде отвечает заглушка curl). sudoku -test проверяет конфиг;
/etc/testbed-sudoku-bad — «новая версия не принимает конфиг»."""
import json
import os
import socket
import sys
import time

a = sys.argv[1:]
singbox = os.path.basename(sys.argv[0]) == "sudoku-sing-box"
if "-h" in a or not a:
    print("Usage of sudoku: -c config -test"); sys.exit(0)
conf = a[a.index("-c") + 1] if "-c" in a else ""
try:
    c = json.load(open(conf))
    port = c["inbounds"][0]["listen_port"] if singbox else c["local_port"]
    if not singbox and not c.get("key"):
        raise ValueError("no key")
except Exception as e:
    print("config error:", e); sys.exit(1)
if "-test" in a:
    if os.path.exists("/etc/testbed-sudoku-bad"):
        print("config error: unknown field httpmask.multiplex"); sys.exit(1)
    print("configuration OK"); sys.exit(0)
try:
    s = socket.socket(socket.AF_INET6)
    s.bind(("::", int(port)))
except OSError:                     # нет IPv6 (как в контейнере стенда)
    s = socket.socket(socket.AF_INET)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(port)))
s.listen()
while True:
    time.sleep(3600)
