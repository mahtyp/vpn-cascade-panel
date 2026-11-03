#!/usr/bin/env python3
"""Стенд: «DC Telegram» на 127.0.1.1…5:443 — отвечают на первый шаг MTProto (obfuscated2 + req_pq_multi) так же,
как настоящий DC: res_pq с тем же nonce. Поведение адреса задаёт /etc/testbed-mtproto.json:
{"127.0.1.5": "silent"} — порт открыт, но молчит (читается при каждом подключении).
Закрытый порт — любой адрес без слушателя, например 127.0.1.9."""
import json
import socket
import struct
import subprocess
import threading

IPS = ["127.0.1.%d" % i for i in range(1, 6)]


def ctr(key, iv, data):
    return subprocess.run(["openssl", "enc", "-aes-256-ctr", "-K", key.hex(), "-iv", iv.hex(), "-nosalt"],
                          input=data, capture_output=True, check=True).stdout


def mode(ip):
    try:
        return json.load(open("/etc/testbed-mtproto.json")).get(ip, "ok")
    except Exception:
        return "ok"


def recv(c, n):
    b = b""
    while len(b) < n:
        p = c.recv(n - len(b))
        if not p:
            raise OSError("closed")
        b += p
    return b


def serve(c, ip):
    try:
        c.settimeout(10)
        if mode(ip) != "ok":
            c.recv(1024)                      # молчим, пока клиент не сдастся
            return
        head = recv(c, 64)
        body = recv(c, 44)
        plain = ctr(head[8:40], head[40:56], head + body)
        if plain[56:60] != b"\xee" * 4 or plain[64 + 24:64 + 28] != bytes.fromhex("f18e7ebe"):
            return                            # не MTProto — настоящий DC тоже промолчит
        nonce = plain[64 + 28:64 + 44]
        rev = head[8:56][::-1]
        res = struct.pack("<I", 80) + b"\0" * 8 + struct.pack("<Q", 1) + struct.pack("<I", 80) + bytes.fromhex("63241605") + nonce
        c.sendall(ctr(rev[:32], rev[32:48], res))
        c.recv(16)
    except OSError:
        pass
    finally:
        c.close()


def listen(ip):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 443))
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c, ip), daemon=True).start()


for ip in IPS:
    threading.Thread(target=listen, args=(ip,), daemon=True).start()
threading.Event().wait()
