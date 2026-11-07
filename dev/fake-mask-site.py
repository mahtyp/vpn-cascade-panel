#!/usr/bin/env python3
"""Стенд: «сайт маскировки» Reality — mask.testbed на 127.0.1.20:443 (TLS 1.3, h2, сертификат от CA стенда).
/etc/testbed-mask-dead есть — «сайт пропал»: соединение сразу закрывается (проверка покажет ошибку)."""
import os
import socket
import ssl
import threading

D = "/etc/testbed-mask"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(D + "/site.crt", D + "/site.key")
ctx.set_alpn_protocols(["h2", "http/1.1"])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.1.20", 443))
srv.listen(32)


def serve(c):
    try:
        if os.path.exists("/etc/testbed-mask-dead"):
            return
        with ctx.wrap_socket(c, server_side=True) as t:
            t.settimeout(5)
            t.recv(1)
    except Exception:
        pass
    finally:
        c.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
