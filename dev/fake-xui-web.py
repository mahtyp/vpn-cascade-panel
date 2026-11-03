"""Стенд: «веб-панель 3X-UI». Берёт порт, адрес и путь из /etc/x-ui/x-ui.db, как настоящая.

Страница входа на секретном пути, вход ставит cookie, /panel/ без входа — редирект с абсолютным адресом
(так делает и настоящая), WebSocket-эхо на <путь>ws. Только для проверки панели каскада.
"""
import base64
import hashlib
import json
import sqlite3
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

st = dict(sqlite3.connect("/etc/x-ui/x-ui.db").execute("select key, value from settings").fetchall())
PORT = int(st.get("webPort") or 2053)
LISTEN = st.get("webListen") or "0.0.0.0"
BASE = "/" + (st.get("webBasePath") or "/").strip("/") + "/"
PAGE = """<!doctype html><meta charset=utf-8><title>3X-UI (стенд)</title><body style="font:16px sans-serif">
<h1 id=h>Вход в 3X-UI (стенд)</h1><button id=login>Войти</button> <span id=st></span>
<script>
document.getElementById("login").onclick = async () => {
  const r = await fetch("%(b)slogin", {method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"}, body: "username=admin&password=admin"});
  const j = await r.json(); document.getElementById("st").textContent = j.success ? "вошли" : "ошибка";
  if (j.success) location.href = "%(b)spanel/";
};
</script>""" % {"b": BASE}
PANEL = """<!doctype html><meta charset=utf-8><title>3X-UI (стенд)</title><body style="font:16px sans-serif">
<h1>Панель 3X-UI (стенд)</h1><div id=ws>ws: …</div><div id=host>Host: %s</div>
<script>
const w = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "%sws");
w.onopen = () => w.send("привет"); w.onmessage = (e) => { document.getElementById("ws").textContent = "ws: " + e.data; };
</script>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="text/html; charset=utf-8", extra=()):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        return "3x-ui=ok" in (self.headers.get("Cookie") or "")

    def do_GET(self):
        p = self.path.split("?")[0]
        if not p.startswith(BASE):
            return self.reply(404, "404 page not found", "text/plain")
        rest = p[len(BASE):]
        if rest == "":
            return self.reply(200, PAGE)
        if rest == "panel/":
            if not self.authed():
                return self.reply(307, "", extra=[("Location", "http://%s%s" % (self.headers.get("Host"), BASE))])
            return self.reply(200, PANEL % (self.headers.get("Host"), BASE))
        if rest == "ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            if not self.authed():
                return self.reply(401, "нет входа", "text/plain")
            acc = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", acc.decode())
            self.end_headers()
            h = self.rfile.read(2)
            n = h[1] & 127
            if n == 126:
                n = struct.unpack(">H", self.rfile.read(2))[0]
            mask = self.rfile.read(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(self.rfile.read(n)))
            msg = ("эхо: " + data.decode("utf-8")).encode("utf-8")
            self.wfile.write(bytes([0x81, len(msg)]) + msg)
            self.close_connection = True
            return
        return self.reply(404, "404 page not found", "text/plain")

    def do_POST(self):
        p = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        if p == BASE + "login":
            return self.reply(200, json.dumps({"success": True}), "application/json",
                              [("Set-Cookie", "3x-ui=ok; Path=%s; HttpOnly; Secure; SameSite=Lax" % BASE)])
        return self.reply(404, "404 page not found", "text/plain")


ThreadingHTTPServer((LISTEN, PORT), H).serve_forever()
