"""Удалённый доступ к панели (через Tailscale): вход по паролю и одноразовому коду, сессии, защита от подбора.

Панель для удалённого доступа слушает ОТДЕЛЬНЫЙ порт на 127.0.0.1 (обычно 8788). Снаружи до него можно
добраться только через `tailscale serve --bg 8788` — то есть только с устройств вашей сети Tailscale.
Всё, что приходит на этот порт, считается удалённым и требует входа; обычный порт 8787 работает как раньше.
"""
import base64
import hashlib
import hmac
import html
import secrets
import struct
import threading
import time

SESSION_IDLE = 12 * 3600          # без действий — выход через 12 часов
SESSION_MAX = 7 * 24 * 3600       # и в любом случае через неделю
FAIL_WINDOW = 15 * 60             # подбор: не больше 5 ошибок за 15 минут, потом пауза
FAIL_LIMIT = 5
COOKIE = "dash_s"


# ------------------------------------------------------------------ пароль и одноразовые коды

def hash_password(pw, salt=None, n=200_000):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, n)
    return "pbkdf2$%d$%s$%s" % (n, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(pw, stored):
    try:
        _, n, salt, dk = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), base64.b64decode(salt), int(n))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, AttributeError):
        return False


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def totp_match(secret, code, now=None, last_used=-1):
    """Номер 30-секундного окна, если код подходит (±1 окно на расхождение часов), иначе None.
    Код из уже использованного окна повторно не принимается."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6 or not secret:
        return None
    t = int((now or time.time()) // 30)
    for c in (t, t - 1, t + 1):
        if c > last_used and hmac.compare_digest(totp(secret, c), code):
            return c
    return None


def otpauth_uri(secret, label="Панель каскада"):
    from urllib.parse import quote
    return "otpauth://totp/%s?secret=%s&issuer=%s&digits=6&period=30" % (quote(label), secret, quote("vpn-dash"))


# ------------------------------------------------------------------ сессии и подбор

class Sessions:
    def __init__(self):
        self.lock = threading.Lock()
        self.items = {}           # token -> {created, last, who, ip}
        self.fails = []           # время неудачных попыток входа
        self.last_counter = -1    # последний принятый одноразовый код (окно)

    def new(self, who, ip):
        tok = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.items[tok] = {"created": now, "last": now, "who": who, "ip": ip}
        return tok

    def get(self, tok):
        if not tok:
            return None
        now = time.time()
        with self.lock:
            s = self.items.get(tok)
            if not s:
                return None
            if now - s["last"] > SESSION_IDLE or now - s["created"] > SESSION_MAX:
                self.items.pop(tok, None)
                return None
            s["last"] = now
            return s

    def drop(self, tok=None):
        with self.lock:
            if tok is None:
                self.items.clear()
            else:
                self.items.pop(tok, None)

    def list(self):
        now = time.time()
        with self.lock:
            return [{"id": hashlib.sha256(t.encode()).hexdigest()[:8], "who": s["who"], "ip": s["ip"],
                     "created": s["created"], "last": s["last"]}
                    for t, s in self.items.items() if now - s["last"] <= SESSION_IDLE]

    def drop_by_id(self, sid):
        with self.lock:
            for t in list(self.items):
                if hashlib.sha256(t.encode()).hexdigest()[:8] == sid:
                    self.items.pop(t)

    def blocked_for(self):
        """Сколько секунд ещё ждать после серии неудачных попыток (0 — можно пробовать)."""
        now = time.time()
        with self.lock:
            self.fails = [t for t in self.fails if now - t < FAIL_WINDOW]
            if len(self.fails) >= FAIL_LIMIT:
                return int(FAIL_WINDOW - (now - self.fails[0])) + 1
            return 0

    def fail(self):
        with self.lock:
            self.fails.append(time.time())


def cookie_of(headers):
    for part in (headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE:
            return v
    return ""


def set_cookie(tok, max_age=SESSION_MAX):
    return "%s=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=%d" % (COOKIE, tok, max_age)


# ------------------------------------------------------------------ страница входа

LOGIN_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход — панель каскада</title>
<style>
:root{color-scheme:dark;--bg:#000000;--surface:#181818;--border:#313131;--text:#EDEDED;--muted:#A1A1A1;--accent:#588EE4;--accent-2:#73A0E8;--bad:#E3635F}
*{box-sizing:border-box}body{margin:0;min-height:100dvh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);
font-family:'Golos Text',system-ui,'Segoe UI',sans-serif;font-size:14px;line-height:20px;padding:16px;-webkit-font-smoothing:antialiased}
form{width:min(380px,100%);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;display:flex;flex-direction:column;gap:16px}
h1{margin:0 0 4px;font-size:20px;line-height:28px;font-weight:600;letter-spacing:-.015em}p{margin:0;color:var(--muted);font-size:14px;line-height:20px}
label{display:flex;flex-direction:column;gap:8px;font-size:12px;line-height:16px;color:var(--muted)}
input{font:inherit;font-size:14px;padding:8px 12px;min-height:40px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text)}
input:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:transparent}
button{font:inherit;font-weight:600;min-height:40px;padding:8px 12px;border:1px solid var(--accent);border-radius:8px;background:var(--accent);color:#0A0A0A;cursor:pointer;transition:background-color .3s cubic-bezier(.22,1,.36,1),transform .2s cubic-bezier(.22,1,.36,1)}
button:hover{background:var(--accent-2)}button:active{transform:scale(.98)}
.err{color:var(--bad);font-size:14px}
</style></head><body>
<form method="post" action="/login" autocomplete="off">
<h1>Панель каскада</h1><p>Удалённый вход. Пароль задан на домашнем компьютере, код — из приложения-аутентификатора.</p>
{{err}}
<label>Пароль<input type="password" name="password" required autofocus></label>
<label>Код из приложения<input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required placeholder="123456"></label>
<button type="submit">Войти</button>
</form></body></html>"""


def login_page(err=""):
    e = '<div class="err">%s</div>' % html.escape(err) if err else ""
    return LOGIN_HTML.replace("{{err}}", e).encode("utf-8")
