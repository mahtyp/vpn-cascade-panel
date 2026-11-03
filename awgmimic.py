"""Пакеты-маски AmneziaWG (I1): перед рукопожатием туннель шлёт пакет, похожий на обычный трафик —
начало QUIC (как браузер к сайту), STUN (как звонок WebRTC) или DNS-запрос. ТСПУ видит в начале
соединения знакомый протокол, а не «непонятный шум».

Шлёт их только та сторона, что начинает соединение, — туннели wgN на входах; выходам ничего менять не нужно.
Формат строки — теги AmneziaWG: <b 0x…> — байты как есть, <r N> — N случайных байт (новые при каждой отправке).
Используем только <b> и <r>: их понимают все версии с 1.5. Формы пакетов — по RFC (QUIC 9000, STUN 8489,
DNS 1035), по образцу генератора из Vadim-Khristenko/awg-containers-and-tools (MIT); код свой.

APPLY_PY идёт на вход по кнопке с подтверждением: копия конфига → новые строки I1–I5 в [Interface] →
перезапуск awg-quick@wgN → ждём свежее рукопожатие (пинг .1 туннеля) → не поднялся — возвращаем копию.
"""
import json
import random
import re

PROFILES = {
    "quic": "QUIC — как браузер открывает сайт по HTTP/3 (так делает и AmneziaVPN по умолчанию)",
    "stun": "STUN — как начало звонка WebRTC (Telegram, WhatsApp, Meet): UDP на любых портах — обычное дело",
    "dns": "DNS — как запрос адреса сайта (короткий пакет)",
}
DNS_HOSTS = ["ya.ru", "vk.com", "mail.ru", "ok.ru", "gosuslugi.ru", "ozon.ru", "avito.ru", "dzen.ru", "rutube.ru", "sberbank.ru"]
IFACE_RE = re.compile(r"^wg\d{1,2}$")
I_RE = re.compile(r"^(<b 0x[0-9a-f]+>|<r \d{1,4}>)+$")


def _hex(b):
    return "<b 0x%s>" % bytes(b).hex()


def _rand(n):
    out = []
    while n > 0:
        k = min(n, 1000)
        out.append("<r %d>" % k)
        n -= k
    return "".join(out)


def quic(rng):
    """QUIC v1 Initial (RFC 9000 §17.2.2): длинный заголовок, версия 1, случайные ID соединения,
    без токена, длина — 2-байтовый varint; добито до 1200–1250 байт, как настоящие Initial."""
    pn_len = rng.randint(1, 4)
    dcid, scid = rng.randint(8, 20), rng.randint(0, 20)
    total = rng.randint(1200, 1250)
    head = 1 + 4 + 1 + dcid + 1 + scid + 1 + 2          # без самих ID: они — <r>
    rest = total - head                                  # номер пакета + «зашифрованное»
    parts = [_hex([0xc0 | (pn_len - 1), 0, 0, 0, 1, dcid]), _rand(dcid), _hex([scid]), _rand(scid) if scid else "",
             _hex([0x00, 0x40 | (rest >> 8), rest & 0xff]), _rand(rest)]
    return "".join(p for p in parts if p)


def stun(rng):
    """STUN Binding Request (RFC 8489) как у ICE-проверки WebRTC: USERNAME, PRIORITY, ICE-CONTROLLING,
    USE-CANDIDATE, MESSAGE-INTEGRITY, FINGERPRINT; transaction id и подписи — случайные при каждой отправке."""
    def attr(t, val_len, static=None):
        pad = (4 - val_len % 4) % 4
        head = [t >> 8, t & 0xff, val_len >> 8, val_len & 0xff]
        if static is not None:
            return _hex(head + list(static) + [0] * pad), 4 + val_len + pad
        return _hex(head) + (_rand(val_len) if val_len else "") + (_hex([0] * pad) if pad else ""), 4 + val_len + pad
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    user = ("".join(rng.choice(letters) for _ in range(rng.choice([4, 8]))) + ":" +
            "".join(rng.choice(letters) for _ in range(rng.choice([4, 8])))).encode()
    attrs = [attr(0x0006, len(user), user), attr(0x0024, 4), attr(0x802a, 8), attr(0x0025, 0, b""),
             attr(0x0008, 20), attr(0x8028, 4)]
    length = sum(n for _, n in attrs)
    return _hex([0x00, 0x01, length >> 8, length & 0xff, 0x21, 0x12, 0xa4, 0x42]) + _rand(12) + "".join(a for a, _ in attrs)


def dns(rng):
    """DNS-запрос A (RFC 1035): id случайный, рекурсия, один вопрос про популярный сайт."""
    host = rng.choice(DNS_HOSTS)
    q = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\0" + bytes([0, 1, 0, 1])
    return _rand(2) + _hex(bytes([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]) + q)


def generate(profile, seed=None):
    """Строки для [Interface]: {"I1": "..."}. Каждый вызов — новые числа (свой отпечаток у каждого туннеля)."""
    rng = random.Random(seed)
    fn = {"quic": quic, "stun": stun, "dns": dns}[profile]
    v = fn(rng)
    assert I_RE.match(v), v
    return {"I1": v}


def size(v):
    """Сколько байт будет в пакете."""
    return sum(len(m) // 2 for m in re.findall(r"<b 0x([0-9a-f]+)>", v)) + sum(int(n) for n in re.findall(r"<r (\d+)>", v))


APPLY_PY = r'''
import json, os, re, shutil, subprocess, time
D = "/etc/amnezia/amneziawg"
res = {"ok": False, "log": []}
def log(s):
    res["log"].append(s)
def sh(cmd, t=40):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
    return r.returncode, (r.stdout + r.stderr).strip()
def handshake(iface):
    rc, out = sh("awg show %s latest-handshakes" % iface, 10)
    ts = [int(x) for x in re.findall(r"\s(\d+)\s*$", out, re.M)]
    return max(ts) if ts else 0
def alive(iface, gw, t0, wait=40):
    end = time.time() + wait
    while time.time() < end:
        if gw:
            sh("ping -c1 -W1 -I %s %s" % (iface, gw), 5)
        if handshake(iface) >= t0:
            return True
        time.sleep(2)
    return False
def restart(iface):
    rc, out = sh("systemctl restart awg-quick@%s" % iface, 60)
    if rc:
        log("перезапуск: " + out[-300:])
    return rc == 0
conf = os.path.join(D, IFACE + ".conf")
try:
    txt = open(conf).read()
    lines = txt.splitlines()
    sect, out, ins = None, [], None
    for l in lines:
        m = re.match(r"^\s*\[(\w+)\]", l)
        if m:
            sect = m.group(1).lower()
        if sect == "interface" and re.match(r"^\s*I[1-5]\s*=", l):
            continue
        out.append(l)
        if sect == "interface" and re.match(r"^\s*[A-Za-z0-9]+\s*=", l):
            ins = len(out)
    if ins is None:
        raise RuntimeError("в конфиге нет раздела [Interface]")
    out[ins:ins] = ["%s = %s" % (k, v) for k, v in sorted(LINES.items())]
    new = "\n".join(out) + "\n"
    a = re.search(r"^\s*Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.\d+", txt, re.M)
    gw = "%s.%s.%s.1" % a.groups() if a else ""
    bak = conf + ".before-mimic-" + time.strftime("%Y-%m-%d_%H%M%S")
    shutil.copy2(conf, bak)
    log("копия конфига: " + bak)
    if new == txt:
        log("конфиг уже такой — ничего не меняю")
        res["ok"] = True
    else:
        with open(conf + ".tmp", "w") as f:
            f.write(new)
        os.chmod(conf + ".tmp", 0o600)
        os.replace(conf + ".tmp", conf)
        log("пакеты-маски " + (", ".join(sorted(LINES)) + " записаны" if LINES else "убраны") + " — перезапускаю " + IFACE)
        t0 = int(time.time())
        if restart(IFACE) and alive(IFACE, gw, t0):
            log("туннель поднялся, рукопожатие свежее — выход нас узнал")
            res["ok"] = True
        else:
            log("туннель не поднялся за 40 с — возвращаю прежний конфиг")
            shutil.copy2(bak, conf)
            t1 = int(time.time())
            res["rolled_back"] = restart(IFACE) and alive(IFACE, gw, t1)
            log("прежний конфиг вернул, туннель " + ("снова работает" if res["rolled_back"] else "НЕ поднялся — проверьте вручную"))
except Exception as e:
    res["error"] = str(e)[:300]
print(json.dumps(res, ensure_ascii=False))
'''


def apply_script(iface, lines):
    """Текст для python3 - на входе. lines — {"I1": "..."} или {} (убрать маски)."""
    if not IFACE_RE.match(iface or ""):
        raise ValueError("странный туннель: %r" % iface)
    for k, v in (lines or {}).items():
        if k not in ("I1", "I2", "I3", "I4", "I5") or not I_RE.match(v):
            raise ValueError("странная строка %s" % k)
    return "IFACE = %r\nLINES = %s\n" % (iface, json.dumps(lines or {})) + APPLY_PY
