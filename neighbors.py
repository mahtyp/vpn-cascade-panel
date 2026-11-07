"""«Шумные соседи»: кто ещё живёт в подсети /24 сервера и чьи TLS-сертификаты там показывают.

Проверка идёт с этого компьютера: по одному разу на порт 443 к каждому адресу /24 сервера (без имени сайта,
как сканеры ТСПУ) — и смотрит, на какие имена выдан сертификат. Сертификат известного сайта (Google, Microsoft, VK, Max…) на адресе
хостера — почти наверняка VLESS Reality, который маскируется под этот сайт: такой же VPN, как наш. Чем их
больше, тем «шумнее» подсеть: ТСПУ такие замечает и может закрыть её целиком.
Настоящий сайт соседа — когда DNS его имени (через DoH 1.1.1.1) указывает именно на этот адрес. Такие с TLS 1.3 и
h2 — лучшие кандидаты для маскировки Reality: сайт по соседству, а не «гугл у хостера».
С сервера только читается, под какой сайт маскируется Reality (база 3X-UI), и открывается ли этот сайт оттуда
(reality_script → probe.reality_mask). Ничего не меняет.
"""
import json
import re
from jsonline import last_json

def reality_script():
    """Скрипт для сервера: под какой сайт маскируется Reality и открывается ли он оттуда (probe.reality_mask)."""
    from pathlib import Path
    src = (Path(__file__).with_name("probe.py")).read_text(encoding="utf-8")
    m = re.search(r"^def reality_mask\(.*?(?=^\S)", src, re.M | re.S)
    return ("import json, re, socket, sqlite3, time\n" + m.group(0).rstrip()
            + "\n\nprint(json.dumps({'reality': reality_mask()}, ensure_ascii=False))\n")


def _der_len(b, i):
    n = b[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    return int.from_bytes(b[i + 1:i + 1 + k], "big"), i + 1 + k


def _der_names(der):
    """Запасной разбор сертификата без библиотек: CN владельца (последний CN в TBS — после издателя) и DNS из SAN."""
    cn, san = [], []
    i = 0
    while True:
        i = der.find(b"\x06\x03\x55\x04\x03", i)
        if i < 0:
            break
        j = i + 5
        if j < len(der) and der[j] in (0x0C, 0x13, 0x16, 0x14):
            n, k = _der_len(der, j + 1)
            cn.append(der[k:k + n].decode("utf-8", "replace"))
        i = j
    i = der.find(b"\x06\x03\x55\x1d\x11")
    if i >= 0:
        j = i + 5
        if der[j] == 0x01:            # critical
            j += 3
        if der[j] == 0x04:            # OCTET STRING → SEQUENCE
            _, j = _der_len(der, j + 1)
            if der[j] == 0x30:
                n, j = _der_len(der, j + 1)
                end = j + n
                while j < end:
                    t = der[j]
                    m, k = _der_len(der, j + 1)
                    if t == 0x82:
                        san.append(der[k:k + m].decode("ascii", "replace"))
                    j = k + m
    return cn[-1:], san, cn[:1]


def cert_names(der):
    import os
    import ssl
    import tempfile
    try:
        fd, p = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(ssl.DER_cert_to_PEM_cert(der))
            c = ssl._ssl._test_decode_cert(p)
        finally:
            os.unlink(p)
        cn = [v for rdn in c.get("subject", ()) for k, v in rdn if k == "commonName"]
        san = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
        iss = [v for rdn in c.get("issuer", ()) for k, v in rdn if k in ("organizationName", "commonName")]
        return cn, san, iss[:1]
    except Exception:  # noqa: BLE001
        try:
            return _der_names(der)
        except Exception:  # noqa: BLE001
            return [], [], []


def _hello(ip, sni=None, verify=False, timeout=4):
    import socket
    import ssl
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((ip, 443), timeout=3) as s:
        s.settimeout(timeout)
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            return t.version(), t.selected_alpn_protocol(), t.getpeercert(binary_form=True)


def _scan_one(ip):
    import socket
    try:
        socket.create_connection((ip, 443), timeout=3).close()
    except OSError:
        return None                       # 443 закрыт или адреса нет
    h = {"ip": ip}
    try:
        ver, alpn, der = _hello(ip)
        h.update(tls=ver, alpn=alpn)
        if der:
            h["cn"], h["san"], h["issuer"] = cert_names(der)
    except Exception as e:  # noqa: BLE001
        h["err"] = type(e).__name__
    return h


def _resolve(name):
    """A-записи имени: DoH 1.1.1.1 (как видит мир), иначе DNS этого компьютера."""
    import socket
    import urllib.request
    try:
        rq = urllib.request.Request("https://1.1.1.1/dns-query?name=%s&type=A" % name, headers={"Accept": "application/dns-json"})
        j = json.loads(urllib.request.urlopen(rq, timeout=6).read().decode())
        if j.get("Status") == 0:
            return [a["data"] for a in j.get("Answer") or [] if a.get("type") == 1]
    except Exception:  # noqa: BLE001
        pass
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except Exception:  # noqa: BLE001
        return []


def scan(ip, log=None):
    """Проверка /24 с этого компьютера: 443 у каждого адреса, сертификат без имени сайта, DNS имён, кандидаты Reality."""
    import concurrent.futures as cf
    import ipaddress
    import time
    t0 = time.time()
    net = ipaddress.ip_network(ip + "/24", strict=False)
    log = log or (lambda s: None)
    log("подсеть %s: стучусь на 443 к %d адресам…" % (net, net.num_addresses - 2))
    with cf.ThreadPoolExecutor(48) as ex:
        hosts = [h for h in ex.map(_scan_one, [str(a) for a in net.hosts()]) if h]
    log("ответили на 443: %d" % len(hosts))
    names = sorted({n[2:] if n.startswith("*.") else n for h in hosts for n in (h.get("san") or h.get("cn") or [])
                    if re.match(r"^[A-Za-z0-9*.-]+\.[A-Za-z]{2,}$", n)})[:150]
    with cf.ThreadPoolExecutor(16) as ex:
        dns = dict(zip(names, ex.map(_resolve, names)))
    for h in hosts:
        h["own"] = sorted({n[2:] if n.startswith("*.") else n for n in h.get("san") or h.get("cn") or []
                           if h["ip"] in dns.get(n[2:] if n.startswith("*.") else n, [])})
    cands = [h for h in hosts if h["own"] and h["ip"] != ip][:20]

    def fit(h):   # подойдёт ли сайт соседа для Reality: настоящий сертификат на это имя, TLS 1.3, h2
        n = next((x for x in h["own"] if not x.startswith("*")), h["own"][0])
        try:
            ver, alpn, _ = _hello(h["ip"], n, verify=True)
            h["fit"] = {"name": n, "tls": ver, "alpn": alpn, "ok": ver == "TLSv1.3" and alpn == "h2"}
        except Exception as e:  # noqa: BLE001
            h["fit"] = {"name": n, "err": type(e).__name__, "ok": False}
    with cf.ThreadPoolExecutor(10) as ex:
        list(ex.map(fit, cands))
    return {"ip": ip, "net": str(net), "hosts": hosts, "total": net.num_addresses - 2, "secs": round(time.time() - t0, 1)}


# Крупные сайты, которые на адресах обычных хостеров не живут: их сертификат у соседа — маскировка Reality.
# Совпадение — по окончанию имени.
BRANDS = {
    "Google": ["google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com", "ytimg.com", "gvt1.com", "dl.google.com", "android.com"],
    "Microsoft": ["microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "bing.com", "azure.com", "msn.com", "xbox.com", "skype.com", "outlook.com"],
    "Apple": ["apple.com", "icloud.com", "itunes.apple.com", "mzstatic.com", "cdn-apple.com"],
    "Amazon": ["amazon.com", "amazonaws.com", "cloudfront.net", "media-amazon.com", "primevideo.com"],
    "Cloudflare": ["cloudflare.com", "one.one.one.one", "cloudflare-dns.com"],
    "Meta": ["facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net", "meta.com"],
    "Telegram": ["telegram.org", "t.me", "telegram.me"],
    "VK": ["vk.com", "vk.ru", "userapi.com", "vkuser.net", "vk-portal.net", "mail.ru", "ok.ru", "mycdn.me", "vkvideo.ru"],
    "Max": ["max.ru", "oneme.ru"],
    "Яндекс": ["yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yastatic.net", "dzen.ru", "kinopoisk.ru"],
    "Сбер": ["sberbank.ru", "sber.ru", "sberbank.com"],
    "Госуслуги": ["gosuslugi.ru", "nalog.ru", "mos.ru"],
    "Крупные РФ": ["ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "rutube.ru", "x5.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru"],
    "Другие крупные": ["samsung.com", "nvidia.com", "intel.com", "amd.com", "oracle.com", "speedtest.net", "github.com", "githubusercontent.com",
                       "discord.com", "discord.gg", "twitter.com", "x.com", "twimg.com", "tiktok.com", "tiktokcdn.com", "spotify.com",
                       "steampowered.com", "steamcommunity.com", "twitch.tv", "netflix.com", "nflxvideo.net", "adobe.com",
                       "logitech.com", "dropbox.com", "zoom.us", "yahoo.com", "ebay.com", "paypal.com", "booking.com",
                       "lovelive-anime.jp", "addons.mozilla.org", "mozilla.org", "cdn.jsdelivr.net", "hp.com", "dell.com", "asus.com"],
}


# «имя из IP» (1-2-3-4.sslip.io и т. п.) — не сайт, для маскировки не годится
WILDCARD_DNS = re.compile(r"(^|\.)(sslip\.io|nip\.io|traefik\.me|localtest\.me|lvh\.me|xip\.io|nip\.direct)$|^\d+[-.]\d+[-.]\d+[-.]\d+\.", re.I)


def brand_of(name):
    n = (name or "").lower().lstrip("*.").rstrip(".")
    for b, sfx in BRANDS.items():
        if any(n == s or n.endswith("." + s) for s in sfx):
            return b
    return None


def host_names(h):
    return [n.lower() for n in (h.get("san") or h.get("cn") or [])]


def plural(n, one, few, many):
    n10, n100 = n % 10, n % 100
    return one if n10 == 1 and n100 != 11 else few if 2 <= n10 <= 4 and not 12 <= n100 <= 14 else many


def summarize(raw):
    """Ответ сервера → то, что показывает страница: шум (чужие сертификаты), настоящие сайты, кандидаты для
    маскировки Reality и как с этим наша маскировка."""
    if not raw or raw.get("error"):
        return {"error": (raw or {}).get("error") or "нет ответа"}
    me = raw.get("ip")
    hosts = [h for h in raw.get("hosts") or [] if h.get("ip") != me]
    foreign, genuine, other = [], [], []
    for h in hosts:
        names = host_names(h)
        b = next((brand_of(n) for n in names if brand_of(n)), None)
        row = {"ip": h["ip"], "name": (h.get("own") or names or [""])[0], "names": names[:6], "n": len(names), "tls": h.get("tls"),
               "alpn": h.get("alpn"), "brand": b, "issuer": (h.get("issuer") or [None])[0], "err": h.get("err")}
        if h.get("own"):
            f = h.get("fit") or {}
            row.update(fit=f.get("ok"), fit_why=None if f.get("ok") else (f.get("err") and "не открылся с именем" or
                       f.get("tls") != "TLSv1.3" and "нет TLS 1.3" or f.get("alpn") != "h2" and "нет h2" or None))
            genuine.append(row)
        elif b:
            foreign.append(row)
        else:
            other.append(row)
    brands = {}
    for r in foreign:
        brands[r["brand"]] = brands.get(r["brand"], 0) + 1
    tls_n = len(hosts)
    nf = len(foreign)
    level = "ok" if nf == 0 else "bad" if nf >= 10 or (tls_n and nf * 4 >= tls_n and nf >= 4) else "warn"
    notes = []

    def note(lv, text):
        notes.append({"level": lv, "text": text})
    top = ", ".join("%s ×%d" % kv for kv in sorted(brands.items(), key=lambda kv: -kv[1]))
    if nf:
        note(level, "%d %s сертификаты известных сайтов (%s) — почти наверняка такие же VPN с маскировкой "
                    "Reality. %s" % (nf, plural(nf, "сосед показывает", "соседа показывают", "соседей показывают"), top, "Подсеть «шумная»: ТСПУ замечает такие и может закрыть её целиком, вместе с вашим адресом"
                                     if level == "bad" else "Немного — обычное дело у популярных хостеров"))
    else:
        note("ok", "чужих сертификатов в подсети нет — по этому признаку подсеть тихая")
    fit = [r for r in genuine if r.get("fit") and not WILDCARD_DNS.search(r["name"] or "")]
    # наша маскировка
    import ipaddress
    mine = []
    try:
        net = ipaddress.ip_network(raw.get("net") or "", strict=False)
    except ValueError:
        net = None
    fit_txt = (" Подойдёт сайт соседа: " + ", ".join(r["name"] for r in fit[:3])) if fit else ""
    for rl in raw.get("reality") or []:
        if rl.get("skip"):
            continue
        names = [n.lower() for n in rl.get("names") or []] or ([rl["dest"].rsplit(":", 1)[0].lower()] if rl.get("dest") else [])
        inside = False
        if "ok" in rl:      # сервер сам попробовал открыть сайт маскировки (как его откроет Xray для чужих)
            sni = rl.get("sni") or (names or ["?"])[0]
            if not rl["ok"]:
                why = {"dns": "имени больше нет в DNS", "timeout": "сайт не отвечает", "refused": "сайт не принимает подключения",
                       "cert": "сертификат не на это имя или просрочен", "tls": "ошибка TLS", "net": "нет связи"}.get(rl.get("err"), "не открывается")
                note("bad", "Reality на порту %s маскируется под %s, но с сервера этот сайт сейчас не открывается (%s) — кто постучится "
                            "на порт, увидит ошибку вместо сайта, маскировки нет. Поменяйте в 3X-UI target и SNI на живой сайт.%s"
                     % (rl.get("port"), sni, why, fit_txt))
                mine.append({"port": rl.get("port"), "remark": rl.get("remark"), "name": sni, "dead": True, "err": rl.get("err")})
                continue
            if rl.get("tls") != "TLSv1.3" or rl.get("alpn") != "h2":
                note("warn", "Reality на порту %s маскируется под %s, а у него нет %s — Reality нужен сайт с TLS 1.3 и h2.%s"
                     % (rl.get("port"), sni, "TLS 1.3" if rl.get("tls") != "TLSv1.3" else "h2", fit_txt))
            try:
                inside = bool(net and rl.get("ip") and ipaddress.ip_address(rl["ip"]) in net)
            except ValueError:
                inside = False
            pub = rl.get("pub_ips")
            if pub is not None and rl.get("ip") and rl["ip"] not in pub:
                # сервер (через DNS хостера) ходит на один адрес, а весь мир видит имя на другом — сайт переехал или DNS подменён
                inside = False
                note("warn", "Reality на порту %s маскируется под %s — сайт открывается, но %s. Сервер (через DNS хостера) ходит "
                             "на %s, где пока отвечает его сертификат; маскировка работает, пока тот адрес жив, а проверка со стороны "
                             "по общему DNS увидит, что имя указывает не туда.%s"
                     % (rl.get("port"), sni, ("по общему DNS (1.1.1.1) его имя теперь указывает на %s" % ", ".join(pub[:3])) if pub
                        else "в общем DNS (1.1.1.1) этого имени больше нет", rl["ip"], fit_txt or " Спокойнее сменить на сайт соседа."))
                rl = dict(rl, _moved=True)
            if not inside and not brand_of(sni) and not rl.get("_moved"):
                note("warn", "Reality на порту %s маскируется под %s — сайт живой, но он не в вашей подсети (сейчас %s). "
                             "Проверка со стороны увидит, что сертификат %s показывает не его сервер.%s"
                     % (rl.get("port"), sni, rl.get("ip") or "?", sni, fit_txt or " Спокойнее — сайт соседа по подсети."))
        for n in names[:3]:
            b = brand_of(n)
            same = sum(1 for r in foreign if any(x == n or x.lstrip("*.") == n.split(".", 1)[-1] for x in r["names"]))
            near = inside or any(n in r["names"] or n == r["name"] for r in genuine)
            m = {"port": rl.get("port"), "remark": rl.get("remark"), "name": n, "brand": b, "same": same, "near": near}
            mine.append(m)
            if near:
                note("ok", "Reality на порту %s маскируется под %s — это настоящий сайт в вашей же подсети, лучше не бывает" % (rl.get("port"), n))
            elif b:
                note("warn", "Reality на порту %s маскируется под %s (%s), а адрес у хостера — при проверке видно, что сертификат "
                             "%s показывает не их сервер%s%s" % (rl.get("port"), n, b, n,
                                                                ("; так же маскируются ещё %d %s" % (same, plural(same, "сосед", "соседа", "соседей"))) if same else "",
                                                                "; спокойнее — сайт соседа из списка ниже" if fit else ""))
    return {"ip": me, "net": raw.get("net"), "total": raw.get("total"), "tls": tls_n, "level": level, "brands": brands,
            "foreign": foreign, "genuine": genuine, "other": other, "fit": [r["name"] for r in fit][:8], "mine": mine,
            "notes": notes, "secs": raw.get("secs")}


parse = last_json   # итог скрипта — последняя строка JSON (jsonline.py)


def public_ip(host):
    """Адрес сервера из панели → IPv4 для /24 (имя — через DNS этого ПК). Частный/непонятный — пусто: сервер узнает сам."""
    import ipaddress
    import socket
    try:
        ip = host if re.match(r"^\d+\.\d+\.\d+\.\d+$", host or "") else socket.gethostbyname(host)
        return "" if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback else ip
    except Exception:  # noqa: BLE001
        return ""
