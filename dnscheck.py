"""DNS на сервере: какие публичные DNS отвечают (обычный UDP, зашифрованные DoH и DoT) и подменяют ли ответы
DNS хостера и обычные запросы к 1.1.1.1 / 8.8.8.8 (по образцу проверки DNS в vernette/censorcheck, MIT; код свой).

DNS_PY идёт на сервер через `python3 -`: только запросы, ничего не меняет. Зашифрованные — с проверкой сертификата
на имя сервиса (cloudflare-dns.com и т. п.): чужой сертификат = кто-то влез посередине. Подмену видно, сравнивая ответ
с ответом через работающий DoH по адресам, которые в РФ заблокированы.
"""
from jsonline import last_json

RESOLVERS = [  # имя, адрес, имя в сертификате
    ("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
    ("Google", "8.8.8.8", "dns.google"),
    ("Quad9", "9.9.9.9", "dns.quad9.net"),
    ("AdGuard", "94.140.14.14", "dns.adguard-dns.com"),
    ("Яндекс", "77.88.8.8", "common.dot.dns.yandex.net"),
]
TEST_DOMAINS = ["rutracker.org", "flibusta.is", "linkedin.com"]   # заблокированы в РФ — их и подменяют

DNS_PY = r'''
import base64, concurrent.futures as cf, ipaddress, json, os, random, re, socket, ssl, struct, subprocess, time

def query(name, qid):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)

def skip(b, i):
    while True:
        n = b[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1

def parse(b):
    """Ответ DNS → (rcode, [IPv4])."""
    qid, fl, qd, an, ns, ar = struct.unpack(">HHHHHH", b[:12])
    i = 12
    for _ in range(qd):
        i = skip(b, i) + 4
    ips = []
    for _ in range(an):
        i = skip(b, i)
        t, c, ttl, ln = struct.unpack(">HHIH", b[i:i + 10])
        i += 10
        if t == 1 and ln == 4:
            ips.append(socket.inet_ntoa(b[i:i + 4]))
        i += ln
    return fl & 0xF, ips

def udp(ip, name, tries=2):
    for _ in range(tries):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            qid = random.randint(1, 65535)
            s.sendto(query(name, qid), (ip, 53))
            while True:
                b, _ = s.recvfrom(4096)
                if len(b) >= 12 and struct.unpack(">H", b[:2])[0] == qid:
                    return parse(b)
        except OSError:
            pass
        finally:
            s.close()
    return None

def tls(ip, host, port):
    ctx = ssl.create_default_context()
    raw = socket.create_connection((ip, port), timeout=4)
    raw.settimeout(5)
    return ctx.wrap_socket(raw, server_hostname=host)

def dot(ip, host, name):
    with tls(ip, host, 853) as t:
        q = query(name, random.randint(1, 65535))
        t.sendall(struct.pack(">H", len(q)) + q)
        b = b""
        while len(b) < 2:
            p = t.recv(2 - len(b))
            if not p:
                raise OSError("closed")
            b += p
        n = struct.unpack(">H", b)[0]
        b = b""
        while len(b) < n:
            p = t.recv(n - len(b))
            if not p:
                raise OSError("closed")
            b += p
        return parse(b)

def doh(ip, host, name):
    q = query(name, 0)
    req = ("POST /dns-query HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
           "Content-Length: %d\r\nUser-Agent: vpn-dash\r\nConnection: close\r\n\r\n" % (host, len(q))).encode() + q
    with tls(ip, host, 443) as t:
        t.sendall(req)
        b = b""
        while True:
            p = t.recv(65536)
            if not p:
                break
            b += p
    head, _, body = b.partition(b"\r\n\r\n")
    st = head.split(b" ", 2)
    if len(st) < 2 or st[1] != b"200":
        raise OSError("HTTP %s" % (st[1].decode("ascii", "replace") if len(st) > 1 else "?"))
    if re.search(rb"(?im)^transfer-encoding:\s*chunked", head):
        out, i = b"", 0
        while True:
            j = body.index(b"\r\n", i)
            n = int(body[i:j].split(b";")[0], 16)
            if n == 0:
                break
            out += body[j + 2:j + 2 + n]
            i = j + 2 + n + 2
        body = out
    return parse(body)

def state(fn, *a):
    try:
        r = fn(*a)
        return ("ok" if r is not None else "blocked"), r
    except ssl.SSLCertVerificationError:
        return "mitm", None          # сертификат не того сервиса — подменяют посередине
    except (socket.timeout, TimeoutError):
        return "blocked", None
    except ConnectionRefusedError:
        return "refused", None
    except Exception as e:
        return "blocked" if isinstance(e, OSError) else "error", None

def nameservers():
    ns = re.findall(r"^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)", open("/etc/resolv.conf").read() if os.path.exists("/etc/resolv.conf") else "", re.M)
    up = []
    if ns and ns[0].startswith("127.0.0.53"):
        try:
            t = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, timeout=5).stdout
            up = sorted(set(re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", t)) - {"127.0.0.53"})
        except Exception:
            pass
    return ns, up

out = {"t0": time.time()}
if FAKE:
    try:
        d = json.load(open(FAKE))
        out.update(d.get(IP) or d.get("*") or {})
    except Exception as e:
        out["error"] = "стенд: %s" % e
else:
    res = []
    with cf.ThreadPoolExecutor(24) as ex:
        futs = {}
        for name, ip, host in RESOLVERS:
            futs[(ip, "udp")] = ex.submit(state, udp, ip, "example.com")
            futs[(ip, "doh")] = ex.submit(state, doh, ip, host, "example.com")
            futs[(ip, "dot")] = ex.submit(state, dot, ip, host, "example.com")
        for name, ip, host in RESOLVERS:
            res.append({"name": name, "ip": ip, "udp": futs[(ip, "udp")].result()[0], "doh": futs[(ip, "doh")].result()[0],
                        "dot": futs[(ip, "dot")].result()[0]})
    out["resolvers"] = res
    ref = next(((n, ip, h) for n, ip, h in RESOLVERS if any(r["ip"] == ip and r["doh"] == "ok" for r in res)), None)
    ns, up = nameservers()
    out["system"] = {"ns": ns[:3], "upstream": up[:4]}
    srcs = [("system", ns[0])] if ns else []
    srcs += [("udp:" + ip, ip) for ip in ("1.1.1.1", "8.8.8.8")]
    with cf.ThreadPoolExecutor(16) as ex:
        refs = {d: ex.submit(state, doh, ref[1], ref[2], d) for d in TEST_DOMAINS} if ref else {}
        asks = {(k, d): ex.submit(udp, ip, d) for k, ip in srcs for d in TEST_DOMAINS}
        out["ref"] = ref[0] if ref else None
        out["ref_ips"] = {d: (f.result()[1] or (None, []))[1] for d, f in refs.items()}
        out["answers"] = {}
        for (k, d), f in asks.items():
            r = f.result()
            out["answers"].setdefault(k, {})[d] = None if r is None else {"rcode": r[0], "ips": r[1]}
out["secs"] = round(time.time() - out.pop("t0"), 1)
print(json.dumps(out, ensure_ascii=False))
'''


def runner(ip="", fake=""):
    """Текст для python3 - на сервере. ip — адрес сервера из панели (стенд выбирает по нему ответ), fake — готовый ответ."""
    return "IP = %r\nFAKE = %r\nRESOLVERS = %r\nTEST_DOMAINS = %r\n" % (ip, fake, RESOLVERS, TEST_DOMAINS) + DNS_PY


def _bogus(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved or a.is_link_local
    except ValueError:
        return True


def classify(ans, ref):
    """Один ответ по заблокированному адресу: clean / spoof / noresp / unknown."""
    if ans is None:
        return "noresp"
    if ans.get("rcode") == 3:
        return "spoof"           # «такого сайта нет» — так глушат
    ips = ans.get("ips") or []
    if not ips:
        return "spoof"
    if any(_bogus(i) for i in ips):
        return "spoof"           # заглушка: 0.0.0.0, 127.x, частные адреса
    if not ref:
        return "unknown"
    return "clean" if set(ips) & set(ref) else "spoof"


def summarize(raw):
    if not raw or raw.get("error"):
        return {"error": (raw or {}).get("error") or "нет ответа"}
    res = raw.get("resolvers") or []
    refs = raw.get("ref_ips") or {}
    src = {}
    for k, per in (raw.get("answers") or {}).items():
        doms = {d: classify(a, refs.get(d)) for d, a in per.items()}
        vals = list(doms.values())
        sp, cl = vals.count("spoof"), vals.count("clean")
        verdict = "spoof" if sp >= 2 or (sp and not cl) else "clean" if cl >= 2 or (cl and not sp) else \
                  "noresp" if vals and all(v == "noresp" for v in vals) else "unknown"
        src[k] = {"verdict": verdict, "doms": doms,
                  "sample": next(((d, (per[d] or {}).get("ips") or [], (per[d] or {}).get("rcode")) for d in per if doms[d] == "spoof"), None)}
    notes = []

    def note(lv, t):
        notes.append({"level": lv, "text": t})
    sysd = raw.get("system") or {}
    s = src.get("system")
    ns = ", ".join(sysd.get("ns") or []) or "?"
    if sysd.get("upstream"):
        ns += " → " + ", ".join(sysd["upstream"])

    def sample(x):
        d, ips, rc = x["sample"]
        return "%s → %s" % (d, "«нет такого сайта»" if rc == 3 else ", ".join(ips[:2]) or "пусто")
    if s and s["verdict"] == "spoof":
        note("warn", "DNS хостера (%s) подменяет заблокированные сайты (%s). Поэтому «напрямую» в Zapret панель "
                     "настраивает через зашифрованный DNS" % (ns, sample(s)))
    elif s and s["verdict"] == "clean":
        note("ok", "DNS хостера (%s) отвечает честно" % ns)
    elif s and s["verdict"] == "noresp":
        note("bad", "DNS хостера (%s) не отвечает" % ns)
    hij = [k[4:] for k, v in src.items() if k.startswith("udp:") and v["verdict"] == "spoof"]
    if hij:
        note("warn", "обычные DNS-запросы к %s перехватываются по дороге — ответы подменены (%s). Зашифрованные (DoH/DoT) "
                     "так не подменить" % (" и ".join(hij), sample(src["udp:" + hij[0]])))
    mitm = [r["name"] + " " + t.upper() for r in res for t in ("doh", "dot") if r.get(t) == "mitm"]
    if mitm:
        note("bad", "у %s чужой сертификат — кто-то встаёт посередине" % ", ".join(mitm))
    doh_ok = [r["name"] for r in res if r.get("doh") == "ok"]
    dot_ok = [r["name"] for r in res if r.get("dot") == "ok"]
    if doh_ok:
        note("ok", "зашифрованный DNS работает: DoH — %s%s" % (", ".join(doh_ok), "; DoT — " + ", ".join(dot_ok) if dot_ok else "; DoT нигде не прошёл"))
    elif res:
        note("bad", "ни один DoH не ответил — зашифрованный DNS с этого сервера не работает")
    level = "bad" if any(n["level"] == "bad" for n in notes) else "warn" if any(n["level"] == "warn" for n in notes) else "ok"
    return {"resolvers": res, "system": sysd, "src": src, "ref": raw.get("ref"), "notes": notes, "level": level,
            "secs": raw.get("secs"), "domains": list(refs) or None}


parse = last_json   # итог скрипта — последняя строка JSON (jsonline.py)
