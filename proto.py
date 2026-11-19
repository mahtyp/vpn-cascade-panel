"""Раздел «Протоколы»: чем серверы связаны между собой и что на них стоит ещё. Только чтение.

Факты собирает probe.py (MODE "proto": исходящие Xray, правила, входящие, Mihomo, AmneziaWG, кто слушает порты);
здесь — разбор: `links()` — пути сервера до других (протокол, куда, место в цепочке, для чего), `inventory()` —
кто слушает порты: наша схема / известная программа не из схемы / неизвестное / системное.
"""
import re

KIND = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "shadowsocks": "Shadowsocks", "wireguard": "WireGuard",
        "hysteria2": "Hysteria2", "hysteria": "Hysteria", "socks": "SOCKS", "http": "HTTP-прокси", "tuic": "TUIC"}
SEC = {"reality": "Reality", "tls": "TLS"}

# программы, которые панель узнаёт по имени процесса, но которые не из нашей схемы
OTHER = {
    "sing-box": "sing-box", "hysteria": "Hysteria", "tuic-server": "TUIC", "naive": "NaiveProxy", "caddy": "Caddy (веб-сервер)",
    "nginx": "nginx (веб-сервер)", "apache2": "Apache (веб-сервер)", "openvpn": "OpenVPN", "ss-server": "Shadowsocks",
    "ssserver": "Shadowsocks", "trojan": "Trojan", "trojan-go": "Trojan-Go", "xrdp": "удалённый рабочий стол (xrdp)",
    "xrdp-sesman": "удалённый рабочий стол (xrdp)", "tailscaled": "Tailscale", "cloudflared": "Cloudflare Tunnel",
    "warp-svc": "Cloudflare WARP", "postgres": "PostgreSQL", "mysqld": "MySQL", "mariadbd": "MariaDB", "redis-server": "Redis",
    "node": "программа на Node.js", "dockerd": "Docker", "containerd": "Docker", "smbd": "Samba (общие папки)",
    "vsftpd": "FTP-сервер", "exim4": "почтовый сервер Exim", "master": "почтовый сервер Postfix", "cupsd": "печать (CUPS)",
    "rpcbind": "rpcbind (NFS)", "dnsmasq": "dnsmasq (DNS/DHCP)", "named": "DNS-сервер BIND", "unbound": "DNS-сервер Unbound",
    "wg-quick": "WireGuard", "3proxy": "3proxy", "danted": "SOCKS-сервер Dante", "squid": "прокси Squid", "ocserv": "OpenConnect VPN",
    "pptpd": "PPTP VPN", "xl2tpd": "L2TP VPN", "charon": "IPsec (strongSwan)", "mtg": "MTProto-прокси", "mtproto-proxy": "MTProto-прокси",
    "telemt": "MTProto-прокси", "AmneziaVPN": "Amnezia", "netdata": "Netdata (мониторинг)", "zabbix_agentd": "Zabbix (мониторинг)",
    "node_exporter": "мониторинг (node_exporter)", "qemu-ga": "агент хостера",
}
SYSTEM = {"systemd-resolve", "systemd-network", "systemd-timesyn", "chronyd", "ntpd", "dhclient", "dhcpcd", "systemd", "avahi-daemon"}


def proto_label(b):
    """«VLESS Reality», «AWG wg0», «Sudoku через SOCKS 1081»."""
    if b.get("kind") == "AWG":
        return "AmneziaWG %s" % b.get("iface", "")
    if b.get("kind") == "Sudoku":
        return "Sudoku (SOCKS %s)" % b.get("socks", "?")
    name = KIND.get(b.get("proto"), b.get("proto") or "?")
    sec = SEC.get(b.get("sec"), "")
    net = b.get("net") if b.get("net") not in ("", "tcp", "raw", None) else ""
    return " ".join(x for x in (name, sec, net) if x)


def links(srv, p, channels, by_host):
    """Пути сервера до других серверов. channels — каналы панели для этого сервера (AWG/Sudoku: выход и ключ проверки)."""
    main = p.get("main") or []
    pins = p.get("pins") or {}
    ch_awg = {c.get("iface"): c for c in channels if c.get("kind") == "AWG"}
    ch_sdk = {c.get("port"): c for c in channels if c.get("kind") == "Sudoku"}
    out = []
    for b in p.get("outs") or []:
        tag = b.get("tag")
        ln = {"tag": tag, "kind": b.get("kind"), "proto": b.get("proto"), "socks": b.get("socks"), "label": proto_label(b), "sub": bool(b.get("sub")),
              "n": main.index(tag) + 1 if tag in main else None, "of": len(main), "pins": pins.get(tag) or [],
              "exit_id": None, "exit": "", "ext": "", "key": None,
              "detail": {k: b[k] for k in ("net", "sec", "sni", "fp", "flow", "port", "via") if b.get(k)}}
        c = ch_awg.get(b.get("iface")) if b.get("kind") == "AWG" else ch_sdk.get(b.get("socks")) if b.get("kind") == "Sudoku" else None
        if c:
            ln.update(exit_id=c.get("exit_id"), exit=c.get("exit") or "", key=c.get("key"))
            if not c.get("exit_id"):
                ln["ext"] = c.get("host") or ""
        elif b.get("kind") not in ("AWG", "Sudoku"):
            x = by_host(b.get("addr") or "")
            if x and x["id"] != srv["id"]:
                ln.update(exit_id=x["id"], exit=x["name"])
            else:
                ln["ext"] = b.get("addr") or ""
        out.append(ln)
    out.sort(key=lambda x: (x["n"] is None, x["n"] or 0, x["tag"] or ""))
    return out


def _local(addr):
    return addr.startswith("127.") or addr in ("::1", "localhost")


def inventory(p):
    """Кто слушает порты: [{cat: ours|other|unknown|system, what, port, proto, scope: net|local, proc, unit}]."""
    xui = p.get("xui") or {}
    inb = {i["port"]: i for i in p.get("inbounds") or []}
    awg_ports = {i.get("port"): i.get("name") for i in ((p.get("awg") or {}).get("ifaces") or []) if i.get("port")}
    for port, name in (p.get("tun_ports") or {}).items():
        awg_ports.setdefault(int(port), name)
    server_if = {i.get("name") for i in ((p.get("awg") or {}).get("ifaces") or []) if (i.get("iface") or {}).get("ListenPort")}
    docker = p.get("docker") or []
    seen, out = {}, []
    for l in p.get("listen") or []:
        proc, port, unit, addr = l.get("proc") or "", l.get("port"), l.get("unit") or "", l.get("addr") or ""
        base = proc.lower()
        cat, what = "unknown", ""
        tcp = l.get("proto") == "tcp"
        if base.startswith("sshd") or unit in ("ssh", "sshd"):
            cat, what = "ours", "SSH"
        elif tcp and port in inb and (base.startswith("xray") or unit == "x-ui" or not proc):
            i = inb[port]
            cat, what = "ours", "вход 3X-UI «%s»: %s" % (i.get("remark") or port, proto_label({"proto": i.get("proto"), "sec": i.get("sec"), "net": i.get("net")}))
        elif tcp and port == xui.get("web_port") and (base.startswith("x-ui") or unit == "x-ui"):
            cat, what = "ours", "веб-панель 3X-UI"
        elif tcp and port == xui.get("sub_port") and (base.startswith("x-ui") or unit == "x-ui"):
            cat, what = "ours", "подписка 3X-UI"
        elif base.startswith("xray") and not tcp and port not in inb:
            cat, what = "system", "Xray: временный порт исходящего UDP-соединения"
        elif base.startswith("xray"):
            i = inb.get(port)
            if i:
                cat, what = "ours", "вход 3X-UI «%s»: %s" % (i.get("remark") or port, proto_label({"proto": i.get("proto"), "sec": i.get("sec"), "net": i.get("net")}))
            elif _local(addr):
                cat, what = "system", "Xray, служебный порт"
            else:
                what = "Xray слушает порт, которого нет во входящих 3X-UI"
        elif base == "x-ui":
            cat = "ours"
            what = "веб-панель 3X-UI" if port == xui.get("web_port") else "подписка 3X-UI" if port == xui.get("sub_port") else "3X-UI"
        elif base.startswith("mihomo") or unit == "mihomo":
            cat, what = "ours", "Mihomo: локальный SOCKS до Sudoku"
            if not _local(addr):
                cat, what = "unknown", "Mihomo слушает не только сам сервер"
        elif base.startswith("sudoku") or (port and port == p.get("sudoku_port")):
            cat, what = "ours", "Sudoku-сервер"
        elif "sudoku" in unit:
            cat, what = "ours", "Sudoku: служебная страница"
        elif l.get("proto") == "udp" and port in awg_ports:
            n = awg_ports[port]
            cat = "ours"
            what = "AmneziaWG %s: %s" % (n, "сюда подключаются входы" if n in server_if else "свой порт туннеля до выхода (снаружи отвечает только выходу)")

        elif base in ("nfqws", "nfqws2") or unit.startswith("zapret"):
            cat, what = "ours", "zapret"
        elif base == "docker-proxy":
            c = next((d for d in docker if re.search(r":%s->" % port, d.get("ports") or "")), None)
            name = (c or {}).get("name", "")
            if "amnezia" in name.lower():
                cat, what = "ours", "Amnezia в Docker: %s" % name
            else:
                cat, what = "other", "контейнер Docker%s" % (" «%s» (%s)" % (name, c.get("image")) if c else "")
        elif base in SYSTEM or unit in SYSTEM:
            cat, what = "system", "системная служба (%s)" % proc
        elif base in OTHER or unit in OTHER:
            cat, what = "other", OTHER.get(base) or OTHER.get(unit)
        elif not proc and l.get("proto") == "udp":
            what = "UDP-порт ядра (возможно, WireGuard)"
        else:
            what = proc or "неизвестный процесс"
        scope = "local" if _local(addr) else "net"
        k = (cat, what, port, l.get("proto"), proc)
        if k in seen:                                   # тот же порт на IPv4 и IPv6
            if scope == "net":
                seen[k]["scope"] = "net"
            continue
        item = {"cat": cat, "what": what, "port": port, "proto": l.get("proto"), "scope": scope, "proc": proc, "unit": unit}
        seen[k] = item
        out.append(item)
    order = {"unknown": 0, "other": 1, "ours": 2, "system": 3}
    out.sort(key=lambda x: (order[x["cat"]], x["scope"] != "net", x["port"] or 0))
    return out


RU = {"geoip:ru", "geosite:category-ru", "geosite:ru", "domain:ru", "domain:su", "domain:xn--p1ai", "domain:рф", "regexp:.*\\.ru$"}


def _what(m, comment):
    """Короткое имя правила для схемы: «Россия», «IPv6», «торренты»…, иначе comment или первые значения."""
    vals = [str(v) for k in ("domain", "ip") for v in m.get(k) or []]
    low = [v.lower() for v in vals]
    if comment.upper().startswith("DC5TG") or any("telegram" in v for v in low):
        return "Telegram"
    if comment.startswith("Z-"):
        return "zapret"
    if comment:
        return comment
    if "bittorrent" in [str(v).lower() for v in m.get("protocol") or []]:
        return "торренты"
    if vals and all(v in ("::/0", "::0/0") for v in vals):
        return "IPv6"
    if vals and all(v in ("geoip:private", "geosite:private") for v in vals):
        return "локальные сети"
    if any("category-ads" in v for v in low):
        return "реклама"
    if vals and all(v in RU or v.endswith(":ru") or v.endswith(".ru") for v in low):
        return "Россия"
    if m.get("user"):
        return "клиенты: " + ", ".join(m["user"][:3])
    if m.get("port") and not vals:
        return "порт " + ", ".join(m["port"])
    return ", ".join(vals[:2]) or ", ".join(str(v) for k, x in m.items() if k != "network" for v in x)[:40] or "без условий"


def rules(p):
    """Правила маршрутизации входа по порядку для схемы: [{what, detail, to: {t: direct|block|dns|chain, tags}, catch, in}].
    Нет общего правила — Xray отдаёт «всё остальное» первому исходящему: оно добавляется в конец как неявное."""
    plain = p.get("plain") or {}
    out = []

    def target(tags):
        real = [t for t in tags if t not in plain]
        if real:
            return {"t": "chain", "tags": real}
        k = plain.get(tags[0]) if tags else None
        return {"t": {"freedom": "direct", "blackhole": "block", "dns": "dns"}.get(k, "none"), "tags": []}

    for k, x in enumerate(p.get("rules") or []):
        m = x.get("m") or {}
        catch = not any(k != "network" for k in m)
        det = [str(v) for k in ("domain", "ip", "protocol", "port", "source", "user") for v in m.get(k) or []]
        more = sum(x.get("n", {}).values()) - sum(len(m.get(k) or []) for k in x.get("n") or {})
        what, to = "всё остальное" if catch else _what(m, x.get("comment") or ""), target(x.get("tags") or [])
        prev = out[-1] if out else None
        if prev and not catch and not prev["catch"] and prev["what"] == what and prev["to"] == to and prev["in"] == (x.get("in") or []):
            prev["detail"] = ", ".join(v for v in (prev["detail"], ", ".join(det[:4])) if v)   # «Россия» доменами и «Россия» адресами — одна строка
            prev["ix"].append(k)
            continue
        out.append({"what": what, "catch": catch, "in": x.get("in") or [], "ix": [k],
                    "detail": ", ".join(det[:4]) + (" и ещё %d" % (len(det) - 4 + max(more, 0)) if len(det) > 4 or more > 0 else ""),
                    "to": to})
        if catch and not x.get("in"):
            break                                   # дальше правила уже не сработают
    else:
        if p.get("first_out") or p.get("main"):
            out.append({"what": "всё остальное", "catch": True, "in": [], "implicit": True, "detail": "", "ix": [],
                        "to": target([p["first_out"]] if p.get("first_out") else p.get("main") or [])})
    return out


# «Куда пойдёт»: какое правило 3X-UI сработает для сайта или адреса — по тем же правилам и базам geosite/geoip, что у Xray на входе.
# Только чтение. Перед кодом подставляется TARGET = "сайт или адрес[:порт]". Нумерация правил — как у probe (без петель _bl_ и api).
ROUTE_PY = r'''
import ipaddress, json, os, re, socket, sqlite3
def varint(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if x < 0x80:
            return r, i
def fields(b):
    i = 0
    while i < len(b):
        k, i = varint(b, i)
        n, t = k >> 3, k & 7
        if t == 2:
            ln, i = varint(b, i); yield n, b[i:i + ln]; i += ln
        elif t == 0:
            v, i = varint(b, i); yield n, v
        elif t == 5: i += 4
        elif t == 1: i += 8
        else: return
DIRS = ["/usr/local/x-ui/bin", "/usr/local/share/xray", "/usr/share/xray"]
def geofile(name):
    return next((os.path.join(d, name) for d in DIRS if os.path.exists(os.path.join(d, name))), None)
notes, SITES, IPS = [], {}, {}
def geosite(code):
    code = code.split("@")[0].upper()
    if code in SITES:
        return SITES[code]
    path, out = geofile("geosite.dat"), None
    if not path:
        notes.append("на входе нет geosite.dat — правила geosite: не проверить")
    else:
        for n, site in fields(open(path, "rb").read()):
            if n != 1:
                continue
            f = dict((m, v) for m, v in fields(site) if m == 1)
            if f.get(1, b"").decode("utf-8", "replace").upper() != code:
                continue
            out = []
            for m, v in fields(site):
                if m == 2:
                    typ, val = 0, ""
                    for q, w in fields(v):
                        if q == 1: typ = w
                        elif q == 2: val = w.decode("utf-8", "replace").lower()
                    out.append((typ, val))
            break
        if out is None:
            notes.append("в geosite.dat нет списка %s" % code.lower())
    SITES[code] = out or []
    return SITES[code]
def geoip(code):
    code = code.upper()
    if code in IPS:
        return IPS[code]
    path, out = geofile("geoip.dat"), None
    if not path:
        notes.append("на входе нет geoip.dat — правила geoip: не проверить")
    else:
        for n, e in fields(open(path, "rb").read()):
            if n != 1:
                continue
            f = list(fields(e))
            if next((v for m, v in f if m == 1), b"").decode("utf-8", "replace").upper() != code:
                continue
            out = []
            for m, v in f:
                if m == 2:
                    ip, pre = b"", 0
                    for q, w in fields(v):
                        if q == 1: ip = w
                        elif q == 2: pre = w
                    try:
                        out.append(ipaddress.ip_network((ipaddress.ip_address(ip), pre), strict=False))
                    except ValueError:
                        pass
            break
    IPS[code] = out or []
    return IPS[code]
def dmatch(p, d):
    if p.startswith("geosite:"):
        for typ, val in geosite(p[8:]):
            if (typ == 0 and val in d) or (typ == 1 and re.search(val, d)) or (typ == 2 and (d == val or d.endswith("." + val))) or (typ == 3 and d == val):
                return True
        return False
    if p.startswith("domain:"):
        v = p[7:].lower(); return d == v or d.endswith("." + v)
    if p.startswith("full:"):
        return d == p[5:].lower()
    if p.startswith("regexp:"):
        try:
            return bool(re.search(p[7:], d))
        except re.error:
            return False
    if p.startswith("keyword:"):
        return p[8:].lower() in d
    if p.startswith("ext:"):
        notes.append("правило со списком из файла (%s) не проверяю" % p); return False
    return p.lower() in d
def imatch(p, ip):
    a = ipaddress.ip_address(ip)
    if p.startswith("geoip:"):
        c = p[6:]; neg = c.startswith("!"); c = c.lstrip("!")
        hit = any(a in n for n in geoip(c) if n.version == a.version)
        return hit != neg
    if p.startswith("ext:"):
        return False
    try:
        return a in ipaddress.ip_network(p, strict=False)
    except ValueError:
        return False
def ports(spec, port):
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit() and int(a) <= port <= int(b):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False
raw = TARGET.strip().lower()
raw = re.sub(r"^[a-z]+://", "", raw).split("/")[0]
host, port = raw, 443
m = re.match(r"^\[?([0-9a-f:.]+?)\]?(?::(\d+))?$", raw) if raw.count(":") != 1 or raw.replace(".", "").split(":")[0].isdigit() else re.match(r"^(.+?):(\d+)$", raw)
if m and m.group(2):
    host, port = m.group(1), int(m.group(2))
elif raw.count(":") == 1:
    host, port = raw.split(":")[0], int(raw.split(":")[1]) if raw.split(":")[1].isdigit() else 443
host = host.strip("[].")
try:
    ipaddress.ip_address(host); dom = None
except ValueError:
    dom = host
c = {}
try:
    c = json.load(open("/usr/local/x-ui/bin/config.json"))
except Exception:
    try:
        db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
        c = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
    except Exception as e:
        print(json.dumps({"error": "не прочитал настройки Xray: %s" % e})); raise SystemExit
r = c.get("routing") or {}
strategy = r.get("domainStrategy") or "AsIs"
rules = [x for x in r.get("rules") or [] if not any(str(i).startswith("_bl_") or i == "api" for i in x.get("inboundTag") or [])]
resolved = []
def resolve():
    if not resolved and dom:
        try:
            resolved.extend(sorted({a[4][0] for a in socket.getaddrinfo(dom, port, socket.AF_INET, socket.SOCK_STREAM)})[:4])
        except OSError:
            notes.append("адрес %s DNS сервера не нашёл" % dom)
    return resolved
def match(x, ips, ondemand):
    if x.get("source") or x.get("user") or x.get("attrs") or x.get("sourcePort"):
        return None                              # зависит от устройства — не знаем
    pr = [str(v).lower() for v in x.get("protocol") or []]
    if pr and not (("tls" in pr and port == 443) or ("http" in pr and port == 80)):
        return None
    if x.get("port") and not ports(x["port"], port):
        return None
    if x.get("network") and "tcp" not in str(x["network"]):
        return None
    dl, il = x.get("domain") or [], x.get("ip") or []
    if not dl and not il:
        return "всё остальное" if not pr else ", ".join(pr)
    if dom:
        for p in dl:
            if dmatch(p, dom):
                return p
    if il and ondemand and dom:
        ips = resolve()
    for p in il:
        for ip in ips:
            if imatch(p, ip):
                return "%s (адрес %s)" % (p, ip) if dom else p
    return None
ips = [] if dom else [host]
hit = None
for i, x in enumerate(rules):
    w = match(x, ips, strategy == "IPOnDemand")
    if w:
        hit = (i, w); break
if hit is None and dom and strategy == "IPIfNonMatch":
    ips = resolve()
    for i, x in enumerate(rules):
        w = match(x, ips, False)
        if w:
            hit = (i, w); break
if dom and strategy == "AsIs" and any(x.get("ip") for x in rules):
    notes.append("правила по адресам (geoip, подсети) для сайта по имени не срабатывают (domainStrategy AsIs) — только если устройство идёт прямо по адресу, как Telegram")
first = ((c.get("outbounds") or [{}])[0]).get("tag") or ""
res = {"target": host, "port": port, "strategy": strategy, "ips": resolved if dom else [host], "notes": sorted(set(notes))}
if hit:
    x = rules[hit[0]]
    res.update(ix=hit[0], why=hit[1], out=x.get("outboundTag") or "", bal=x.get("balancerTag") or "",
               comment=x.get("comment") or "")
    # Реальный путь по selector/fallbackTag, а не вывод из одного названия балансировщика.
    bals = {str(b.get("tag") or ""): b for b in r.get("balancers") or [] if b.get("tag")}
    def walk(tag, seen=None):
        seen = set(seen or ())
        if not tag or tag in seen:
            return []
        seen.add(tag)
        b = bals.get(tag)
        if not b:
            return [tag]
        out = []
        for v in b.get("selector") or []:
            if str(v) not in out:
                out.append(str(v))
        for z in walk(str(b.get("fallbackTag") or ""), seen):
            if z not in out:
                out.append(z)
        return out
    res["chain"] = walk(res.get("bal") or res.get("out"))
else:
    res.update(ix=None, why="ни одно правило не подошло — Xray отдаёт первому исходящему", out=first,
               comment="", chain=[first] if first else [])
print(json.dumps(res, ensure_ascii=False))
'''
