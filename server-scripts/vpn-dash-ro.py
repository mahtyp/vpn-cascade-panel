#!/usr/bin/python3 -I
# vpn-dash-ro — проверки «только чтение» для агента «Аналитики» панели.
#
# Как это устроено на сервере (ставит панель по кнопке, см. readonly.py):
#   пользователь vpn-ro, вход только по ключу; в authorized_keys у ключа
#     restrict,command="/usr/local/sbin/vpn-dash-ro"
#   — что бы ни прислали по SSH, запускается только обёртка, без терминала и пробросов;
#   обёртка: printf '%s' "$SSH_ORIGINAL_COMMAND" | sudo -n /usr/bin/python3 -I /usr/local/lib/vpn-dash-ro/ro.py
#   sudoers разрешает vpn-ro ровно эту команду, без «*» (sudo-rs в Ubuntu 26.04 подстановок в аргументах не понимает). Этот файл и копия probe.py рядом принадлежат root.
#
# Здесь — список названных проверок с проверкой аргументов. Ничего на сервере не меняется.
# Ключи, UUID, пароли и пути веб-панели вырезаются здесь же, до отправки; адреса панель заменяет на имена у себя.
import json
import os
import re
import shutil
import subprocess
import sys

LIB = os.path.dirname(os.path.abspath(__file__))
VERSION = "3"     # поднимать, когда меняются сами проверки: панель предложит переставить
MAX_OUT = 60000

UNITS = re.compile(r"^(x-ui|fail2ban|ssh|sshd|zapret2|vpn-dash-govblock|ufw|awg-quick@(wg|awg)\d{1,2})$")


def run(cmd, timeout=30):
    try:
        p = subprocess.run(["/bin/bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                           env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"})
        return p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "(не уложилось в %d с)" % timeout


SECRETS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "[uuid]"),
    (re.compile(r"(?i)((?:private|public|preshared|password|passwd|secret|token|key|psk|auth)\w*\s*[=:]\s*\"?)[^\s\",;]{6,}"), r"\1[скрыто]"),
    (re.compile(r"\b[A-Za-z0-9+/]{42,43}=(?![A-Za-z0-9+/=])"), "[ключ]"),          # ключи WireGuard/AWG (base64, 32 байта)
    (re.compile(r"\b[A-Za-z0-9_-]{43}\b"), "[ключ]"),                             # ключи Reality (base64url)
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), "[hex]"),
    (re.compile(r"(webBasePath\W+)/[^\s\"']+"), r"\1/[путь]"),
]


def clean(text):
    for rx, rep in SECRETS:
        text = rx.sub(rep, text)
    if len(text) > MAX_OUT:
        text = text[:MAX_OUT] + "\n…(обрезано)"
    return text


def probe(mode_or_lib):
    """Копия probe.py панели рядом с этим файлом: режим целиком (вывод JSON) или как библиотека функций."""
    src = open(os.path.join(LIB, "probe.py"), encoding="utf-8").read()
    if mode_or_lib == "lib":
        g = {"MODE": "lib", "__name__": "probe"}
        exec(compile(src, "probe.py", "exec"), g)
        return g
    p = subprocess.run([sys.executable, "-I", "-"], input=('MODE = "%s"\n' % mode_or_lib + src).encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    return p.stdout.decode("utf-8", "replace").strip()


def num(a, lo, hi, default):
    if a is None:
        return default
    if not re.fullmatch(r"\d{1,5}", a):
        raise ValueError("число ожидалось, а не %r" % a)
    return max(lo, min(hi, int(a)))


def tunnels():
    return [i for i in run("awg show interfaces 2>/dev/null || wg show interfaces 2>/dev/null").split()
            if re.fullmatch(r"(wg|awg)\d{1,2}", i)]


# ---------------------------------------------------------------- проверки

def c_system(args):
    return run("date -u; uptime; uname -r; cat /etc/os-release | grep PRETTY; free -m; df -h / | tail -1; "
               "echo; echo 'Упавшие службы:'; systemctl --no-pager --plain --no-legend list-units --type=service --state=failed")


def c_services(args):
    units = ["x-ui", "fail2ban", "vpn-dash-govblock", "zapret2"]
    out = []
    for u in units:
        if run("systemctl list-unit-files %s.service --no-legend 2>/dev/null" % u).strip():
            since = run("systemctl show -p ActiveEnterTimestamp --value %s" % u).strip()
            out.append("%-22s %s%s" % (u, run("systemctl is-active %s" % u).strip(), " (с %s)" % since if since else ""))
    for u in run("systemctl list-units --plain --no-legend 'awg-quick@*' | awk '{print $1}'").split():
        out.append("%-22s %s" % (u, run("systemctl is-active %s" % u).strip()))
    if shutil.which("ufw"):     # по самому ufw: его служба бывает inactive, хотя правила включены (ufw enable без перезагрузки)
        out.append("%-22s %s" % ("фаервол ufw", (run("ufw status 2>/dev/null | head -1").strip() or "?").replace("Status: ", "")))
    return "\n".join(out) or "(известных служб нет)"


def c_diag(args):
    try:
        secs = json.loads(probe("diag")).get("sections") or []
    except ValueError:
        return "диагностика не удалась"
    return "\n\n".join("== %s\n%s" % (t, b) for t, b in secs)


def c_awg(args):
    return probe("awg")


def c_handshakes(args):
    if not shutil.which("awg") and not shutil.which("wg"):
        return "AmneziaWG здесь нет"
    return run("T=$(command -v awg || command -v wg); now=$(date +%s); "
               "$T show all latest-handshakes | while read i p t; do "
               "[ \"$t\" = 0 ] && a='никогда' || a=\"$((now - t)) с назад\"; echo \"$i пир …${p: -6} рукопожатие: $a\"; done; "
               "echo; $T show all transfer | while read i p rx tx; do echo \"$i пир …${p: -6} принято $((rx/1048576)) МБ, отдано $((tx/1048576)) МБ\"; done; "
               "echo; $T show all endpoints")


def c_journal(args):
    unit = args[0] if args else ""
    if not UNITS.fullmatch(unit):
        raise ValueError("служба не из списка: x-ui, fail2ban, ssh, zapret2, vpn-dash-govblock, ufw, awg-quick@wgN")
    n = num(args[1] if len(args) > 1 else None, 10, 400, 120)
    h = num(args[2] if len(args) > 2 else None, 1, 72, 6)
    return run("journalctl -u %s --since '-%d hour' --no-pager -o short-iso | tail -n %d" % (unit, h, n), 40) or "(пусто)"


def c_xray_errors(args):
    n = num(args[0] if args else None, 10, 400, 120)
    try:
        import sqlite3
        db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
        row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
        t = json.loads(row[0]) if row else {}
    except Exception:
        t = {}
    lg = (t.get("log") or {}).get("error") or ""
    path = lg if lg.startswith("/") else next((p for p in ("/usr/local/x-ui/" + lg, "/usr/local/x-ui/bin/" + lg) if lg and os.path.exists(p)), "")
    if not path or not os.path.exists(path):
        return "отдельного журнала ошибок Xray нет (log.error в шаблоне: %r) — ошибки Xray в журнале x-ui: journal x-ui" % lg
    return run("tail -n 2000 %s | grep -vE 'accepted' | tail -n %d" % (path, n))


def c_routing(args):
    out = c_diag(args)
    m = re.search(r"== маршрутизация Xray\n(.*?)(?:\n\n== |\Z)", out, re.S)
    return m.group(1) if m else "маршрутизации Xray здесь нет"


def c_conns(args):
    return run("ss -s | head -6; echo; "
               "echo \"conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) из $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)\"; "
               "echo; echo 'Открытые соединения по локальным портам (порт: штук):'; "
               "ss -Htn state established | awk '{split($3,a,\":\"); print a[length(a)]}' | sort | uniq -c | sort -rn | head -15; "
               "x=$(pgrep -f xray-linux | head -1); [ -n \"$x\" ] && echo \"xray: файлов $(ls /proc/$x/fd | wc -l) из $(awk '/open files/{print $4}' /proc/$x/limits)\"")


def c_channel(args):
    """Задержка по каналу: туннель wgN (ping до .1 в туннеле)."""
    ch = args[0] if args else ""
    if re.fullmatch(r"(wg|awg)\d{1,2}", ch):
        if ch not in tunnels():
            return "туннеля %s нет" % ch
        addr = run("ip -4 -o addr show dev %s | awk '{print $4}' | head -1" % ch).strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+/\d+", addr):
            return "у %s нет адреса" % ch
        peer = ".".join(addr.split("/")[0].split(".")[:3]) + ".1"
        return run("ping -I %s -c 5 -i 0.3 -W 2 %s | tail -3" % (ch, peer), 20)
    raise ValueError("канал: wgN (туннель AmneziaWG)")


def c_mask(args):
    g = probe("lib")
    return json.dumps(g["reality_mask"](), ensure_ascii=False, indent=1)


def c_e2e(args):
    g = probe("lib")
    r = g["xray_e2e"]() or {}
    r.pop("pc", None)            # параметры клиента (UUID) — не уходят
    return json.dumps(r, ensure_ascii=False, indent=1)


def c_versions(args):
    g = probe("lib")
    return json.dumps(g["sw_versions"](), ensure_ascii=False, indent=1)


def c_dmesg(args):
    n = num(args[0] if args else None, 10, 200, 40)
    return run("dmesg -T 2>/dev/null | grep -iE 'conntrack|oom|killed process|table full|segfault|amnezia|wireguard|link is down|"
               "hung task|nf_|tcp:|out of memory|error' | tail -n %d" % n) or "(ничего примечательного)"


def c_firewall(args):
    return run("ufw status verbose 2>/dev/null | head -40; echo; nft list tables 2>/dev/null; echo; "
               "nft list chain inet vpn_dash_gov input 2>/dev/null | grep counter; "
               "echo; fail2ban-client status 2>/dev/null | tail -2")


def c_dns(args):
    return run("cat /etc/resolv.conf | grep -v '^#'; echo; resolvectl status 2>/dev/null | grep -E 'DNS Servers|Current DNS' | head -6; echo; "
               "for d in ya.ru google.com www.cloudflare.com; do printf '%s → ' $d; getent ahostsv4 $d | awk 'NR==1{print $1}'; done")


def _short(v, n=25):
    if isinstance(v, list) and len(v) > n:
        return v[:n] + ["…ещё %d" % (len(v) - n)]
    return v


def _stream(st):
    """Транспорт без секретов: сеть, защита, имя сайта, отпечаток (publicKey/shortId/пароли не выводятся)."""
    st = st or {}
    d = {"сеть": st.get("network") or "tcp", "защита": st.get("security") or "none"}
    rs = st.get("realitySettings") or {}
    if rs:
        inner = rs.get("settings") or {}
        for k, name in (("dest", "сайт маскировки"), ("target", "сайт маскировки"), ("serverNames", "имена"),
                        ("serverName", "имя"), ("fingerprint", "отпечаток"), ("spiderX", "spiderX"), ("xver", "xver")):
            v = rs.get(k, inner.get(k) if k in ("fingerprint", "spiderX", "serverName") else None)
            if v not in (None, "", []):
                d[name] = v
        if rs.get("shortIds") is not None:
            d["shortId, шт"] = len(rs.get("shortIds") or [])
    ts = st.get("tlsSettings") or {}
    for k, name in (("serverName", "имя"), ("fingerprint", "отпечаток"), ("alpn", "alpn")):
        if ts.get(k):
            d[name] = ts[k]
    so = st.get("sockopt") or {}
    for k in ("interface", "dialerProxy", "mark", "tcpMaxSeg", "domainStrategy", "tcpFastOpen"):
        if so.get(k) not in (None, "", 0):
            d["sockopt." + k] = so[k]
    for k in ("xhttpSettings", "wsSettings", "grpcSettings", "httpupgradeSettings"):
        x = st.get(k) or {}
        if x.get("path") or x.get("serviceName") or x.get("mode"):
            d[k] = {kk: x[kk] for kk in ("path", "serviceName", "mode", "host") if x.get(kk)}
    return d


def _outbound(o):
    p, s = o.get("protocol"), o.get("settings") or {}
    d = {"протокол": p}
    if p == "freedom":
        for k in ("domainStrategy", "redirect"):
            if s.get(k):
                d[k] = s[k]
        if s.get("fragment"):
            d["fragment"] = s["fragment"]
        if s.get("noises"):
            d["noises, шт"] = len(s["noises"])
    elif p == "loopback":
        d["inboundTag"] = s.get("inboundTag")
    elif p in ("vless", "vmess"):
        vn = (s.get("vnext") or [{}])[0] if s.get("vnext") else s
        d["куда"] = "%s:%s" % (vn.get("address"), vn.get("port"))
        u = (vn.get("users") or [{}])[0] if vn.get("users") else vn
        for k in ("flow", "encryption"):
            if u.get(k):
                d[k] = u[k]
    elif p in ("socks", "http", "trojan", "shadowsocks", "wireguard", "hysteria2"):
        sv = s.get("servers") or s.get("peers") or []
        d["куда"] = ["%s:%s" % (x.get("address") or x.get("endpoint"), x.get("port", "")) for x in sv][:6]
    if o.get("streamSettings"):
        d.update(_stream(o["streamSettings"]))
    if (o.get("mux") or {}).get("enabled"):
        d["mux"] = True
    if o.get("proxySettings"):
        d["proxySettings"] = o["proxySettings"]
    return d


def c_xray_config(args):
    """Как настроен Xray входа сейчас: исходящие, маршрутизация целиком, цепочки, наблюдатель, входящие, DNS."""
    import sqlite3
    db = None
    if os.path.exists("/etc/x-ui/x-ui.db"):
        try:
            db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
        except Exception:
            db = None
    cfg, src = None, ""
    try:
        cfg = json.load(open("/usr/local/x-ui/bin/config.json", encoding="utf-8"))
        src = "config.json (с ним Xray запущен сейчас, вместе с исходящими из подписок 3X-UI)"
    except Exception:
        pass
    if cfg is None and db is not None:
        try:
            cfg = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
            src = "шаблон Xray в базе 3X-UI (config.json не прочитать)"
        except Exception:
            pass
    if cfg is None:
        return "3X-UI/Xray здесь нет"
    xb = next((os.path.join("/usr/local/x-ui/bin", f) for f in sorted(os.listdir("/usr/local/x-ui/bin"))
               if f.startswith("xray-linux")), "") if os.path.isdir("/usr/local/x-ui/bin") else ""
    out = ["Источник: " + src]
    if xb:
        out.append("Xray: " + (run("%s version 2>/dev/null | head -1" % xb).strip() or "?"))
    if os.access("/usr/local/x-ui/x-ui", os.X_OK):         # сама программа 3X-UI (не меню x-ui): -v — только версия
        v = run("timeout 10 /usr/local/x-ui/x-ui -v 2>/dev/null | head -1", 15).strip()
        out.append("3X-UI: " + (v or "?"))
    lg = cfg.get("log") or {}
    out.append("Журнал: уровень %s, ошибки %s, доступ %s" % (lg.get("loglevel"), lg.get("error") or "—", lg.get("access") or "—"))
    dns = cfg.get("dns") or {}
    if dns:
        out.append("DNS Xray: %s" % json.dumps({k: _short(v, 10) for k, v in dns.items() if k in ("servers", "queryStrategy", "disableFallback", "hosts")},
                                                ensure_ascii=False))
    out.append("\n== Исходящие (%d)" % len(cfg.get("outbounds") or []))
    for o in cfg.get("outbounds") or []:
        out.append("%s: %s" % (o.get("tag"), json.dumps(_outbound(o), ensure_ascii=False)))
    r = cfg.get("routing") or {}
    out.append("\n== Маршрутизация: domainStrategy %s" % r.get("domainStrategy"))
    for b in r.get("balancers") or []:
        out.append("цепочка %s: %s → %s, запасной %s" % (b.get("tag"), (b.get("strategy") or {}).get("type") or "random",
                                                        b.get("selector"), b.get("fallbackTag") or "—"))
    bl = 0
    for i, x in enumerate(r.get("rules") or []):
        if any(str(t).startswith("_bl_") for t in x.get("inboundTag") or []):
            bl += 1
            continue
        k = {f: _short(x[f]) for f in ("inboundTag", "domain", "ip", "port", "sourcePort", "network", "protocol", "source", "user", "attrs")
             if f in x}
        if "user" in k:
            k["user"] = "%d адресатов" % len(x["user"]) if isinstance(x["user"], list) else "?"
        out.append("правило %d%s %s → %s" % (i, " [%s]" % x["ruleTag"] if x.get("ruleTag") else "", json.dumps(k, ensure_ascii=False),
                                              x.get("balancerTag") or x.get("outboundTag")))
    if bl:
        out.append("(служебных правил цепочек _bl_*: %d)" % bl)
    for k in ("observatory", "burstObservatory"):
        ob = cfg.get(k)
        if ob:
            pc = ob.get("pingConfig") or {}
            out.append("%s: следит за %s, проверка %s, раз в %s" % (k, ob.get("subjectSelector"), ob.get("probeURL") or pc.get("destination"),
                                                                ob.get("probeInterval") or pc.get("interval")))
    out.append("\n== Входящие")
    rows = []
    if db is not None:
        try:
            rows = db.execute("select remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing from inbounds").fetchall()
        except Exception:
            rows = []
    if rows:
        for remark, en, listen, port, proto, st, ss, tag, sn in rows:
            try:
                st = json.loads(st or "{}")
                ss = json.loads(ss or "{}")
                sn = json.loads(sn or "{}")
            except ValueError:
                st, ss, sn = {}, {}, {}
            cl = st.get("clients") or []
            d = {"порт": port, "слушает": listen or "все адреса", "протокол": proto, "включён": bool(en), "тег": tag}
            if cl:
                d["клиентов"] = "%d, включено %d" % (len(cl), sum(1 for c in cl if c.get("enable", True)))
                fl = sorted({c.get("flow") or "—" for c in cl})
                d["flow"] = fl
                if any(c.get("limitIp") for c in cl):
                    d["с limitIp"] = sum(1 for c in cl if c.get("limitIp"))
            if st.get("decryption") not in (None, "none"):
                d["decryption"] = "задано"
            d.update(_stream(ss))
            if sn:
                d["sniffing"] = sn.get("destOverride") if sn.get("enabled") else "выкл"
            out.append("%s: %s" % (remark or tag, json.dumps(d, ensure_ascii=False)))
    else:
        for i in cfg.get("inbounds") or []:
            if str(i.get("tag", "")).startswith(("api", "_bl_")):
                continue
            d = {"порт": i.get("port"), "слушает": i.get("listen") or "все адреса", "протокол": i.get("protocol")}
            d.update(_stream(i.get("streamSettings")))
            out.append("%s: %s" % (i.get("tag"), json.dumps(d, ensure_ascii=False)))
    return "\n".join(out)


CHECKS = {
    "system": (c_system, "время, нагрузка, память, диск, ядро, упавшие службы"),
    "services": (c_services, "состояние служб каскада и туннелей"),
    "diag": (c_diag, "полная диагностика (как кнопка «Диагностика» в панели)"),
    "awg": (c_awg, "конфиги и пиры AmneziaWG (без ключей)"),
    "handshakes": (c_handshakes, "рукопожатия и трафик AmneziaWG по пирам"),
    "journal": (c_journal, "журнал службы: journal <служба> [строк] [часов]"),
    "xray-errors": (c_xray_errors, "журнал ошибок Xray: xray-errors [строк]"),
    "routing": (c_routing, "маршрутизация Xray: правила, цепочки, DNS"),
    "xray-config": (c_xray_config, "как настроен Xray: исходящие, все правила, цепочки, наблюдатель, входящие (без секретов)"),
    "conns": (c_conns, "соединения, conntrack, файлы Xray"),
    "channel": (c_channel, "задержка по каналу: channel wgN"),
    "mask": (c_mask, "сайт маскировки Reality: открывается ли, TLS, сертификат"),
    "e2e": (c_e2e, "сквозная проверка через Xray входа (зарубежный и российский сайт)"),
    "versions": (c_versions, "версия AmneziaWG и протокол туннелей"),
    "dmesg": (c_dmesg, "сообщения ядра: conntrack, oom, туннели"),
    "firewall": (c_firewall, "ufw, таблицы nftables, сети госорганов, fail2ban"),
    "dns": (c_dns, "DNS сервера и как он видит имена"),
    "version": (lambda a: VERSION, "версия этого скрипта"),
}


def main():
    line = (sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read(400)).strip()     # обёртка шлёт строку через stdin
    if len(line) > 200 or not re.fullmatch(r"[a-z0-9-]+(?: [A-Za-z0-9@._-]{1,40}){0,3}", line):
        print("отказ: ожидается «проверка [аргументы]», список: list")
        return 2
    name, *args = line.split()
    if name == "list":
        print("\n".join("%-12s %s" % (k, v[1]) for k, v in CHECKS.items()))
        return 0
    if name not in CHECKS:
        print("отказ: такой проверки нет (%s). Список: list" % name)
        return 2
    try:
        print(clean(str(CHECKS[name][0](args))))
    except ValueError as e:
        print("отказ: %s" % e)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
