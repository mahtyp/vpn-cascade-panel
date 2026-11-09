# probe.py — запускается на сервере по SSH (python3 -), печатает JSON с состоянием.
# Только читает: ничего на сервере не меняет. Работает и на входе, и на выходе.
# Режим задаёт первая строка, которую добавляет панель: MODE = "status" | "dc" | "config" | "precheck" | "lat" | …
# (для "quality" перед этим файлом идёт исходник quality.py)
import glob
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time

try:
    MODE
except NameError:
    MODE = "status"

AWG_DIR = "/etc/amnezia/amneziawg"
TG_DC = globals().get("TG_DC_OVERRIDE") or [  # список приходит из настроек панели
    ("DC1", "149.154.175.53"), ("DC2", "149.154.167.51"), ("DC3", "149.154.175.100"),
    ("DC4", "149.154.167.91"), ("DC5", "91.108.56.130")]


_CHILDREN = set()


def run(cmd, timeout=15):
    """Команда с пределом времени. По истечении убивается вся её группа процессов, а не только
    оболочка: иначе зависший apt остаётся жить и на маленьком сервере копии съедают память.
    Возвращает (код, stdout, stderr); код -9 — не уложилась во время."""
    import signal
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True)
    except Exception as e:
        return -1, "", str(e)
    _CHILDREN.add(p)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.communicate()
        return -9, "", "timeout"
    finally:
        _CHILDREN.discard(p)


def sh(cmd, timeout=15):
    return run(cmd, timeout)[1].strip()


def _watchdog(secs):
    """Вся проверка не дольше secs: панель всё равно перестанет ждать, а скрипт не должен остаться висеть."""
    import signal

    def bye(*_):
        for p in list(_CHILDREN):
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
        os._exit(3)
    signal.signal(signal.SIGALRM, bye)
    signal.alarm(secs)


_watchdog({"status": 80, "config": 55, "dc": 55, "fw": 50, "quality": 290, "lat": 100, "precheck": 115, "pkgs": 290, "dpi": 170, "diag": 170}.get(MODE, 110))


def mem_available_mb():
    m = re.search(r"^MemAvailable:\s+(\d+)", read("/proc/meminfo"), re.M)
    return int(m.group(1)) // 1024 if m else None


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ------------------------------------------------------------------ система

def cpu_percent():
    """(загрузка CPU %, steal %) за полсекунды. steal — сколько процессора хостер отдал соседним машинам,
    пока нашей он был нужен: на дешёвых VPS под нагрузкой это главный признак «слабого» сервера."""
    def snap():
        v = list(map(int, read("/proc/stat").splitlines()[0].split()[1:]))
        return sum(v[:8]), v[3] + (v[4] if len(v) > 4 else 0), v[7] if len(v) > 7 else 0
    try:
        t1, i1, s1 = snap()
        time.sleep(0.5)
        t2, i2, s2 = snap()
        d = max(1, t2 - t1)
        return round(100 * (1 - (i2 - i1) / d)), round(100 * (s2 - s1) / d)
    except Exception:
        return None, None


def hardware():
    """Из чего сделан сервер: процессор, ядра, частота, виртуализация, swap. Только чтение /proc и /sys."""
    info = read("/proc/cpuinfo")
    m = re.search(r"^(?:model name|Model|cpu model)\s*:\s*(.+)$", info, re.M)
    model = m.group(1).strip() if m else ""
    ghz = None
    g = re.search(r"@\s*([\d.]+)\s*GHz", model)
    if g:
        ghz = float(g.group(1))
    else:
        mx = read("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").strip()
        mh = re.search(r"^cpu MHz\s*:\s*([\d.]+)", info, re.M)
        if mx.isdigit():
            ghz = int(mx) / 1e6
        elif mh:
            ghz = float(mh.group(1)) / 1000
    model = re.sub(r"\((?:R|TM|tm)\)|\bCPU\b|\bProcessor\b|@\s*[\d.]+\s*GHz|\s+\d+-Core", " ", model)
    model = re.sub(r"\s+", " ", model).strip()
    swap = 0
    for line in read("/proc/meminfo").splitlines():
        if line.startswith("SwapTotal:"):
            swap = int(line.split()[1]) // 1024
    virt = sh("systemd-detect-virt 2>/dev/null", 5)
    return {"cpu_model": model, "cores": os.cpu_count(), "ghz": round(ghz, 1) if ghz else None, "arch": os.uname().machine,
            "virt": "" if virt == "none" else virt, "swap_mb": swap}


def system():
    mem = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        mem[k] = int(v.split()[0]) if v.split() else 0
    total = mem.get("MemTotal", 0)
    avail = mem.get("MemAvailable", 0)
    du = shutil.disk_usage("/")
    osname = ""
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', read("/etc/os-release"), re.M)
    if m:
        osname = m.group(1)
    # только то, что поставит apt-get --with-new-pkgs upgrade, как кнопка «Обновления» (с новыми ядрами, но без «отложенных» пакетов, которые Ubuntu выкатывает постепенно).
    # Подсчёт тяжёлый (на сервере с 0,5 ГБ — минуты), поэтому только когда панель просит (раз в несколько часов)
    # и когда памяти хватает; иначе панель покажет прошлое число.
    upd = ""
    if globals().get("PKG_COUNT") and (mem_available_mb() or 0) >= 120:
        # считаем так же, как окно «Обновления»: пакеты из apt list --upgradable, которые apt поставит сейчас
        # (новые пакеты ядра вроде linux-image-6.8.0-NNN-generic отдельно не считаются — они идут с linux-generic)
        rc, o, _ = run("LC_ALL=C nice -n 19 apt-get -s -o Debug::NoLocking=1 --with-new-pkgs upgrade 2>/dev/null", 45)
        if rc != -9:
            inst = set(re.findall(r"^Inst (\S+)", o, re.M))
            upl = {l.split("/")[0] for l in sh("LC_ALL=C apt list --upgradable 2>/dev/null", 30).splitlines() if "/" in l}
            upd = str(len(inst & upl))
    cpu, steal = cpu_percent()
    return {
        "hostname": socket.gethostname(),
        "os": osname,
        "kernel": os.uname().release,
        "uptime_s": int(float(read("/proc/uptime").split()[0] or 0)) if read("/proc/uptime") else None,
        "load": os.getloadavg()[0],
        "cpu": cpu,
        "steal": steal,
        "hw": hardware(),
        "mem": round(100 * (total - avail) / total) if total else None,
        "mem_total_mb": total // 1024,
        "disk": round(100 * du.used / du.total),
        "disk_total_gb": round(du.total / 2**30, 1),
        "disk_free_gb": round(du.free / 2**30, 1),
        "reboot_required": os.path.exists("/var/run/reboot-required"),
        "updates": int(upd) if upd.isdigit() else None,
    }


def xray_running():
    """Процесс Xray запущен (по имени процесса; `pgrep -f` совпал бы с собственной оболочкой)."""
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                with open("/proc/%s/comm" % d) as f:
                    if f.read().startswith("xray-linux"):
                        return True
            except OSError:
                pass
    return False


def unit_exists(name):
    return bool(sh("systemctl list-unit-files %s.service --no-legend 2>/dev/null" % name))


def unit_active(name):
    return sh("systemctl is-active %s 2>/dev/null" % name) == "active"


def first_line(cmd):
    out = sh(cmd)
    return out.splitlines()[0] if out else ""


# ------------------------------------------------------------------ AWG на входе

def awg_clients():
    """Туннели входа до выходов: wg0, wg1, ..."""
    res = []
    hs = {}
    for line in sh("awg show all latest-handshakes 2>/dev/null").splitlines():
        p = line.split()
        if len(p) >= 3 and p[2].isdigit():
            hs[p[0]] = int(p[2])
    now = int(time.time())
    for f in sorted(glob.glob(AWG_DIR + "/wg*.conf")):
        iface = os.path.basename(f)[:-5]
        txt = read(f)
        m = re.search(r"^\s*Endpoint\s*=\s*(\S+)", txt, re.M)
        ep = m.group(1) if m else ""
        host = ep.rsplit(":", 1)[0] if ":" in ep else ep
        a = re.search(r"^\s*Address\s*=\s*([^\s,]+)", txt, re.M)
        t = hs.get(iface)
        res.append({
            "iface": iface,
            "endpoint": ep,
            "host": host,
            "address": a.group(1) if a else "",
            "up": unit_active("awg-quick@" + iface),
            "handshake_age": (now - t) if t else None,
        })
    return res


# ------------------------------------------------------------------ AmneziaWG: настройки наглядно (только чтение)

AWG_SECRET = {"PrivateKey", "PresharedKey"}           # не уходят с сервера вовсе
AWG_FPRINT = {"HeaderProtectionKey"}                  # общий для обоих концов — только отпечаток, чтобы сравнить


def awg_view():
    """Конфиги wgN/awgN: параметры (секреты скрыты, у общего ключа — отпечаток), пиры с именами из комментариев
    и живое состояние из `awg show all dump`: рукопожатие, трафик, откуда подключён."""
    import hashlib
    now = int(time.time())
    live, ifl = {}, {}
    for line in sh("awg show all dump 2>/dev/null").splitlines():
        f = line.split("\t")
        if len(f) == 5:                        # интерфейс: имя, приватный, публичный, порт, fwmark
            ifl[f[0]] = {"pub": f[2][:8], "port": int(f[3]) if f[3].isdigit() else None}
        elif len(f) >= 9:                      # пир: имя, публичный, psk, endpoint, allowed, handshake, rx, tx, keepalive
            hs = int(f[5]) if f[5].isdigit() else 0
            live[(f[0], f[1])] = {"endpoint": "" if f[3] == "(none)" else f[3], "handshake_age": (now - hs) if hs else None,
                                  "rx": int(f[6]) if f[6].isdigit() else 0, "tx": int(f[7]) if f[7].isdigit() else 0}
    out = []
    for path in sorted(glob.glob(AWG_DIR + "/*.conf")):
        name = os.path.basename(path)[:-5]
        if not re.match(r"^(wg|awg)\d+$", name):
            continue
        txt = read(path)
        sect, cur, iface, peers, masked, comment = None, None, {}, [], [], None
        for line in txt.splitlines():
            st = line.strip()
            m = re.match(r"^\[(\w+)\]$", st)
            if m:
                sect = m.group(1).lower()
                if sect == "peer":
                    cur = {"name": comment, "params": {}}
                    peers.append(cur)
                comment = None
                masked.append(line)
                continue
            c = re.match(r"^#\s*(?:vpn-(?:restore|client):\s*)?(.+)$", st)
            if c:
                if sect == "peer" and cur is not None and not cur["name"] and not cur["params"]:
                    cur["name"] = c.group(1).strip()[:40]      # «# vpn-restore: имя» сразу под [Peer]
                else:
                    comment = c.group(1).strip()[:40]          # комментарий перед [Peer]
                masked.append(line)
                continue
            kv = re.match(r"^([A-Za-z0-9]+)\s*=\s*(.*)$", st)
            if not kv:
                masked.append(line)
                continue
            k, v = kv.group(1), kv.group(2)
            if k in AWG_SECRET:
                masked.append("%s = ••• скрыт" % k)
                continue
            if k in AWG_FPRINT:
                v = "отпечаток " + hashlib.sha256(v.encode()).hexdigest()[:8]
                masked.append("%s = ••• (%s)" % (k, v))
            else:
                masked.append(line)
            if sect == "interface":
                iface[k] = v
            elif sect == "peer" and cur is not None:
                cur["params"][k] = v
        il = ifl.get(name, {})
        for pr in peers:
            pk = pr["params"].get("PublicKey", "")
            pr["pub"] = pk[:8]
            pr["live"] = live.get((name, pk))
            pr["params"].pop("PublicKey", None)
        out.append({"name": name, "role": "server" if "ListenPort" in iface and not any("Endpoint" in p["params"] for p in peers) else "client",
                    "up": unit_active("awg-quick@" + name), "proto": awg_proto(txt), "iface": iface, "peers": peers,
                    "port": il.get("port"), "pub": il.get("pub"), "conf": "\n".join(masked)})
    return {"ifaces": out, "sw": sw_versions().get("awg")}


# ------------------------------------------------------------------ 3X-UI на входе

def xui():
    db_path = "/etc/x-ui/x-ui.db"
    if not os.path.exists(db_path):
        return None
    out = {"active": unit_active("x-ui"), "chain": [], "inbounds": [], "sub": None, "cert_days": None}
    out["version"] = (re.findall(r"\d+\.\d+\.\d+", sh("/usr/local/x-ui/x-ui -v 2>/dev/null")) or [""])[0]
    xb = sorted(glob.glob("/usr/local/x-ui/bin/xray-linux-*"))
    out["xray"] = (re.findall(r"\d+\.\d+\.\d+", first_line("%s version 2>/dev/null" % xb[0])) or [""])[0] if xb else ""
    out["xray_running"] = xray_running()
    try:
        db = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
        st = dict(db.execute("select key, value from settings").fetchall())
        for port, remark, enable in db.execute("select port, remark, enable from inbounds"):
            out["inbounds"].append({"port": port, "remark": remark, "enable": bool(enable)})
        if st.get("subEnable", "true") != "false":
            out["sub"] = {"port": int(st.get("subPort") or 2096)}
        cert = st.get("subCertFile") or st.get("webCertFile")
        if cert and os.path.exists(cert):
            dates = dict(l.split("=", 1) for l in sh("openssl x509 -in '%s' -noout -startdate -enddate 2>/dev/null" % cert).splitlines() if "=" in l)
            ts = sh("date -d '%s' +%%s 2>/dev/null" % dates.get("notAfter", ""))
            t0 = sh("date -d '%s' +%%s 2>/dev/null" % dates.get("notBefore", ""))
            if ts.isdigit():
                out["cert_days"] = round((int(ts) - time.time()) / 86400, 1)
                if t0.isdigit():
                    out["cert_life"] = round((int(ts) - int(t0)) / 86400, 1)   # у IP-сертификатов ~6 дней
            out["acme"] = acme_info(cert)
        t = json.loads(st.get("xrayTemplateConfig") or "{}")
    except Exception as e:
        out["error"] = "x-ui.db: %s" % e
        return out

    obs = {o.get("tag"): o for o in t.get("outbounds", [])}

    def describe(tag):
        o = obs.get(tag) or {}
        so = (o.get("streamSettings") or {}).get("sockopt") or {}
        if o.get("protocol") == "freedom" and so.get("interface"):
            return {"tag": tag, "kind": "AWG", "iface": so["interface"]}
        return {"tag": tag, "kind": o.get("protocol") or "?"}

    r = t.get("routing") or {}
    bals = r.get("balancers") or []
    byl = {"_bl_" + b["tag"]: b for b in bals}
    referenced = {b.get("fallbackTag") for b in bals}
    heads = [b for b in bals if "_bl_" + b["tag"] not in referenced]
    # основная цепочка — та, на которую ведёт общее правило (без ip/domain/служебных петель)
    bal_by = {b["tag"]: b for b in bals}
    main_rule = next((x for x in reversed(r.get("rules") or []) if x.get("balancerTag") in bal_by and not x.get("ip")
                      and not x.get("domain") and not any(str(i).startswith("_bl_") for i in x.get("inboundTag") or [])), None)
    seen = set()
    b = bal_by.get(main_rule["balancerTag"]) if main_rule else (heads[0] if heads else None)
    while b is not None and b["tag"] not in seen:
        seen.add(b["tag"])
        for s in b.get("selector") or []:
            out["chain"].append(describe(s))
        b = byl.get(b.get("fallbackTag") or "")
    # отдельные правила вида «IP → конкретный выход» (например, DC5 Telegram → один из выходов)
    def bal_tags(tag):   # цепочка резерва отдельного правила (vpn-pin-chain.sh, обходы панели): A → B → C
        names, b, seen = [], bal_by.get(tag), set()
        while b is not None and b["tag"] not in seen and len(names) < 20:
            seen.add(b["tag"])
            names += b.get("selector") or []
            b = byl.get(b.get("fallbackTag") or "")
        return names
    main_tag = main_rule["balancerTag"] if main_rule else None
    out["pinned"] = []     # отдельные правила «эти IP / сайты → своя цепочка» (DC5TG, обходы)
    for x in r.get("rules", []):
        if not (x.get("ip") or x.get("domain")) or any(str(i).startswith("_bl_") for i in x.get("inboundTag") or []):
            continue
        item = {"comment": x.get("comment", ""), "ip": x.get("ip") or [], "domain": x.get("domain") or []}
        if x.get("outboundTag") not in (None, "blocked", "direct"):
            item["chain"] = [x["outboundTag"]]
        elif x.get("balancerTag") and x["balancerTag"] != main_tag:
            item["chain"] = bal_tags(x["balancerTag"])
        else:
            continue
        item["outbound"] = " → ".join(item["chain"])
        out["pinned"].append(item)
    return out


E2E_URL = "https://www.cloudflare.com/cdn-cgi/trace"   # отвечает адресом и страной, с которых пришёл запрос


def xray_e2e():
    """Сквозная проверка входа: временный клиент Xray (тот же бинарник, что у 3X-UI) подключается к своему же входу
    VLESS Reality — как телефон — и открывает страницу через все правила, цепочку резерва, DNS Xray и туннель.
    Настройки сервера не меняются: процесс живёт секунды, его файл — во временной папке и удаляется."""
    fake = "/etc/testbed-e2e-bad.json" if os.path.exists("/etc/testbed-e2e-bad.json") else "/etc/testbed-e2e.json"
    if os.path.exists(fake):
        try:
            return json.load(open(fake))
        except Exception:
            return None
    xb = [b for b in sorted(glob.glob("/usr/local/x-ui/bin/xray-linux-*")) if ".before" not in b]
    if not xb or not xray_running():
        return None
    try:
        db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
        rows = db.execute("select port, listen, remark, settings, stream_settings from inbounds where enable=1 and protocol='vless'").fetchall()
    except Exception as e:
        return {"ok": False, "skip": True, "err": "x-ui.db: %s" % e}
    why = "нет входа VLESS Reality по TCP"
    for port, listen, remark, settings, ss in rows:
        try:
            st, sv = json.loads(ss or "{}"), json.loads(settings or "{}")
        except ValueError:
            continue
        r = st.get("realitySettings") or {}
        if st.get("security") != "reality" or st.get("network", "tcp") not in ("tcp", "raw") or not r.get("privateKey"):
            continue
        if (sv.get("decryption") or "none") != "none":
            why = "вход с VLESS Encryption — такой клиент проверка не собирает"
            continue
        now_ms = time.time() * 1000
        cl = [c for c in sv.get("clients") or [] if c.get("id") and c.get("enable", True) is not False
              and not (0 < (c.get("expiryTime") or 0) < now_ms)]
        cl.sort(key=lambda c: bool(c.get("limitIp")))     # лимит по IP не трогаем: проверка — ещё один адрес
        if not cl:
            why = "у входа нет включённых клиентов"
            continue
        c = cl[0]
        flow = c.get("flow")
        if flow is None:
            try:
                flow = (db.execute("select flow from clients where email=?", (c.get("email"),)).fetchone() or [""])[0]
            except Exception:
                flow = ""
        pbk = (r.get("settings") or {}).get("publicKey")
        if not pbk:
            m = re.search(r"(?:Public key|Password[^:\n]*):\s*(\S+)", sh("%s x25519 -i '%s'" % (xb[0], r["privateKey"])))
            pbk = m and m.group(1)
        if not pbk:
            return {"ok": False, "skip": True, "port": port, "err": "не узнать открытый ключ Reality"}
        host = listen if listen and listen not in ("0.0.0.0", "::", "::0") else "127.0.0.1"
        v = {"address": host, "port": port, "id": c["id"], "flow": flow or "",
             "sni": (r.get("serverNames") or [""])[0], "pbk": pbk, "sid": next(iter(r.get("shortIds") or []), "")}
        out = _e2e_run(xb[0], port, remark, v)
        out["pc"] = dict(v, listen=listen or "")      # для проверки с ПК панели — та вынимает до сохранения статуса
        return out
    return {"ok": False, "skip": True, "err": why}


def _e2e_run(xbin, port, remark, v):
    import signal, shutil, socket, tempfile
    t0 = time.time()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    sp = s.getsockname()[1]
    s.close()
    cfg = {"log": {"loglevel": "none"},
           "inbounds": [{"listen": "127.0.0.1", "port": sp, "protocol": "socks", "settings": {"udp": False}}],
           "outbounds": [{"protocol": "vless",
                          "settings": {"vnext": [{"address": v["address"], "port": v["port"],
                                                  "users": [{"id": v["id"], "encryption": "none", "flow": v["flow"]}]}]},
                          "streamSettings": {"network": "tcp", "security": "reality",
                                             "realitySettings": {"serverName": v["sni"], "fingerprint": "chrome",
                                                                 "publicKey": v["pbk"], "shortId": v["sid"]}}}]}
    d = tempfile.mkdtemp(prefix="vpn-dash-e2e-")
    out = {"ok": False, "port": port, "remark": remark}
    p = None
    try:
        path = os.path.join(d, "c.json")
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            json.dump(cfg, f)
        p = subprocess.Popen([xbin, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
        _CHILDREN.add(p)
        for _ in range(40):                 # ждём, пока клиент начнёт слушать
            if p.poll() is not None:
                out["err"] = "временный клиент Xray не запустился: " + (p.stderr.read() or "")[-200:].strip()
                return out
            try:
                socket.create_connection(("127.0.0.1", sp), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        rc, body, err = run("curl -s -m 12 --noproxy '' -w '\\ncode=%%{http_code}' --socks5-hostname 127.0.0.1:%d %s" % (sp, E2E_URL), 15)
        kv = dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
        out["ms"] = int((time.time() - t0) * 1000)
        if kv.get("code") == "200" and kv.get("ip"):
            out.update(ok=True, ip=kv["ip"], loc=kv.get("loc", ""))
        else:
            code = kv.get("code") or "000"
            out["err"] = ("страница через вход вернула HTTP %s" % code if code != "000" else
                          "нет ответа за 12 с" if rc in (28, -9) else "соединение через вход оборвалось (curl %s)" % rc)
        return out
    finally:
        if p is not None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            p.wait()
            _CHILDREN.discard(p)
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------ диагностика (кнопка «диагностика»)

def diag():
    """Всё, что обычно просят прислать при сбое, одним махом. Только чтение; ключи и пароли сюда не попадают,
    адреса панель заменяет на имена уже у себя."""
    out = []

    def sec(title, cmd, timeout=20, tail=None):
        rc, o, e = run(cmd, timeout)
        txt = (o + (("\n" + e) if e.strip() and rc else "")).rstrip()
        if tail:
            txt = "\n".join(txt.splitlines()[-tail:])
        out.append([title, txt or "(пусто)" if rc != -9 else "(не уложилось в %d с)" % timeout])

    sec("время и нагрузка", "date -u; uptime; uname -r; free -m; df -h / | tail -1")
    sec("службы", "systemctl --no-pager --plain list-units --type=service --state=failed | head -20; echo; "
        "for u in x-ui fail2ban ufw nftables vpn-dash-govblock zapret2; do "
        "systemctl list-unit-files $u.service >/dev/null 2>&1 && printf '%-20s %s\\n' $u \"$(systemctl is-active $u)\"; done; "
        "for u in $(systemctl list-units --plain --no-legend 'awg-quick@*' | awk '{print $1}'); do printf '%-20s %s\\n' $u \"$(systemctl is-active $u)\"; done")
    x = sh("pgrep -f 'xray-linux' | head -1")
    if x:
        sec("xray: процесс, файлы, соединения",
            "ps -o pid,rss,etime,args -p %s | cut -c1-120; echo \"открыто файлов: $(ls /proc/%s/fd | wc -l) из $(awk '/open files/{print $4}' /proc/%s/limits)\"; "
            "ss -s | head -3; echo \"conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) из $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)\"; "
            "echo \"подключений к 443: $(ss -Htn state established '( sport = :443 )' | wc -l)\"" % (x, x, x))
    if shutil.which("awg") or shutil.which("wg"):
        sec("туннели AmneziaWG", "(awg show 2>/dev/null || wg show 2>/dev/null) | grep -E '^interface|endpoint|latest handshake|transfer|listening port'")
    ifs = [i for i in sh("awg show interfaces 2>/dev/null").split() if re.fullmatch(r"[\w.-]{1,15}", i) and os.path.exists("/sys/class/net/" + i)]
    if ifs:
        sec("наружу через туннели", "; ".join(
            ["printf '%s: '; curl -s -m 8 --noproxy '*' --interface %s https://ifconfig.me || echo нет; echo" % (i, i) for i in ifs]), 60)
    if os.path.exists("/etc/x-ui/x-ui.db"):
        sec("журнал x-ui (2 ч)", "journalctl -u x-ui --since '-2 hour' --no-pager | grep -vE 'accepted|TLS handshake error'", 20, 50)
        try:
            db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
            t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
            lg = (t.get("log") or {}).get("error") or ""
            if lg and lg not in ("none",):
                path = lg if lg.startswith("/") else next((p for p in ("/usr/local/x-ui/" + lg, "/usr/local/x-ui/bin/" + lg) if os.path.exists(p)), "")
                if path:
                    sec("ошибки Xray (%s)" % path, "tail -n 400 %s | grep -vE 'accepted' | tail -n 40" % path)
            r = t.get("routing") or {}
            lines = ["DNS: %s" % json.dumps((t.get("dns") or {}).get("servers"), ensure_ascii=False),
                     "наблюдатель: %s" % ("есть" if t.get("observatory") or t.get("burstObservatory") else "нет")]
            for b in r.get("balancers") or []:
                lines.append("цепочка %s → %s, запасной %s" % (b.get("tag"), b.get("selector"), b.get("fallbackTag") or "—"))
            for i, x in enumerate(r.get("rules") or []):
                if any(str(t).startswith("_bl_") for t in x.get("inboundTag") or []):
                    continue
                k = {f: x[f] for f in ("inboundTag", "domain", "ip", "port", "network", "protocol") if f in x}
                k = {f: (v[:3] + ["…"] if isinstance(v, list) and len(v) > 3 else v) for f, v in k.items()}
                lines.append("правило %d %s → %s" % (i, json.dumps(k, ensure_ascii=False), x.get("balancerTag") or x.get("outboundTag")))
            out.append(["маршрутизация Xray", "\n".join(lines)])
        except Exception as e:
            out.append(["маршрутизация Xray", "не прочитать: %s" % e])
    sec("ядро (dmesg)", "dmesg -T 2>/dev/null | grep -iE 'conntrack|oom|killed process|table full|segfault|amnezia|link is down|hung task' | tail -n 15")
    sec("фаервол", "ufw status 2>/dev/null | head -25; echo; nft list tables 2>/dev/null")
    print(json.dumps({"sections": out}, ensure_ascii=False))


# ------------------------------------------------------------------ веб-панель 3X-UI

def acme_conf(cert=None):
    """Настройки acme.sh для сертификата (или все): когда следующее продление и как проверяется сервер."""
    res = []
    for f in glob.glob("/root/.acme.sh/*/*.conf"):
        if f.endswith(".csr.conf") or os.path.basename(f) == "account.conf":
            continue
        kv = dict(re.findall(r"^(Le_\w+)='([^']*)'", read(f), re.M))
        if not kv.get("Le_Domain"):
            continue
        if cert and cert not in (kv.get("Le_RealFullChainPath"), kv.get("Le_RealCertPath")):
            continue
        res.append(kv)
    return res


def ufw_port_open(port):
    """Пропускает ли ufw порт снаружи: None — ufw выключен (пропускает всё), True/False — есть ли правило allow."""
    if not shutil.which("ufw"):
        return None
    out = sh("ufw status 2>/dev/null", 10)
    if "Status: active" not in out:
        return None
    return bool(re.search(r"^(?:allow\s+)?%d(?:/tcp)?(?:\s+(?:ALLOW|comment)|\s*$)" % port, out, re.M | re.I))


def acme_info(cert):
    """Сертификат продлевает acme.sh сам? Для проверки «standalone» Let's Encrypt стучится на порт 80 —
    если ufw его закрыл, продление не пройдёт."""
    cf = acme_conf(cert)
    if not cf:
        return None
    kv = cf[0]
    nxt = kv.get("Le_NextRenewTime", "")
    standalone = kv.get("Le_Webroot", "") == "no"
    return {"next": int(nxt) if nxt.isdigit() else None, "standalone": standalone,
            "port80": ufw_port_open(80) if standalone else None,
            "cron": bool(re.search(r"acme\.sh.*--cron", sh("crontab -l 2>/dev/null")))}


def awg_proto(text):
    """Какая версия протокола AmneziaWG в конфиге: 3.x — HeaderProtectionKey/ContentPaddingAddition/…, 2.0 — S3/S4 или диапазоны в H1–H4, 1.5 — пакеты I1–I5,
    1.0 — Jc/S1/H1…, иначе обычный WireGuard."""
    keys = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$", line)
        if m:
            keys[m.group(1)] = m.group(2)
    if any(k in keys for k in ("HeaderProtectionKey", "ContentPaddingAddition", "RandomTrailers", "DisableCookies",
                               "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts")):
        return "3.x"     # защита самого потока: шифрование заголовков, добивка пакетов, случайные таймеры
    if "S3" in keys or "S4" in keys or any("-" in keys.get("H%d" % i, "") for i in range(1, 5)):
        return "2.0"
    if any("I%d" % i in keys for i in range(1, 6)):
        return "1.5"
    if any(k in keys for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")):
        return "1.0"
    return "wg"


def sw_versions():
    """Версия AmneziaWG: пакеты и модуль ядра (в памяти и на диске — после обновления пакета они расходятся
    до перезапуска), версия протокола в каждом конфиге."""
    out = {}
    if shutil.which("awg") or glob.glob(AWG_DIR + "/*.conf"):
        pk = {}
        for line in sh("dpkg-query -W -f='${Package} ${Version}\\n' amneziawg amneziawg-dkms amneziawg-tools 2>/dev/null").splitlines():
            f = line.split()
            if len(f) == 2:
                pk[f[0]] = f[1]
        cand = {}
        for name in pk:
            m = re.search(r"Candidate:\s*(\S+)", sh("apt-cache policy %s 2>/dev/null" % name))
            if m and m.group(1) != "(none)":
                cand[name] = m.group(1)
        out["awg"] = {"pkg": pk, "cand": cand,
                      "mod_loaded": read("/sys/module/amneziawg/version").strip() or None,
                      "mod_disk": sh("modinfo -F version amneziawg 2>/dev/null") or None,
                      "proto": {os.path.basename(f)[:-5]: awg_proto(read(f)) for f in sorted(glob.glob(AWG_DIR + "/*.conf"))
                                if re.match(r"^(wg\d+|awg\d+)\.conf$", os.path.basename(f))}}
    return out


def web_listen_addrs(port):
    """На каких адресах сейчас слушает порт (по ss)."""
    out = []
    for line in sh("ss -Htln 'sport = :%d' 2>/dev/null" % port).splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append(f[3].rsplit(":", 1)[0].split("%")[0])
    return out


def gov_info():
    """«Сети госорганов» (govblock.py): включено ли, сколько сетей, от какого числа список, сколько подключений отброшено."""
    meta = read("/etc/vpn-dash/govblock.json")
    if not meta and not os.path.exists("/etc/vpn-dash/govblock.nft"):
        return None
    try:
        m = json.loads(meta) if meta else {}
    except ValueError:
        m = {}
    out = sh("nft list chain inet vpn_dash_gov input 2>/dev/null")
    drops = sum(int(x) for x in re.findall(r"counter packets (\d+)", out))
    return {"on": bool(out.strip()), "boot": unit_active("vpn-dash-govblock") or
            sh("systemctl is-enabled vpn-dash-govblock 2>/dev/null").strip() == "enabled",
            "undo": os.path.exists("/root/.vpn-dash-gov-undo"), "drops": drops, "meta": m}


def reality_mask():
    """Под какой сайт маскируется Reality и открывается ли он С ЭТОГО СЕРВЕРА так, как его будет открывать Xray для
    чужих (проверка со стороны, сканер ТСПУ): TLS 1.3, h2, настоящий сертификат на имя из serverNames.
    Сайт пропал или сертификат не тот — Reality остаётся без «прикрытия», проверка увидит ошибку вместо сайта."""
    import ssl
    out = []
    try:
        db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
        rows = db.execute("select port, remark, stream_settings from inbounds where enable=1").fetchall()
    except Exception:
        return out
    for port, remark, ss in rows:
        try:
            st = json.loads(ss or "{}")
        except ValueError:
            continue
        if st.get("security") != "reality":
            continue
        r = st.get("realitySettings") or {}
        names = [n for n in r.get("serverNames") or [] if n]
        dest = str(r.get("target") or r.get("dest") or "").strip()
        m = re.match(r"^\[?([^\]]+?)\]?(?::(\d+))?$", dest)
        if not dest or dest.startswith(("/", "@")) or not m:
            out.append({"port": port, "remark": remark, "names": names, "dest": dest, "skip": True})
            continue
        host, dport = m.group(1), int(m.group(2) or 443)
        sni = names[0] if names else host
        it = {"port": port, "remark": remark, "names": names, "dest": dest, "sni": sni}
        t0 = time.time()
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((host, dport), timeout=5) as sock:
                sock.settimeout(6)
                with ctx.wrap_socket(sock, server_hostname=sni) as t:
                    na = (t.getpeercert() or {}).get("notAfter")
                    it.update(ok=True, tls=t.version(), alpn=t.selected_alpn_protocol(), ip=t.getpeername()[0],
                              ms=int((time.time() - t0) * 1000),
                              days=int((ssl.cert_time_to_seconds(na) - time.time()) // 86400) if na else None)
        except ssl.SSLCertVerificationError as e:
            it.update(ok=False, err="cert", why=str(getattr(e, "verify_message", "") or e)[:120])
        except socket.gaierror:
            it.update(ok=False, err="dns")
        except socket.timeout:
            it.update(ok=False, err="timeout")
        except ConnectionRefusedError:
            it.update(ok=False, err="refused")
        except ssl.SSLError as e:
            it.update(ok=False, err="tls", why=str(e)[:120])
        except OSError as e:
            it.update(ok=False, err="net", why=str(e)[:120])
        out.append(it)
    return out[:6]


def web_info():
    """Где слушает веб-панель 3X-UI. Путь панели нужен нашей панели, чтобы открыть её через SSH; на страницу он не уходит."""
    if not os.path.exists("/etc/x-ui/x-ui.db"):
        return None
    try:
        db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
        st = dict(db.execute("select key, value from settings where key in "
                             "('webPort','webListen','webBasePath','webCertFile','webKeyFile','webDomain')").fetchall())
        db.close()
    except Exception as e:
        return {"error": "x-ui.db: %s" % e}
    port = int(st.get("webPort") or 2053)
    path = "/" + (st.get("webBasePath") or "/").strip("/") + "/"
    addrs = web_listen_addrs(port)
    local = lambda a: a.startswith("127.") or a in ("[::1]", "localhost")
    return {"port": port, "listen": st.get("webListen") or "", "path": path.replace("//", "/"),
            "https": bool(st.get("webCertFile") and st.get("webKeyFile")), "domain": st.get("webDomain") or "",
            "up": bool(addrs), "exposed": any(not local(a) for a in addrs)}


# ------------------------------------------------------------------ выход

def exit_info():
    res = {"awg": None, "xui_present": os.path.exists("/usr/local/x-ui/x-ui"), "xui": None}
    if res["xui_present"]:              # 3X-UI на выходе: работает ли, версия, сколько включённых входящих
        xi = {"active": unit_active("x-ui"),
              "version": (re.findall(r"\d+\.\d+\.\d+", sh("/usr/local/x-ui/x-ui -v 2>/dev/null")) or [""])[0], "inbounds": None}
        try:
            db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
            xi["inbounds"] = db.execute("select count(*) from inbounds where enable=1").fetchone()[0]
            db.close()
        except Exception:
            pass
        res["xui"] = xi
    names, dump, mode, container = {}, "", None, ""
    if shutil.which("docker"):
        cs = [c for c in sh("docker ps --format '{{.Names}}' 2>/dev/null").splitlines() if c.startswith("amnezia-awg")]
        if cs:
            container, mode = cs[0], "docker"
            dump = sh("docker exec %s awg show all dump 2>/dev/null" % container)
            try:
                for c in json.loads(sh("docker exec %s cat /opt/amnezia/awg/clientsTable 2>/dev/null") or "[]"):
                    names[c.get("clientId")] = (c.get("userData") or {}).get("clientName", "")
            except Exception:
                pass
    if mode is None and os.path.exists(AWG_DIR + "/awg0.conf"):
        mode = "native"
        dump = sh("awg show all dump 2>/dev/null")
        cur = None
        for line in read(AWG_DIR + "/awg0.conf").splitlines():
            m = re.match(r"\s*#\s*vpn-(?:restore|client):\s*(\S+)", line)
            if m:
                cur = m.group(1)
            m = re.match(r"\s*PublicKey\s*=\s*(\S+)", line)
            if m and cur:
                names[m.group(1)] = cur
                cur = None
    if mode:
        now = int(time.time())
        peers, port = [], None
        for line in dump.splitlines():
            f = line.split("\t")
            if len(f) >= 8 and "/" in f[4]:
                hs = int(f[5]) if f[5].isdigit() else 0
                peers.append({"name": names.get(f[1], ""), "ip": f[4].split(",")[0], "endpoint": f[3],
                              "handshake_age": (now - hs) if hs else None,
                              "rx": int(f[6]) if f[6].isdigit() else 0, "tx": int(f[7]) if f[7].isdigit() else 0})
            elif len(f) >= 4 and port is None and f[3].isdigit():
                port = int(f[3])
        if mode == "docker":
            hp = sh("docker port %s 2>/dev/null | grep udp | head -n1" % container)
            port = int(hp.rsplit(":", 1)[-1]) if hp.rsplit(":", 1)[-1].isdigit() else port
        res["awg"] = {"mode": mode, "container": container, "port": port, "peers": peers,
                      "up": (bool(container) if mode == "docker" else unit_active("awg-quick@awg0"))}
    return res


# ------------------------------------------------------------------ фаервол: что слушает и что уже есть (только чтение)

def fw_audit():
    out = {"listen": [], "awg": {}, "awg_server": [], "docker": [], "ssh_ports": [], "xui": None,
           "ufw": None, "firewalld": unit_active("firewalld"), "ipt": {}, "nft_lines": 0, "ip_forward": read("/proc/sys/net/ipv4/ip_forward").strip(),
           "default_if": "", "fwd_ok": []}
    for line in sh("ss -Htulnp 2>/dev/null").splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        addr, _, port = f[4].rpartition(":")
        dev = ""
        if "%" in addr:
            addr, dev = addr.split("%", 1)
        m = re.search(r'\(\("([^"]+)"', line)
        out["listen"].append({"proto": f[0], "addr": addr, "port": int(port) if port.isdigit() else 0, "dev": dev,
                              "proc": m.group(1) if m else ""})
    for tool in ("awg", "wg"):
        if shutil.which(tool):
            for line in sh("%s show all listen-port 2>/dev/null" % tool).splitlines():
                p = line.split()
                if len(p) == 2 and p[1].isdigit():
                    out["awg"][p[0]] = int(p[1])
    for f in glob.glob(AWG_DIR + "/*.conf") + glob.glob("/etc/wireguard/*.conf"):
        if re.search(r"^\s*ListenPort\s*=", read(f), re.M):      # сервер туннеля: через него пересылается трафик
            out["awg_server"].append(os.path.basename(f)[:-5])
    if shutil.which("docker"):
        for line in sh("docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null").splitlines():
            n, _, ports = line.partition("\t")
            out["docker"].append({"name": n, "ports": ports})
    out["ssh_ports"] = sorted({int(x) for x in re.findall(r"^port (\d+)", sh("sshd -T 2>/dev/null"), re.M)})
    if os.path.exists("/etc/x-ui/x-ui.db"):
        try:
            db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=5)
            st = dict(db.execute("select key, value from settings").fetchall())
            ibs = [{"port": p, "listen": l or "", "remark": r or "", "protocol": pr}
                   for p, l, r, pr in db.execute("select port, listen, remark, protocol from inbounds where enable=1")]
            db.close()
            out["xui"] = {"inbounds": ibs, "web_port": int(st.get("webPort") or 2053),
                          "sub_port": int(st.get("subPort") or 2096) if st.get("subEnable", "true") != "false" else None}
        except Exception as e:
            out["xui"] = {"error": str(e)}
    out["acme_standalone"] = any(kv.get("Le_Webroot") == "no" for kv in acme_conf())
    if shutil.which("ufw"):
        st = sh("ufw status verbose 2>/dev/null")
        out["ufw"] = {"active": "Status: active" in st, "status": st[:3000],
                      "added": [l for l in sh("ufw show added 2>/dev/null").splitlines() if l.startswith("ufw ")][:40]}
    for ch in ("INPUT", "FORWARD"):
        rules = sh("iptables -S %s 2>/dev/null" % ch).splitlines()
        pol = next((r.split()[-1] for r in rules if r.startswith("-P ")), "")
        own = [r for r in rules if r.startswith("-A ") and not re.search(r"ufw|DOCKER|f2b-", r)]
        out["ipt"][ch] = {"policy": pol, "own": own[:30], "f2b": any("f2b-" in r for r in rules)}
    out["nft_lines"] = len(sh("nft list ruleset 2>/dev/null").splitlines())
    m = re.search(r"\bdev (\S+)", sh("ip -o route show default 2>/dev/null"))
    out["default_if"] = m.group(1) if m else ""
    for r in out["ipt"].get("FORWARD", {}).get("own", []):
        m = re.search(r"-[io] (\S+).*-j ACCEPT", r)
        if m:
            out["fwd_ok"].append(m.group(1))
    return out


# ------------------------------------------------------------------ Telegram DC

def _aes_ctr(key, iv, data):
    """AES-256-CTR через openssl (есть почти везде: от него зависит ca-certificates). None — openssl нет."""
    if not shutil.which("openssl"):
        return None
    p = subprocess.run(["openssl", "enc", "-aes-256-ctr", "-K", key.hex(), "-iv", iv.hex(), "-nosalt"],
                       input=data, capture_output=True, timeout=10)
    return p.stdout if p.returncode == 0 and len(p.stdout) == len(data) else None


def mtproto_hello(sock, dc_id):
    """Первый шаг входа в Telegram, как у приложения: obfuscated2 + req_pq_multi, ждём res_pq с нашим nonce.
    Порт 443 может открываться, а Telegram за ним — молчать (так бывает, когда DC режут по пути).
    Повторяет проверку censorcheck (github.com/vernette/censorcheck, MIT), переписано на Python.
    True — DC ответил как Telegram; False — нет; None — нечем шифровать (нет openssl)."""
    import struct
    while True:
        h = bytearray(os.urandom(64))
        if h[0] == 0xEF or bytes(h[:4]) in (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xdd" * 4, b"\xee" * 4, b"\x16\x03\x01\x02") \
                or h[4:8] == b"\0\0\0\0":
            continue
        break
    h[56:60] = b"\xee" * 4                                 # «intermediate»-обёртка
    h[60:62] = struct.pack("<h", dc_id)
    nonce = os.urandom(16)
    req = struct.pack("<I", 40) + b"\0" * 8 + struct.pack("<II", 0, int(time.time())) + struct.pack("<I", 20) \
        + bytes.fromhex("f18e7ebe") + nonce                # длина, auth_key_id=0, msg_id, длина, req_pq_multi, nonce
    sealed = _aes_ctr(bytes(h[8:40]), bytes(h[40:56]), bytes(h) + req)
    if sealed is None:
        return None
    sock.sendall(bytes(h[:56]) + sealed[56:])
    reply = b""
    while len(reply) < 44:
        part = sock.recv(44 - len(reply))
        if not part:
            return False
        reply += part
    rev = bytes(h[8:56])[::-1]
    plain = _aes_ctr(rev[:32], rev[32:48], reply)
    return bool(plain) and plain[24:28] == bytes.fromhex("63241605") and plain[28:44] == nonce


def dc_check():
    out = {}

    def one(name, ip):
        dc_id = int((re.findall(r"\d+", name) or ["2"])[0]) or 2
        res = {"ok": False}
        for _ in range(2):                              # как у censorcheck: вторая попытка, если первая сорвалась
            t = time.time()
            try:
                s = socket.create_connection((ip, 443), timeout=5)
            except OSError as e:
                res = {"ok": False, "tcp": False, "error": str(e)[:60]}
                continue
            tcp_ms = round((time.time() - t) * 1000)
            try:
                s.settimeout(5)
                mt = mtproto_hello(s, dc_id)
            except (OSError, subprocess.SubprocessError) as e:
                mt, err = False, str(e)[:60]
            else:
                err = "" if mt else "не ответил как Telegram"
            finally:
                s.close()
            if mt is None:                              # нет openssl — как раньше, только порт
                res = {"ok": True, "tcp": True, "mt": None, "ms": tcp_ms}
                break
            res = {"ok": mt, "tcp": True, "mt": mt, "tcp_ms": tcp_ms}
            if mt:
                res["ms"] = round((time.time() - t) * 1000)
                break
            res["error"] = "порт 443 открыт, но Telegram молчит" + (" (%s)" % err if err and "Telegram" not in err else "")
        out[name] = res

    th = [threading.Thread(target=one, args=x) for x in TG_DC]
    for x in th:
        x.start()
    for x in th:
        x.join()
    return [dict(name=n, ip=ip, **out[n]) for n, ip in TG_DC]


# ------------------------------------------------------------------ проверка нового сервера перед установкой

def tcp_ms(host, port, tries=3):
    """Медиана времени TCP-подключения в мс, или None."""
    res = []
    for _ in range(tries):
        t = time.time()
        try:
            socket.create_connection((host, int(port)), timeout=4).close()
            res.append(round((time.time() - t) * 1000))
        except OSError:
            pass
    return sorted(res)[len(res) // 2] if res else None


def precheck():
    out = {}
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', read("/etc/os-release"), re.M))
    out["os"] = {"pretty": osr.get("PRETTY_NAME", ""), "id": osr.get("ID", ""), "version": osr.get("VERSION_ID", "")}
    out["virt"] = sh("systemd-detect-virt 2>/dev/null") or "unknown"
    out["kernel"] = sh("uname -r")
    pol = sh("apt-cache policy linux-headers-$(uname -r) 2>/dev/null", 30)
    m = re.search(r"Candidate:\s*(\S+)", pol)
    out["headers"] = bool(m and m.group(1) != "(none)") or os.path.isdir("/lib/modules/%s/build" % out["kernel"])
    out["cpu"] = os.cpu_count()
    out["cpu_model"] = (re.findall(r"^model name\s*:\s*(.+)$", read("/proc/cpuinfo"), re.M) or [""])[0]
    mem = dict((l.split(":")[0], int(l.split()[1])) for l in read("/proc/meminfo").splitlines() if l.split()[1:2])
    out["mem_mb"] = round(mem.get("MemTotal", 0) / 1024)
    out["swap_mb"] = round(mem.get("SwapTotal", 0) / 1024)
    du = shutil.disk_usage("/")
    out["disk_gb"], out["disk_free_gb"] = round(du.total / 2**30, 1), round(du.free / 2**30, 1)
    found = []
    for name, test in (("Docker", "command -v docker"), ("3X-UI", "test -e /usr/local/x-ui/x-ui"), ("nginx", "command -v nginx"),
                       ("Apache", "command -v apache2"), ("WireGuard", "command -v wg"), ("AmneziaWG", "command -v awg"),
                       ("Marzban", "test -d /opt/marzban"), ("Outline", "test -d /opt/outline")):
        if subprocess.run(test, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            found.append(name)
    out["software"] = found
    ports = []
    for line in sh("ss -Hltnup 2>/dev/null").splitlines():
        p = line.split()
        if len(p) >= 5:
            port = p[4].rsplit(":", 1)[-1]
            proc = (re.findall(r'"([^"]+)"', line) or [""])[0]
            if port.isdigit():
                ports.append({"proto": p[0], "port": int(port), "proc": proc})
    out["ports"] = sorted({(x["proto"], x["port"], x["proc"]) for x in ports})
    out["ipv4"] = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", sh("ip -4 -o addr show scope global"))
    out["ipv6"] = re.findall(r"inet6 ([0-9a-f:]+)/", sh("ip -6 -o addr show scope global"))
    out["public_ip"] = sh("curl -4 -s -m 8 https://ifconfig.me", 12)
    dns = {}
    for h in ("github.com", "raw.githubusercontent.com", "ppa.launchpadcontent.net"):
        try:
            socket.getaddrinfo(h, 443)
            dns[h] = True
        except OSError:
            dns[h] = False
    out["dns"] = dns
    web = {}
    for u in ("https://github.com", "https://raw.githubusercontent.com", "https://ppa.launchpadcontent.net"):
        code = sh("curl -s -o /dev/null -m 10 -w '%%{http_code}' %s" % u, 15)
        web[u.split("//")[1]] = code not in ("", "000")
    out["web"] = web
    out["updates"] = len([l for l in sh("apt list --upgradable 2>/dev/null", 60).splitlines() if "/" in l])
    out["reboot_required"] = os.path.exists("/var/run/reboot-required")
    out["dc"] = dc_check()
    out["lat"] = {name: tcp_ms(h, p) for name, h, p in globals().get("TARGETS_OVERRIDE") or []}
    return out


# ------------------------------------------------------------------ конфигурация входа для сравнения

SECRET_RE = re.compile(r"(private|secret|password|passwd|token|psk|presharedkey|^key$|shortids?|^id$|uuid|sub_?id)", re.I)
VOLATILE_RE = re.compile(r"^(id|user_id|up|down|total|all_time|alltime|last_online|lastonline|online|"
                         r".*traffic.*|.*_at|.*At|last_.*|.*_time_reset.*)$")


def fp(v):
    import hashlib
    return "#" + hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest()[:8]


def scrub(o, key=""):
    """Секреты → отпечаток: сравнить можно, прочитать нельзя."""
    if key and SECRET_RE.search(key):
        return fp(o)
    if isinstance(o, dict):
        return {k: scrub(v, k) for k, v in o.items()}
    if isinstance(o, list):
        return [scrub(v, key) for v in o]
    return o


def maybe_json(v):
    if isinstance(v, str) and v[:1] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            pass
    return v


def config_snapshot():
    out = {}
    db_path = "/etc/x-ui/x-ui.db"
    if os.path.exists(db_path):
        db = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        x = {}
        st = dict(db.execute("select key, value from settings").fetchall())
        x["template"] = scrub(maybe_json(st.pop("xrayTemplateConfig", "{}")))
        x["settings"] = scrub({k: v for k, v in st.items()
                               if not re.search(r"(CertFile|KeyFile|Domain|Listen)$", k)})
        ib_names = {}
        x["inbounds"] = {}
        for r in db.execute("select * from inbounds"):
            d = dict(r)
            name = "%s:%s" % (d.get("remark") or "", d.get("port"))
            ib_names[d.get("id")] = name
            x["inbounds"][name] = scrub({k: maybe_json(v) for k, v in d.items() if not VOLATILE_RE.match(k)})
        if "clients" in tables:
            cl_names = {}
            x["clients"] = {}
            for r in db.execute("select * from clients"):
                d = dict(r)
                name = d.get("email") or d.get("name") or str(d.get("id"))
                cl_names[d.get("id")] = name
                x["clients"][name] = scrub({k: maybe_json(v) for k, v in d.items() if not VOLATILE_RE.match(k)})
            if "client_inbounds" in tables:
                cols = [c[1] for c in db.execute("pragma table_info(client_inbounds)")]
                ccol = next((c for c in cols if c.startswith("client")), None)
                icol = next((c for c in cols if c.startswith("inbound")), None)
                if ccol and icol:
                    links = {}
                    for r in db.execute("select %s, %s from client_inbounds" % (ccol, icol)):
                        links.setdefault(cl_names.get(r[0], str(r[0])), []).append(ib_names.get(r[1], str(r[1])))
                    for k in links:
                        x["clients"].setdefault(k, {})["inbounds"] = sorted(links[k])
        out["xui"] = x
    awg = {}
    for f in sorted(glob.glob(AWG_DIR + "/wg*.conf")):
        d = {}
        for line in read(f).splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = (s.strip() for s in line.split("=", 1))
                if k in ("PrivateKey", "PresharedKey", "Address", "DNS"):
                    continue          # у каждого входа свои — это нормально
                d[k] = v
        awg[os.path.basename(f)[:-5]] = d
    out["awg"] = awg
    return out


# ------------------------------------------------------------------ обновления пакетов (только чтение)

def apt_locked():
    """Занят ли apt прямо сейчас: держит ли кто-то его замки. По именам процессов судить нельзя —
    служба unattended-upgrades висит в памяти всегда, даже когда ничего не ставит."""
    import fcntl
    for f in ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock"):
        try:
            fd = os.open(f, os.O_RDWR)
        except OSError:
            continue
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)     # взять и сразу отпустить — так проверяет и сам apt
            fcntl.lockf(fd, fcntl.LOCK_UN)
        except OSError:
            return True
        finally:
            os.close(fd)
    return False


def pkgs_info(refresh=False):
    env = "LC_ALL=C DEBIAN_FRONTEND=noninteractive "
    out = {}
    if refresh:     # обновить списки пакетов — то же, что делает сама Ubuntu раз в сутки (apt-daily)
        rc, _, err = run(env + "apt-get update -q -o DPkg::Lock::Timeout=60", 150)
        out["refresh_rc"] = rc
        if rc:
            out["refresh_err"] = "не уложилось в 2,5 минуты" if rc == -9 else (err.strip().splitlines() or [""])[-1][:300]
    sim = sh(env + "nice -n 10 apt-get -s -o Debug::NoLocking=1 --with-new-pkgs upgrade 2>/dev/null", 90)
    inst = set(re.findall(r"^Inst (\S+)", sim, re.M))
    items = []
    for line in sh(env + "apt list --upgradable 2>/dev/null", 60).splitlines():
        m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            name, suite, new, old = m.groups()
            items.append({"name": name, "suite": suite, "new": new, "old": old,
                          "held": name not in inst, "security": "security" in suite})
    out["items"] = items
    lists = glob.glob("/var/lib/apt/lists/*_InRelease")
    out["lists_at"] = int(max(os.path.getmtime(f) for f in lists)) if lists else None
    out["reboot_required"] = os.path.exists("/var/run/reboot-required")
    out["reboot_pkgs"] = sorted(set(read("/var/run/reboot-required.pkgs").split()))
    out["kernel"] = os.uname().release
    out["uptime_s"] = int(float(read("/proc/uptime").split()[0] or 0)) if read("/proc/uptime") else None
    out["docker"] = sh("docker ps --format '{{.Names}}' 2>/dev/null", 15).split()
    out["dpkg_busy"] = apt_locked()
    return out


# ------------------------------------------------------------------ проверка сайта через каналы (только чтение)

def site_check(urls, channels, diag=False):
    """Открыть каждый адрес через каждый канал: туннель до выхода (--interface wgN) или напрямую.
    diag — для неоткрывшихся напрямую адресов выяснить почему: DNS, TCP или режут по имени сайта (SNI)."""
    import shlex
    import urllib.parse
    from concurrent.futures import ThreadPoolExecutor

    def dns_via(host, iface):
        """Адрес сайта глазами выхода: DNS-запрос к 1.1.1.1 (потом 8.8.8.8) через сам туннель.
        Иначе адрес даёт DNS входа в России — для видео и картинок это бывают кэш-серверы внутри
        российских сетей, до которых из-за границы не достучаться, и проверка врёт."""
        import random
        import struct as st
        qid = random.randint(0, 65535)
        q = st.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(
            bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\0" + st.pack(">HH", 1, 1)
        for srv in ("1.1.1.1", "8.8.8.8"):
            s_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s_.setsockopt(socket.SOL_SOCKET, 25, iface.encode())     # SO_BINDTODEVICE
                s_.settimeout(3)
                s_.sendto(q, (srv, 53))
                data = s_.recv(2048)
            except OSError:
                continue
            finally:
                s_.close()
            if len(data) < 12 or st.unpack(">H", data[:2])[0] != qid:
                continue
            an = st.unpack(">H", data[6:8])[0]
            i = 12
            while data[i]:
                i += data[i] + 1
            i += 5
            for _ in range(an):
                if data[i] & 0xC0 == 0xC0:
                    i += 2
                else:
                    while data[i]:
                        i += data[i] + 1
                    i += 1
                typ, _cl, _ttl, ln = st.unpack(">HHIH", data[i:i + 10])
                i += 10
                if typ == 1 and ln == 4:
                    return ".".join(str(b) for b in data[i:i + 4])
                i += ln
        return None

    def curl(u, ch, resolve=None):
        a = ["curl", "-4", "-s", "-m", "10", "-o", "/dev/null", "-A", "Mozilla/5.0",
             "-w", "%{http_code} %{time_total} %{remote_ip}"]
        if u.startswith("https://api.anthropic.com/v1/"):   # API без ключа: 401 — пускает, 403 — не пускает по стране
            a += ["-X", "POST", "-H", "anthropic-version: 2023-06-01", "-H", "content-type: application/json", "-d", "{}"]
        if ch.get("iface"):
            a += ["--interface", ch["iface"]]
            if not resolve:
                host = urllib.parse.urlparse(u).hostname
                try:
                    ip = dns_via(host, ch["iface"])
                except Exception:   # noqa: BLE001 — не вышло: пусть решает DNS входа
                    ip = None
                if ip:
                    resolve = "%s:443:%s" % (host, ip)
        if resolve:
            a += ["--resolve", resolve]
        rc, o, _ = run(" ".join(shlex.quote(x) for x in a + [u]), 14)
        f = o.split()
        code = int(f[0]) if f and f[0].isdigit() else 0
        try:
            t = round(float(f[1]), 2) if len(f) > 1 else 0
        except ValueError:
            t = 0
        return {"code": code, "t": t, "ip": f[2] if len(f) > 2 else ""}

    jobs = [(c, u) for c in channels for u in urls]
    with ThreadPoolExecutor(max_workers=min(24, max(1, len(jobs)))) as ex:
        res = list(ex.map(lambda j: curl(j[1], j[0]), jobs))
    out = {}
    for (c, u), r in zip(jobs, res):
        out.setdefault(c["key"], {})[u] = r
    why = {}
    if diag:
        for u in urls:
            if any(out[c["key"]][u]["code"] for c in channels):
                continue
            host = urllib.parse.urlparse(u).hostname
            ips = sh("getent ahostsv4 %s | awk 'NR==1{print $1}'" % shlex.quote(host), 8)
            if not ips:
                why[u] = "dns"
                continue
            rc, _, _ = run("timeout 5 bash -c '</dev/tcp/%s/443'" % ips, 7)
            if rc != 0:
                why[u] = "tcp"
                continue
            ctl = curl("https://www.google.com/generate_204", {}, "www.google.com:443:%s" % ips)
            why[u] = "sni" if ctl["code"] else "tls"      # тот же адрес с другим именем сайта открывается → режут по имени
    return {"res": out, "why": why}


# ------------------------------------------------------------------ что режут по пути напрямую (ТСПУ на входах)

def dpi_check(sites):
    """Открыть сайты прямо с этого сервера, мимо туннелей, и для неоткрывшихся выяснить, как именно режут.
    Те же приёмы, что у censorcheck --mode dpi/dns (github.com/vernette/censorcheck, MIT), плюс разбор причины:
      dns   — DNS хостера не даёт адреса;     spoof — даёт неверный (с адресом от DoH сайт открывается);
      ip    — не открывается соединение;     sni   — TLS с именем сайта рвётся, с чужим именем — проходит;
      stall — соединение есть, но данные обрываются (типично ~16 КБ); tls — TLS не проходит ни с каким именем;
      stub  — чужой сертификат (заглушка);    denied — сайт сам отвечает 403/451.
    sites: [[имя, путь], …]."""
    import ipaddress
    import shlex
    import ssl
    from concurrent.futures import ThreadPoolExecutor

    fake = "/etc/testbed-dpi.json"           # стенд: {"IP входа": {"youtube.com": "sni", …}}
    if os.path.exists(fake):
        me = ((os.environ.get("SSH_CONNECTION") or "").split()[2:3] or [""])[0]
        try:
            rules = json.load(open(fake)).get(me, {})
        except Exception:
            rules = {}
        time.sleep(1.5)
        zl = []        # стенд: zapret2 «включён» — адреса его списков открываются
        if "zapret2=active" in read("/etc/testbed-units"):
            for f in glob.glob("/opt/zapret2/ipset/vpn-dash-*.txt"):
                zl += read(f).split()
        out = {}
        for host, _ in sites:
            st = rules.get(host, "ok")
            if st in ("sni", "stall", "tls") and any(host == d or host.endswith("." + d) for d in zl) \
                    and not os.path.exists("/etc/testbed-zapret-nohelp"):
                st = "ok"
            out[host] = {"st": st, "ip": "203.0.113.%d" % (len(host) * 7 % 250), "t": round(0.3 + len(host) % 7 / 10, 1)}
            if st == "stall":
                out[host]["kb"] = 16
            if st == "slow":
                out[host]["t"] = 4.2
            if st == "spoof":
                out[host]["dns_ip"] = "10.10.34.36"
        return out

    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"

    def sys_ips(host):
        try:
            return list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)))
        except OSError:
            return []

    def doh(host):
        """Адреса мимо DNS хостера — DoH Cloudflare, потом Google. None — DoH не ответил."""
        for url in ("https://1.1.1.1/dns-query?name=%s&type=A", "https://8.8.8.8/resolve?name=%s&type=A"):
            o = sh("curl -4 -s -m 6 -H 'accept: application/dns-json' %s" % shlex.quote(url % host), 8)
            try:
                ans = json.loads(o).get("Answer") or []
            except ValueError:
                continue
            return [a["data"] for a in ans if a.get("type") == 1]
        return None

    def fetch(host, path, ip):
        a = ["curl", "-4", "-s", "-L", "--max-redirs", "3", "-o", "/dev/null", "-m", "10", "--connect-timeout", "6",
             "-A", UA, "-H", "Accept-Language: en-US,en;q=0.5", "-w", "%{http_code} %{time_total} %{size_download}",
             "--resolve", "%s:443:%s" % (host, ip), "https://%s%s" % (host, path)]
        rc, o, _ = run(" ".join(shlex.quote(x) for x in a), 14)
        f = (o.split() + ["0", "0", "0"])[:3]
        try:
            return {"rc": rc, "code": int(f[0]), "t": round(float(f[1]), 2), "size": int(float(f[2]))}
        except ValueError:
            return {"rc": rc, "code": 0, "t": 0, "size": 0}

    def good(f):
        return f["rc"] == 0 and 0 < f["code"] < 400

    def tcp(ip):
        try:
            socket.create_connection((ip, 443), timeout=5).close()
            return True
        except OSError:
            return False

    def tls(ip, name):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, 443), timeout=5) as s:
                s.settimeout(5)
                with ctx.wrap_socket(s, server_hostname=name):
                    return True
        except (OSError, ssl.SSLError):
            return False

    def bogus(ip):
        try:
            a = ipaddress.ip_address(ip)
            return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved or a.is_link_local
        except ValueError:
            return True

    def one(site):
        host, path = site[0], site[1] if len(site) > 1 else "/"
        ips = sys_ips(host)
        r = {"ip": ips[0] if ips else ""}
        if not ips or bogus(ips[0]):
            d = doh(host)
            if not d:
                r["st"] = "dns" if not ips else "spoof"
                return r
            f = fetch(host, path, d[0])
            r.update(st="dns" if not ips else "spoof", dns_ip=r["ip"], ip=d[0], alt_ok=good(f),
                     alt_st="ok" if good(f) else "http" if f["rc"] == 0 and f["code"] else "bad")
            return r
        f = fetch(host, path, ips[0])
        if not good(f) and f["rc"] != 28 and not (f["code"] and f["rc"] == 0):
            f = fetch(host, path, ips[0])          # быстрый сбой — ещё раз; таймаут не повторяем, он долгий
        r["t"] = f["t"]
        if good(f):
            r["st"] = "slow" if f["t"] > 3 else "ok"
            return r
        if f["rc"] == 0 and f["code"] in (403, 451):
            r.update(st="denied", code=f["code"])
            return r
        if f["rc"] == 0:
            r.update(st="http", code=f["code"])
            return r
        d = doh(host)
        if d and not set(d) & set(ips):          # DNS хостера отдал другой адрес — вдруг с правильным откроется
            f2 = fetch(host, path, d[0])
            if good(f2):
                r.update(st="spoof", dns_ip=ips[0], ip=d[0], alt_ok=True)
                return r
        if not tcp(ips[0]):
            r["st"] = "ip"
        elif tls(ips[0], host):
            if f["rc"] in (51, 60):
                r["st"] = "stub"
            elif f["rc"] in (16, 18, 28, 52, 55, 56, 92):     # TLS прошёл, а ответ оборвался или завис
                r["st"] = "stall"
                if f["size"]:
                    r["kb"] = round(f["size"] / 1024)
            else:
                r.update(st="http", rc=f["rc"])
        elif tls(ips[0], "www.example.com"):
            r["st"] = "sni"
        else:
            r["st"] = "tls"
        return r

    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(one, sites))
    return {s[0]: r for s, r in zip(sites, res)}


# ------------------------------------------------------------------ zapret2 (раздел «Zapret»)

def zapret_info():
    z = "/opt/zapret2"
    if not os.path.isdir(z):
        return None
    lists = sorted(os.path.basename(f)[9:-4] for f in glob.glob(z + "/ipset/vpn-dash-*.txt"))
    return {"ver": read(z + "/.vpn-dash-ver").strip() or "?", "active": unit_active("zapret2"),
            "running": bool(sh("pgrep -x nfqws2")), "lists": lists}


# ------------------------------------------------------------------ main

if MODE == "diag":
    diag()
elif MODE == "config":
    print(json.dumps({"config": config_snapshot()}, ensure_ascii=False))
elif MODE == "site":
    print(json.dumps({"site": site_check(globals().get("URLS") or [], globals().get("CHANNELS") or [],
                                         globals().get("DIAG", False))}))
elif MODE == "pkgs":
    print(json.dumps({"pkgs": pkgs_info(globals().get("REFRESH", False))}, ensure_ascii=False))
elif MODE == "awg":
    print(json.dumps({"awg": awg_view()}, ensure_ascii=False))
elif MODE == "fw":
    print(json.dumps({"fw": fw_audit()}, ensure_ascii=False))
elif MODE == "dpi":
    print(json.dumps({"dpi": dpi_check(globals().get("SITES") or [])}))
elif MODE == "dc":
    print(json.dumps({"dc": dc_check()}))
elif MODE == "precheck":
    print(json.dumps({"precheck": precheck()}, ensure_ascii=False))
elif MODE == "quality":   # функции — из quality.py, панель присылает его исходник перед этим файлом
    print(json.dumps({"quality": globals()["entry_run"](Q_TARGETS, Q_TESTS, Q_CH)}, ensure_ascii=False))  # noqa: F821
elif MODE == "lat":
    print(json.dumps({"lat": {name: tcp_ms(h, p) for name, h, p in globals().get("TARGETS_OVERRIDE") or []}}))
else:
    data = {"system": system(), "services": {}}
    for u in ("fail2ban",):
        if unit_exists(u):
            data["services"][u] = unit_active(u)
    data["exit"] = exit_info()
    # вход — туннели до выходов или 3X-UI на сервере, который сам не выход AmneziaWG
    if glob.glob(AWG_DIR + "/wg*.conf") or os.path.exists("/etc/x-ui/x-ui.db") and not data["exit"].get("awg"):
        data["entry"] = {"awg": awg_clients(), "xui": xui(), "mask": reality_mask()}
        if os.path.exists("/etc/x-ui/x-ui.db"):
            data["entry"]["e2e"] = xray_e2e()
    data["web"] = web_info()
    data["gov"] = gov_info()
    data["sw"] = sw_versions()
    if data.get("entry"):
        data["zapret"] = zapret_info()
    print(json.dumps(data, ensure_ascii=False))
