# quality.py — замеры качества каналов. Только читает и меряет, ничего не меняет.
# Работает в двух местах:
#  * на входе — панель шлёт исходник этого файла перед probe.py (MODE = "quality"), там вызывается entry_run();
#  * на этом компьютере — dash.py импортирует модуль и вызывает pc_run() (пинг, порт VLESS, трассировка до входа).
# Поэтому здесь только стандартная библиотека и ничего не выполняется при загрузке.
import ipaddress
import os
import re
import socket
import struct
import subprocess
import threading
import time

Q_URL_DOWN = "https://speed.cloudflare.com/__down?bytes=%d"
Q_SPEED_CAP = 20          # один замер скорости — не дольше стольких секунд
_Q_IDENT = [int.from_bytes(os.urandom(2), "big")]
_Q_LOCK = threading.Lock()


def q_ident():
    """Своя метка для пакетов каждой трассировки. Раньше бралась из номера потока, а у потоков младшие биты совпадают —
    одновременные трассировки до разных выходов принимали чужие ответы."""
    with _Q_LOCK:
        _Q_IDENT[0] = (_Q_IDENT[0] + 1) & 0xFFFF
        return _Q_IDENT[0]
Q_WIN = os.name == "nt"


def q_run(args, timeout):
    """Команда списком, без оболочки. На Windows — без мигающего окна консоли."""
    kw = {"creationflags": 0x08000000} if Q_WIN else {}
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired as e:
        return -9, (e.stdout or b"").decode("utf-8", "replace")
    except OSError as e:
        return -1, str(e)
    return p.returncode, p.stdout.decode("oem" if Q_WIN else "utf-8", "replace")


def q_stats(times, sent, method):
    """Сводка серии: задержка (медиана), потери, разброс (среднее изменение между соседними ответами)."""
    if not times:
        return {"n": sent, "got": 0, "loss": 100, "ms": None, "jit": None, "method": method}
    s = sorted(times)
    jit = sum(abs(a - b) for a, b in zip(times, times[1:])) / (len(times) - 1) if len(times) > 1 else 0
    return {"n": sent, "got": len(times), "loss": round(100 * (sent - len(times)) / sent), "ms": round(s[len(s) // 2], 1),
            "jit": round(jit, 1), "method": method}


def q_ping(host, count=20, iface=None):
    """Обычный пинг. iface — через туннель (ping -I wgN)."""
    if Q_WIN:
        rc, out = q_run(["ping", "-n", str(count), "-w", "1000", host], count * 1.5 + 10)
        times = [float(x) for x in re.findall(r"[=<]\s*(\d+)\s*\S{0,4}\s+TTL=", out, re.I)]
    else:
        iv = 0.1 if count > 20 else 0.2          # 50 пингов на сервере — те же ~5 секунд
        a = ["ping", "-n", "-c", str(count), "-i", str(iv), "-W", "1"] + (["-I", iface] if iface else []) + [host]
        rc, out = q_run(a, count * iv + 8)
        if rc == -1:
            return {"error": "нет команды ping"}
        times = [float(x) for x in re.findall(r"time[=<]([\d.]+)", out)]
    return q_stats(times[:count], count, "ping")


def q_tcp(host, port, count=10, iface=None, pause=0.2):
    """Серия TCP-подключений к порту: сколько удалось и за сколько. Подключились — сразу закрыли, данных не шлём.
    Нужна, когда сервер не отвечает на пинг, и для порта VLESS (к нему подключаются телефоны)."""
    times = []
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if iface:
                s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())   # SO_BINDTODEVICE
            s.settimeout(3)
            t = time.time()
            s.connect((host, int(port)))
            times.append((time.time() - t) * 1000)
        except OSError:
            pass
        finally:
            s.close()
        if i + 1 < count:
            time.sleep(pause)
    return q_stats(times, count, "tcp")


def q_ping_or_tcp(host, port, iface=None, count=20):
    """Пинг; если сервер на пинг не отвечает совсем — 10 подключений к порту SSH."""
    r = q_ping(host, count, iface)
    if r.get("error") or not r.get("got"):
        t = q_tcp(host, port, 10, iface)
        if t["got"] or r.get("error"):
            return t
    return r


# ------------------------------------------------------------------ трассировка

def q_trace(host, rounds=10, max_hops=24):
    """Путь до host по узлам: потери и задержка на каждом. На сервере (root) — свои ICMP-пакеты с растущим TTL,
    как mtr, по rounds штук на узел. На Windows — tracert (3 пробы на узел, больше без прав администратора нельзя)."""
    if Q_WIN:
        return q_tracert(host, max_hops)
    try:
        dst = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (OSError, PermissionError) as e:
        return {"error": "трассировка недоступна: %s" % e}
    ident = q_ident()
    dst_b = socket.inet_aton(dst)
    sent, got, ips, target_ttl = {}, {}, {}, [max_hops + 1]

    def csum(b):
        if len(b) % 2:
            b += b"\0"
        s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def send(ttl, rnd):
        seq = rnd * 100 + ttl
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + b"vpn-dash quality"
        pkt = hdr[:2] + struct.pack("!H", csum(hdr)) + hdr[4:]
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sent[seq] = time.time()
        try:
            sock.sendto(pkt, (dst, 0))
        except OSError:
            pass

    stop = [False]

    def recv():
        sock.settimeout(0.2)
        while not stop[0]:
            try:
                data, addr = sock.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                return
            t = time.time()
            ihl = (data[0] & 0x0F) * 4
            typ = data[ihl]
            if typ == 0:                                    # ответ самого адресата
                if addr[0] != dst:
                    continue
                pid, seq = struct.unpack("!HH", data[ihl + 4:ihl + 8])
            elif typ == 11 and len(data) >= ihl + 8 + 28:   # «время жизни истекло» от узла по пути
                o = ihl + 8
                if data[o + 16:o + 20] != dst_b:            # в ответе — наш исходный пакет: он шёл именно к этому адресату?
                    continue
                oihl = (data[o] & 0x0F) * 4
                pid, seq = struct.unpack("!HH", data[o + oihl + 4:o + oihl + 8])
            else:
                continue
            if pid != ident or seq not in sent:
                continue
            ttl = seq % 100
            got.setdefault(ttl, []).append((t - sent[seq]) * 1000)
            ips.setdefault(ttl, addr[0])
            if typ == 0:
                target_ttl[0] = min(target_ttl[0], ttl)

    th = threading.Thread(target=recv, daemon=True)
    th.start()
    for rnd in range(rounds):
        for ttl in range(1, min(max_hops, target_ttl[0]) + 1):
            send(ttl, rnd)
            time.sleep(0.004)
        time.sleep(0.25)
    time.sleep(1.0)
    stop[0] = True
    th.join(1)
    sock.close()
    last = target_ttl[0] if target_ttl[0] <= max_hops else max(ips or [0])
    hops = []
    for ttl in range(1, last + 1):
        g = got.get(ttl, [])
        hops.append({"n": ttl, "ip": ips.get(ttl, ""), "loss": round(100 * (rounds - min(len(g), rounds)) / rounds),
                     "ms": round(sorted(g)[len(g) // 2], 1) if g else None})
    q_names(hops)
    return {"hops": hops, "reached": target_ttl[0] <= max_hops, "probes": rounds}


def q_tracert(host, max_hops):
    rc, out = q_run(["tracert", "-d", "-h", str(max_hops), "-w", "700", host], max_hops * 3 * 0.8 + 15)
    hops, reached = [], False
    try:
        dst = socket.gethostbyname(host)
    except OSError:
        dst = host
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not m:
            continue
        body = m.group(2)
        cols = re.findall(r"(\*|<?\d+\s*\S*)\s+", body + " ")[:3]
        times = [float(re.sub(r"\D", "", c) or 0) for c in cols if c != "*"]
        stars = sum(1 for c in cols if c == "*")
        ipm = re.findall(r"(\d+\.\d+\.\d+\.\d+)", body)
        ip = ipm[-1] if ipm else ""
        hops.append({"n": int(m.group(1)), "ip": ip, "loss": round(100 * stars / 3) if cols else 100,
                     "ms": sorted(times)[len(times) // 2] if times else None})
        if ip == dst:
            reached = True
            break
    q_names(hops)
    return {"hops": hops, "reached": reached, "probes": 3}


def q_names(hops, wait=2.5):
    """Имена узлов (обратный DNS) — по возможности, не дольше wait секунд на всё."""
    def one(h):
        try:
            h["name"] = socket.gethostbyaddr(h["ip"])[0]
        except (OSError, UnicodeError):
            pass
    th = [threading.Thread(target=one, args=(h,), daemon=True) for h in hops
          if h.get("ip") and not ipaddress.ip_address(h["ip"]).is_private]
    for t in th:
        t.start()
    end = time.time() + wait
    for t in th:
        t.join(max(0, end - time.time()))


# ------------------------------------------------------------------ на входе

def q_live(flt):
    """Живой трафик: все установленные TCP-соединения по фильтру ss — доля повторно отправленных пакетов и задержка
    (их считает само ядро). Соединения короче 20 пакетов не считаем — по ним цифры случайные."""
    rc, out = q_run(["ss", "-tinH", "state", "established"] + flt.split(), 10)
    if rc != 0:
        return {"error": "ss: %s" % out.strip()[:80]}
    retr = segs = 0
    rtts = []
    for line in out.splitlines():
        m = re.search(r"segs_out:(\d+)", line)
        if not m or int(m.group(1)) < 20:
            continue
        segs += int(m.group(1))
        r = re.search(r"retrans:\d+/(\d+)", line)
        retr += int(r.group(1)) if r else 0
        t = re.search(r"\brtt:([\d.]+)/", line)
        if t:
            rtts.append(float(t.group(1)))
    if not rtts:
        return {"n": 0}
    rtts.sort()
    return {"n": len(rtts), "retr": round(100 * retr / max(segs, 1), 1), "rtt": round(rtts[len(rtts) // 2])}


def q_speed(iface, mb=2):
    """Скачать mb мегабайт через канал, не дольше Q_SPEED_CAP секунд. Не успело докачать, но шло — это скорость
    (partial); встало (меньше 2 КБ/с четыре секунды подряд) — сколько успело прийти."""
    want = int(mb) * 1000000
    a = ["curl", "-4", "-s", "-m", str(Q_SPEED_CAP), "--speed-limit", "2048", "--speed-time", "4", "-o", "/dev/null",
         "-w", "%{http_code} %{size_download} %{speed_download} %{time_total}"]
    a += ["--interface", iface]
    rc, out = q_run(a + [Q_URL_DOWN % want], Q_SPEED_CAP + 8)
    f = out.split()
    try:
        code, size, spd, tt = int(f[0]), int(float(f[1])), float(f[2]), float(f[3])
    except (IndexError, ValueError):
        return {"error": "нет ответа"}
    if size >= want * 0.95:
        return {"mbps": round(spd * 8 / 1e6, 1), "mb": mb}
    if size > 0 and tt >= Q_SPEED_CAP - 0.5 and spd > 50000:
        return {"mbps": round(spd * 8 / 1e6, 1), "mb": round(size / 1e6, 1), "partial": True}
    if size > 0:
        return {"stall_kb": round(size / 1024)}
    return {"error": "не скачалось (код %s)" % code}


def q_conf(iface):
    """Адрес входа в туннеле и адрес выхода в нём же (у выхода всегда .1 в той же сети)."""
    try:
        txt = open("/etc/amnezia/amneziawg/%s.conf" % iface).read()
        a = re.search(r"^\s*Address\s*=\s*([^\s,/]+)", txt, re.M).group(1)
        return a, str(ipaddress.ip_network(a + "/24", strict=False).network_address + 1)
    except (OSError, AttributeError, ValueError):
        return None, None


def run_bg(r, th, name, fn, *a):
    """fn(*a) в отдельном потоке: результат (или ошибка) — в r[name], поток — в th (потом join)."""
    def w():
        try:
            r[name] = fn(*a)
        except Exception as e:   # noqa: BLE001
            r[name] = {"error": "%s: %s" % (type(e).__name__, e)}
    x = threading.Thread(target=w)
    x.start()
    th.append(x)


def entry_run(targets, tests, ch):
    """На входе. targets: [{key, host, sshport, iface|None}] — по одному на выход."""
    out = {}

    def one(t):
        r = out[t["key"]] = {}
        th = []

        def bg(name, fn, *a):
            run_bg(r, th, name, fn, *a)
        if tests.get("base"):
            bg("raw", q_ping_or_tcp, t["host"], t["sshport"], None, 50)   # не отвечает на пинг — 10 подключений к SSH
            if ch.get("awg") and t.get("iface"):
                addr, peer = q_conf(t["iface"])
                if peer:
                    bg("awg_ping", q_ping_or_tcp, peer, t["sshport"], t["iface"], 50)
                    bg("awg_live", q_live, "src %s" % addr)
        if tests.get("trace"):
            bg("trace", q_trace, t["host"])
        for x in th:
            x.join()
        r["has_awg"] = bool(t.get("iface"))

    th = [threading.Thread(target=one, args=(t,)) for t in targets]
    for x in th:
        x.start()
    for x in th:
        x.join()
    if tests.get("speed"):     # после пингов и строго по очереди: иначе замеры делят канал входа между собой
        mb = int(tests.get("mb") or 2)
        for t in targets:
            r = out[t["key"]]
            if ch.get("awg") and t.get("iface"):
                r["awg_speed"] = q_speed(iface=t["iface"], mb=mb)
    return out


# ------------------------------------------------------------------ с этого компьютера

def pc_run(host, vless_port, tests):
    """С этого компьютера до входа: пинг, подключения к порту VLESS, трассировка."""
    r, th = {}, []

    def bg(name, fn, *a):
        run_bg(r, th, name, fn, *a)
    if tests.get("base"):
        bg("ping", q_ping, host)
        if vless_port:
            bg("tcp", q_tcp, host, vless_port, 10)
    if tests.get("trace"):
        bg("trace", q_trace, host)
    for x in th:
        x.join()
    return r
