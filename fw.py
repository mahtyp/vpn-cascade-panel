"""Фаервол (ufw): по данным проверки (probe MODE "fw") решаем, какие порты оставить открытыми, какие закроются.

Только план и объяснения простыми словами — сама проверка ничего на сервере не меняет.
"""

import re

LOOPBACK = ("127.", "::1", "[::1]", "localhost")


def _local(addr):
    return addr.startswith(LOOPBACK)


ACME80 = {"what": "продление сертификата Let's Encrypt", "c": "ACME http-01",
          "why": "раз в несколько дней Let's Encrypt проверяет сервер по порту 80 (сертификат подписки и 3X-UI живёт ~6 дней); "
                 "в остальное время там ничего не слушает"}


def plan(srv, a):
    """→ {rows: [{proto, port, what, verdict: keep|close|auto, why, warn}], notes: [{level, text}], cmds: [...], state}"""
    xui = a.get("xui") or {}
    inb = {i["port"]: i for i in xui.get("inbounds") or []} if "error" not in xui else {}
    ssh_ports = set(a.get("ssh_ports") or []) | {int(srv.get("port") or 22)}   # порт, по которому ходит панель, — всегда
    awg_by_port = {p: i for i, p in (a.get("awg") or {}).items()}
    exit_role = srv.get("role") == "exit"
    servers = set(a.get("awg_server") or []) if exit_role else set()   # на входе туннели — клиенты, пересылки нет
    docker_ports = set()
    for d in a.get("docker") or []:
        for part in (d.get("ports") or "").split(","):
            hp = part.strip().split("->")[0]
            if ":" in hp and hp.rsplit(":", 1)[1].isdigit():
                docker_ports.add(int(hp.rsplit(":", 1)[1]))

    rows, seen = [], {}
    for l in a.get("listen") or []:
        if not l.get("port") or _local(l.get("addr", "")):
            continue
        proto, port, proc, dev = l["proto"], l["port"], l.get("proc") or "", l.get("dev") or ""
        key = (proto, port)
        if key in seen:                         # один и тот же порт на IPv4 и IPv6
            if proc and not rows[seen[key]]["proc"]:
                rows[seen[key]]["proc"] = proc
            continue
        if dev:                                 # сокет привязан к туннелю (исходящие Xray через wgN) — снаружи не достать
            continue
        r = {"proto": proto, "port": port, "proc": proc, "verdict": "close", "what": proc or "неизвестно", "why": "", "warn": False}
        if proto == "tcp" and port == 80 and a.get("acme_standalone"):
            r.update(verdict="keep", **ACME80)
        elif proto == "tcp" and port in ssh_ports:
            r.update(verdict="keep", what="SSH", why="через него работают эта панель и консоль", c="SSH")
        elif port in inb and proc.startswith("xray"):
            i = inb[port]
            r.update(verdict="keep", what="вход %s «%s»" % ((i.get("protocol") or "").upper(), i.get("remark") or port),
                     why="по нему подключаются ваши устройства", c="3X-UI inbound %s" % (i.get("protocol") or ""))
        elif xui.get("sub_port") == port and proc.startswith("x-ui"):
            r.update(verdict="keep", what="подписка 3X-UI", why="по ней телефоны обновляют ссылки", c="3X-UI subscription")
        elif xui.get("web_port") == port and proc.startswith("x-ui"):
            r.update(what="веб-панель 3X-UI", why="открывается кнопкой «3X-UI» через SSH — снаружи не нужна")
        elif proto == "udp" and port in awg_by_port:
            i = awg_by_port[port]
            r.update(verdict="keep", what="AmneziaWG %s" % i,
                     why=("туннель от входов" if i in servers else "туннель до выхода") + " — на чужие пакеты не отвечает", c="AmneziaWG %s" % i)
        elif proc == "docker-proxy" or port in docker_ports:
            r.update(verdict="auto", what="Docker" + (" (%s)" % proc if proc and proc != "docker-proxy" else ""),
                     why="Docker открывает свои порты сам, ufw их не касается")
        elif proto == "udp" and port in (68, 546):
            r.update(verdict="auto", what="DHCP", why="служебное, ufw пропускает сам")
        elif proc.startswith("xray") and proto == "udp" and port >= 32768:
            r.update(verdict="auto", what="Xray, временный UDP",
                     why="так Xray сам отправляет UDP наружу (QUIC, звонки, DNS — например, «напрямую» с входа); номер каждый раз "
                         "новый, ответы проходят и при включённом фаерволе — открывать не нужно")
        elif proc.startswith("xray"):
            r.update(what="Xray", why="порт не от включённого входящего 3X-UI")
        else:
            r.update(why="не знаю, что это — закроется; если нужно, скажите", warn=True)
        seen[key] = len(rows)
        rows.append(r)
    for p in sorted(ssh_ports):                 # SSH открыт всегда, даже если ss не показал
        if ("tcp", p) not in seen:
            rows.insert(0, {"proto": "tcp", "port": p, "proc": "sshd", "verdict": "keep", "what": "SSH", "c": "SSH",
                            "why": "через него работают эта панель и консоль", "warn": False})
    if a.get("acme_standalone") and ("tcp", 80) not in seen:   # порт 80 слушается только во время продления
        rows.append(dict({"proto": "tcp", "port": 80, "proc": "acme.sh", "verdict": "keep", "warn": False}, **ACME80))
    rows.sort(key=lambda r: ({"keep": 0, "close": 1, "auto": 2}[r["verdict"]], r["port"]))

    notes = []
    ufw = a.get("ufw")
    if a.get("firewalld"):
        notes.append({"level": "bad", "text": "работает firewalld — ufw вместе с ним ставить нельзя; сначала разберёмся с ним"})
    if ufw and ufw.get("active"):
        state = "on"
        notes.append({"level": "info", "text": "ufw уже включён — ниже его текущие правила"})
    else:
        state = "off" if ufw else "none"
        notes.append({"level": "info", "text": "ufw не установлен — поставится при включении (apt)" if not ufw else "ufw установлен, но выключен"})
    ipt_in = (a.get("ipt") or {}).get("INPUT") or {}
    own_in = ipt_in.get("own") or []
    ping_off = [r for r in own_in if re.search(r"-p icmp\b.*--icmp-type (8|echo-request)\b.*-j (DROP|REJECT)", r)]
    if ping_off:                                # знакомое правило: сервер не отвечает на ping — безвредно
        own_in = [r for r in own_in if r not in ping_off]
        notes.append({"level": "info", "text": "сервер не отвечает на ping (правило DROP) — ufw его не трогает; "
                                               "для VPN это неважно, а сервер так даже незаметнее"})
    if ipt_in.get("f2b"):
        notes.append({"level": "info", "text": "fail2ban уже блокирует подбор паролей SSH — с ufw работает вместе"})
    if own_in:
        notes.append({"level": "warn", "text": "на сервере уже есть свои правила фаервола (%d) — ufw их не удалит и не изменит: %s"
                      % (len(own_in), "; ".join(own_in[:5]))})
    added = [x for x in (ufw or {}).get("added") or [] if not (ufw or {}).get("active")]
    if added:
        notes.append({"level": "warn", "text": "в выключенном ufw уже записаны правила — при включении заработают и они: %s" % "; ".join(added[:8])})
    fwd = sorted(servers)                       # пересылку разрешаем всегда: правила AmneziaWG могут пропасть при перезапуске
    if fwd:
        notes.append({"level": "info", "text": "через %s пересылается трафик входов — разрешу пересылку в интернет (%s), иначе туннель встанет"
                      % (", ".join(fwd), a.get("default_if") or "eth0")})
    if a.get("docker"):
        notes.append({"level": "info", "text": "Docker (%s) сам управляет своими правилами — ufw их не трогает и не ломает"
                      % ", ".join(d["name"] for d in a["docker"])})
    notes.append({"level": "info", "text": "исходящие соединения и ответы на них ufw пропускает сам"})

    cmds = ["ufw default deny incoming", "ufw default allow outgoing"]
    for r in rows:
        if r["verdict"] == "keep":
            c = re.sub(r"[^A-Za-z0-9 ._-]", "", r.get("c") or "")[:40]
            cmds.append("ufw allow %d/%s" % (r["port"], r["proto"]) + (" comment '%s'" % c if c else ""))
    for i in fwd:
        cmds.append("ufw route allow in on %s out on %s" % (i, a.get("default_if") or "eth0"))
    return {"rows": rows, "notes": notes, "cmds": cmds, "state": state,
            "ufw_status": (ufw or {}).get("status", "") if state == "on" else "", "role": "exit" if exit_role else "entry"}


# ------------------------------------------------------------------ шаг 2: включение (на сервере, python3 -)
# P = {"do": "enable", "cmds": [...], "undo_s": 300} | {"do": "confirm"} | {"do": "disable"}
# enable: ставит ufw (если нет), заводит «ремень»: через undo_s секунд ufw сам выключится, если панель не скажет confirm.

CMD_RE = re.compile(r"^ufw (default (deny|allow) (incoming|outgoing)|allow \d{1,5}/(tcp|udp)( comment '[A-Za-z0-9 ._-]{0,40}')?"
                    r"|route allow in on [A-Za-z0-9_.-]{1,15} out on [A-Za-z0-9_.-]{1,15})$")

FW_PY = r'''
import json, os, re, shlex, signal, subprocess, time
UNDO = "/root/.vpn-dash-fw-undo"


def sh(c, t=600):
    try:
        r = subprocess.run(c, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=t)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return 124, "не уложилось в %d с" % t


def done(ok, msg, **kw):
    kw.update(ok=ok, msg=msg)
    print(json.dumps(kw, ensure_ascii=False))
    raise SystemExit(0)


def cancel_undo():
    try:
        pid = int(open(UNDO).read().strip())
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    try:
        os.remove(UNDO)
    except OSError:
        pass


def active():
    return "Status: active" in sh("ufw status 2>/dev/null")[1]


if P["do"] == "confirm":
    cancel_undo()
    done(True, "фаервол оставлен включённым", active=active())
if P["do"] == "disable":
    cancel_undo()
    rc, out = sh("ufw --force disable")
    done(rc == 0 and not active(), "фаервол выключен" if rc == 0 else out.strip()[-300:], active=active())

# enable
if active():
    done(False, "ufw уже включён — ничего не менял", active=True)
if sh("systemctl is-active --quiet firewalld")[0] == 0:
    done(False, "работает firewalld — ufw вместе с ним не включаю", active=False)
if not sh("command -v ufw")[1].strip():
    env = "DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=300 "
    rc, out = sh(env + "install ufw")
    if rc != 0:
        sh(env + "update")
        rc, out = sh(env + "install ufw")
    if rc != 0:
        done(False, "не удалось поставить ufw: " + out.strip()[-300:], active=False)
cancel_undo()
p = subprocess.Popen(["sh", "-c", "sleep %d; ufw --force disable; rm -f %s" % (int(P["undo_s"]), UNDO)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
open(UNDO, "w").write(str(p.pid))
log = []
for c in P["cmds"]:
    rc, out = sh(c, 60)
    log.append("%s → %s" % (c, (out.strip().splitlines() or ["ok"])[-1]))
    if rc != 0:
        done(False, "команда не прошла: %s — %s (ufw не включал)" % (c, out.strip()[-200:]), active=active(), log=log)
rc, out = sh("ufw --force enable", 120)
log.append("ufw --force enable → " + (out.strip().splitlines() or ["ok"])[-1])
if rc != 0 or not active():
    sh("ufw --force disable")
    cancel_undo()
    done(False, "ufw не включился: " + out.strip()[-300:], active=False, log=log)
done(True, "ufw включён; если панель не подтвердит, сам выключится через %d с" % int(P["undo_s"]), active=True, log=log)
'''
