"""Раздел «Zapret»: zapret2 (github.com/bol-van/zapret2) на входах, чтобы отдельные сайты шли с входа напрямую,
а не через выходы.

Цель — название и адреса сайта (вводит пользователь; подсказку даёт база geosite самого входа). Для каждой цели на
каждом входе: подбор стратегий (blockcheck2, задача в фоне) → выбор стратегии → «Включить» (zapret с этой стратегией
только для адресов цели) → «Пустить напрямую» (правило 3X-UI «эти адреса → direct», как обходы, код Z-<id>).
Автовозврат: панель проверяет адреса цели прямо с входа; два провала подряд — правило «напрямую» снимается, и сайт
снова идёт через выходы. Всё на серверах — только по кнопке, кроме этого автовозврата (его включают галочкой).
"""
import json
import re
import time

import sites

ZAP_REPO = "bol-van/zapret2"
ZAP_TAG = "v1.0.6"                    # проверенный выпуск; новее — только прочитав изменения
ZAP_DIR = "/opt/zapret2"
TID_RE = re.compile(r"^[a-z0-9]{1,12}$")
# стратегия из blockcheck2 попадает в настройки, которые читает оболочка от root — только безопасные символы
STRAT_RE = re.compile(r"^[A-Za-z0-9_=:,.+/@%#\- ]{3,600}$")
AUTO_FAILS = 2                        # столько провалов подряд — и сайт возвращается на выходы
DOH_SERVERS = ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"]   # +local — прямо с входа, мимо выходов


def zap_url(tag=ZAP_TAG):
    return "https://github.com/%s/releases/download/%s/zapret2-%s.tar.gz" % (ZAP_REPO, tag, tag)


def clean_hosts(text):
    """«youtube.com, https://www.youtube.com/watch …» → ['youtube.com', 'www.youtube.com']; плохие — в ValueError."""
    out = []
    for w in re.split(r"[\s,;]+", (text or "").strip().lower()):
        if not w:
            continue
        w = re.sub(r"^(https?://)?(domain:|full:)?", "", w).split("/")[0].split(":")[0].strip(".")
        if not sites.HOST_RE.match(w):
            raise ValueError("«%s» — не похоже на адрес сайта (нужно вида example.com)" % w)
        if w not in out:
            out.append(w)
    return out


def parse_progress(text):
    """Журнал blockcheck2 без итога (подбор остановили): «- curl_test… ipv4 адрес : nfqws2 стратегия», потом
    «!!!!! AVAILABLE !!!!!» — значит, все повторы прошли. → те же строки, что в SUMMARY."""
    out, host, cur = [], None, None
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^\* (curl_test_\S+) ipv\d (\S+)$", line)
        if m:
            host, cur = m.group(2), None
            continue
        m = re.match(r"^- (curl_test_\S+) ipv\d (\S+) : ((?:nfqws2|winws2) .+)$", line)
        if m:
            cur = (m.group(1), m.group(2), m.group(3))
            continue
        if line == "- checking without DPI bypass" and host:
            cur = ("curl_test_https_tls13", host, "working without bypass")
            continue
        if line.startswith("- "):
            cur = None
        elif "!!!!! AVAILABLE !!!!!" in line and cur:
            out.append("%s ipv4 %s : %s" % cur)
            cur = None
    return out


def parse_blockcheck(text):
    """Итог blockcheck2 (раздел SUMMARY) → какие стратегии сработали для каких адресов.
    {"hosts": {адрес: "free"|"none"|"ok"}, "strategies": [{"s": стратегия, "hosts": [...], "n": сколько адресов
    открылось (вместе с теми, что и так открываются)}], "of": всего адресов, "skipped": стратегии с опасными символами}"""
    partial = "* SUMMARY" not in text
    if partial:
        summ = "\n".join(parse_progress(text))
        if not summ:
            return None
    else:
        summ = text.split("* SUMMARY", 1)[1].split("* COMMON", 1)[0].split("Please note", 1)[0]
    hosts, per, order, skipped = {}, {}, [], 0
    for line in summ.splitlines():
        m = re.match(r"^\s*(curl_test_\S+) ipv\d (\S+) : (.+?)\s*$", line)
        if not m:
            continue
        host, val = m.group(2), m.group(3)
        hosts.setdefault(host, "none")
        if val == "working without bypass":
            hosts[host] = "free"
        elif val.startswith("nfqws2 ") or val.startswith("winws2 "):
            s = val.split(" ", 1)[1].strip()
            if not STRAT_RE.match(s):
                skipped += 1
                continue
            if hosts[host] != "free":
                hosts[host] = "ok"
            if s not in per:
                per[s] = []
                order.append(s)
            if host not in per[s]:
                per[s].append(host)
    free = [h for h, v in hosts.items() if v == "free"]
    strats = [{"s": s, "hosts": per[s], "n": len(set(per[s]) | set(free))} for s in order]
    strats.sort(key=lambda x: (-x["n"], order.index(x["s"])))     # больше адресов — выше; при равенстве — как нашёл blockcheck
    return {"hosts": hosts, "strategies": strats[:40], "of": len(hosts), "free": free, "skipped": skipped, "partial": partial}


def build_config(targets):
    """Цели, включённые на входе: [(tid, адреса, стратегия)] → (переменные для config, {файл списка: текст})."""
    lines, lists = [], {}
    for tid, hosts, strat in targets:
        f = "%s/ipset/vpn-dash-%s.txt" % (ZAP_DIR, tid)
        lists[f] = "\n".join(hosts) + "\n"
        lines.append("--filter-tcp=443 --filter-l7=tls --hostlist=%s %s" % (f, strat))
    opt = " --new\n".join(lines)
    conf = ("# vpn-dash: дописано после config.default и перекрывает его\n"
            "NFQWS2_ENABLE=1\nNFQWS2_PORTS_TCP=443\nNFQWS2_PORTS_UDP=\nNFQWS2_PORTS_TCP_KEEPALIVE=\nNFQWS2_PORTS_UDP_KEEPALIVE=\n"
            "MODE_FILTER=none\nDISABLE_IPV6=1\nNFQWS2_OPT=\"\n%s\n\"\n" % opt)
    return conf, lists


# Скрипт для входа: где в базе geosite (её использует Xray из 3X-UI) встречается адрес. Только чтение.
GEOSITE_PY = r'''
import json, os, time
WANT = DOMAIN
PATHS = ["/usr/local/x-ui/bin/geosite.dat", "/usr/local/share/xray/geosite.dat", "/usr/share/xray/geosite.dat"]
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
path = next((p for p in PATHS if os.path.exists(p)), None)
if not path:
    print(json.dumps({"error": "на этом входе нет файла geosite.dat"})); raise SystemExit
raw = open(path, "rb").read()
parts = WANT.split(".")
keys = [".".join(parts[i:]).encode() for i in range(len(parts) - 1)]   # www.youtube.com → youtube.com (без «com»)
hits = []
for n, site in fields(raw):
    if n != 1 or not any(k in site for k in keys):
        continue
    code, doms, other, match = "", [], 0, False
    for m, v in fields(site):
        if m == 1:
            code = v.decode("utf-8", "replace")
        elif m == 2:
            typ, val = 0, ""
            for q, w in fields(v):
                if q == 1: typ = w
                elif q == 2: val = w.decode("utf-8", "replace")
            if typ in (2, 3):                  # домен с поддоменами / точный адрес
                doms.append(val)
                if WANT == val or WANT.endswith("." + val):
                    match = True
            else:
                other += 1
    if match:
        hits.append({"code": code.lower(), "n": len(doms), "other": other, "domains": sorted(set(doms))[:400]})
hits.sort(key=lambda h: h["n"])
print(json.dumps({"path": path, "mtime": os.path.getmtime(path), "hits": hits[:8]}))
'''


class Zapret:
    def __init__(self, dash, probe):
        self.d = dash
        self.PROBE = probe
        self.watch = {}        # "tid:eid" → провалов подряд (автовозврат)
        self.stopped = set()   # (tid, eid): подбор остановлен кнопкой — задача не должна считать это ошибкой

    # ------------------------------------------------------------ реестр целей
    def reg(self):
        return self.d.cfg.data.setdefault("zapret", {"targets": {}})

    def targets(self):
        return self.reg().setdefault("targets", {})

    def ent(self, tid, eid):
        t = self.targets().get(tid)
        if not t:
            raise ValueError("такой цели нет — обновите страницу")
        return t.setdefault("ents", {}).setdefault(eid, {})

    def save_target(self, body):
        name = str(body.get("name") or "").strip()[:30]
        if not name:
            raise ValueError("нужно название цели, например «YouTube»")
        hosts = clean_hosts(body.get("hosts"))
        if not hosts:
            raise ValueError("нужен хотя бы один адрес")
        if len(hosts) > 200:
            raise ValueError("больше 200 адресов — слишком много для одной цели")
        check = clean_hosts(body.get("check")) or hosts[:3]
        if len(check) > 6:
            raise ValueError("для подбора — не больше 6 адресов: каждый проверяется долго")
        tid = str(body.get("id") or "")
        ts = self.targets()
        with self.d.lock:
            if tid:
                if tid not in ts:
                    raise ValueError("такой цели нет — обновите страницу")
                t = ts[tid]
                if t.get("hosts") != hosts and any(e.get("direct") or e.get("zap") for e in (t.get("ents") or {}).values()):
                    raise ValueError("адреса можно менять, когда цель нигде не включена — сначала «Выключить» и «Вернуть через выходы»")
            else:
                tr = dict(zip("абвгдеёжзийклмнопрстуфхцчшщыэюя", "abvgdeejziiklmnoprstufhccssyeuy"))
                base = re.sub(r"[^a-z0-9]", "", "".join(tr.get(c, c) for c in name.lower()))[:8] or "t"
                tid, n = base, 2
                while tid in ts:
                    tid, n = "%s%d" % (base, n), n + 1
                ts[tid] = {"created": time.time(), "ents": {}, "auto": True}
                t = ts[tid]
            t.update(name=name, hosts=hosts, check=check)
            if "auto" in body:
                t["auto"] = bool(body.get("auto"))
            self.d.cfg.save()
        return tid

    def del_target(self, tid):
        t = self.targets().get(tid)
        if not t:
            return
        if any(e.get("direct") or e.get("zap") for e in (t.get("ents") or {}).values()):
            raise ValueError("цель где-то включена — сначала «Выключить» и «Вернуть через выходы» на всех входах")
        with self.d.lock:
            self.targets().pop(tid, None)
            self.d.cfg.save()

    def code(self, tid):
        return "Z-" + tid

    # ------------------------------------------------------------ подсказка адресов (geosite на входе)
    def geosite(self, eid, domain):
        e = self.d.cfg.by_id(eid)
        if not e or e["role"] != "entry":
            raise ValueError("выберите вход")
        dom = clean_hosts(domain)
        if len(dom) != 1:
            raise ValueError("для подсказки — один адрес, например youtube.com")
        rc, out, err = self.d.ssh.run(e, "python3 -", stdin="DOMAIN = %r\n" % dom[0] + GEOSITE_PY, timeout=90)
        try:
            r = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise ValueError("вход не ответил: %s" % ((err.strip().splitlines() or ["код %s" % rc])[-1][:200]))
        r["domain"] = dom[0]
        r["entry"] = e["name"]
        return r

    # ------------------------------------------------------------ что включить на входе
    def plan_for(self, eid, extra=None, without=None):
        """Цели, которые должны работать в zapret на этом входе: [(tid, адреса, стратегия)]."""
        out = []
        for tid, t in self.targets().items():
            e = (t.get("ents") or {}).get(eid) or {}
            want = (extra and extra[0] == tid) or (e.get("zap") and tid != without)
            strat = extra[1] if extra and extra[0] == tid else e.get("chosen")
            if want and strat:
                out.append((tid, t["hosts"], strat))
        return out

    # ------------------------------------------------------------ итог подбора: журнал blockcheck2 на входе
    LOG = "/root/.vpn-dash-job/zapcheck"

    def collect(self, tid, eid, stop=False):
        """Прочитать журнал подбора на входе (при stop — сначала остановить подбор; blockcheck2 по TERM сам убирает
        свои правила сети) и запомнить найденные стратегии. → итог parse_blockcheck или None."""
        e = self.d.cfg.by_id(eid)
        if stop:
            self.stopped.add((tid, eid))
        kill = ("p=$(cat %s.pid 2>/dev/null); if [ -n \"$p\" ] && kill -0 $p 2>/dev/null; then kill -TERM -- -$p 2>/dev/null || kill -TERM $p; "
                "for i in $(seq 1 25); do pgrep -f '[b]lockcheck2.sh' >/dev/null || break; sleep 1; done; fi; " % self.LOG) if stop else ""
        rc, out, err = self.d.ssh.run(e, kill + "tail -c 4000000 %s.log 2>/dev/null" % self.LOG, timeout=90)
        res = parse_blockcheck(out)
        if res is None:
            return None
        with self.d.lock:
            st = self.ent(tid, eid)
            st["found"] = res
            st["found_at"] = time.time()
            self.d.cfg.save()
        return res

    # ------------------------------------------------------------ правило «напрямую» в 3X-UI
    def direct(self, tid, eid, on, why=""):
        t = self.targets().get(tid)
        e = self.d.cfg.by_id(eid)
        if not t or not e:
            raise ValueError("нет такой цели или входа")
        match = {"domain": ["domain:" + h for h in t["hosts"]], "network": "tcp"}
        code = self.code(tid)
        # своё исходящее «напрямую», которое узнаёт адреса через DNS самого Xray; в нём адреса цели — через DoH
        # (DNS хостера и обычные запросы к 1.1.1.1/8.8.8.8 бывают перехвачены — так бывает у некоторых российских хостеров)
        log = self.d.sites.apply(code, [e], "create" if on else "remove", match=match, chain=[code + "-out"],
                                 out=code + "-out", doh=DOH_SERVERS)
        r = log[0] if log else {"ok": False, "msg": "нет ответа"}
        if r.get("ok"):
            with self.d.lock:
                st = self.ent(tid, eid)
                st["direct"] = bool(on)
                st["direct_at"] = time.time()
                if on:
                    st.pop("auto_off", None)
                elif why:
                    st["auto_off"] = {"at": time.time(), "why": why}
                self.d.cfg.save()
            self.watch.pop("%s:%s" % (tid, eid), None)
        return r

    # ------------------------------------------------------------ проверка: открываются ли адреса цели прямо с входа
    def probe_hosts(self, eid, hosts):
        e = self.d.cfg.by_id(eid)
        sites_ = [[h, "/"] for h in hosts]
        rc, out, err = self.d.ssh.run(e, "python3 -", stdin="MODE = \"dpi\"\nSITES = %r\n" % sites_ + self.PROBE, timeout=190)
        if rc != 0 or not out.strip():
            raise RuntimeError((err.strip().splitlines() or ["код %s" % rc])[-1][:200])
        return json.loads(out)["dpi"]

    def verify(self, tid, eid):
        """Открыть адреса цели (для подбора) прямо с входа — через zapret, если он включён."""
        t = self.targets().get(tid)
        res = self.probe_hosts(eid, t["check"])
        # открылся = сервер ответил по HTTPS, с любым кодом: у redirector.googlevideo.com, i.ytimg.com и подобных на «/»
        # всегда 404 — это ответ самого сервера, а не блокировка (так считает и blockcheck2)
        # DNS хостера адрес не даёт (или подменяет) — не беда: для адресов цели Xray узнаёт их через DoH, поэтому
        # считается то, открылся ли сайт по адресу от DoH
        ok_ = ("ok", "slow", "http", "denied")
        good = [h for h, r in res.items() if r.get("st") in ok_ or r.get("st") in ("dns", "spoof") and r.get("alt_st") in ok_]
        out = {"at": time.time(), "ok": len(good) == len(res), "res": res,
               "text": "открываются все %d" % len(res) if len(good) == len(res) else
               "не открываются: %s" % ", ".join(h for h in res if h not in good)}
        with self.d.lock:
            self.ent(tid, eid)["last"] = out
            self.d.cfg.save()
        return out

    def monitor(self):
        """Автовозврат: для целей «напрямую» с галочкой — проверка адресов прямо с входа; два провала подряд —
        правило «напрямую» снимается (сайт снова идёт через выходы)."""
        for tid, t in list(self.targets().items()):
            if not t.get("auto"):
                continue
            for eid, st in list((t.get("ents") or {}).items()):
                if not st.get("direct") or not self.d.cfg.by_id(eid) or not self.d.cfg.get_pw(eid):
                    continue
                key = "%s:%s" % (tid, eid)
                try:
                    r = self.verify(tid, eid)
                except Exception as ex:  # noqa: BLE001 — вход не ответил: это не провал сайта, пропускаем
                    self.d.note("warn", "Zapret %s: проверка на %s не прошла — %s" % (t["name"], self.d.cfg.by_id(eid)["name"], ex))
                    continue
                if r["ok"]:
                    self.watch[key] = 0
                    continue
                self.watch[key] = self.watch.get(key, 0) + 1
                name = self.d.cfg.by_id(eid)["name"]
                if self.watch[key] < AUTO_FAILS:
                    self.d.note("warn", "Zapret %s на %s: %s — проверю ещё раз" % (t["name"], name, r["text"]))
                    continue
                for _ in range(60):                 # правку обходов делаем по одной
                    if "bypass" not in self.d.running:
                        break
                    time.sleep(2)
                with self.d.busy("bypass"):
                    rr = self.direct(tid, eid, False, why=r["text"])
                if rr.get("ok"):
                    self.d.note("bad", "Zapret %s на %s: %s %d раза подряд — вернул через выходы" % (t["name"], name, r["text"], AUTO_FAILS))
                else:
                    self.d.note("bad", "Zapret %s на %s не работает, а вернуть через выходы не вышло: %s" % (t["name"], name, rr.get("msg")))

    # ------------------------------------------------------------ для страницы
    def view(self):
        ents = [s for s in self.d.cfg.servers if s["role"] == "entry"]
        tl = []
        for tid, t in self.targets().items():
            tl.append({"id": tid, "name": t.get("name"), "hosts": t.get("hosts") or [], "check": t.get("check") or [],
                       "auto": bool(t.get("auto")), "ents": {e["id"]: (t.get("ents") or {}).get(e["id"]) or {} for e in ents},
                       "fails": {e["id"]: self.watch.get("%s:%s" % (tid, e["id"]), 0) for e in ents}})
        return {"targets": tl, "tag": ZAP_TAG}
