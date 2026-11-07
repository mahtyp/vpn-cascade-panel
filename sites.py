"""«Сайты и обходы»: проверка сайта через все входы и выходы и отдельные цепочки (обходы) для сайтов.

Проверка только читает: на каждом входе probe.py (MODE "site") открывает адреса сервиса через каждый
канал — туннель AWG (curl --interface wgN), — и прямо с каждого выхода. Обход — правило
3X-UI на входах «эти сайты → своя цепочка выходов», как DC5TG; ставится и убирается только по кнопке.
"""
import concurrent.futures as cf
import json
import re
import time

# Готовые сервисы: что проверять и каким правилом пускать в обход.
#   urls: (адрес, что считать успехом): "page" — страница (<400, 403/451 — «не пускает»), "reach" — любой ответ,
#   "api" — API без ключа (POST, см. probe: 401/400 — пускает, 403/451 — «не пускает» по стране)
SERVICES = {
    "youtube": {"title": "YouTube", "code": "YT",
                "urls": [("https://www.youtube.com/", "page"), ("https://redirector.googlevideo.com/generate_204", "reach"),
                         ("https://i.ytimg.com/generate_204", "reach")],
                "parts": ["сайт", "видео", "картинки"],
                "match": {"domain": ["geosite:youtube"]}},
    "instagram": {"title": "Instagram", "code": "IG",
                  "urls": [("https://www.instagram.com/", "page"), ("https://static.cdninstagram.com/", "reach")],
                  "parts": ["сайт", "картинки и видео"],
                  "match": {"domain": ["domain:instagram.com", "domain:cdninstagram.com", "domain:fbcdn.net"]}},
    "telegram": {"title": "Telegram", "code": "TG",
                 "urls": [("https://telegram.org/", "page"), ("https://web.telegram.org/", "page")],
                 "parts": ["сайт", "веб-версия"],
                 "match": {"ip": ["91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
                                  "91.108.56.0/22", "149.154.160.0/20", "95.161.64.0/20", "185.76.151.0/24"]},
                 "note": "Приложение Telegram ходит по IP своих серверов, поэтому обход для него — по адресам DC, а не по имени сайта."},
    "whatsapp": {"title": "WhatsApp", "code": "WA",
                 "urls": [("https://www.whatsapp.com/", "page"), ("https://web.whatsapp.com/", "page")],
                 "parts": ["сайт", "веб-версия"],
                 "match": {"domain": ["domain:whatsapp.com", "domain:whatsapp.net", "domain:wa.me"]}},
    "claude": {"title": "Claude", "code": "CLAUDE",
               # claude.ai за защитой Cloudflare: curl'у отдаёт 403 из любой страны — сайт проверяем только на «открывается»,
               # а пускает ли по стране — по API без ключа (как в «как видят»): 401 — пускает, 403 «Request not allowed» — нет
               "urls": [("https://claude.ai/", "reach"), ("https://api.anthropic.com/v1/messages", "api")],
               "parts": ["сайт", "API"],
               "match": {"domain": ["domain:claude.ai", "domain:claude.com", "domain:anthropic.com",
                                    "domain:claudeusercontent.com"]}},
}
# «Что режут на входах»: сайты, которые в России режет ТСПУ, — список из censorcheck --mode dpi
# (github.com/vernette/censorcheck, MIT) + российский сайт для контроля. (имя, путь, подпись)
DPI_SITES = [
    ("ya.ru", "/", "ya.ru — контроль"),
    ("youtube.com", "/", "YouTube"), ("redirector.googlevideo.com", "/report_mapping?di=no", "YouTube — видео"),
    ("discord.com", "/", "Discord"), ("instagram.com", "/", "Instagram"), ("facebook.com", "/", "Facebook"),
    ("x.com", "/", "X (Twitter)"), ("linkedin.com", "/", "LinkedIn"), ("api.telegram.org", "/", "Telegram API"),
    ("play.google.com", "/", "Google Play"), ("github.com", "/", "GitHub"), ("raw.githubusercontent.com", "/", "GitHub — файлы"),
    ("digitalocean.com", "/", "DigitalOcean"), ("amnezia.org", "/", "Amnezia"), ("getoutline.org", "/", "Outline"),
    ("mailfence.com", "/", "Mailfence"), ("rutracker.org", "/", "RuTracker"), ("flibusta.is", "/", "Флибуста"),
    ("rezka.ag", "/", "HDRezka"),
]
HOST_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
CODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,20}$")


def service_for(target):
    """Готовый сервис или произвольный адрес → описание проверки."""
    t = (target or "").strip().lower()
    if t in SERVICES:
        return dict(SERVICES[t], id=t)
    host = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    if not HOST_RE.match(host):
        raise ValueError("адрес сайта в виде example.com")
    for sid, s in SERVICES.items():                      # youtube.com → готовый сервис YouTube
        if any(host in u for u, _ in s["urls"]):
            return dict(s, id=sid)
    code = ("S-" + re.sub(r"[^A-Za-z0-9]", "", host.split(".")[0]).upper())[:20]
    return {"id": host, "title": host, "code": code, "urls": [("https://%s/" % host, "page")], "parts": ["сайт"],
            "match": {"domain": ["domain:" + host]}}


def judge(r, need):
    """Ответ curl → ok / denied / bad и короткий текст."""
    c, t = r.get("code") or 0, r.get("t") or 0
    if not c:
        return "bad", "нет ответа"
    if need in ("page", "api") and c in (403, 451):
        return "denied", "%d не пускает" % c
    if need == "api" and c not in (200, 400, 401, 404, 405, 429):
        return "warn", "ответ %d" % c
    if need == "page" and c >= 500:
        return "warn", "ответ %d" % c
    return ("ok" if t < 2 else "slow"), ("%.1f с" % t).replace(".", ",")


def cell(results, urls, parts=None):
    """Несколько адресов сервиса через один канал → одна ячейка таблицы."""
    if not results:
        return {"st": "none", "text": "—"}
    marks = [judge(results.get(u, {}), need) for u, need in urls]
    sts = [m[0] for m in marks]
    if all(s in ("ok", "slow") for s in sts):
        return {"st": "slow" if "slow" in sts else "ok", "text": marks[0][1]}
    if "denied" in sts:
        return {"st": "denied", "text": next(m[1] for m in marks if m[0] == "denied")}
    if all(s == "bad" for s in sts):
        return {"st": "bad", "text": "нет ответа"}
    bad = [i for i, s in enumerate(sts) if s not in ("ok", "slow")]
    names = [parts[i] for i in bad if parts and i < len(parts)]
    return {"st": "part", "bad": bad, "text": ("нет: " + ", ".join(names)) if names else "частично"}


class Sites:
    def __init__(self, dash, probe):
        self.d = dash
        self.PROBE = probe

    # ------------------------------------------------------------ проверка
    def _probe(self, srv, urls, channels, diag=False, timeout=90):
        pre = "MODE = \"site\"\nURLS = %r\nCHANNELS = %r\nDIAG = %r\n" % (urls, channels, diag)
        rc, out, err = self.d.ssh.run(srv, "python3 -", stdin=pre + self.PROBE, timeout=timeout)
        if rc != 0 or not out.strip():
            raise RuntimeError((err.strip().splitlines() or ["код %s" % rc])[-1][:200])
        return json.loads(out)["site"]

    def check(self, target):
        svc = service_for(target)
        urls = [u for u, _ in svc["urls"]]
        cfg = self.d.cfg
        entries = [s for s in cfg.servers if s["role"] == "entry" and cfg.get_pw(s["id"])]
        exits = [s for s in cfg.servers if s["role"] == "exit"]
        t0 = time.time()

        def on_entry(e):
            chans = [c for c in self.d.channels.get(e["id"], []) if c.get("exit_id")]
            spec = [{"key": c["key"], "iface": c["iface"]} for c in chans]
            try:
                return e["id"], self._probe(e, urls, spec)["res"], None
            except Exception as ex:  # noqa: BLE001
                return e["id"], {}, str(ex)

        def on_exit(x):
            if not cfg.get_pw(x["id"]):
                return x["id"], None, "нет пароля"
            try:
                r = self._probe(x, urls, [{"key": "direct"}], diag=True)
                return x["id"], r, None
            except Exception as ex:  # noqa: BLE001
                return x["id"], None, str(ex)
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            ent = list(ex.map(on_entry, entries))
            ext = list(ex.map(on_exit, exits))
        ent_res = {sid: (res, err) for sid, res, err in ent}
        ext_res = {sid: (res, err) for sid, res, err in ext}

        # строки: каналы основного входа в порядке цепочки (туннель до каждого выхода)
        main = entries[0] if entries else None
        order = []
        for c in sorted(self.d.channels.get(main["id"], []) if main else [], key=lambda c: (c.get("n") is None, c.get("n") or 0)):
            if c.get("exit_id"):
                order.append((c["exit_id"], c["kind"]))
        rows = []
        for xid, kind in order:
            x = cfg.by_id(xid) or {"name": xid}
            cells = []
            for e in entries:
                res, err = ent_res.get(e["id"], ({}, None))
                ch = next((c for c in self.d.channels.get(e["id"], []) if c.get("exit_id") == xid and c["kind"] == kind), None)
                if err:
                    cells.append({"st": "none", "text": "вход не ответил"})
                elif not ch:
                    cells.append({"st": "none", "text": "нет канала"})
                else:
                    cells.append(cell(res.get(ch["key"]), svc["urls"], svc.get("parts")))
            r, err = ext_res.get(xid, (None, None))
            if r is None:
                direct = {"st": "none", "text": err or "—"}
            else:
                direct = cell(r["res"].get("direct"), svc["urls"], svc.get("parts"))
                why = set(r.get("why", {}).values())
                if direct["st"] in ("bad", "part") and why:
                    direct["text"] = {"sni": "режут по имени", "tcp": "нет соединения", "dns": "не находится адрес",
                                      "tls": "не отвечает"}.get(sorted(why)[0], direct["text"])
                    direct["why"] = sorted(why)[0]
            rows.append({"exit_id": xid, "exit": x["name"], "kind": kind, "cells": cells, "direct": direct,
                         "tag": next((c.get("tag") for c in self.d.channels.get(main["id"], [])
                                      if c.get("exit_id") == xid and c["kind"] == kind), None)})
        result = {"target": svc["id"], "title": svc["title"], "code": svc["code"], "urls": urls, "parts": svc.get("parts"),
                  "note": svc.get("note", ""), "entries": [{"id": e["id"], "name": e["name"]} for e in entries],
                  "rows": rows, "secs": round(time.time() - t0), "at": time.time(),
                  "errors": {e["name"]: ent_res[e["id"]][1] for e in entries if ent_res[e["id"]][1]}}
        result.update(self.verdict(result, svc))
        return result

    def active_exit(self, entry_id):
        """Выход, через который сейчас идёт трафик входа: первый исправный канал основной цепочки."""
        chans = sorted([c for c in self.d.channels.get(entry_id, []) if c.get("n")], key=lambda c: c["n"])
        for c in chans:
            r = self.d.results.get("%s:%s" % (entry_id, c["key"])) or {}
            if r.get("status") in ("ok", "warn"):
                return c.get("exit_id")
        return chans[0].get("exit_id") if chans else None

    def verdict(self, r, svc):
        title, rows = r["title"], r["rows"]
        okx = lambda row: all(c["st"] in ("ok", "slow") for c in row["cells"] if c["st"] != "none")
        by_exit = {}
        for row in rows:
            by_exit.setdefault(row["exit_id"], []).append(row)
        works = [xid for xid, rs in by_exit.items() if any(okx(x) for x in rs)]
        broken = [xid for xid, rs in by_exit.items() if not any(okx(x) for x in rs)]
        name = lambda xid: (self.d.cfg.by_id(xid) or {"name": xid})["name"]
        main = r["entries"][0]["id"] if r["entries"] else None
        act = self.active_exit(main) if main else None
        for row in rows:
            row["active"] = row["exit_id"] == act and row["kind"] == "AWG"

        def why_text(xid):
            d = next((x["direct"] for x in by_exit.get(xid, []) if x["direct"].get("st") != "none"), {})
            w = d.get("why")
            if w == "sni":
                return "Прямо с выхода %s сервер сайта отвечает, но запросы с именем %s зависают — по пути от выхода его режут по имени сайта. Это на стороне хостера этого выхода." % (
                    name(xid), title)
            if d.get("st") == "denied":
                return "%s отвечает «%s» — сайт не пускает адрес этого выхода." % (title, d.get("text"))
            if d.get("st") in ("ok", "slow"):
                return "Прямо с выхода %s сайт открывается, а через туннели — нет: похоже, дело в канале до выхода." % name(xid)
            if d.get("st") == "bad":
                return "Прямо с выхода %s сайт тоже не открывается." % name(xid)
            return ""
        fix = None
        if not works:
            v = ("bad", "не работает нигде", "%s не открывается ни через один выход." % title,
                 "Похоже, проблема у самого сайта или его режут везде — обходом тут не помочь.")
        elif not broken:
            slow = [row for row in rows if any(c["st"] == "slow" for c in row["cells"])]
            v = ("ok", "работает везде", "%s открывается через все выходы и со всех входов." % title,
                 ("Медленно (больше 2 с): %s." % ", ".join("%s %s" % (x["exit"], x["kind"]) for x in slow)) if slow else "Ничего делать не нужно.")
        elif act in broken:
            v = ("warn", "не работает через выход %s" % name(act),
                 "%s не открывается через выход %s — а трафик сейчас идёт именно туда." % (title, name(act)),
                 "%s Через %s %s — открывается." % (why_text(act), "выходы" if len(works) > 1 else "выход", ", ".join(name(x) for x in works)))
            fix = [row["tag"] for row in rows if row["exit_id"] in works and row["tag"] and okx(row)]
        else:
            v = ("ok", "работает через основной выход",
                 "%s открывается через выход %s — там сейчас идёт трафик." % (title, name(act)) if act else "%s открывается через основной выход." % title,
                 "Не открывается через %s %s. %s Сейчас это не мешает, но если трафик уйдёт туда, понадобится обход." % (
                     "выходы" if len(broken) > 1 else "выход", ", ".join(name(x) for x in broken), " ".join(why_text(x) for x in broken)))
        out = {"level": v[0], "pill": v[1], "headline": v[2], "detail": (v[3] + (" " + r["note"] if r.get("note") else "")).strip()}
        if fix:
            out["fix"] = {"code": svc["code"], "title": title, "chain": fix, "match": svc["match"], "service": svc["id"],
                          "reason": "%s не открывается через выход %s%s (проверка %s)" % (
                              title, name(act), " — режут по имени сайта" if "по имени" in v[3] else "",
                              time.strftime("%d.%m %H:%M"))}
        return out

    # ------------------------------------------------------------ что режут на входах
    def dpi(self):
        """Каждый вход открывает сайты из DPI_SITES напрямую, мимо туннелей (probe MODE "dpi"). Только чтение."""
        cfg = self.d.cfg
        entries = [s for s in cfg.servers if s["role"] == "entry" and cfg.get_pw(s["id"])]
        if not entries:
            raise ValueError("нет входов с сохранённым паролем")
        sites = [[h, p] for h, p, _ in DPI_SITES]
        t0 = time.time()

        def on_entry(e):
            pre = "MODE = \"dpi\"\nSITES = %r\n" % sites
            try:
                rc, out, err = self.d.ssh.run(e, "python3 -", stdin=pre + self.PROBE, timeout=190)
                if rc != 0 or not out.strip():
                    raise RuntimeError((err.strip().splitlines() or ["код %s" % rc])[-1][:200])
                return {"id": e["id"], "name": e["name"], "res": json.loads(out)["dpi"]}
            except Exception as ex:  # noqa: BLE001
                return {"id": e["id"], "name": e["name"], "error": str(ex)}
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            res = list(ex.map(on_entry, entries))
        return {"at": time.time(), "secs": round(time.time() - t0), "entries": res,
                "sites": [{"host": h, "label": l} for h, _, l in DPI_SITES]}

    # ------------------------------------------------------------ обходы
    def registry(self):
        return self.d.cfg.data.setdefault("bypasses", {})

    def where(self):
        """Какие отдельные правила (обходы, DC5TG) стоят на каких входах — по данным последней проверки."""
        out = {}
        for s in self.d.cfg.servers:
            if s["role"] != "entry":
                continue
            st = self.d.status.get(s["id"]) or {}
            for p in (((st.get("data") or {}).get("entry") or {}).get("xui") or {}).get("pinned") or []:
                if p.get("comment"):
                    out.setdefault(p["comment"], {"rule": p, "on": {}})["on"][s["id"]] = True
        return out

    def view(self):
        """Список для страницы: обходы панели + чужие правила (DC5TG и т. п.) с отметками, где стоят."""
        reg = self.registry()
        wh = {k: v for k, v in self.where().items() if not k.startswith("Z-")}   # Z-… — правила раздела «Zapret»
        changed = False
        gone = self.d.cfg.data.get("bypass_gone") or {}
        for code, w in wh.items():                       # правило с этим кодом поставлено вручную — берём под учёт
            rule = w["rule"]
            if code in reg or not (rule.get("domain") or rule.get("ip")) or time.time() - gone.get(code, 0) <= 900:
                continue
            if code == "DC5TG":
                reg[code] = {"title": "Telegram DC5", "service": "dc5", "match": {"ip": rule["ip"]}, "chain": rule.get("chain") or [],
                             "reason": "DC5 Telegram открывается не со всех выходов — правило ставил скрипт vpn-pin-chain.sh",
                             "created": time.time()}
            else:
                svc = next((sid for sid, x in SERVICES.items() if rule.get("domain") and x["match"].get("domain") == rule["domain"]), None)
                match = {"domain": rule["domain"]} if rule.get("domain") else {"ip": rule["ip"]}
                reg[code] = {"title": SERVICES[svc]["title"] if svc else code, "service": svc or "",
                             "match": match, "chain": rule.get("chain") or [], "reason": "поставлен вручную", "created": time.time()}
            changed = True
        if changed:
            self.d.cfg.save()
        ents = [s for s in self.d.cfg.servers if s["role"] == "entry"]
        items = []
        for code, b in reg.items():
            on = (wh.get(code) or {}).get("on", {})
            items.append(dict(b, code=code, managed=True, on={e["id"]: bool(on.get(e["id"])) for e in ents}))
        for code, w in wh.items():
            if code not in reg:
                items.append({"code": code, "title": "Telegram DC5" if code == "DC5TG" else code, "managed": False,
                              "chain": w["rule"].get("chain") or [], "reason": "отдельное правило 3X-UI",
                              "on": {e["id"]: bool(w["on"].get(e["id"])) for e in ents}})
        return items

    def apply(self, code, entries, mode, match=None, chain=None, out=None, doh=None):
        """Поставить (create) или убрать (remove) обход на входах по очереди. Возвращает журнал по входам.
        out — создать своё исходящее freedom (UseIPv4) с этим тегом; doh — адреса правила узнавать через эти DoH (Zapret)."""
        log = []
        for e in entries:
            params = {"mode": mode, "code": code, "match": match or {}, "chain": chain or [], "out": out or "", "doh": doh or []}
            try:
                rc, out, err = self.d.ssh.run(e, "python3 -", stdin="PARAMS = %s\n" % json.dumps(params) + BYPASS_PY, timeout=120)
                r = json.loads(out.strip().splitlines()[-1]) if out.strip() else {"ok": False, "msg": (err.strip().splitlines() or ["код %s" % rc])[-1]}
            except Exception as ex:  # noqa: BLE001
                r = {"ok": False, "msg": str(ex)[:200]}
            log.append(dict(r, entry=e["name"], id=e["id"]))
            if not r.get("ok"):
                break                               # на первом сбое — стоп, остальные входы не трогаем
        return log


# Скрипт для входа: правит шаблон Xray в базе 3X-UI. Перед правкой — копия базы, после — проверка, что
# Xray поднялся; не поднялся — откат. Печатает одну строку JSON.
BYPASS_PY = r'''
import json, os, shutil, sqlite3, subprocess, time
DB = "/etc/x-ui/x-ui.db"
P = PARAMS
code = P["code"]

def xray_up():
    for _ in range(25):
        time.sleep(1)
        for d in os.listdir("/proc"):
            if d.isdigit():
                try:
                    if open("/proc/%s/comm" % d).read().startswith("xray-linux"):
                        return True
                except OSError:
                    pass
    return False

def done(ok, msg, **kw):
    print(json.dumps(dict(kw, ok=ok, msg=msg), ensure_ascii=False))
    raise SystemExit(0)

db = sqlite3.connect(DB)
t = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
obs, r = t.setdefault("outbounds", []), t.setdefault("routing", {})
rules, bals = r.setdefault("rules", []), r.setdefault("balancers", [])
mine = lambda tag: str(tag).startswith(code + "-") or str(tag).startswith("_bl_" + code + "-")
has = any(x.get("comment") == code for x in rules)

MARK = "full:%s.vpn-dash.invalid" % code.lower()     # метка наших записей DNS (такого адреса не бывает)

def remove():
    rules[:] = [x for x in rules if x.get("comment") != code and not any(mine(j) for j in x.get("inboundTag") or [])]
    bals[:] = [b for b in bals if not mine(b.get("tag"))]
    obs[:] = [o for o in obs if not mine(o.get("tag"))]
    dns = t.get("dns")
    if isinstance(dns, dict) and isinstance(dns.get("servers"), list):
        dns["servers"] = [s for s in dns["servers"] if not (isinstance(s, dict) and MARK in (s.get("domains") or []))]

def create(match, before=None):
    if P.get("out") and not any(o.get("tag") == P["out"] for o in obs):
        obs.append({"tag": P["out"], "protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}})
    if P.get("doh") and match.get("domain"):
        dns = t.setdefault("dns", {})
        srv = dns.setdefault("servers", [])
        if not srv:
            srv.append("localhost")             # остальные адреса — как раньше, через DNS сервера
        srv[0:0] = [{"address": a, "domains": list(match["domain"]) + [MARK], "skipFallback": True} for a in P["doh"]]
    have = {o.get("tag") for o in obs}
    tags = [x for x in P["chain"] if x in have]
    if not tags:
        db.close(); done(False, "на этом входе нет исходящих " + ", ".join(P["chain"]))
    names = ["%s-%d-%s" % (code, i, x) for i, x in enumerate(tags, 1)]
    for i, (n, x) in enumerate(zip(names, tags)):
        bals.append({"tag": n, "selector": [x], "fallbackTag": "_bl_" + names[i + 1] if i + 1 < len(names) else ""})
    for n in names[1:]:
        obs.append({"tag": "_bl_" + n, "protocol": "loopback", "settings": {"inboundTag": "_bl_" + n}})
    bal_tags = {b["tag"] for b in bals}
    pos = rules.index(before) if before is not None and before in rules else next(
        (i for i, x in enumerate(rules) if x.get("balancerTag") in bal_tags and not x.get("ip") and not x.get("domain")
         and not any(str(j).startswith("_bl_") for j in x.get("inboundTag") or [])), len(rules))
    rule = {"type": "field", "enabled": True, "comment": code, "balancerTag": names[0]}
    rule.update(match)
    rules[pos:pos] = [{"type": "field", "inboundTag": ["_bl_" + n], "balancerTag": n} for n in names[1:]] + [rule]
    ob = t.get("burstObservatory") or t.get("observatory")
    if ob is not None:
        sel = ob.setdefault("subjectSelector", [])
        sel += [x for x in tags[:-1] if x not in sel]
    return tags

if P["mode"] == "create":
    if has:
        db.close(); done(True, "уже стоит", changed=False)
    msg = "поставлен: " + " → ".join(create(P["match"]))
elif P["mode"] == "set":            # новая цепочка для обхода: правило остаётся на своём месте и с тем же условием
    old = next((x for x in rules if x.get("comment") == code), None)
    match = {k: old[k] for k in ("domain", "ip") if old and old.get(k)} or P["match"]
    if not match:
        db.close(); done(False, "на этом входе обхода нет, и неизвестно, для каких сайтов его ставить")
    before = None
    if old is not None:
        i = rules.index(old) + 1
        while i < len(rules) and (rules[i].get("comment") == code or any(mine(j) for j in rules[i].get("inboundTag") or [])):
            i += 1
        before = rules[i] if i < len(rules) else None
    remove()
    msg = "цепочка: " + " → ".join(create(match, before))
else:
    if not has and not any(mine(b.get("tag")) for b in bals):
        db.close(); done(True, "и так не было", changed=False)
    remove()
    msg = "убран"
db.close()
sniff = []
for remark, s in sqlite3.connect("file:%s?mode=ro" % DB, uri=True).execute("select remark, sniffing from inbounds where enable=1"):
    try:
        if not json.loads(s or "{}").get("enabled"):
            sniff.append(remark)
    except ValueError:
        pass
ts = time.strftime("%Y-%m-%d_%H%M%S")
bak = DB + ".before-bypass-" + ts
src = sqlite3.connect("file:%s?mode=ro" % DB, uri=True); dst = sqlite3.connect(bak); src.backup(dst); dst.close(); src.close()
os.chmod(bak, 0o600)
subprocess.run(["systemctl", "stop", "x-ui"], capture_output=True)
db = sqlite3.connect(DB)
db.execute("update settings set value=? where key='xrayTemplateConfig'", (json.dumps(t, indent=2, ensure_ascii=False),))
db.commit(); db.close()
subprocess.run(["systemctl", "start", "x-ui"], capture_output=True)
if xray_up():
    done(True, msg, changed=True, backup=bak, no_sniff=sniff if P["mode"] in ("create", "set") and "domain" in (P["match"] or {}) else [])
subprocess.run(["systemctl", "stop", "x-ui"], capture_output=True)
for f in ("x-ui.db-wal", "x-ui.db-shm"):
    p = "/etc/x-ui/" + f
    if os.path.exists(p):
        os.rename(p, p + ".failed-" + ts)
shutil.copy2(bak, DB)
subprocess.run(["systemctl", "start", "x-ui"], capture_output=True)
done(False, "Xray не поднялся с новым правилом — база возвращена как было" + ("" if xray_up() else ", но и после отката Xray не запущен! journalctl -u x-ui -n 50"))
'''
