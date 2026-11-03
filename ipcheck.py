"""Как базы геолокации и сервисы (YouTube, Google, ChatGPT, …) видят адрес сервера.

Панель отправляет на сервер проверенную копию server-scripts/third_party/ipregion.sh (vernette/ipregion, MIT)
и запускает её от nobody с --json -4. Скрипт только делает запросы к сервисам и ничего не меняет.
Вместо `column` и `nslookup`, если их нет, подставляются заменители — иначе скрипт спросил бы, ставить ли
пакеты, и вышел. «Кому принадлежит адрес» (registered country, ASN) скрипт в JSON не отдаёт — это берём
у MaxMind тем же запросом, что и он.
Пускают ли ИИ (ChatGPT, Claude, Copilot, Grok) и метки «хостинг» / «VPN» (ip-api, ipinfo, proxycheck) — запросы
по образцу XaksFlaX/ipregion-fixed (MIT), написаны здесь же, в RUNNER; Gemini — из ipregion.
"""
import base64
import re
from pathlib import Path
from jsonline import last_json

IPR_FILE = Path(__file__).resolve().parent / "server-scripts" / "third_party" / "ipregion.sh"

RUNNER = r'''
import base64, json, os, pwd, shutil, subprocess, tempfile, urllib.error, urllib.request
out = {}
d = tempfile.mkdtemp(prefix="vpn-dash-ipr.")
try:
    os.chmod(d, 0o755)
    p = os.path.join(d, "ipregion.sh")
    with open(p, "wb") as f:
        f.write(base64.b64decode(IPR))
    os.chmod(p, 0o644)
    b = os.path.join(d, "bin"); os.mkdir(b); os.chmod(b, 0o755)
    shims = {"column": "#!/bin/sh\ncat\n",                                   # нужен скрипту только для таблицы
             "nslookup": "#!/bin/sh\nfor a; do d=$a; done\ngetent ahostsv4 \"$d\" >/dev/null\n"}   # «DNS работает?»
    for name, body in shims.items():
        if not shutil.which(name):
            with open(os.path.join(b, name), "w") as f:
                f.write(body)
            os.chmod(os.path.join(b, name), 0o755)
    t = os.path.join(d, "tmp"); os.mkdir(t)
    miss = [c for c in ("jq", "curl", "bash", "ip") if not shutil.which(c)]
    if miss:
        out["error"] = "на сервере нет программ: " + ", ".join(miss)
        out["miss"] = miss
    elif FAKE:
        out["ipr"] = json.load(open(FAKE))
    else:
        cmd = ["bash", p, "--json", "-4", "-t", "12"]   # 5 с по умолчанию мало: скрипт шлёт ~40 запросов разом, на 1 ядре не успевает
        if os.geteuid() == 0 and shutil.which("runuser"):
            nb = pwd.getpwnam("nobody")
            os.chown(t, nb.pw_uid, nb.pw_gid)
            cmd = ["runuser", "-u", "nobody", "--"] + cmd
        env = {"PATH": b + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": t, "TMPDIR": t, "LANG": "C.UTF-8"}
        try:
            r = subprocess.run(cmd, cwd=t, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=170)
            txt = r.stdout.decode("utf-8", "replace")
            i = txt.find("{")
            try:
                out["ipr"] = json.loads(txt[i:]) if i >= 0 else None
            except ValueError:
                out["ipr"] = None
            if not out["ipr"]:
                import re
                clean = lambda x: re.sub(r"\x1b\[[0-9;]*m", "", x).strip().splitlines()
                er, so = clean(r.stderr.decode("utf-8", "replace")), clean(txt)
                err = [l for l in er + so if "ERROR" in l] or er or so or ["код %d" % r.returncode]
                out["error"] = err[-1].replace("[ERROR]", "").strip()[:200]
        except subprocess.TimeoutExpired:
            out["error"] = "не уложился в 170 секунд"
    try:
        if FAKE:
            out["mm"] = json.load(open(FAKE.replace(".json", "-mm.json")))
        else:
            rq = urllib.request.Request("https://geoip.maxmind.com/geoip/v2.1/city/me",
                                        headers={"Referer": "https://www.maxmind.com", "User-Agent": "Mozilla/5.0"})
            m = json.loads(urllib.request.urlopen(rq, timeout=10).read().decode("utf-8"))
            tr = m.get("traits") or {}
            out["mm"] = {"registered": (m.get("registered_country") or {}).get("iso_code"),
                         "country": (m.get("country") or {}).get("iso_code"),
                         "asn": tr.get("autonomous_system_number"), "org": tr.get("autonomous_system_organization"),
                         "ip": tr.get("ip_address")}
    except Exception as e:
        out["mm"] = {"error": str(e)[:120]}
    # репутация адреса: открытые страницы AbuseIPDB (жалобы) и Scamalytics (оценка мошенничества)
    import re
    ip = ((out.get("ipr") or {}).get("ipv4")) or (out.get("mm") or {}).get("ip")
    rep = out["rep"] = {}
    if FAKE:
        try:
            out["rep"] = json.load(open(FAKE.replace(".json", "-rep.json")))
        except Exception:
            pass
    elif ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        def page(url):
            rq = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
                                                      "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.8"})
            try:
                with urllib.request.urlopen(rq, timeout=15) as f:
                    return f.status, f.read(600000).decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                return e.code, ""
            except Exception as e:
                return 0, str(e)[:100]
        code, html = page("https://www.abuseipdb.com/check/" + ip)
        rep["abuse"] = dict(abuse_parse(html), code=code)
        code, html = page("https://scamalytics.com/ip/" + ip)
        sc = {"code": code}
        m = re.search(r'"score"\s*:\s*"?(\d+)', html) or re.search(r"Fraud Score:?\s*(?:<[^>]+>\s*)*(\d+)", html, re.I)
        r = re.search(r'"risk"\s*:\s*"([a-z ]+)"', html, re.I) or re.search(r">\s*(Low|Medium|High|Very High) Risk\s*<", html, re.I)
        if m:
            sc["score"] = int(m.group(1))
        if r:
            sc["risk"] = r.group(1).lower()
        rep["scam"] = sc
        code, body = page("https://api.stopforumspam.org/api?ip=%s&json" % ip)   # открытый API, без ключа
        sfs = {"code": code}
        try:
            j = (json.loads(body) or {}).get("ip") or {}
            sfs.update(appears=int(j.get("appears") or 0), freq=int(j.get("frequency") or 0),
                       conf=float(j.get("confidence") or 0), last=(j.get("lastseen") or "")[:10])
        except Exception:
            pass
        rep["sfs"] = sfs
    # пускают ли ИИ-сервисы и считают ли адрес хостингом / VPN — как в XaksFlaX/ipregion-fixed (MIT), своим кодом
    if FAKE:
        try:
            out.update(json.load(open(FAKE.replace(".json", "-ai.json"))))
        except Exception:
            pass
    elif ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        import threading
        UA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

        def call(url, headers=None, data=None):
            rq = urllib.request.Request(url, data=data, headers=dict({"User-Agent": UA}, **(headers or {})))
            try:
                with urllib.request.urlopen(rq, timeout=12) as f:
                    return f.status, f.read(300000).decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                try:
                    return e.code, e.read(300000).decode("utf-8", "replace")
                except Exception:
                    return e.code, ""
            except Exception as e:
                return 0, str(e)[:100]

        def verdict(code, body, yes, no_code, no_text):
            # True — пускает, False — «не в вашей стране», None — непонятно (капча, сбой)
            if no_text in body and (no_code is None or code == no_code):
                return False
            return True if code == yes else None

        def chatgpt():   # 403 unsupported_country_region_territory, где ChatGPT не работает
            c, b = call("https://api.openai.com/compliance/cookie_requirements", {"Authorization": "Bearer null"})
            return {"ok": verdict(c, b, 200, None, "unsupported_country"), "code": c}

        def claude():    # без ключа: 401 там, где Claude работает, 403 «Request not allowed» — где нет
            c, b = call("https://api.anthropic.com/v1/messages", {"anthropic-version": "2023-06-01", "Content-Type": "application/json"}, b"{}")
            return {"ok": verdict(c, b, 401, 403, "Request not allowed"), "code": c}

        def copilot():   # Cloudflare отвечает «error code: 1009» (страна запрещена), где Copilot не работает
            c, b = call("https://copilot.microsoft.com/", {"Accept": "text/html", "Accept-Language": "en-US,en;q=0.8"})
            return {"ok": verdict(c, b, 200, None, "error code: 1009"), "code": c}

        def grok():      # без ключа: 401, где Grok работает, 403 «not available in your region» — где нет
            c, b = call("https://api.x.ai/v1/models")
            return {"ok": verdict(c, b, 401, 403, "not available in your region"), "code": c}

        def ipapi():     # ip-api.com: hosting = адрес дата-центра
            c, b = call("https://demo.ip-api.com/json/%s?fields=status,hosting" % ip, {"Origin": "https://ip-api.com"})
            try:
                j = json.loads(b)
                return {"code": c, "hosting": j.get("hosting")} if j.get("status") == "success" else {"code": c}
            except Exception:
                return {"code": c}

        def proxycheck():   # proxycheck.io: VPN / прокси (без ключа — 100 запросов в день с адреса)
            c, b = call("https://proxycheck.io/v2/%s?vpn=1&asn=1" % ip)
            try:
                j = json.loads(b)
            except Exception:
                return {"code": c}
            if j.get("status") == "denied":
                return {"code": c, "limit": True}
            x = j.get(ip) or {}
            return {"code": c, "proxy": x.get("proxy"), "type": x.get("type"), "provider": x.get("provider")}

        def ipinfo():    # ipinfo.io: тип сети (isp/hosting/business) и пометки vpn/proxy/tor/relay
            c, b = call("https://ipinfo.io/widget/demo/" + ip)
            try:
                dd = json.loads(b).get("data") or {}
            except Exception:
                return {"code": c}
            pv = dd.get("privacy") or {}
            return {"code": c, "type": (dd.get("asn") or {}).get("type") or (dd.get("company") or {}).get("type"),
                    "flags": [k for k in ("vpn", "proxy", "tor", "relay") if pv.get(k) is True]}

        res = {}
        jobs = {"ai.ChatGPT": chatgpt, "ai.Claude": claude, "ai.Copilot": copilot, "ai.Grok": grok,
                "net.ipapi": ipapi, "net.proxycheck": proxycheck, "net.ipinfo": ipinfo}

        def run(k, fn):
            try:
                res[k] = fn()
            except Exception as e:
                res[k] = {"code": 0, "err": str(e)[:80]}
        th = [threading.Thread(target=run, args=kv) for kv in jobs.items()]
        for x in th:
            x.start()
        for x in th:
            x.join(30)
        for k, v in list(res.items()):
            grp, name = k.split(".")
            out.setdefault(grp, {})[name] = v
finally:
    shutil.rmtree(d, ignore_errors=True)
print(json.dumps(out, ensure_ascii=False))
'''


def abuse_parse(html):
    """Страница AbuseIPDB → {reports, conf}. Та же функция работает и на сервере: её текст уходит в RUNNER."""
    import re
    txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html or ""))
    if re.search(r"was not found in our database", txt, re.I):
        return {"reports": 0, "conf": 0}
    a = {}
    m = re.search(r"reported (?:a total of )?([\d,]+) times?", txt, re.I)
    c = re.search(r"Confidence of Abuse is ?(\d+) ?%", txt, re.I)
    if m:
        a["reports"] = int(m.group(1).replace(",", ""))
    if c:
        a["conf"] = int(c.group(1))
    return a


def runner(fake=""):
    """Текст для python3 - на сервере. fake — путь к готовому ответу (стенд)."""
    data = base64.b64encode(IPR_FILE.read_bytes()).decode()
    import inspect
    return "IPR = %r\nFAKE = %r\n" % (data, fake) + inspect.getsource(abuse_parse) + RUNNER


# программы для ipregion → пакеты Debian/Ubuntu (ставятся только по кнопке с подтверждением)
PKGS = {"jq": "jq", "curl": "curl", "ip": "iproute2"}


def install_cmd(miss):
    """Команда для сервера: поставить пакеты (если списки пакетов старые — сначала apt-get update) и проверить."""
    miss = [m for m in miss if m in PKGS]
    if not miss:
        return None
    ap = "DEBIAN_FRONTEND=noninteractive timeout 240 apt-get install -y -o DPkg::Lock::Timeout=120 " + " ".join(PKGS[m] for m in miss)
    return ("{ %s || { timeout 180 apt-get update -o DPkg::Lock::Timeout=120 && %s; }; } 2>&1 | tail -n 5; "
            "ok=1; for c in %s; do command -v $c >/dev/null || ok=; done; [ -n \"$ok\" ] && echo VPN_DASH_OK" % (ap, ap, " ".join(miss)))


# страны, где ChatGPT / Gemini / Claude официально не работают (для подсветки)
AI_BLOCKED = {"RU", "BY", "CN", "HK", "IR", "KP", "SY", "CU", "VE"}
SANCTION = {"RU", "BY", "IR", "KP", "SY", "CU"}
NAMES = {"RU": "Россия", "SE": "Швеция", "FI": "Финляндия", "FR": "Франция", "DE": "Германия", "ES": "Испания",
         "NL": "Нидерланды", "GB": "Великобритания", "US": "США", "BY": "Беларусь", "KZ": "Казахстан", "PL": "Польша",
         "LV": "Латвия", "LT": "Литва", "EE": "Эстония", "CH": "Швейцария", "AT": "Австрия", "IT": "Италия",
         "CZ": "Чехия", "TR": "Турция", "AE": "ОАЭ", "SG": "Сингапур", "JP": "Япония", "HK": "Гонконг", "CN": "Китай"}
KEY_SERVICES = ["YouTube", "Google", "YouTube Premium", "ChatGPT", "Gemini Supported", "Netflix", "Spotify", "Apple",
                "Microsoft", "Twitch", "Tiktok", "Steam", "Reddit", "Disney+"]


def cc(v):
    """«NL», «NL (AMS)» → «NL»; иначе None."""
    m = re.match(r"^([A-Z]{2})\b", str(v or ""))
    return m.group(1) if m else None


def summarize(raw):
    """Ответ сервера → то, что показывает страница: страна по базам (большинство), владелец адреса,
    ключевые сервисы и пометки простыми словами."""
    mm0 = (raw or {}).get("mm") or {}
    if not raw or raw.get("error") and not raw.get("ipr") and (not mm0.get("ip") or mm0.get("error")):
        return {"error": (raw or {}).get("error") or "нет ответа"}
    ipr = raw.get("ipr") or {}
    res = ipr.get("results") or {}
    mm = raw.get("mm") or {}
    geo = [(x.get("service"), x.get("ipv4")) for x in res.get("primary") or []]
    svc = {x.get("service"): x.get("ipv4") for x in res.get("custom") or []}
    cdn = [(x.get("service"), x.get("ipv4")) for x in res.get("cdn") or []]
    votes = {}
    for _, v in geo:
        c = cc(v)
        if c:
            votes[c] = votes.get(c, 0) + 1
    order = sorted(votes.items(), key=lambda kv: -kv[1])
    main = order[0][0] if order else mm.get("country")
    notes = []

    def note(level, text):
        notes.append({"level": level, "text": text})
    if not raw.get("ipr"):
        e = raw.get("error") or "не ответил"
        note("warn", "базы геолокации и сервисы (YouTube, Google, Netflix…) не проверены: %s%s. Остальное — ниже"
             % (e, " — кнопка ниже поставит их (apt-get install) и повторит проверку" if raw.get("miss") else ""))
    reg = mm.get("registered")
    if reg and main and reg != main:
        note("warn" if reg in SANCTION else "info",
             "сеть зарегистрирована: %s (%s), а по базам адрес — %s; сервисы, которые смотрят на владельца сети, "
             "могут считать его %s" % (NAMES.get(reg, reg), mm.get("org") or "?", NAMES.get(main, main),
                                       "российским" if reg == "RU" else "адресом страны владельца"))
    yt, gg = cc(svc.get("YouTube")), cc(svc.get("Google"))
    if yt:
        note("bad" if yt == "RU" else "info", "YouTube видит страну: %s%s" % (
            NAMES.get(yt, yt), " — реклама и рекомендации этой страны" if yt != "RU" else " — российский YouTube"))
    if gg and yt and gg != yt:
        note("warn", "Google и YouTube видят разные страны: %s и %s" % (gg, yt))
    # ИИ: пускают ли (проверки ipregion-fixed) + Gemini из ipregion (по стране, которую видит Google)
    ai_raw = raw.get("ai") or {}
    ai = []
    for name in ("ChatGPT", "Claude", "Gemini", "Copilot", "Grok"):
        if name == "Gemini":
            if not svc:
                continue        # ipregion не отработал — про Gemini не знаем
            gv = str(svc.get("Gemini Supported") or "").lower()
            ok = True if gv == "yes" else False if gv == "no" else None
            ai.append((name, ok, None))
        elif name in ai_raw:
            x = ai_raw[name] or {}
            ai.append((name, x.get("ok"), x.get("code")))
    gpt = cc(svc.get("ChatGPT"))
    closed = [n for n, ok, _ in ai if ok is False]
    if closed:
        expected = main in AI_BLOCKED   # российский вход: так и должно быть
        note("info" if expected else "bad", "не пускают ИИ: %s — %s" % (", ".join(closed),
             "для адреса в %s это ожидаемо" % NAMES.get(main, main) if expected else
             "сервис считает, что адрес в стране, где он не работает (смотрите, какую страну видят Google и ChatGPT)"))
    elif gpt in AI_BLOCKED and "ChatGPT" not in ai_raw:
        note("bad", "ChatGPT видит %s — там он не работает" % NAMES.get(gpt, gpt))
    # хостинг / VPN: ip-api, ipinfo, proxycheck
    nr = raw.get("net") or {}
    ia, pc, ii = nr.get("ipapi") or {}, nr.get("proxycheck") or {}, nr.get("ipinfo") or {}
    host_by = [s for s, v in (("ip-api", ia.get("hosting") is True), ("ipinfo", ii.get("type") == "hosting")) if v]
    isp_by = [s for s, v in (("ip-api", ia.get("hosting") is False), ("ipinfo", ii.get("type") in ("isp", "business", "education"))) if v]
    vpn = []
    if pc.get("proxy") == "yes":
        vpn.append("proxycheck: " + (pc.get("type") or "прокси"))
    if ii.get("flags"):
        vpn.append("ipinfo: " + ", ".join(f.upper() if f in ("vpn", "tor") else f for f in ii["flags"]))
    vpn_clean = [s for s, v in (("proxycheck", pc.get("proxy") == "no"), ("ipinfo", "flags" in ii and not ii["flags"])) if v]
    net = None
    if nr:
        net = {"hosting": host_by, "isp": isp_by, "ii_type": ii.get("type"), "vpn": vpn, "clean": vpn_clean,
               "pc_limit": bool(pc.get("limit"))}
        if vpn:
            note("warn", "адрес помечен как VPN/прокси (%s) — стриминги, банки и часть сайтов могут не пускать "
                 "или чаще показывать капчу" % "; ".join(vpn))
    nores = [k for k, v in svc.items() if v in (None, "", "N/A", "null")]
    geo_nores = [k for k, v in geo if not cc(v)]
    if svc and len(nores) * 3 >= len(svc):
        missed = [k for k in ("YouTube", "Google", "ChatGPT", "Gemini Supported") if k in nores]
        note("warn", "не ответили %d из %d сервисов%s и %d из %d баз геолокации — скорее всего, сервер не успел: скрипт опрашивает "
             "всех разом, на слабом сервере часть запросов не укладывается во время. Повторите проверку; если так же — "
             "сервисы отказывают этому адресу"
             % (len(nores), len(svc), (" (в том числе " + ", ".join(missed) + ")") if missed else "", len(geo_nores), len(geo)))
    if len(order) > 1 and order[1][1] >= 2:
        note("info", "базы расходятся: " + ", ".join("%s ×%d" % (c, n) for c, n in order))
    rp = raw.get("rep") or {}
    ab, scm = rp.get("abuse") or {}, rp.get("scam") or {}
    if ab.get("conf") is not None and (ab["conf"] >= 25 or (ab.get("reports") or 0) >= 5):
        note("bad" if ab["conf"] >= 75 else "warn", "на адрес жаловались в AbuseIPDB: %s раз, уверенность «вредный» %d%% — "
             "чаще капчи и проверки «вы робот?», могут не пускать в аккаунты" % (ab.get("reports", "?"), ab["conf"]))
    if scm.get("score") is not None and scm["score"] >= 50:
        note("bad" if scm["score"] >= 75 else "warn", "Scamalytics оценивает риск мошенничества в %d из 100 — банки, магазины и "
             "сервисы с оплатой могут относиться к адресу с подозрением" % scm["score"])
    sfs = rp.get("sfs") or {}
    if sfs.get("appears"):
        note("warn" if (sfs.get("conf") or 0) < 50 else "bad", "адрес есть в базе спамеров StopForumSpam: %d записей, последняя %s — "
             "форумы и регистрации могут его не пускать" % (sfs.get("freq") or 0, sfs.get("last") or "?"))
    reput = {"abuse": ab, "scam": scm, "sfs": sfs} if rp else None
    shown = [k for k in KEY_SERVICES if k in svc and k != "Gemini Supported"]   # Gemini — в строке «ИИ»
    return {"ip": ipr.get("ipv4") or mm.get("ip"), "registered": reg, "rep": reput, "asn": mm.get("asn"), "org": mm.get("org"),
            "country": main, "votes": order, "geo": geo, "cdn": cdn, "ai": ai, "net": net,
            "services": [(k, svc[k]) for k in shown] + [(k, v) for k, v in svc.items() if k not in KEY_SERVICES],
            "notes": notes, "warn": raw.get("error"), "miss": raw.get("miss") or []}


def abuse_from_pc(ip):
    """AbuseIPDB за Cloudflare часто не пускает запросы из датацентров — тогда спрашиваем с этого компьютера."""
    import urllib.error
    import urllib.request
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or ""):
        return None
    rq = urllib.request.Request("https://www.abuseipdb.com/check/" + ip, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.8"})
    a = {"pc": True}
    try:
        with urllib.request.urlopen(rq, timeout=15) as f:
            a["code"], html = f.status, f.read(600000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        a["code"] = e.code
        return a
    except Exception:  # noqa: BLE001
        a["code"] = 0
        return a
    a.update(abuse_parse(html))
    return a


parse = last_json   # итог скрипта — последняя строка JSON (jsonline.py)
