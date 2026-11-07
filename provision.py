"""Мастер «Новый сервер»: проверка нового VPS, замер скорости и установка выхода.

Задачи (jobs) выполняются в фоне внутри панели, их журнал хранится в jobs/<id>.json рядом с
панелью (без паролей), поэтому страницу можно закрыть и открыть снова. Долгие шаги идут на
самом сервере отдельным процессом (nohup) — обрыв SSH их не прерывает, панель дочитывает журнал.

Пароль нового сервера живёт только в памяти задачи, пока не установка не закончится успешно
(тогда он сохраняется в Диспетчере учётных данных, как у остальных серверов).
"""
import base64
import codecs
import json
import re
import secrets
import shlex
import tarfile
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path, PurePosixPath

import zapret as zapret_mod

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\r")
REMOTE = "/root/.vpn-dash-job"
TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,19}$")
TRANSLIT = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
                    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "i", "k", "l", "m", "n", "o", "p", "r", "s", "t",
                     "u", "f", "h", "c", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"]))


def latin(name):
    s = "".join(TRANSLIT.get(c, c) for c in str(name).lower())
    s = re.sub(r"[^a-z0-9]", "", s)
    s = re.sub(r"^[0-9]+", "", s)
    return (s[:1].upper() + s[1:])[:20] or "Exit"


class Stop(Exception):
    pass


class Job:
    def __init__(self, mgr, kind, params, jid=None):
        self.mgr, self.kind, self.params = mgr, kind, params
        self.id = jid or time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)
        self.status, self.error, self.result = "run", "", {}
        self.steps, self.cur = [], -1
        self.lines = []
        self.started, self.finished = time.time(), None
        self.lock = threading.Lock()
        self._saved = 0

    # --- журнал и шаги
    def log(self, text):
        text = ANSI.sub("", str(text))
        with self.lock:
            for line in text.splitlines() or [""]:
                self.lines.append(line[:400])
            if len(self.lines) > 5000:
                self.lines = self.lines[-5000:]
        self.save(lazy=True)

    def plan(self, steps):
        self.steps = [{"key": k, "title": t, "where": w, "status": "wait", "note": ""} for k, t, w in steps]

    def begin(self, key):
        for i, s in enumerate(self.steps):
            if s["key"] == key:
                self.cur = i
                s["status"] = "run"
                s["t0"] = time.time()
                self.log("")
                self.log("== %s%s" % (s["title"], " · " + s["where"] if s["where"] else ""))
        self.save()

    def end(self, key, status="ok", note=""):
        for s in self.steps:
            if s["key"] == key:
                s["status"], s["note"] = status, note
                s["secs"] = round(time.time() - s.get("t0", time.time()))
        self.save()

    def skip(self, key, note=""):
        self.end(key, "skip", note)

    def snapshot(self, since=0):
        with self.lock:
            return {"id": self.id, "kind": self.kind, "status": self.status, "error": self.error,
                    "params": self.params, "steps": self.steps, "cur": self.cur, "result": self.result,
                    "started": self.started, "finished": self.finished,
                    "log_from": since, "log": self.lines[since:], "log_n": len(self.lines)}

    def save(self, lazy=False):
        if lazy and time.time() - self._saved < 2:
            return
        self._saved = time.time()
        try:
            self.mgr.dir.mkdir(exist_ok=True)
            p = self.mgr.dir / ("%s.json" % self.id)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.snapshot(), ensure_ascii=False), encoding="utf-8")
            tmp.replace(p)
        except OSError:
            pass


class Provisioner:
    def __init__(self, dash, app_dir, scripts_dir, helpers):
        self.d = dash
        self.h = helpers          # CheckError, PROBE, parse_dc, TG_DC_DEFAULT из dash.py
        self.dir = Path(app_dir) / "jobs"
        self.secrets_dir = Path(app_dir) / "secrets"
        self.scripts = Path(scripts_dir)
        self.jobs = {}
        self.dir.mkdir(exist_ok=True)
        # прошлые задачи: незавершённые помечаем прерванными (пароль после перезапуска уже не в памяти)
        for p in sorted(self.dir.glob("*.json"))[-30:]:
            try:
                j = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            job = Job(self, j.get("kind"), j.get("params") or {}, j.get("id"))
            job.status, job.error, job.result = j.get("status"), j.get("error", ""), j.get("result") or {}
            job.steps, job.cur, job.lines = j.get("steps") or [], j.get("cur", -1), j.get("log") or []
            job.started, job.finished = j.get("started") or 0, j.get("finished")
            if job.status == "run":
                job.status = "interrupted"
                job.error = ("панель перезапускалась во время задачи. Шаг на сервере мог доработать сам — "
                             "журнал ниже. Установку можно запустить заново: уже сделанное она пропустит.")
                for s in job.steps:
                    if s["status"] == "run":
                        s["status"] = "error"
                job.save()
            self.jobs[job.id] = job

    # ------------------------------------------------------------ API
    def list(self):
        return [{"id": j.id, "kind": j.kind, "status": j.status, "name": j.params.get("name"), "role": j.params.get("role"), "sid": j.params.get("sid"),
                 "started": j.started, "finished": j.finished} for j in sorted(self.jobs.values(), key=lambda x: x.started)][-15:]

    def get(self, jid, since=0):
        j = self.jobs.get(jid)
        return j.snapshot(since) if j else None

    def start(self, kind, params, password):
        if kind == "install" and any(j.kind == "install" and j.status == "run" for j in self.jobs.values()):
            raise ValueError("уже идёт другая установка — дождитесь её окончания")
        clean = {k: v for k, v in params.items() if k != "password"}
        job = Job(self, kind, clean)
        self.jobs[job.id] = job
        fn = {"check": self._check, "bench": self._bench, "install": self._install, "geo": self._geo}[kind]
        return self._spawn(job, fn, password)

    def start_geo(self, srv, install=None):
        """«Как видят адрес» у уже добавленного сервера (только запросы к сервисам). install — список программ
        (jq, curl, ip), которые сначала поставить: только по кнопке «Поставить и проверить заново» с подтверждением."""
        if any(j.kind == "geo" and j.status == "run" and j.params.get("sid") == srv["id"] for j in self.jobs.values()):
            raise ValueError("проверка этого сервера уже идёт")
        import ipcheck
        install = [m for m in install or [] if m in ipcheck.PKGS]
        job = Job(self, "geo", {"sid": srv["id"], "name": srv["name"], "install": install})
        self.jobs[job.id] = job
        return self._spawn(job, self._geo, None)

    def _geo(self, job, password):
        """Как базы геолокации и сервисы видят адрес: ipregion (проверенная копия) от nobody + владелец сети у MaxMind."""
        import ipcheck
        p = job.params
        if p.get("sid"):
            srv = self.d.cfg.by_id(p["sid"])
            if not srv:
                raise Stop("сервера больше нет в панели")
            name = srv["name"]
        else:
            srv, name = self.new_srv(job, password), p.get("name") or p["host"]
        inst = p.get("install") or []
        job.plan(([("pkg", "Поставить программы для проверки: " + ", ".join(ipcheck.PKGS[m] for m in inst), name)] if inst else [])
                 + [("geo", "Базы геолокации и сервисы: YouTube, Google, ChatGPT, Gemini, Netflix…", name)])
        if inst:
            job.begin("pkg")
            cmd = ipcheck.install_cmd(inst)
            if STAND:   # стенд: jq «прячется» как /usr/bin/jq.testbed-off — имитация apt-get install
                cmd = 'echo "стенд: имитация apt-get install"; [ -e /usr/bin/jq.testbed-off ] && mv /usr/bin/jq.testbed-off /usr/bin/jq; echo VPN_DASH_OK'
            rc, out, err = self.sh(srv, cmd, timeout=300)
            for line in (out or "").strip().splitlines()[-5:]:
                if line.strip() and line.strip() != "VPN_DASH_OK":
                    job.log(line)
            if "VPN_DASH_OK" not in (out or ""):
                raise Stop("не поставилось (apt-get): %s" % ((out or err or "").strip().splitlines() or ["?"])[-1][:200])
            job.end("pkg", "ok", "поставлено")
        job.begin("geo")
        fake = "/etc/testbed-ipregion.json" if STAND else ""
        rc, out, err = self.sh(srv, "python3 -", stdin=ipcheck.runner(fake), timeout=300)
        try:
            raw = ipcheck.parse(out)
        except ValueError:
            raw = None
        if not raw:
            raise Stop("проверка не ответила: %s" % ((err.strip().splitlines() or ["код %s" % rc])[-1][:200]))
        ab = (raw.get("rep") or {}).get("abuse") or {}
        if raw.get("rep") is not None and ab.get("conf") is None and not STAND:   # сервер не пустили — спросим с этого ПК
            pc = ipcheck.abuse_from_pc(((raw.get("ipr") or {}).get("ipv4")) or (raw.get("mm") or {}).get("ip"))
            if pc and pc.get("conf") is not None:
                raw["rep"]["abuse"] = pc
        sm = ipcheck.summarize(raw)
        job.result = {"geo": sm}
        if sm.get("error"):
            raise Stop("проверка не прошла: %s" % sm["error"])
        for n in sm["notes"]:
            job.log(("! " if n["level"] in ("warn", "bad") else "") + n["text"])
        job.end("geo", "warn" if any(n["level"] == "bad" for n in sm["notes"]) else "ok",
                "по базам: %s · владелец сети: %s" % (sm.get("country") or "?", sm.get("registered") or "?"))
        if p.get("sid"):
            with self.d.lock:
                self.d.geo[p["sid"]] = dict(sm, at=time.time())
            self.d.addr_save()

    def start_mimic(self, srv, iface, profile):
        """Пакеты-маски AmneziaWG на туннеле входа (I1): записать (profile) или убрать (""). По кнопке с подтверждением;
        не поднялся туннель — на входе вернётся прежний конфиг."""
        import awgmimic
        if srv["role"] != "entry":
            raise ValueError("пакеты-маски ставятся только на входах — их шлёт тот, кто начинает соединение")
        if not awgmimic.IFACE_RE.match(iface or ""):
            raise ValueError("странный туннель")
        if profile and profile not in awgmimic.PROFILES:
            raise ValueError("нет такого вида маски")
        if any(j.kind == "mimic" and j.status == "run" for j in self.jobs.values()):
            raise ValueError("уже меняются маски на другом туннеле — дождитесь окончания")
        job = Job(self, "mimic", {"sid": srv["id"], "name": srv["name"], "iface": iface, "profile": profile})
        self.jobs[job.id] = job
        return self._spawn(job, self._mimic, None)

    def _mimic(self, job, password):
        import awgmimic
        p = job.params
        srv = self.d.cfg.by_id(p["sid"])
        if not srv:
            raise Stop("сервера больше нет в панели")
        what = ("маска %s" % p["profile"].upper()) if p["profile"] else "убрать маски"
        job.plan([("mimic", "%s · %s: %s, перезапуск туннеля, проверка рукопожатия" % (srv["name"], p["iface"], what), "")])
        job.begin("mimic")
        lines = awgmimic.generate(p["profile"]) if p["profile"] else {}
        for k, v in lines.items():
            job.log("%s = %s  (%d байт)" % (k, v if len(v) < 160 else v[:150] + "…", awgmimic.size(v)))
        rc, out, err = self.sh(srv, "python3 -", stdin=awgmimic.apply_script(p["iface"], lines), timeout=200)
        try:
            r = json.loads((out or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Stop("скрипт на входе не ответил: %s" % ((err or "").strip().splitlines() or ["код %s" % rc])[-1][:200])
        for line in r.get("log") or []:
            job.log(line)
        if r.get("error"):
            raise Stop(r["error"])
        if not r.get("ok"):
            raise Stop("туннель с масками не поднялся — " + ("вернул прежний конфиг, туннель работает" if r.get("rolled_back")
                                                            else "прежний конфиг вернул, но туннель не поднялся: проверьте вручную"))
        job.end("mimic", "ok", "готово")

    def start_dns(self, srv):
        """DNS на сервере: какие публичные DNS отвечают (UDP/DoH/DoT) и подменяют ли ответы. Только запросы."""
        if any(j.kind == "dns" and j.status == "run" and j.params.get("sid") == srv["id"] for j in self.jobs.values()):
            raise ValueError("проверка DNS этого сервера уже идёт")
        job = Job(self, "dns", {"sid": srv["id"], "name": srv["name"]})
        self.jobs[job.id] = job
        return self._spawn(job, self._dns, None)

    def _dns(self, job, password):
        import dnscheck
        srv = self.d.cfg.by_id(job.params["sid"])
        if not srv:
            raise Stop("сервера больше нет в панели")
        job.plan([("dns", "DNS: Cloudflare, Google, Quad9, AdGuard, Яндекс — UDP, DoH, DoT; подмена ответов", srv["name"])])
        job.begin("dns")
        rc, out, err = self.sh(srv, "python3 -", stdin=dnscheck.runner(srv["host"], "/etc/testbed-dns.json" if STAND else ""), timeout=90)
        try:
            raw = dnscheck.parse(out)
        except ValueError:
            raw = None
        if not raw:
            raise Stop("проверка не ответила: %s" % ((err.strip().splitlines() or ["код %s" % rc])[-1][:200]))
        sm = dnscheck.summarize(raw)
        job.result = {"dns": sm}
        if sm.get("error"):
            raise Stop(sm["error"])
        for n in sm["notes"]:
            job.log(("! " if n["level"] in ("warn", "bad") else "") + n["text"])
        job.end("dns", {"ok": "ok", "warn": "warn", "bad": "warn"}[sm["level"]], "")
        with self.d.lock:
            self.d.dns[srv["id"]] = dict(sm, at=time.time())
        self.d.addr_save()

    def start_nb(self, srv):
        """«Шумные соседи»: подсеть /24 сервера проверяется с этого компьютера; с сервера — только настройки Reality."""
        if any(j.kind == "nb" and j.status == "run" and j.params.get("sid") == srv["id"] for j in self.jobs.values()):
            raise ValueError("проверка соседей этого сервера уже идёт")
        job = Job(self, "nb", {"sid": srv["id"], "name": srv["name"]})
        self.jobs[job.id] = job
        return self._spawn(job, self._nb, None)

    def _nb(self, job, password):
        import neighbors
        srv = self.d.cfg.by_id(job.params["sid"])
        if not srv:
            raise Stop("сервера больше нет в панели")
        job.plan([("mask", "Под какой сайт маскируется Reality и открывается ли он с сервера (только чтение)", srv["name"]),
                  ("scan", "Соседи по подсети /24 — с этого компьютера, порт 443", "")])
        job.begin("mask")
        reality = []
        try:
            rc, out, err = self.sh(srv, "python3 -", stdin=neighbors.reality_script(), timeout=90)
            reality = (neighbors.parse(out) or {}).get("reality") or []
            for r in reality:      # как имя видят публичные DNS (DoH Яндекса/Google/Cloudflare с этого ПК) — сервер спрашивает DNS хостера
                if r.get("sni") and not STAND:
                    got = neighbors.doh_ips(r["sni"])
                    if got:            # никто не ответил — не сравниваем
                        r["pub_ips"], r["pub_by"] = sorted(set().union(*got.values())), list(got)
            dead = [r for r in reality if r.get("ok") is False]
            job.end("mask", "warn" if dead else "ok", ", ".join("порт %s → %s%s" % (r["port"], ", ".join(r["names"]) or r["dest"] or "?",
                                                                     " (не открывается!)" if r.get("ok") is False else "") for r in reality)
                    or "Reality на сервере нет")
        except (Stop, ValueError) as e:
            job.end("mask", "warn", "не прочитал: %s" % e)
        job.begin("scan")
        if STAND:
            raw = json.loads(Path("/etc/testbed-neighbors.json").read_text(encoding="utf-8"))
            job.log("стенд: готовый ответ для подсети %s" % raw.get("net"))
        else:
            ip = neighbors.public_ip(srv["host"])
            if not ip:
                raise Stop("не понял внешний адрес сервера «%s» — нужен обычный IPv4" % srv["host"])
            raw = neighbors.scan(ip, job.log)
        raw["reality"] = reality
        sm = neighbors.summarize(raw)
        job.result = {"nb": sm}
        if sm.get("error"):
            raise Stop(sm["error"])
        for n in sm["notes"]:
            job.log(("! " if n["level"] in ("warn", "bad") else "") + n["text"])
        job.end("scan", {"ok": "ok", "warn": "warn", "bad": "warn"}[sm["level"]],
                "ответили %d · чужих сертификатов %d · настоящих сайтов %d" % (sm["tls"], len(sm["foreign"]), len(sm["genuine"])))
        with self.d.lock:
            self.d.nb[srv["id"]] = dict(sm, at=time.time())
        self.d.addr_save()

    def start_upgrade(self, srv, reboot, only_reboot=False):
        """Обновление пакетов (или только перезагрузка) уже добавленного сервера. Одно за раз."""
        if any(j.kind == "upgrade" and j.status == "run" for j in self.jobs.values()):
            raise ValueError("уже обновляется другой сервер — дождитесь окончания, чтобы не уронить два сразу")
        job = Job(self, "upgrade", {"sid": srv["id"], "name": srv["name"], "reboot": reboot, "only_reboot": only_reboot})
        self.jobs[job.id] = job
        return self._spawn(job, self._upgrade, None)

    def start_migrate(self, srv, awg_net):
        """Выход с Amnezia в Docker → AmneziaWG без Docker (как у выходов, поставленных мастером). Одна задача за раз."""
        if any(j.kind in ("migrate", "install") and j.status == "run" for j in self.jobs.values()):
            raise ValueError("уже идёт установка или перевод другого выхода — дождитесь окончания")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$", awg_net or ""):
            raise ValueError("подсеть туннелей в виде 10.11.0")
        job = Job(self, "migrate", {"sid": srv["id"], "name": srv["name"], "awg_net": awg_net})
        self.jobs[job.id] = job
        return self._spawn(job, self._migrate, None)

    def _migrate(self, job, _password):
        p = job.params
        cfg = self.d.cfg
        srv = cfg.by_id(p["sid"])
        if not srv or srv["role"] != "exit":
            raise Stop("выхода больше нет в панели")
        pw = cfg.get_pw(srv["id"])
        if not pw:
            raise Stop("нет пароля от %s" % srv["name"])
        x = (((self.d.status.get(srv["id"]) or {}).get("data") or {}).get("exit") or {}).get("awg") or {}
        if x.get("mode") != "docker":
            raise Stop("на %s AmneziaWG и так без Docker — переводить нечего" % srv["name"])
        container = x.get("container") or "amnezia-awg2"
        entries, tag = [], ""
        for e in cfg.servers:
            if e["role"] != "entry":
                continue
            chans = [c for c in self.d.channels.get(e["id"], []) if c.get("exit_id") == srv["id"] and c.get("kind") == "AWG"]
            if chans:
                entries.append(e)
                tag = tag or (chans[0].get("tag") or "")[4:]
        if not TAG_RE.match(tag):
            tag = latin(srv["name"]) or "Exit"
        for e in entries:
            if not cfg.get_pw(e["id"]):
                raise Stop("нет пароля от %s" % e["name"])
        steps = [("setup", "AmneziaWG без Docker на выходе — сборка модуля ядра 5–10 мин", srv["name"])]
        steps += [("link-" + e["id"], "Туннель переводится на новый AmneziaWG (3X-UI не меняется)", e["name"]) for e in entries]
        steps += [("docker", "Остановить и удалить контейнер Amnezia (%s)" % container, srv["name"]),
                  ("panel", "Проверка выхода и каналов", "панель")]
        job.plan(steps)

        job.begin("setup")
        self.put(srv, self.scripts / "vpn-exit-setup.sh", "/root/vpn-exit-setup.sh")
        rc = self.detached(job, srv, "migrate-setup", "ONLY_AWG=1 AWG_SUBNET=%s bash /root/vpn-exit-setup.sh\n" % p["awg_net"], timeout=3600)
        if rc != 0:
            raise Stop("AmneziaWG на выходе не встал (код %d) — журнал выше. Входы не трогал, контейнер работает как раньше." % rc)
        rc, out, _ = self.sh(srv, "awg show awg0 listen-port; ufw status 2>/dev/null | head -n1; "
                                  "ip -o route show default 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' | head -n1")
        lines = out.split("\n") + ["", ""]
        port, ufw, wan = lines[0].strip(), lines[1].strip(), lines[2].strip() or "eth0"
        if not port.isdigit():
            raise Stop("awg0 на выходе не отвечает — журнал выше. Входы не трогал.")
        job.result["awg_port"] = port
        if "Status: active" in ufw:       # фаервол включали панелью: новый порт и пересылку через awg0 — разрешить
            self.sh(srv, "ufw allow %s/udp comment 'AmneziaWG awg0' && ufw route allow in on awg0 out on %s" % (port, shlex.quote(wan)))
            job.log("ufw на выходе: открыт UDP %s, разрешена пересылка awg0 → %s" % (port, wan))
        job.end("setup", note="UDP %s" % port)

        done = []
        try:
            for e in entries:
                key = "link-" + e["id"]
                job.begin(key)
                for f in ("vpn-restore.sh", "vpn-add-exit.sh"):
                    self.put(e, self.scripts / f, "/root/" + f)
                self.sh(e, "mkdir -p %s/pw && chmod 700 %s/pw" % (REMOTE, REMOTE))
                self.put(e, pw.encode("utf-8"), "%s/pw/%s" % (REMOTE, srv["host"]), 0o600)
                self.put(e, str(int(srv.get("port") or 22)).encode(), "%s/pw/%s.port" % (REMOTE, srv["host"]), 0o600)
                rc = self.detached(job, e, "migrate-awg", "export VPN_PWDIR=%s/pw MIGRATE=1\nbash /root/vpn-add-exit.sh %s %s\n"
                                   % (REMOTE, tag, srv["host"]), timeout=900)
                if rc != 0:
                    raise Stop("%s: перевод туннеля не прошёл (код %d) — журнал выше. На этом входе вернулся старый туннель; "
                               "%sконтейнер Amnezia не тронут — всё работает" % (
                                   e["name"], rc, ("уже переведены: %s; " % ", ".join(done)) if done else ""))
                done.append(e["name"])
                job.end(key)
        finally:
            for e in entries:
                try:
                    self.sh(e, "rm -rf %s/pw" % REMOTE, timeout=30)
                except Stop:
                    job.log("не удалось удалить временный пароль на %s: удалите %s/pw вручную" % (e["name"], REMOTE))

        job.begin("docker")
        rc, out, _ = self.sh(srv, "docker rm -f %s 2>&1 && echo REMOVED" % shlex.quote(container), timeout=120)
        if "REMOVED" not in out:
            job.log(out.strip()[-300:])
            job.end("docker", "warn", "не удалось удалить — входы уже на новом AmneziaWG, контейнер можно убрать позже")
        else:
            job.end("docker", note="удалён")

        job.begin("panel")
        self.d.check_server(srv["id"])
        for _ in range(120):
            if "all" not in self.d.running:
                break
            time.sleep(1)
        self.d.check_all(True)
        post = []
        for e in entries:
            res = [self.d.results.get("%s:%s" % (e["id"], c["key"]), {}) for c in self.d.channels.get(e["id"], []) if c.get("exit_id") == srv["id"]]
            okn = sum(1 for r in res if r.get("status") in ("ok", "warn"))
            post.append({"entry": e["name"], "ok": okn, "n": len(res)})
            job.log("%s: каналы до %s — в норме %d из %d" % (e["name"], srv["name"], okn, len(res)))
        job.result["post"] = post
        self.d.note("ok", "%s: AmneziaWG переведён с Docker на модуль ядра (UDP %s), входы: %s" % (
            srv["name"], port, ", ".join(done) or "—"))
        job.end("panel", "ok" if all(x["ok"] == x["n"] for x in post) else "warn")

    def start_zapret(self, srv, action, tid=None, strat=None):
        """install / check (подбор для цели) / apply (включить цель с выбранной стратегией) / disable (выключить цель) /
        off (выключить zapret целиком) / remove. Одна задача на вход."""
        if srv["role"] != "entry":
            raise ValueError("zapret ставится только на входы")
        if action not in ("install", "check", "apply", "disable", "off", "remove"):
            raise ValueError("что сделать?")
        if any(j.kind == "zapret" and j.status == "run" and j.params.get("sid") == srv["id"] for j in self.jobs.values()):
            raise ValueError("на этом входе уже идёт действие с zapret — дождитесь окончания")
        zp = self.d.zapret
        if tid and tid not in zp.targets():
            raise ValueError("такой цели нет — обновите страницу")
        if action in ("off", "remove"):
            busy = [t["name"] for t in zp.targets().values() if ((t.get("ents") or {}).get(srv["id"]) or {}).get("direct")]
            if busy:
                raise ValueError("сначала «Вернуть через выходы» для: %s — иначе эти сайты на этом входе перестанут открываться" % ", ".join(busy))
        if action == "apply":
            if not strat or not zapret_mod.STRAT_RE.match(strat):
                raise ValueError("выберите стратегию из найденных")
        if action == "disable" and ((zp.targets()[tid].get("ents") or {}).get(srv["id"]) or {}).get("direct"):
            raise ValueError("сначала «Вернуть через выходы» — иначе сайт на этом входе перестанет открываться")
        job = Job(self, "zapret", {"sid": srv["id"], "name": srv["name"], "action": action, "tid": tid or "",
                                   "target": zp.targets()[tid]["name"] if tid else "", "strat": strat or ""})
        self.jobs[job.id] = job
        return self._spawn(job, self._zapret, None)

    def _zapret(self, job, _password):
        p, zp = job.params, self.d.zapret
        srv = self.d.cfg.by_id(p["sid"])
        if not srv or not self.d.cfg.get_pw(srv["id"]):
            raise Stop("нет входа или пароля от него")
        env = "STAND=1 " if os.environ.get("VPN_DASH_STAND") else ""
        script = "/root/vpn-zapret.sh"
        act, tid = p["action"], p.get("tid")
        t = zp.targets().get(tid) if tid else None
        titles = {"install": ("install", "zapret2 %s в /opt/zapret2 — служба выключена, ничего не меняется" % zapret_mod.ZAP_TAG),
                  "check": ("check", "Подбор стратегий для «%s»: %s" % (p.get("target"), " ".join(t["check"]) if t else "")),
                  "apply": ("apply", "Включить zapret для «%s»" % p.get("target")),
                  "disable": ("apply", "Выключить zapret для «%s»" % p.get("target")),
                  "off": ("off", "Выключить zapret на входе"), "remove": ("off", "Удалить zapret с входа")}
        key, title = titles[act]
        steps = [(key, title, srv["name"])]
        if act == "apply":
            steps.append(("verify", "Проверка: открываются ли адреса прямо с входа", srv["name"]))
        job.plan(steps)
        self.put(srv, self.scripts / "vpn-zapret.sh", script)
        job.begin(key)
        if act == "install":
            rc, out, err = self.sh(srv, "%sbash %s install %s %s 2>&1" % (env, script, shlex.quote(zapret_mod.zap_url()), zapret_mod.ZAP_TAG), timeout=420)
            for line in (out + err).strip().splitlines():
                job.log(line)
            if rc != 0:
                raise Stop("zapret2 не поставился (журнал выше)")
        elif act == "check":
            try:
                self.detached(job, srv, "zapcheck", "%sbash %s check %s\n" % (env, script, shlex.quote(" ".join(t["check"]))), timeout=7200)
            except Stop as e:
                if (tid, srv["id"]) not in zp.stopped:    # остановили кнопкой — это не ошибка, берём найденное
                    raise
                job.log(str(e) if "оборвался" not in str(e) else "")
            zp.stopped.discard((tid, srv["id"]))
            res = zp.collect(tid, srv["id"])          # весь журнал с сервера: в окне задачи хранится только конец
            if res is None:
                tail = "\n".join(job.lines[-30:])
                if "could not find working DoH" in tail:
                    raise Stop("DNS на этом входе подменяют, а ни один зашифрованный DNS (DoH) не ответил — без него подбор не идёт")
                raise Stop("подбор не дошёл до итога и ничего не нашёл (журнал выше)")
            if res.get("partial"):
                job.log("")
                job.log("Подбор остановлен — беру то, что он успел найти.")
            job.result = {"found": res}
            n = len(res["strategies"])
            job.end(key, note="найдено стратегий: %d" % n if n else "ничего не нашлось")
            job.log("")
            job.log("ИТОГ: " + ("стратегий найдено %d; лучшая открыла %d из %d адресов" % (n, res["strategies"][0]["n"], res["of"])
                                if n else "ни одна стратегия не помогла" + (" — но эти адреса и так открываются: " + ", ".join(res["free"]) if res["free"] else "")))
            return
        elif act in ("apply", "disable"):
            plan = zp.plan_for(srv["id"], extra=(tid, p["strat"]) if act == "apply" else None, without=tid if act == "disable" else None)
            if not plan:
                rc, out, err = self.sh(srv, "%sbash %s off 2>&1" % (env, script), timeout=120)
            else:
                conf, lists = zapret_mod.build_config(plan)
                for f, txt in lists.items():
                    self.put(srv, txt.encode(), f, mode=0o644)
                self.put(srv, conf.encode(), "/root/.vpn-dash-zapret.conf", mode=0o600)
                for tid_, _, s_ in plan:
                    job.log("  %s: %s" % (zp.targets()[tid_]["name"], s_))
                rc, out, err = self.sh(srv, "%sbash %s apply /root/.vpn-dash-zapret.conf 2>&1; r=$?; rm -f /root/.vpn-dash-zapret.conf; exit $r"
                                       % (env, script), timeout=180)
            for line in (out + err).strip().splitlines():
                job.log(line)
            if rc != 0:
                raise Stop("не получилось — zapret работает как раньше (журнал выше)")
            with self.d.lock:
                st = zp.ent(tid, srv["id"])
                st["zap"] = act == "apply"
                if act == "apply":
                    st["chosen"] = p["strat"]
                self.d.cfg.save()
            job.end(key)
            if act == "apply":
                job.begin("verify")
                try:
                    v = zp.verify(tid, srv["id"])
                except Exception as e:  # noqa: BLE001
                    job.end("verify", "error", str(e)[:100])
                    job.log("проверка не прошла: %s" % e)
                    return
                for h, r in v["res"].items():
                    job.log("  %s — %s" % (h, r.get("st")))
                job.result = {"verify": v}
                job.end("verify", "ok" if v["ok"] else "error", v["text"])
                job.log("ИТОГ: " + ("zapret работает — с ним все адреса открываются прямо с входа. Устройства пока ходят "
                                    "к «%s» через выходы, как раньше; чтобы пустить их напрямую — шаг 3 «Пустить напрямую»." % p.get("target")
                                    if v["ok"] else v["text"] + " — попробуйте другую стратегию или подбор заново"))
            return
        else:      # off / remove
            rc, out, err = self.sh(srv, "%sbash %s %s 2>&1" % (env, script, act), timeout=180)
            for line in (out + err).strip().splitlines():
                job.log(line)
            if rc != 0:
                raise Stop("не получилось (журнал выше)")
            with self.d.lock:
                for t_ in zp.targets().values():
                    st = (t_.get("ents") or {}).get(srv["id"])
                    if st:
                        st["zap"] = False
                        if act == "remove":
                            st.pop("found", None)
                self.d.cfg.save()
        job.end(key)
        try:
            self.d.check_server(srv["id"])
        except Exception:  # noqa: BLE001
            pass

    def _spawn(self, job, fn, password):
        def run():
            try:
                fn(job, password)
                if job.status == "run":
                    job.status = "ok"
            except Stop as e:
                job.status, job.error = "error", str(e)
            except Exception as e:  # noqa: BLE001 — любую ошибку показываем человеку, а не роняем панель
                job.status, job.error = "error", "%s: %s" % (type(e).__name__, e)
                job.log(traceback.format_exc())
            finally:
                for s in job.steps:
                    if s["status"] == "run":
                        s["status"] = "error" if job.status != "ok" else "ok"
                job.finished = time.time()
                if job.error:
                    job.log("")
                    job.log("ОШИБКА: " + job.error)
                job.save()
                self.d.ssh.drop("_new_" + job.id)
                if job.kind == "upgrade":
                    self.d.upgrade_done(job)
        threading.Thread(target=run, daemon=True).start()
        return job.id

    # ------------------------------------------------------------ SSH-помощники
    def new_srv(self, job, password):
        p = job.params
        return {"id": "_new_" + job.id, "name": p.get("name") or "новый", "host": p["host"],
                "port": int(p.get("port") or 22), "user": p.get("user") or "root", "_pw": password}

    def sh(self, srv, cmd, timeout=120, stdin=None):
        try:
            return self.d.ssh.run(srv, cmd, stdin=stdin, timeout=timeout)
        except self.h["CheckError"] as e:
            raise Stop("%s: %s" % (srv.get("name") or srv["host"], e))

    def put(self, srv, local_or_bytes, remote, mode=0o700):
        c = self.d.ssh.client(srv)
        sftp = c.open_sftp()
        try:
            import io
            data = local_or_bytes if isinstance(local_or_bytes, bytes) else Path(local_or_bytes).read_bytes()
            sftp.putfo(io.BytesIO(data), remote)
            sftp.chmod(remote, mode)
            # vpn-exit-setup.sh и vpn-restore.sh берут общие функции AmneziaWG из vpn-awg-common.sh рядом
            # путь на сервере — всегда через «/»: на Windows Path() сделал бы из него «\root\…»
            rp = PurePosixPath(remote)
            if not isinstance(local_or_bytes, bytes) and rp.name in ("vpn-exit-setup.sh", "vpn-restore.sh"):
                common = Path(local_or_bytes).with_name("vpn-awg-common.sh")
                if common.exists():
                    dst = str(rp.with_name("vpn-awg-common.sh"))
                    sftp.putfo(io.BytesIO(common.read_bytes()), dst)
                    sftp.chmod(dst, 0o644)
        finally:
            sftp.close()

    def detached(self, job, srv, key, script, timeout=3600):
        """Запустить bash-скрипт на сервере отдельным процессом и дочитывать его журнал.
        Возвращает код завершения. Обрыв SSH не прерывает скрипт: переподключаемся и читаем дальше."""
        d = REMOTE
        # Если такой шаг уже идёт на сервере (повтор установки, пока прошлая ещё работает) — не запускаем
        # вторую копию, а подключаемся к журналу идущей.
        rc0, out0, _ = self.sh(srv, "mkdir -p %s && chmod 700 %s; p=$(cat %s/%s.pid 2>/dev/null); "
                                    "if [ -n \"$p\" ] && [ ! -f %s/%s.rc ] && kill -0 $p 2>/dev/null; then echo RUNNING; "
                                    "else rm -f %s/%s.rc %s/%s.log %s/%s.pid; echo NEW; fi"
                               % (d, d, d, key, d, key, d, key, d, key, d, key))
        if "RUNNING" in out0:
            job.log("этот шаг уже идёт на сервере (запущен раньше) — подключаюсь к его журналу")
        else:
            self.put(srv, script.encode("utf-8"), "%s/%s.sh" % (d, key))
            # запуск — строго один раз: под нагрузкой сервер может не ответить вовремя, и повтор команды
            # не должен стартовать вторую копию (проверка по pid-файлу на самом сервере)
            self.sh(srv, "cd /root; p=$(cat %s/%s.pid 2>/dev/null); if [ -n \"$p\" ] && kill -0 $p 2>/dev/null; then exit 0; fi; "
                         "nohup setsid bash -c 'echo $$ > %s/%s.pid; bash %s/%s.sh > %s/%s.log 2>&1; echo $? > %s/%s.rc' "
                         ">/dev/null 2>&1 < /dev/null &" % (d, key, d, key, d, key, d, key, d, key), timeout=300)
        off, t0, buf = 0, time.time(), ""
        lost, dead = None, 0          # с какого момента нет связи; сколько раз подряд процесс шага не найден
        dec = codecs.getincrementaldecoder("utf-8")("replace")   # русские буквы не рвутся между кусками
        while True:
            time.sleep(2)
            try:
                rc, out, _ = self.sh(srv, "f=%s/%s.log; x=%d; s=$(stat -c %%s $f 2>/dev/null || echo 0); "
                                          "[ $((s - x)) -gt 262144 ] && s=$((x + 262144)); echo $s; "
                                          "tail -c +$((x + 1)) $f 2>/dev/null | head -c $((s - x)) | base64 -w0; echo; "
                                          "echo \"$(cat %s/%s.rc 2>/dev/null)\"; kill -0 $(cat %s/%s.pid 2>/dev/null) 2>/dev/null && echo alive"
                                     % (d, key, off, d, key, d, key), timeout=60)
                if lost:
                    job.log("…связь с сервером снова есть (не было %d с)" % (time.time() - lost))
                lost = None
            except Stop as e:
                # SSH иногда пропадает на минуты (обновление перезапускает sshd, сервер перезагружается) —
                # шаг на сервере идёт сам, ждём до 15 минут
                if lost is None:
                    lost = time.time()
                    job.log("…нет связи с сервером по SSH (%s) — жду, шаг на сервере продолжается" % e)
                elif time.time() - lost > 900:
                    raise Stop("%s — нет связи больше 15 минут. Проверьте сервер (консоль хостера), потом «Повторить установку»." % e)
                self.d.ssh.drop(srv["id"])
                time.sleep(8)
                continue
            parts = out.split("\n")
            size = int((parts[0] or "0").strip() or 0)
            chunk = base64.b64decode(parts[1].strip()) if len(parts) > 1 and parts[1].strip() else b""
            rcs = parts[2].strip() if len(parts) > 2 else ""
            alive = len(parts) > 3 and parts[3].strip() == "alive"
            if chunk:
                buf += dec.decode(chunk)
                *done, buf = buf.split("\n")
                for line in done:
                    job.log(line)
                off = size
            if rcs and size >= off and not chunk:
                if buf:
                    job.log(buf)
                return int(rcs)
            dead = 0 if (alive or rcs) else dead + 1
            if dead >= 3 and not chunk:      # процесса нет и кода завершения нет — сервер перезагрузился или процесс убит
                if buf:
                    job.log(buf)
                raise Stop("шаг «%s» оборвался на сервере (перезагрузка? нехватка памяти?) — журнал выше. "
                           "Можно нажать «Повторить установку»." % key)
            if time.time() - t0 > timeout:
                raise Stop("шаг «%s» идёт дольше %d мин — проверьте сервер вручную: %s/%s.log" % (key, timeout // 60, d, key))

    def wait_back(self, job, srv, limit=600):
        """После перезагрузки ждём, пока сервер снова пустит по SSH."""
        self.d.ssh.drop(srv["id"])
        time.sleep(20)
        t0 = time.time()
        while time.time() - t0 < limit:
            try:
                rc, out, _ = self.d.ssh.run(srv, "cat /proc/uptime", timeout=15)
                if rc == 0:
                    job.log("сервер снова на связи через %d с, аптайм %s с" % (time.time() - t0 + 20, out.split()[0]))
                    return
            except Exception:  # noqa: BLE001
                self.d.ssh.drop(srv["id"])
            time.sleep(10)
        raise Stop("сервер не вернулся после перезагрузки за %d мин" % (limit // 60))

    def probe(self, srv, mode, extra="", timeout=120):
        rc, out, err = self.sh(srv, "python3 -", stdin='MODE = "%s"\n%s\n' % (mode, extra) + self.h["PROBE"], timeout=timeout)
        if rc != 0 or not out.strip():
            raise Stop("%s: проверка не выполнилась (%s)" % (srv.get("name") or srv["host"], (err.strip().splitlines() or ["код %s" % rc])[-1][:200]))
        return json.loads(out)

    # ------------------------------------------------------------ обновление пакетов
    def _upgrade(self, job, _password):
        p = job.params
        srv = self.d.cfg.by_id(p["sid"])
        if not srv:
            raise Stop("сервера больше нет в панели")
        steps = [] if p.get("only_reboot") else [("upg", "Установка обновлений", srv["name"])]
        if p.get("reboot") or p.get("only_reboot"):
            steps.append(("reboot", "Перезагрузка", srv["name"]))
        steps.append(("check", "Проверка сервера и каналов", "панель"))
        job.plan(steps)
        if not p.get("only_reboot"):
            job.begin("upg")
            rc = self.detached(job, srv, "upgrade", UPGRADE_SH, timeout=2400)
            if rc != 0:
                raise Stop("apt-get завершился с ошибкой (код %d) — журнал выше. Сервер работает на старых пакетах; "
                           "можно повторить позже или разобраться в консоли" % rc)
            n = sum(1 for l in job.lines if l.startswith("Unpacking ") or l.startswith("Распаковывается"))
            job.result["installed"] = n
            job.end("upg", note="пакетов: %d" % n if n else "")
        if p.get("reboot") or p.get("only_reboot"):
            job.begin("reboot")
            rc, out, _ = self.sh(srv, "test -f /var/run/reboot-required && echo yes || echo no")
            if out.strip() != "yes" and not p.get("only_reboot"):
                job.skip("reboot", "не требуется")
            elif STAND:
                job.log("стенд: перезагрузка пропущена")
                job.end("reboot", note="стенд")
            else:
                job.log("перезагружаю сервер…")
                self.sh(srv, "nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &", timeout=15)
                self.wait_back(job, srv)
                job.result["rebooted"] = True
                job.end("reboot")
        job.begin("check")
        self.d.ssh.drop(srv["id"])
        self.d.pkg_count.pop(srv["id"], None)     # пересчитать, сколько обновлений осталось
        self.d.check_all(True)
        st = (self.d.status.get(srv["id"]) or {})
        sysd = ((st.get("data") or {}).get("system") or {}) if st.get("ok") else {}
        if not st.get("ok"):
            job.end("check", "warn", "сервер не отвечает: %s" % st.get("error"))
        else:
            left = sysd.get("updates") or 0
            job.end("check", note="осталось обновлений: %d%s" % (left, ", нужна перезагрузка" if sysd.get("reboot_required") else ""))
            job.result.update({"left": left, "reboot_required": bool(sysd.get("reboot_required"))})

    # ------------------------------------------------------------ проверка
    def _check(self, job, password):
        p = job.params
        role = p.get("role", "exit")
        srv = self.new_srv(job, password)
        job.plan([("reach", "Доступен ли сервер (порт SSH)", p["host"]), ("ssh", "Подключение по SSH", p["host"]),
                  ("probe", "Проверка сервера", p["host"]), ("lat", "Задержки до ваших серверов", "")])
        job.begin("reach")
        self._reach(job, p)
        job.end("reach")
        job.begin("ssh")
        rc, out, _ = self.sh(srv, "id -u; hostname", timeout=30)
        lines = out.split()
        if not lines or lines[0] != "0":
            raise Stop("нужен пользователь root (сейчас: uid %s)" % (lines[0] if lines else "?"))
        job.log("вход выполнен: %s" % (lines[1] if len(lines) > 1 else ""))
        job.end("ssh")

        job.begin("probe")
        st = self.d.cfg.settings
        dcs = self.h["parse_dc"](st.get("tg_dc")) or self.h["parse_dc"](self.h["TG_DC_DEFAULT"])
        targets = []
        if role == "entry":
            targets = [(x["name"], x["host"], int(x.get("port") or 22)) for x in self.d.cfg.servers if x["role"] == "exit"]
        pre = self.probe(srv, "precheck", "TG_DC_OVERRIDE = %r\nTARGETS_OVERRIDE = %r" % (dcs, targets), timeout=180)["precheck"]
        job.end("probe")

        job.begin("lat")
        lat = dict(pre.get("lat") or {})
        if role != "entry":
            for e in [x for x in self.d.cfg.servers if x["role"] == "entry"]:
                try:
                    r = self.probe(e, "lat", "TARGETS_OVERRIDE = %r" % ([(p["host"], p["host"], int(p.get("port") or 22))],), timeout=60)
                    lat[e["name"]] = (r.get("lat") or {}).get(p["host"])
                except Stop as ex:
                    job.log(str(ex))
                    lat[e["name"]] = None
        job.end("lat")
        job.result = verdict(role, p, pre, lat)
        job.log("итог: " + job.result["verdict"]["text"])

    def _reach(self, job, p):
        """До SSH: открывается ли порт с этого компьютера. Если нет — проверить с ваших серверов и объяснить,
        где режется: в России, у хостера или сервер не отвечает вовсе (иначе SSH просто долго ждёт)."""
        import socket
        host, port = p["host"], int(p.get("port") or 22)
        t0 = time.time()
        try:
            socket.create_connection((host, port), timeout=8).close()
            job.log("с этого компьютера порт %d открыт (%d мс)" % (port, (time.time() - t0) * 1000))
            return
        except OSError as e:
            here = "отказ (на сервере порт закрыт)" if isinstance(e, ConnectionRefusedError) else "нет ответа"
        job.log("с этого компьютера порт %d: %s — проверяю с ваших серверов" % (port, here))
        cmd = ("ping -c 2 -W 2 %s >/dev/null 2>&1 && echo PING_OK; "
               "o=$(timeout 6 bash -c '</dev/tcp/%s/%d' 2>&1); r=$?; case \"$o\" in *refused*) r=111;; esac; echo TCP_$r"
               % (host, host, port))
        srvs = [x for x in self.d.cfg.servers if self.d.cfg.get_pw(x["id"])]

        def one(x):
            try:
                rc, out, _ = self.d.ssh.run(x, cmd, timeout=25)
                tcp = re.search(r"TCP_(\d+)", out)
                return x, "PING_OK" in out, int(tcp.group(1)) if tcp else None
            except Exception:  # noqa: BLE001
                return x, None, None
        # свой пул и общий предел времени: занятый сервер или зависшее соединение не должны тормозить проверку
        import concurrent.futures as cf
        pool = cf.ThreadPoolExecutor(max_workers=max(1, len(srvs)))
        futs = {pool.submit(one, x): x for x in srvs}
        done, _ = cf.wait(futs, timeout=45)
        pool.shutdown(wait=False)
        res = [f.result() if f in done else (futs[f], None, None) for f in futs]
        names = lambda rows: ", ".join(x["name"] for x, _, _ in rows)
        for x, ping, tcp in res:
            job.log("  с %s: пинг %s, порт %d — %s" % (x["name"], "есть" if ping else "нет" if ping is False else "?", port,
                    {0: "открыт", 111: "отказ (порт закрыт на сервере)", 124: "нет ответа", 1: "нет маршрута"}.get(tcp, "не проверить")))
        ok_ru = [r for r in res if r[0]["role"] == "entry" and r[2] == 0]
        ok_eu = [r for r in res if r[0]["role"] == "exit" and r[2] == 0]
        silent_ru = [r for r in res if r[0]["role"] == "entry" and r[2] in (1, 124)]
        if ok_ru or (ok_eu and not silent_ru):
            raise Stop("с ваших серверов (%s) порт %d открыт, а с этого компьютера — %s. Проверьте домашний интернет, "
                       "антивирус или VPN на этом компьютере." % (names(ok_ru or ok_eu), port, here))
        if ok_eu and silent_ru:
            raise Stop("из Европы (%s) порт %d открыт, а из России (%s) подключения молча режутся — похоже, адрес %s "
                       "блокируется на пути из России. Такой сервер не подойдёт: входы не смогут до него достучаться. "
                       "Попросите у хостера другой IP или другую локацию." % (names(ok_eu), port, names(silent_ru), host))
        if any(r[2] == 111 for r in res) or here.startswith("отказ"):
            raise Stop("сервер отвечает, но порт %d закрыт. В консоли хостера проверьте SSH: systemctl status ssh "
                       "(или ssh.socket) и номер порта." % port)
        if any(r[1] for r in res):
            raise Stop("сервер пингуется, но порт %d не отвечает ни откуда — похоже на файрвол хостера. Проверьте в панели "
                       "хостера настройки файрвола / Security group для этого сервера." % port)
        raise Stop("сервер %s не отвечает совсем (ни пинг, ни порт %d) — он ещё не запустился, выключен или IP неверный." % (host, port))

    # ------------------------------------------------------------ замер скорости
    def _bench(self, job, password):
        p = job.params
        srv = self.new_srv(job, password)
        if (p.get("mode") or "ours") == "ours":
            return self._bench_ours(job, srv, password)
        yabs = p.get("mode") == "yabs" or bool(p.get("yabs"))
        job.plan([("bench", "yabs.sh (диск fio, сеть iperf3, без Geekbench)" if yabs else "bench.sh", p["host"])])
        job.begin("bench")
        rc = self.detached(job, srv, "bench", BENCH_SH % ("yabs" if yabs else "bench"), timeout=1800)
        if rc != 0:
            if any("I/O Speed" in x or "fio Disk Speed" in x for x in job.lines):
                job.end("bench", "warn", "диск измерился, сеть — нет (скрипт не скачал speedtest) — журнал выше")
                return
            raise Stop("замер завершился с ошибкой (код %d) — журнал выше" % rc)
        job.end("bench")

    def _bench_ours(self, job, srv, password):
        """Наш замер: диск, скачивание из России и Европы, и главное — каналы до наших серверов."""
        p, cfg = job.params, self.d.cfg
        name = p.get("name") or p["host"]
        urls = parse_urls(cfg.settings.get("speed_urls")) or parse_urls(SPEED_URLS_DEFAULT)
        # пары «кто качает → откуда»: для входа — новый сервер ↔ каждый выход; для выхода — каждый вход ↔ новый
        pairs = []
        if p.get("role") == "exit":
            for e in cfg.servers:
                if e["role"] == "entry" and cfg.get_pw(e["id"]):
                    pairs.append((e, {"id": "_new", "name": name, "host": p["host"], "port": int(p.get("port") or 22)}, password))
        else:
            for x in cfg.servers:
                if x["role"] == "exit" and cfg.get_pw(x["id"]):
                    pairs.append((srv, x, cfg.get_pw(x["id"])))
        job.plan([("disk", "Диск: запись 256 МБ", name), ("net", "Скачивание из интернета: " + ", ".join(n for n, _ in urls), name)] +
                 [("link%d" % i, "Канал %s ↔ %s" % (a["name"] if a is not srv else name, b["name"]), "") for i, (a, b, _) in enumerate(pairs)])
        res = {"disk": None, "net": [], "links": []}
        job.result = {"bench": res}

        job.begin("disk")
        start = len(job.lines)
        self.detached(job, srv, "disk", DISK_SH, timeout=300)
        m = re.search(r"DISK ([\d.]+)", "\n".join(job.lines[start:]))
        res["disk"] = float(m.group(1)) if m else None
        job.end("disk", "ok" if m else "warn", ("%.0f МБ/с" % res["disk"]) if m else "не измерился — журнал выше")

        job.begin("net")
        script = "export LC_ALL=C\n" + "".join(
            "r=$(curl -o /dev/null -sL --connect-timeout 8 --max-time 15 -w '%%{http_code} %%{speed_download} %%{size_download}' %s); echo \"NET %s|$r\"\n"
            % (shlex.quote(u), n.replace('"', "")) for n, u in urls)
        start = len(job.lines)
        self.detached(job, srv, "net", script, timeout=300)
        for n, code, spd, size in re.findall(r"^NET (.+?)\|(\d+) ([\d.]+) ([\d.]+)$", "\n".join(job.lines[start:]), re.M):
            ok = code in ("200", "206") and float(size) > 1e6
            res["net"].append({"name": n, "mbit": round(float(spd) * 8 / 1e6, 1) if ok else None,
                               "error": "" if ok else ("файл не найден (код %s) — поменяйте адрес в «Настройках»" % code if code not in ("000", "200", "206") else "не открылся")})
        bad = [x["name"] for x in res["net"] if x["mbit"] is None]
        job.end("net", "warn" if bad else "ok", " · ".join("%s %s" % (x["name"], "%.0f Мбит/с" % x["mbit"] if x["mbit"] is not None else "— " + x["error"]) for x in res["net"]))

        for i, (a, b, bpw) in enumerate(pairs):
            key = "link%d" % i
            job.begin(key)
            start = len(job.lines)        # разбираем только строки этого замера, а не предыдущих
            try:
                self.sh(a, "mkdir -p %s/pw && chmod 700 %s/pw" % (REMOTE, REMOTE))
                self.put(a, bpw.encode("utf-8"), "%s/pw/%s" % (REMOTE, b["host"]), 0o600)
                self.detached(job, a, "link", LINK_SH % {"host": b["host"], "port": int(b.get("port") or 22), "pw": "%s/pw/%s" % (REMOTE, b["host"])}, timeout=300)
            finally:
                try:
                    self.sh(a, "rm -f %s/pw/%s" % (REMOTE, b["host"]), timeout=30)
                except Stop:
                    pass
            tail = "\n".join(job.lines[start:])
            dm, um = re.search(r"^DOWN ([\d.]+)", tail, re.M), re.search(r"^UP ([\d.]+)", tail, re.M)
            an = name if a is srv else a["name"]
            link = {"a": an, "b": b["name"], "down": float(dm.group(1)) if dm else None, "up": float(um.group(1)) if um else None}
            res["links"].append(link)
            f = lambda v: "%.0f Мбит/с" % v if v is not None else "—"   # noqa: E731
            job.end(key, "ok" if dm and um else "warn", "%s → %s %s · %s → %s %s" % (b["name"], an, f(link["down"]), an, b["name"], f(link["up"])))

    # ------------------------------------------------------------ установка выхода
    def _install(self, job, password):
        p = job.params
        if p.get("role") == "entry":
            return self._install_entry(job, password)
        if p.get("role") != "exit":
            raise Stop("неизвестная роль: %s" % p.get("role"))
        tag, name = p["tag"], p["name"]
        old = self.d.cfg.by_id(p.get("replace") or "") if p.get("replace") else None
        if p.get("replace") and (not old or old["role"] != "exit"):
            raise Stop("заменяемого выхода нет в панели (или это не выход)")
        if old:
            p["dc5"] = False          # места в цепочках, включая DC5, новый выход берёт у старого
        if not TAG_RE.match(tag):
            raise Stop("имя латиницей: буквы и цифры, начинается с буквы, до 20 символов")
        comps = p.get("comps") or {}
        cfg = self.d.cfg
        entries = [cfg.by_id(e) for e in p.get("entries") or []]
        entries = [e for e in entries if e]
        for e in entries:
            if not cfg.get_pw(e["id"]):
                raise Stop("нет пароля от %s" % e["name"])
        if cfg.by_host(p["host"]):
            raise Stop("сервер с адресом %s уже есть в панели" % p["host"])
        srv = self.new_srv(job, password)
        steps = first_steps(comps, name)
        steps.append(("setup", "AmneziaWG" + (", fail2ban" if comps.get("f2b", True) else "") + " — сборка модуля ядра 5–10 мин", name))
        for e in entries:
            steps.append(("link-" + e["id"], ("Замена «%s» → «%s»: туннель, цепочки 3X-UI, старый убирается" % (old["name"], name))
                          if old else "Подключение выхода: туннель и цепочка в 3X-UI", e["name"]))
        if p.get("dc5") and entries:
            steps.append(("dc5", "Цепочка Telegram DC5: добавить AWG-" + tag, ", ".join(e["name"] for e in entries)))
        steps += [("panel", "Добавление в панель и проверка каналов", "панель")]
        job.plan(steps)
        self._prepare(job, srv, comps)

        job.begin("setup")
        self.put(srv, self.scripts / "vpn-exit-setup.sh", "/root/vpn-exit-setup.sh")
        env = []
        if str(p.get("awg_port") or "").isdigit():
            env.append("AWG_PORT=%d" % int(p["awg_port"]))
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$", str(p.get("awg_net") or "")):
            env.append("AWG_SUBNET=%s" % p["awg_net"])
        if not comps.get("f2b", True):
            env.append("SKIP_FAIL2BAN=1")
        rc = self.detached(job, srv, "setup", "%s bash /root/vpn-exit-setup.sh\n" % " ".join(env), timeout=3600)
        if rc != 0:
            raise Stop("установка выхода не прошла (код %d) — журнал выше. Повторный запуск пропустит уже сделанное." % rc)
        rc, out, _ = self.sh(srv, "awg show awg0 listen-port; awg show awg0 public-key")
        vals = (out.split() + ["", ""])[:2]
        job.result.update({"awg_port": vals[0], "awg_pub": vals[1]})
        job.end("setup")

        # пароль выхода нужен входам на время подключения (скрипт ходит с входа на выход по SSH)
        linked = []
        try:
            for e in entries:
                key = "link-" + e["id"]
                job.begin(key)
                for f in ("vpn-restore.sh", "vpn-add-exit.sh", "vpn-pin-chain.sh"):
                    self.put(e, self.scripts / f, "/root/" + f)
                self.sh(e, "mkdir -p %s/pw && chmod 700 %s/pw" % (REMOTE, REMOTE))
                self.put(e, password.encode("utf-8"), "%s/pw/%s" % (REMOTE, p["host"]), 0o600)
                self.put(e, str(int(p.get("port") or 22)).encode(), "%s/pw/%s.port" % (REMOTE, p["host"]), 0o600)
                pos = self.position_for(e, p.get("position") or "end")
                if old:
                    job.log("на место выхода «%s» (%s); если его на этом входе нет — %s" % (old["name"], old["host"], {"end": "в конец"}.get(pos, pos)))
                else:
                    job.log("место в цепочке: %s" % {"end": "в конце"}.get(pos, pos))
                rc = self.detached(job, e, "add-exit", "export VPN_PWDIR=%s/pw POSITION=%s%s\nbash /root/vpn-add-exit.sh %s %s\n"
                                   % (REMOTE, shlex.quote(pos), (" REPLACE=" + old["host"]) if old else "", tag, p["host"]), timeout=1200)
                if rc != 0:
                    raise Stop("%s: подключение выхода не прошло (код %d) — журнал выше. Изменения в 3X-UI скрипт откатывает сам." % (e["name"], rc))
                rc, out, _ = self.sh(e, "grep -l 'Endpoint *= *%s:' /etc/amnezia/amneziawg/wg*.conf 2>/dev/null | head -n1 | xargs -r basename | sed 's/.conf$//'"
                                     % re.escape(p["host"]))
                iface = (out.split() + ["?"])[0]
                linked.append({"entry": e["name"], "iface": iface})
                job.end(key, note=iface)
        finally:
            for e in entries:
                try:
                    self.sh(e, "rm -rf %s/pw" % REMOTE, timeout=30)
                except Stop:
                    job.log("не удалось удалить временный пароль на %s: удалите %s/pw вручную" % (e["name"], REMOTE))
        job.result["linked"] = linked

        if p.get("dc5") and entries:
            job.begin("dc5")
            bad = []
            for e in entries:
                rc = self.detached(job, e, "dc5", "bash /root/vpn-pin-chain.sh DC5TG --append AWG-%s\n" % tag, timeout=300)
                if rc != 0:
                    bad.append(e["name"])
            job.end("dc5", "warn" if bad else "ok", ("не получилось на: " + ", ".join(bad)) if bad else "")

        job.begin("panel")
        sid = self.unique_id(latin(tag).lower()[:12])
        new = {"id": sid, "name": name, "host": p["host"], "port": int(p.get("port") or 22), "user": p.get("user") or "root",
               "role": "exit", "provider": p.get("provider") or "", "note": "", "cc": (p.get("cc") or "")[:3].upper()}
        with self.d.lock:
            ids = [x["id"] for x in cfg.data["servers"]]
            at = ids.index(old["id"]) if old and old["id"] in ids else len(ids)   # на место старого в списке
            cfg.data["servers"].insert(at, new)
            cfg.save()
        cfg.set_pw(sid, password)
        if old:
            self.d.remove_server(old["id"])
            job.result["replaced"] = old["name"]
            self.d.note("ok", "Мастер: выход %s (%s) поставлен вместо выхода «%s» (%s) на %s; старый убран из панели" % (
                name, p["host"], old["name"], old["host"], ", ".join(e["name"] for e in entries) or "—"))
        else:
            self.d.note("ok", "Мастер: выход %s (%s) установлен и подключён к %s" % (name, p["host"], ", ".join(e["name"] for e in entries) or "—"))
        job.result["server_id"] = sid
        self.save_secrets(job, new, entries)
        for _ in range(120):                              # дождаться, если полная проверка уже идёт
            if "all" not in self.d.running:
                break
            time.sleep(1)
        self.d.check_all(True)
        post = []
        for e in entries:
            res = [self.d.results.get("%s:%s" % (e["id"], c["key"]), {}) for c in self.d.channels.get(e["id"], []) if c.get("exit_id") == sid]
            okn = sum(1 for r in res if r.get("status") in ("ok", "warn"))
            post.append({"entry": e["name"], "ok": okn, "n": len(res)})
            job.log("%s: каналы до нового выхода — в норме %d из %d" % (e["name"], okn, len(res)))
        job.result["post"] = post
        if post and all(x["n"] and not x["ok"] for x in post):
            lg = "\n".join(job.lines)
            ap = re.findall(r"AWG: UDP (\d+)", lg)
            job.result["awg_port"] = (ap or [""])[-1]
            job.log("! ни один вход не достучался до нового выхода по порту AWG, хотя SSH открывается. "
                    "Чаще всего это фаервол в панели хостера (Network/Firewall): откройте там UDP %s "
                    "(или все входящие) — каналы оживут сами, переустанавливать не нужно" % (job.result.get("awg_port") or "порт AWG"))
        job.end("panel")

    def _prepare(self, job, srv, comps):
        """Общее начало установки: вход по SSH, обновление с перезагрузкой, оптимизация."""
        job.begin("ssh")
        rc, out, _ = self.sh(srv, "id -u; . /etc/os-release; echo $PRETTY_NAME", timeout=30)
        if not out.startswith("0"):
            raise Stop("нужен пользователь root")
        job.log("вход выполнен, %s" % out.split("\n", 1)[-1].strip())
        job.end("ssh")
        if comps.get("upd", True):
            job.begin("upd")
            rc = self.detached(job, srv, "upd", UPDATE_SH, timeout=2400)
            if rc != 0:
                raise Stop("обновление системы не прошло (код %d) — журнал выше" % rc)
            rc, out, _ = self.sh(srv, "test -f /var/run/reboot-required && echo yes || echo no")
            if out.strip() == "yes":
                job.log("нужна перезагрузка — перезагружаю")
                try:
                    self.sh(srv, "nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &", timeout=15)
                except Stop:
                    pass
                self.wait_back(job, srv)
            job.end("upd")
        if comps.get("opt"):
            job.begin("opt")
            rc = self.detached(job, srv, "opt", OPTIMIZE_SH, timeout=600)
            job.end("opt", "ok" if rc == 0 else "warn", "" if rc == 0 else "не всё получилось — журнал выше, на установку не влияет")

    def _install_entry(self, job, password):
        """Новый вход — копия образца из бэкапа (как резервный вход): vpn-restore.sh на новом сервере."""
        p = job.params
        cfg, tag, name = self.d.cfg, p["tag"], p["name"]
        if not TAG_RE.match(tag):
            raise Stop("имя латиницей: буквы и цифры, начинается с буквы, до 20 символов")
        if cfg.by_host(p["host"]):
            raise Stop("сервер с адресом %s уже есть в панели" % p["host"])
        comps = p.get("comps") or {}
        src = p.get("source") or {}
        bdir = Path(self.h["BACKUP_DIR"])
        srv = self.new_srv(job, password)
        steps = first_steps(comps, name)
        src_srv = cfg.by_id(src.get("id") or "") if src.get("kind") == "server" else None
        steps += [("backup", "Свежий бэкап образца" if src_srv else "Бэкап из файла", src_srv["name"] if src_srv else "панель"),
                  ("restore", "Установка из бэкапа: AmneziaWG, клиенты на выходах, 3X-UI, fail2ban", name),
                  ("panel", "Добавление в панель и проверка каналов", "панель")]
        job.plan(steps)
        self._prepare(job, srv, comps)

        job.begin("backup")
        if src_srv:
            for _ in range(300):
                if "backup" not in self.d.running:
                    break
                time.sleep(1)
            self.d.do_backup(src_srv["id"])
            b = self.d.backup
            if not b.get("ok"):
                raise Stop("бэкап %s не удался: %s" % (src_srv["name"], b.get("error")))
            archive = bdir / b["file"]
        else:
            fname = Path(str(src.get("file") or "")).name
            archive = bdir / fname
            if not fname or not archive.exists():
                raise Stop("нет файла бэкапа %s в папке backups" % fname)
        job.log("бэкап: %s (%d КБ)" % (archive.name, archive.stat().st_size // 1024))
        # какие выходы прописаны в бэкапе — к каждому новый вход должен попасть с паролем
        hosts = []
        with tarfile.open(archive) as t:
            for m in t.getmembers():
                if re.search(r"/files/etc/amnezia/amneziawg/wg\d+\.conf$", m.name) and m.isfile():
                    txt = t.extractfile(m).read().decode("utf-8", "replace")
                    mm = re.search(r"^\s*Endpoint\s*=\s*([\d.]+):", txt, re.M)
                    if mm and mm.group(1) not in hosts:
                        hosts.append(mm.group(1))
        exits = []
        for h in hosts:
            x = cfg.by_host(h)
            if not x:
                raise Stop("в бэкапе есть выход %s, которого нет в панели — добавьте его на странице «Серверы и пароли»" % h)
            if not cfg.get_pw(x["id"]):
                raise Stop("нет пароля от выхода %s" % x["name"])
            exits.append(x)
        job.log("выходы из бэкапа: %s" % (", ".join(x["name"] for x in exits) or "нет"))
        job.end("backup", note=archive.name)

        job.begin("restore")
        rarch = "/root/" + archive.name
        try:
            self.put(srv, archive, rarch, 0o600)
            self.put(srv, self.scripts / "vpn-restore.sh", "/root/vpn-restore.sh")
            self.put(srv, self.scripts / "vpn-backup.sh", "/root/vpn-backup.sh")
            self.sh(srv, "mkdir -p %s/pw && chmod 700 %s/pw" % (REMOTE, REMOTE))
            for x in exits:
                self.put(srv, cfg.get_pw(x["id"]).encode("utf-8"), "%s/pw/%s" % (REMOTE, x["host"]), 0o600)
                self.put(srv, str(int(x.get("port") or 22)).encode(), "%s/pw/%s.port" % (REMOTE, x["host"]), 0o600)
            rc = self.detached(job, srv, "restore", "export VPN_PWDIR=%s/pw VPN_NAME=%s XUI_SSL_MODE=ip XUI_SERVER_IP=%s\nbash /root/vpn-restore.sh %s%s\n"
                               % (REMOTE, tag, p["host"], shlex.quote(rarch), RESTORE_EXTRA), timeout=3600)
        finally:
            try:   # пароли выходов и архив со всеми ключами на сервере не оставляем
                self.sh(srv, "rm -rf %s/pw; rm -f %s" % (REMOTE, shlex.quote(rarch)), timeout=30)
            except Stop:
                job.log("не удалось удалить временные файлы: %s/pw и %s — удалите вручную" % (REMOTE, rarch))
        if rc != 0:
            raise Stop("установка из бэкапа не прошла (код %d) — журнал выше. Повторный запуск пропустит уже сделанное." % rc)
        # ссылки из отчёта vpn-restore.sh
        log = "\n".join(job.lines[-400:])
        m = re.search(r"Панель:\s+(\S+)", log)
        job.result["panel_url"] = m.group(1) if m else ""
        job.result["subs"] = [{"name": a, "url": b} for a, b in re.findall(r"Подписка\s+(\S+)\s+(https?://\S+)", log)]
        job.result["warnings"] = [x.strip(" !") for x in re.findall(r"^\s+! (.+)$", log, re.M)][-8:]
        job.result["exits"] = [x["name"] for x in exits]
        for x in exits:     # чтобы потом можно было убрать клиентов этого входа одной командой
            try:
                self.put(x, self.scripts / "vpn-remove-client.sh", "/root/vpn-remove-client.sh")
            except Exception as e:  # noqa: BLE001
                job.log("не удалось положить vpn-remove-client.sh на %s: %s" % (x["name"], e))
        job.end("restore", "warn" if job.result["warnings"] else "ok",
                "есть замечания — см. итог" if job.result["warnings"] else "")

        job.begin("panel")
        sid = self.unique_id(latin(tag).lower()[:12])
        new = {"id": sid, "name": name, "host": p["host"], "port": int(p.get("port") or 22), "user": p.get("user") or "root",
               "role": "entry", "provider": p.get("provider") or "", "note": "вход · резерв", "cc": ""}
        with self.d.lock:
            cfg.data["servers"].append(new)
            cfg.save()
        cfg.set_pw(sid, password)
        self.d.note("ok", "Мастер: вход %s (%s) развёрнут из %s" % (name, p["host"], archive.name))
        job.result["server_id"] = sid
        self.save_secrets_entry(job, new, archive.name)
        for _ in range(120):
            if "all" not in self.d.running:
                break
            time.sleep(1)
        self.d.check_all(True)
        res = [self.d.results.get("%s:%s" % (sid, c["key"]), {}) for c in self.d.channels.get(sid, [])]
        okn = sum(1 for r in res if r.get("status") in ("ok", "warn"))
        job.result["post"] = [{"entry": name, "ok": okn, "n": len(res)}]
        job.log("%s: каналы до выходов — в норме %d из %d" % (name, okn, len(res)))
        job.end("panel")

    def save_secrets_entry(self, job, srv, archive):
        r = job.result
        self.secrets_dir.mkdir(exist_ok=True)
        f = self.secrets_dir / ("%s-%s.txt" % (re.sub(r"[^\w-]", "_", srv["name"]), datetime.now().strftime("%Y-%m-%d_%H%M")))
        lines = ["Вход %s, %s — развёрнут из %s" % (srv["name"], srv["host"], archive),
                 "Установлен панелью %s" % datetime.now().strftime("%d.%m.%Y %H:%M"), "",
                 "Панель 3X-UI: %s (логин и пароль — как на образце)" % r.get("panel_url"), ""]
        lines += ["Подписка %s: %s" % (x["name"], x["url"]) for x in r.get("subs") or []]
        lines += ["", "AWG-клиенты этого входа на выходах называются %s-wg0, %s-wg1, …" % (job.params["tag"], job.params["tag"]),
                  "Убрать их, если вход больше не нужен (на каждом выходе):",
                  "  bash /root/vpn-remove-client.sh %s" % job.params["tag"]]
        if r.get("warnings"):
            lines += ["", "Замечания установки:"] + ["  ! " + w for w in r["warnings"]]
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r["secrets_file"] = str(f)

    # ------------------------------------------------------------ мелочи
    def position_for(self, entry, position):
        """end | first | after:<id выхода> → значение POSITION для vpn-add-exit.sh на этом входе."""
        if not position.startswith("after:"):
            return position if position in ("end", "first") else "end"
        xid = position[6:]
        tags = [c.get("tag") for c in self.d.channels.get(entry["id"], []) if c.get("n") and c.get("exit_id") == xid and c.get("tag")]
        return "after:" + tags[-1] if tags else "end"

    def unique_id(self, base):
        base = re.sub(r"[^a-z0-9_-]", "", base) or "srv"
        sid, n = base, 2
        while self.d.cfg.by_id(sid):
            sid, n = "%s%d" % (base, n), n + 1
        return sid

    def save_secrets(self, job, srv, entries):
        r = job.result
        self.secrets_dir.mkdir(exist_ok=True)
        f = self.secrets_dir / ("%s-%s.txt" % (re.sub(r"[^\w-]", "_", srv["name"]), datetime.now().strftime("%Y-%m-%d_%H%M")))
        lines = ["Выход %s (тег AWG-%s), %s" % (srv["name"], job.params["tag"], srv["host"]),
                 "Установлен панелью %s" % datetime.now().strftime("%d.%m.%Y %H:%M")
                 + (" вместо выхода «%s»" % r["replaced"] if r.get("replaced") else ""), "",
                 "AmneziaWG: UDP %s, публичный ключ awg0 %s" % (r.get("awg_port"), r.get("awg_pub")), ""]
        for x in r.get("linked") or []:
            lines.append("Вход %s: туннель %s" % (x["entry"], x["iface"]))
        lines += ["", "На выходе лежит /root/vpn-exit-setup.sh:",
                  "  bash /root/vpn-exit-setup.sh client ИМЯ   — AWG-клиент для телефона или ноутбука (конфиг + QR)",
                  "  bash /root/vpn-exit-setup.sh status       — что работает и на каких портах"]
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r["secrets_file"] = str(f)


import os  # noqa: E402

SPEED_URLS_DEFAULT = ("Москва · Яндекс | https://mirror.yandex.ru/ubuntu-releases/24.04/ubuntu-24.04.5-live-server-amd64.iso\n"
                      "Германия · FAU | https://ftp.fau.de/ubuntu-releases/24.04/ubuntu-24.04.5-live-server-amd64.iso")


def parse_urls(text):
    out = []
    for line in str(text or "").splitlines():
        if "|" in line:
            n, u = (x.strip() for x in line.split("|", 1))
            if n and re.match(r"^https?://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/%+-]*)?$", u):
                out.append((n[:40], u))
    return out[:6]


DISK_SH = r"""export LC_ALL=C
f=/root/.vpn-dash-job/dd.tmp
free=$(df -Pm /root | awk 'NR==2 {print $4}')
[ "${free:-0}" -gt 700 ] || { echo "мало места на диске (${free} МБ) — пропускаю"; exit 0; }
out=$(dd if=/dev/zero of=$f bs=1M count=256 oflag=direct conv=fdatasync 2>&1 || dd if=/dev/zero of=$f bs=1M count=256 conv=fdatasync 2>&1)
rm -f $f
echo "$out" | tail -n1
echo "$out" | tail -n1 | awk -F', ' '{print $NF}' | awk '{v=$1; if ($2 ~ /^GB/) v*=1000; if ($2 ~ /^kB/) v/=1000; print "DISK " v}'
"""

# Скорость канала между двумя нашими серверами: 50 МБ «туда» и 25 МБ «обратно» по SSH (как AWG — шифрованный
# поток), время подключения вычитаем. Пароль второго сервера — во временном файле, панель удаляет его сразу.
LINK_SH = r"""export LC_ALL=C
command -v sshpass >/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -q sshpass >/dev/null 2>&1 || { apt-get update -q >/dev/null 2>&1; apt-get install -y -q sshpass >/dev/null 2>&1; }; }
command -v sshpass >/dev/null || { echo "не поставился sshpass — канал не измерить"; exit 0; }
o="-p %(port)d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -c aes128-gcm@openssh.com"
S="sshpass -f %(pw)s ssh $o root@%(host)s"
# время подключения — меньшее из трёх: одно случайно долгое подключение раньше давало «4194 Мбит/с»;
# и вычитаем не больше половины времени передачи
h=999
for i in 1 2 3; do
  t0=$(date +%%s.%%N); $S true || { echo "не удалось подключиться к %(host)s"; exit 0; }; t1=$(date +%%s.%%N)
  h=$(python3 -c "print(min($h, $t1-$t0))")
done
t0=$(date +%%s.%%N); n=$(timeout 90 $S 'head -c 52428800 /dev/zero' | wc -c); t1=$(date +%%s.%%N)
python3 -c "t=$t1-$t0; d=max(t-$h, t/2, 0.05); print('DOWN %%.1f  (%%d МБ за %%.1f с)' %% ($n*8/d/1e6, $n/1048576, d))"
t0=$(date +%%s.%%N); head -c 26214400 /dev/zero | timeout 90 $S 'cat > /dev/null'; t1=$(date +%%s.%%N)
python3 -c "t=$t1-$t0; d=max(t-$h, t/2, 0.05); print('UP %%.1f  (25 МБ за %%.1f с)' %% (26214400*8/d/1e6, d))"
"""

# Скрипт замера скачиваем с таймаутом: с сайта автора, а если он не открывается (из РФ бывает) —
# копию с GitHub. Без таймаута curl мог висеть без единой строки в журнале.
BENCH_SH = r"""export LC_ALL=C TERM=dumb
kind=%s
if [ "$kind" = yabs ]; then
  urls="https://yabs.sh https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/yabs.sh"; args="-g"
else
  urls="https://bench.sh https://raw.githubusercontent.com/teddysun/across/master/bench.sh"; args=""
fi
f=$(mktemp /tmp/vpn-dash-bench.XXXXXX.sh)
for u in $urls; do
  echo "скачиваю $u"
  if curl -fsSL --connect-timeout 10 --max-time 60 "$u" -o "$f" && [ -s "$f" ]; then ok=1; break; fi
  echo "  не открылся"
done
[ -n "${ok:-}" ] || { echo "скрипт замера не скачался ни с одного адреса"; exit 2; }
echo "запускаю (сеть меряется до нескольких городов, это несколько минут)…"
bash "$f" $args; rc=$?
rm -f "$f"
exit $rc
"""

UPGRADE_SH = r"""export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a LC_ALL=C
apt-get update -q -o DPkg::Lock::Timeout=1200
apt-get -y -q -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=1200 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
rc=$?
# обновление openssh-server на Ubuntu 24.04 останавливает ssh — поднимаем сами
systemctl start ssh.socket >/dev/null 2>&1 || true
systemctl is-active --quiet ssh || systemctl start ssh >/dev/null 2>&1 || systemctl start sshd >/dev/null 2>&1 || true
[ -f /var/run/reboot-required ] && echo "после обновления нужна перезагрузка"
exit $rc
"""

UPDATE_SH = r"""set -e
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
apt-get -y -q autoremove
# обновление openssh-server на Ubuntu 24.04 останавливает ssh и может оставить сервер без входа
# по SSH на минуты — поднимаем сами (скрипт идёт на сервере и без связи с панелью)
systemctl start ssh.socket >/dev/null 2>&1 || true
systemctl is-active --quiet ssh || systemctl start ssh >/dev/null 2>&1 || systemctl start sshd >/dev/null 2>&1 || true
echo "обновлено"
"""

OPTIMIZE_SH = r"""set -e
if [ "$(swapon --show --noheadings | wc -l)" = 0 ]; then
  fallocate -l 512M /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=512
  chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "swap 512 МБ включён"
else
  echo "swap уже есть: $(swapon --show --noheadings | awk '{print $3}' | head -n1)"
fi
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/50-vpn-size.conf
systemctl restart systemd-journald
apt-get clean
echo "журналы ограничены 100 МБ, кэш пакетов очищен; свободно на диске: $(df -h / | awk 'NR==2 {print $4}')"
"""


def plural(n, one, few, many):
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return one
    return few if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else many


def verdict(role, p, pre, lat):
    """Пункты проверки «как в нашей схеме» и общий итог."""
    items = []

    def add(k, v, st):
        items.append({"k": k, "v": v, "st": st})

    os_ = pre.get("os") or {}
    if os_.get("id") == "ubuntu" and os_.get("version") == "24.04":
        add("ОС", os_.get("pretty"), "ok")
    elif os_.get("id") == "ubuntu":
        add("ОС", "%s — скрипты проверены только на 24.04" % os_.get("pretty"), "warn")
    else:
        add("ОС", "%s — нужна Ubuntu 24.04" % (os_.get("pretty") or "?"), "bad")
    v = pre.get("virt") or "?"
    if v in ("openvz", "lxc", "lxc-libvirt"):
        add("Виртуализация", "%s — AmneziaWG здесь не встанет, нужен KVM" % v, "bad")
    elif v in ("kvm", "qemu", "vmware", "microsoft", "xen", "amazon", "oracle", "none", "bochs"):
        add("Виртуализация", "%s — AmneziaWG встанет" % v.upper(), "ok")
    else:
        add("Виртуализация", "%s — необычная, установка может не пройти" % v, "warn")
    add("Ядро", "%s, заголовки %s" % (pre.get("kernel"), "есть в репозитории" if pre.get("headers") else "не найдены — появятся после обновления системы"),
        "ok" if pre.get("headers") else "warn")
    mem, free = pre.get("mem_mb") or 0, pre.get("disk_free_gb") or 0
    res = "%s vCPU · %s МБ RAM%s · диск %s ГБ, свободно %s ГБ" % (pre.get("cpu"), mem, (" + swap %s МБ" % pre["swap_mb"]) if pre.get("swap_mb") else "",
                                                                  pre.get("disk_gb"), free)
    swap = pre.get("swap_mb") or 0
    # мало памяти — это ещё не приговор, если есть swap: на swap держится сборка модуля AWG,
    # а в работе входу/выходу хватает 300–400 МБ
    too_small = mem < 300 or (mem < 400 and swap < 512) or free < 2
    add("Ресурсы", res + (" — памяти впритык, выручит swap" if not too_small and mem < 600 else ""),
        "bad" if too_small else "warn" if mem < 900 or free < 5 else "ok")
    sw = pre.get("software") or []
    add("Чужой софт", ", ".join(sw) + " — уже стоит" if sw else "Docker, 3X-UI, nginx, WireGuard — не найдены", "warn" if sw else "ok")
    busy = [x for x in pre.get("ports") or [] if x[1] not in (22, 53) and not (x[0] == "udp" and x[1] in (68, 546))   # DHCP — служебное
            and not (x[2] or "").startswith(("sshd", "systemd-resolve", "chronyd"))]
    add("Порты", "заняты: " + ", ".join("%s/%s %s" % (x[1], x[0], x[2]) for x in busy[:8]) if busy else "кроме SSH ничего не слушает", "warn" if busy else "ok")
    ip4 = pre.get("ipv4") or []
    nat = p["host"] not in ip4 and pre.get("public_ip") and pre.get("public_ip") != p["host"]
    add("Адреса", "IPv4 %s%s · IPv6 %s" % (", ".join(ip4) or "?", " (снаружи виден %s — сервер за NAT?)" % pre["public_ip"] if nat else "",
                                         ", ".join(pre.get("ipv6") or []) or "нет (нам не нужен)"), "warn" if nat else "ok")
    dns_bad = [h for h, ok in (pre.get("dns") or {}).items() if not ok]
    web_bad = [h for h, ok in (pre.get("web") or {}).items() if not ok]
    add("DNS и доступ для установки", "не открываются: " + ", ".join(sorted(set(dns_bad + web_bad))) if dns_bad or web_bad
        else "GitHub, PPA Amnezia, установщики — открываются", "bad" if dns_bad or web_bad else "ok")
    upd, rb = pre.get("updates") or 0, pre.get("reboot_required")
    add("Обновления", ("%d %s%s — обновим при установке" % (upd, plural(upd, "пакет", "пакета", "пакетов"), ", нужна перезагрузка" if rb else "")) if upd or rb else "система свежая",
        "warn" if upd or rb else "ok")
    lat_txt = " · ".join("%s %s" % (k, "%d мс" % v if v is not None else "нет связи") for k, v in lat.items())
    lat_bad = [k for k, v in lat.items() if v is None]
    lat_all_bad = bool(lat) and len(lat_bad) == len(lat)
    if lat_all_bad and role != "entry":
        lat_txt += " — входы не достают до сервера по TCP, установка не пройдёт (адрес режется из России?)"
    elif lat_bad and role != "entry":
        lat_txt += " — с этих входов связи нет, подключение к ним не пройдёт"
    add("Задержка до выходов" if role == "entry" else "Задержка с входов", lat_txt or "нет серверов для сравнения",
        "bad" if lat_all_bad else "warn" if lat_bad else "ok")
    dc = pre.get("dc") or []
    dc5 = next((x for x in dc if x["name"] == "DC5"), None)
    dc5_ok = bool(dc5 and dc5.get("ok"))
    if role == "entry":
        dc_text = "Для входа это справка: Telegram с устройств идёт через выходы."
    elif dc5 and not dc5_ok:
        dc_text = ("DC5 с этого сервера недоступен. Правило DC5 на входах ведёт Telegram своей цепочкой, так что работать будет; "
                   "в цепочку DC5 этот выход не добавляем.")
    elif dc and all(x.get("ok") for x in dc):
        dc_text = "Все DC доступны — выход можно добавить в цепочку DC5 запасным звеном (шаг «Связи»)."
    else:
        dc_text = "Недоступны: " + ", ".join(x["name"] for x in dc if not x.get("ok"))
    n_bad = sum(1 for x in items if x["st"] == "bad")
    n_warn = sum(1 for x in items if x["st"] == "warn")
    if n_bad:
        v = {"level": "bad", "text": "ставить нельзя: %d %s" % (n_bad, "проблема" if n_bad == 1 else "проблемы")}
    elif n_warn:
        v = {"level": "warn", "text": "можно ставить · замечаний: %d" % n_warn}
    else:
        v = {"level": "ok", "text": "можно ставить"}
    return {"items": items, "dc": dc, "dc_text": dc_text, "dc5_ok": dc5_ok, "verdict": v,
            "facts": {"public_ip": pre.get("public_ip"), "os": os_.get("pretty"), "mem_mb": mem, "swap_mb": pre.get("swap_mb") or 0}}


RESTORE_EXTRA = ""
def first_steps(comps, name):
    """Общее начало установки выхода и входа: SSH, обновление системы, оптимизация маленького VPS."""
    steps = [("ssh", "Подключение по SSH", name)]
    if comps.get("upd", True):
        steps.append(("upd", "Обновление системы (и перезагрузка, если нужна)", name))
    if comps.get("opt"):
        steps.append(("opt", "Оптимизация маленького VPS", name))
    return steps


STAND = os.environ.get("VPN_DASH_STAND") == "1"

if STAND:   # стенд разработчика (dev/testbed.sh): не трогать систему по-настоящему
    RESTORE_EXTRA = " --only awg --force-awg"    # без apt и установщика 3X-UI: клиенты на выходах и отчёт
    UPDATE_SH = 'echo "стенд: apt-get upgrade пропущен"\n'
    UPGRADE_SH = ('echo "стенд: имитация apt-get upgrade"; for p in libfoo1 openssh-server; do echo "Unpacking $p (2.0) over (1.0) ..."; '
                  'sleep 1; echo "Setting up $p (2.0) ..."; done\n')
    OPTIMIZE_SH = 'echo "стенд: оптимизация пропущена"\n'
