#!/usr/bin/env python3
"""Панель VPN-каскада: локальная веб-страница с состоянием серверов и тестами каналов.

Запуск:  start.bat           (Windows: панель уходит в трей, браузер откроется сам)
         py dash.py          (Windows, в окне консоли — как раньше; так же start.bat console)
         python3 dash.py     (Linux / macOS)

Серверы и их роли — в servers.json рядом (редактируются со страницы «Серверы и пароли»).
Пароли хранятся в «Диспетчере учётных данных» Windows (через keyring), не в файлах.
Проверки на серверах только читают состояние. Меняет что-то на сервере только бэкап
(временно кладёт скрипт и архив в /root и сразу их удаляет) и, конечно, консоль.
"""
import base64
import concurrent.futures as cf
import hashlib
import html
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import remote

try:
    import paramiko
except ImportError:
    _msg = "Не установлен paramiko. Запустите start.bat или: py -m pip install -r requirements.txt"
    if sys.stdout is None:   # запуск без консоли (pythonw, автозапуск) — показать окном
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, _msg, "Панель каскада", 0x10)
    print(_msg)
    sys.exit(1)
try:
    import keyring
except ImportError:
    keyring = None

APP = Path(__file__).resolve().parent
CFG_FILE = APP / "servers.json"
KNOWN_HOSTS = APP / "known_hosts"
LOG_FILE = APP / "checks.log"
HIST_FILE = APP / "history.db"
GOV_FILE = APP / "govblock.json"        # «Сети госорганов»: последний скачанный список (только адреса сетей)
ADDR_FILE = APP / "addrcheck.json"      # «Качество»: последние «как видят» и «соседи» по серверам (адреса — только здесь)
BACKUP_DIR = APP / "backups"
BACKUP_SCRIPT = APP / "server-scripts" / "vpn-backup.sh"
PROBE = (APP / "probe.py").read_text(encoding="utf-8")


def probe_func(name):
    """Текст функции из probe.py — чтобы небольшие скрипты для сервера не дублировали её код."""
    m = re.search(r"^def %s\(.*?(?=^\S)" % re.escape(name), PROBE, re.M | re.S)
    if not m:
        raise RuntimeError("в probe.py нет функции %s" % name)
    return "import os\n" + m.group(0).rstrip() + "\n\n"
ACME80_SH = r"""# панель каскада: открыть порт 80 для продления сертификата Let's Encrypt (только это)
if ! command -v ufw >/dev/null 2>&1 || ! ufw status 2>/dev/null | grep -q "Status: active"; then
  echo '{"ok": true, "msg": "фаервол выключен — порт 80 и так открыт"}'; exit 0
fi
ufw allow 80/tcp comment 'ACME http-01' >/dev/null || { echo '{"ok": false, "msg": "ufw не принял правило"}'; exit 0; }
r="правило добавлено"
# продлеваем сразу только то, чему уже пора (без acme.sh --cron: он сперва обновляет сам себя с GitHub — это долго)
now=$(date +%s)
for f in /root/.acme.sh/*/*.conf; do
  case "$f" in *.csr.conf|*/account.conf) continue ;; esac
  grep -q "^Le_Webroot='no'" "$f" 2>/dev/null || continue
  d=$(sed -n "s/^Le_Domain='\(.*\)'$/\1/p" "$f"); nx=$(sed -n "s/^Le_NextRenewTime='\([0-9]*\)'$/\1/p" "$f")
  [ -n "$d" ] || continue
  if [ -n "$nx" ] && [ "$nx" -gt "$now" ]; then r="$r, продление $d — само, через $(( (nx - now) / 3600 )) ч"; continue; fi
  ecc=""; case "$(dirname "$f")" in *_ecc) ecc="--ecc" ;; esac
  if timeout 90 /root/.acme.sh/acme.sh --renew -d "$d" $ecc --home /root/.acme.sh >/root/.vpn-dash-acme.log 2>&1; then
    r="$r, сертификат $d продлён"
  else
    r="$r; продлить $d сейчас не вышло: $(grep -iE 'error|fail|timeout' /root/.vpn-dash-acme.log | tail -1 | tr -d '"\\' | cut -c1-100)"
  fi
  rm -f /root/.vpn-dash-acme.log
done
echo "{\"ok\": true, \"msg\": \"$r\"}"
"""
QUALITY_SRC = (APP / "quality.py").read_text(encoding="utf-8")   # замеры качества: шлётся на вход перед probe.py
INDEX = APP / "index.html"
STATIC = APP / "static"
KR_SERVICE = "vpn-dash"
TOKEN = secrets.token_urlsafe(18)   # новый при каждом запуске: без него страница не управляет панелью
BOOT_ID = secrets.token_hex(4)      # по нему открытая страница замечает перезапуск панели и обновляется

TG_DC_DEFAULT = "DC1 149.154.175.53\nDC2 149.154.167.51\nDC3 149.154.175.100\nDC4 149.154.167.91\nDC5 91.108.56.130"
# Все настройки панели: (ключ, по умолчанию, тип, мин, макс, группа, подпись, пояснение).
# Страница «Настройки» строится из этого списка; значения хранятся в servers.json → settings.
SETTINGS = [
    ("auto_minutes", 5, "int", 1, 240, "Проверки", "Проверять серверы и каналы каждые, мин", "Полная проверка: все серверы, все каналы, порты входов, сравнение входов."),
    ("dc_minutes", 30, "int", 5, 240, "Проверки", "Проверять Telegram DC каждые, мин", ""),
    ("slow_s", 2.0, "float", 0.3, 30, "Проверки", "Канал медленный (жёлтый), если ответ дольше, с", ""),
    ("channel_timeout", 15, "int", 3, 60, "Проверки", "Ждать ответа через канал, с", "Не дождались — канал красный."),
    ("check_url", "https://ifconfig.me", "url", None, None, "Проверки", "Адрес для проверки канала",
     "Должен отвечать голым IP-адресом. Другие варианты: https://api.ipify.org, https://icanhazip.com"),
    ("hs_stale_min", 5, "int", 1, 120, "Проверки", "Рукопожатие AWG считать старым после, мин", ""),
    ("cpu_warn", 60, "int", 1, 100, "Пороги", "CPU: жёлтый от, %", ""),
    ("cpu_bad", 85, "int", 1, 100, "Пороги", "CPU: красный от, %", ""),
    ("mem_warn", 75, "int", 1, 100, "Пороги", "Память: жёлтый от, %", ""),
    ("mem_bad", 90, "int", 1, 100, "Пороги", "Память: красный и замечание от, %", ""),
    ("disk_warn", 75, "int", 1, 100, "Пороги", "Диск: жёлтый от, %", ""),
    ("disk_bad", 85, "int", 1, 100, "Пороги", "Диск: красный и замечание от, %", ""),
    ("disk_free_gb", 1.5, "float", 0, 100, "Пороги", "Замечание, если свободно меньше, ГБ", ""),
    ("cert_days", 2, "int", 0, 90, "Пороги", "Предупредить о сертификате панели за, дн", ""),
    ("tg_dc", TG_DC_DEFAULT, "dclist", None, None, "Telegram", "Какие DC проверять с выходов",
     "По строке на DC: имя и IP через пробел. Проверяется подключение к порту 443."),
    ("speed_urls", "Москва · Яндекс | https://mirror.yandex.ru/ubuntu-releases/24.04/ubuntu-24.04.5-live-server-amd64.iso\n"
                   "Германия · FAU | https://ftp.fau.de/ubuntu-releases/24.04/ubuntu-24.04.5-live-server-amd64.iso",
     "urllist", None, None, "Замер скорости", "Откуда качать при замере нового сервера",
     "По строке: название | адрес большого файла (от 100 МБ). Каждый качается 15 секунд. Если файл пропал с зеркала — замените адрес."),
    ("gov_hours", 24, "int", 0, 168, "Сети госорганов", "Обновлять список раз в, ч (0 — не обновлять)",
     "Свежий список скачивается этим компьютером; на входах, где включено, он ставится с тем же замером и «ремнём», что и при включении."),
    ("gov_keep", "", "iplist", None, None, "Сети госорганов", "Свои адреса, которые не блокировать",
     "IP или сети через пробел или по строке — например, рабочий адрес, если он вдруг попал в список. Адрес этого компьютера добавляется сам."),
    ("drift_auto", True, "bool", None, None, "Сверка резервов", "Сверять при каждой полной проверке",
     "Основной вход (первый в списке серверов) сравнивается с каждым резервным. Иначе — только по кнопке «Сверить»."),
    ("backup_server", "", "entry", None, None, "Бэкап", "Чей бэкап делать", "Пусто — первый вход в списке серверов."),
    ("backup_hours", 24, "int", 0, 720, "Бэкап", "Автоматически раз в, ч (0 — выкл.)", ""),
    ("backup_keep", 10, "int", 1, 100, "Бэкап", "Сколько архивов хранить", "Лишние старые удаляются из папки backups."),
    ("hist_days", 30, "int", 1, 365, "История", "Хранить историю проверок, дн", "Для графиков. Сутки истории — примерно 1 МБ."),
    ("tray_notify", True, "bool", None, None, "Windows", "Уведомления о сбоях", "Всплывающее уведомление, когда значок в трее меняет цвет."),
    ("notify_warn", True, "bool", None, None, "Windows", "Уведомлять и о жёлтом", "Выключите — будут только красные (вход недоступен или без каналов)."),
    ("autostart", True, "bool", None, None, "Windows", "Запускать вместе с Windows", "Панель стартует без окна после входа в Windows."),
    ("port", 8787, "int", 1024, 65535, "Windows", "Порт панели", "Меняется после перезапуска панели (меню значка → Выход, потом start.bat)."),
]
SETTINGS_BY_KEY = {x[0]: x for x in SETTINGS}
NO_FILL = {"autostart"}     # не заполнять по умолчанию: по отсутствию узнаём первый запуск со значком


def _port():
    if os.environ.get("DASH_PORT"):
        return int(os.environ["DASH_PORT"])
    try:
        p = int(json.loads(CFG_FILE.read_text(encoding="utf-8")).get("settings", {}).get("port") or 8787)
        return p if 1024 <= p <= 65535 else 8787
    except (OSError, ValueError, AttributeError):
        return 8787


PORT = _port()


def parse_dc(text):
    out = []
    for line in str(text or "").splitlines():
        parts = line.replace(",", " ").replace("=", " ").split()
        if len(parts) == 2 and re.match(r"^[A-Za-z0-9_-]{1,12}$", parts[0]) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[1]):
            out.append((parts[0], parts[1]))
    return out


def clean_setting(key, val, cfg=None):
    """Проверяет и приводит значение. ValueError — с понятным текстом."""
    k, dflt, typ, lo, hi, grp, label, _ = SETTINGS_BY_KEY[key]
    if typ in ("int", "float"):
        try:
            v = float(str(val).replace(",", "."))
        except ValueError:
            raise ValueError("«%s»: нужно число" % label)
        v = max(lo, min(hi, v))
        return int(round(v)) if typ == "int" else round(v, 2)
    if typ == "bool":
        return bool(val) and val not in ("false", "0", 0)
    if typ == "url":
        v = str(val).strip()
        if not re.match(r"^https?://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?$", v):
            raise ValueError("«%s»: нужен адрес вида https://ifconfig.me" % label)
        return v
    if typ == "dclist":
        lst = parse_dc(val)
        if not lst:
            raise ValueError("«%s»: ни одной строки вида «DC5 91.108.56.130»" % label)
        return "\n".join("%s %s" % x for x in lst[:12])
    if typ == "urllist":
        from provision import parse_urls
        lst = parse_urls(val)
        if not lst:
            raise ValueError("«%s»: ни одной строки вида «Название | https://адрес»" % label)
        return "\n".join("%s | %s" % x for x in lst)
    if typ == "iplist":
        import govblock
        bad = [x for x in re.split(r"[\s,;]+", str(val or "")) if x and not govblock.keep_list(x)]
        if bad:
            raise ValueError("«%s»: не адрес — %s" % (label, ", ".join(bad[:3])))
        return "\n".join(govblock.keep_list(val))
    if typ == "entry":
        v = str(val or "")
        if v and cfg and not cfg.by_id(v):
            raise ValueError("«%s»: нет такого сервера" % label)
        return v
    return str(val)[:200]


DEFAULT_CFG = {
    "settings": {k[0]: k[1] for k in SETTINGS if k[0] not in NO_FILL},
    "servers": [],          # серверы добавляются на странице «Серверы и пароли»
}


class CheckError(Exception):
    pass


def now():
    return time.time()


def hhmm(t=None):
    return time.strftime("%H:%M", time.localtime(t or now()))


# ------------------------------------------------------------------ настройки и пароли

class Config:
    def __init__(self):
        if CFG_FILE.exists():
            self.data = json.loads(CFG_FILE.read_text(encoding="utf-8"))
        else:
            self.data = json.loads(json.dumps(DEFAULT_CFG))
            self.save()
        st = self.data.setdefault("settings", {})
        for k, v in DEFAULT_CFG["settings"].items():
            st.setdefault(k, v)
        self.mem_pw = {}        # если keyring недоступен — пароль живёт до перезапуска

    def save(self):
        tmp = CFG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(CFG_FILE)

    @property
    def servers(self):
        return self.data["servers"]

    @property
    def settings(self):
        return self.data["settings"]

    def by_id(self, sid):
        return next((s for s in self.servers if s["id"] == sid), None)

    def by_host(self, host):
        return next((s for s in self.servers if s["host"] == host), None)

    def get_pw(self, sid):
        if sid in self.mem_pw:
            return self.mem_pw[sid]
        if keyring:
            try:
                return keyring.get_password(KR_SERVICE, sid)
            except Exception:
                return None
        return None

    def set_pw(self, sid, pw):
        if keyring:
            try:
                if pw:
                    keyring.set_password(KR_SERVICE, sid, pw)
                else:
                    try:
                        keyring.delete_password(KR_SERVICE, sid)
                    except Exception:
                        pass
                self.mem_pw.pop(sid, None)
                return "keyring"
            except Exception:
                pass
        if pw:
            self.mem_pw[sid] = pw
        else:
            self.mem_pw.pop(sid, None)
        return "memory"


# ------------------------------------------------------------------ SSH

class SSHPool:
    def __init__(self, cfg):
        self.cfg = cfg
        self.clients = {}
        self.locks = {}
        self.glock = threading.Lock()
        self.route = None       # (srv, id входа) → (вход, адрес, порт, как) — консоль «через вход»; ставит Dash

    def _lock(self, sid):
        with self.glock:
            return self.locks.setdefault(sid, threading.Lock())

    def drop(self, sid):
        c = self.clients.pop(sid, None)
        if c:
            try:
                c.close()
            except Exception:
                pass

    def client(self, srv):
        with self._lock(srv["id"]):
            c = self.clients.get(srv["id"])
            if c and c.get_transport() and c.get_transport().is_active():
                return c
            pw = srv.get("_pw") or self.cfg.get_pw(srv["id"])   # _pw — новый сервер из мастера
            if not pw:
                raise CheckError("не задан пароль (страница «Серверы и пароли»)")
            c, _ = self.connect(srv, pw)
            c.get_transport().set_keepalive(30)
            self.clients[srv["id"]] = c
            return c

    def connect(self, srv, pw, via=None):
        """Новое SSH-соединение: напрямую или через вход (via — id входа). Ключ сервера проверяется по его
        обычному адресу в known_hosts, как бы ни шли пакеты: через туннель отвечает тот же sshd.
        Возвращает (клиент, {"via": имя входа или "", "how": …})."""
        sock, path = None, {"via": "", "how": "напрямую"}
        if via:
            if not self.route:
                raise CheckError("путь через вход ещё не готов — повторите через минуту")
            entry, host, port, how, iface = self.route(srv, via)
            try:
                tr = self.client(entry).get_transport()
            except CheckError as e:
                raise CheckError("через вход %s: %s" % (entry["name"], e))
            try:
                if iface:
                    sock = self._relay(tr, entry, host, port, iface)
                else:
                    sock = tr.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=10)
            except paramiko.ChannelException as e:
                raise CheckError("вход %s не достучался до выхода (%s:%d, %s): %s" % (
                    entry["name"], host, port, how, "соединение не открылось" if e.code == 2 else e))
            except (paramiko.SSHException, OSError, EOFError) as e:
                self.drop(entry["id"])
                raise CheckError("через вход %s: %s" % (entry["name"], e or type(e).__name__))
            path = {"via": entry["name"], "via_id": entry["id"], "how": how, "addr": "%s:%d" % (host, port)}
        c = paramiko.SSHClient()
        KNOWN_HOSTS.touch(exist_ok=True)
        c.load_host_keys(str(KNOWN_HOSTS))
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pre = "через вход %s: " % path["via"] if via else ""
        try:
            c.connect(srv["host"], port=int(srv.get("port") or 22), username=srv.get("user") or "root",
                      password=pw, timeout=10, banner_timeout=15, auth_timeout=15,
                      look_for_keys=False, allow_agent=False, sock=sock)
        except paramiko.AuthenticationException:
            raise CheckError("неверный пароль")
        except paramiko.BadHostKeyException:
            raise CheckError("ключ сервера изменился (переустановка или подмена?) — удалите его строку из known_hosts")
        except (socket.timeout, TimeoutError):
            raise CheckError(pre + "SSH не отвечает (таймаут)")
        except (paramiko.SSHException, OSError) as e:
            raise CheckError(pre + "SSH: %s" % e)
        c.save_host_keys(str(KNOWN_HOSTS))
        return c, path

    # Туннели AWG на входах — с Table = off: маршрутов в них нет, Xray и проверки выбирают туннель сами
    # (sockopt interface, ping -I). Поэтому sshd входа (direct-tcpip) до адреса выхода в туннеле не дойдёт —
    # соединение открывает маленький python3 на входе с SO_BINDTODEVICE и гоняет байты через stdin/stdout.
    # На сервере ничего не меняется: процесс живёт, пока открыто это SSH-соединение.
    RELAY_PY = r"""
import errno, os, socket, sys, threading
s = socket.socket()
try:
    s.setsockopt(socket.SOL_SOCKET, 25, IFACE.encode())       # SO_BINDTODEVICE
except OSError as e:
    if not (e.errno == errno.ENODEV and os.path.exists("/etc/x-ui/.testbed")):   # стенд: туннелей-интерфейсов нет
        sys.stderr.write("туннель %s не поднят (%s)\n" % (IFACE, e.strerror)); sys.exit(2)
try:
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1240)    # как у Xray для AWG: крупные пакеты в туннеле не пролезают
except OSError:
    pass
s.settimeout(10)
try:
    s.connect((HOST, PORT))
except OSError as e:
    sys.stderr.write("по туннелю %s до %s:%d не подключиться: %s\n" % (IFACE, HOST, PORT, e.strerror or "таймаут")); sys.exit(3)
s.settimeout(None)
os.write(1, b"OK\n")
def up():
    try:
        while True:
            d = os.read(0, 65536)
            if not d:
                break
            s.sendall(d)
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass
threading.Thread(target=up, daemon=True).start()
while True:
    d = s.recv(65536)
    if not d:
        break
    while d:
        d = d[os.write(1, d):]
"""

    def _relay(self, tr, entry, host, port, iface):
        import base64
        code = "IFACE = %r\nHOST = %r\nPORT = %d\n" % (iface, host, port) + self.RELAY_PY
        ch = tr.open_session(timeout=10)
        ch.exec_command("python3 -u -c 'import base64; exec(base64.b64decode(\"%s\"))'" % base64.b64encode(code.encode()).decode())
        ch.settimeout(15)
        got = b""
        try:
            while len(got) < 3:
                part = ch.recv(3 - len(got))
                if not part:
                    break
                got += part
        except socket.timeout:
            pass
        if got != b"OK\n":
            err = b""
            try:
                while ch.recv_stderr_ready() or not ch.exit_status_ready():
                    part = ch.recv_stderr(4096)
                    if not part:
                        break
                    err += part
            except socket.timeout:
                pass
            ch.close()
            raise CheckError("вход %s: %s" % (entry["name"], err.decode("utf-8", "replace").strip() or "по туннелю %s не подключиться (таймаут)" % iface))
        ch.settimeout(None)
        return ch

    def tunnel(self, srv, host, port):
        """Сокет, соединённый через SSH с host:port на самом сервере (как ssh -L). Нужен, чтобы открыть 3X-UI,
        закрытую из интернета."""
        for attempt in (1, 2):
            try:
                ch = self.client(srv).get_transport().open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=10)
                break
            except paramiko.ChannelException as e:
                raise CheckError("на сервере никто не отвечает на %s:%d — x-ui работает?" % (host, port) if e.code == 2 else
                                 "сервер не разрешает такие соединения по SSH (AllowTcpForwarding): %s" % e)
            except CheckError:
                raise
            except (paramiko.SSHException, OSError, EOFError) as e:
                self.drop(srv["id"])
                if attempt == 2:
                    raise CheckError("SSH: %s" % (e or type(e).__name__))
        a, b = socket.socketpair()
        left = [2]
        lk = threading.Lock()

        def finish():
            with lk:
                left[0] -= 1
                if left[0]:
                    return
            for x in (a, ch):
                try:
                    x.close()
                except Exception:
                    pass

        def to_server():
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    ch.sendall(d)
                ch.shutdown_write()
            except Exception:
                pass
            finally:
                finish()

        def to_us():
            try:
                while True:
                    d = ch.recv(65536)
                    if not d:
                        break
                    a.sendall(d)
            except Exception:
                pass
            finally:
                try:
                    a.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                finish()

        threading.Thread(target=to_server, daemon=True).start()
        threading.Thread(target=to_us, daemon=True).start()
        return b

    def run(self, srv, cmd, stdin=None, timeout=60):
        for attempt in (1, 2):
            try:
                c = self.client(srv)
                si, so, se = c.exec_command(cmd, timeout=timeout)
                if stdin is not None:
                    si.write(stdin)
                    si.channel.shutdown_write()
                out = so.read().decode("utf-8", "replace")
                err = se.read().decode("utf-8", "replace")
                return so.channel.recv_exit_status(), out, err
            except CheckError:
                raise
            except (paramiko.SSHException, OSError, EOFError) as e:
                self.drop(srv["id"])
                if attempt == 2:
                    raise CheckError("SSH: %s" % (e or type(e).__name__))


# ------------------------------------------------------------------ история

class History:
    """Результаты проверок за последние 30 дней (history.db рядом с панелью)."""

    def __init__(self, days=lambda: 30):
        self.days = days
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(HIST_FILE), check_same_thread=False)
        self.db.execute("pragma journal_mode=wal")
        self.db.execute("create table if not exists samples(ts real, kind text, key text, status text, ms real)")
        self.db.execute("create index if not exists samples_k on samples(kind, key, ts)")
        self.db.commit()
        self.last_prune = 0
        self.cache = (0, None)

    def add(self, kind, key, status, ms=None):
        with self.lock:
            self.db.execute("insert into samples values(?,?,?,?,?)", (now(), kind, key, status, ms))
            self.db.commit()
            if now() - self.last_prune > 3600:
                self.last_prune = now()
                self.db.execute("delete from samples where ts < ?", (now() - self.days() * 86400,))
                self.db.commit()

    def series(self, kind, key, hours):
        with self.lock:
            rows = self.db.execute("select ts, status, ms from samples where kind=? and key=? and ts>=? order by ts",
                                   (kind, key, now() - hours * 3600)).fetchall()
        return [[round(t), s, m] for t, s, m in rows]

    def summary(self):
        """Для обзора: по каждому каналу и DC — доступность за 24 ч и 48 точек для мини-графика."""
        if now() - self.cache[0] < 20:
            return self.cache[1]
        since = now() - 86400
        with self.lock:
            rows = self.db.execute("select kind, key, ts, status, ms from samples where ts>=? and kind in ('ch','dc') "
                                   "order by ts", (since,)).fetchall()
        out = {}
        for kind, key, ts, st, ms in rows:
            d = out.setdefault(kind + ":" + key, {"n": 0, "ok": 0, "b": [None] * 48})
            d["n"] += 1
            d["ok"] += st in ("ok", "warn")
            i = min(47, int((ts - since) / 1800))
            cur = d["b"][i]
            bad = st not in ("ok", "warn")
            if cur is None:
                d["b"][i] = [ms, bad]
            else:
                cur[0] = max(x for x in (cur[0], ms) if x is not None) if (cur[0] is not None or ms is not None) else None
                cur[1] = cur[1] or bad
        for d in out.values():
            d["up"] = round(100.0 * d["ok"] / d["n"], 1) if d["n"] else None
            del d["ok"]
        self.cache = (now(), out)
        return out


# ------------------------------------------------------------------ сравнение конфигураций входов

def flatten(o, prefix="", out=None):
    """Вложенный JSON → {путь: значение}; списки объектов индексируются по tag/name/email/remark."""
    if out is None:
        out = {}
    if isinstance(o, dict):
        if not o and prefix:
            out[prefix] = "{}"
        for k, v in o.items():
            flatten(v, "%s.%s" % (prefix, k) if prefix else str(k), out)
    elif isinstance(o, list):
        if o and all(isinstance(x, dict) for x in o):
            for i, x in enumerate(o):
                name = next((x[k] for k in ("tag", "name", "email", "remark", "comment") if x.get(k)), None)
                flatten(x, "%s[%s]" % (prefix, name if name is not None else i), out)
        else:
            out[prefix] = json.dumps(o, ensure_ascii=False, sort_keys=True)
    else:
        out[prefix] = o
    return out


GROUPS = [
    (r"^xui\.clients", "Клиенты"),
    (r"^xui\.inbounds", "Входящие"),
    (r"^xui\.template\.routing\.balancers", "Балансировщики"),
    (r"^xui\.template\.routing", "Маршрутизация"),
    (r"^xui\.template\.outbounds", "Исходящие"),
    (r"^xui\.template\.(burstObservatory|observatory)", "Проверка здоровья"),
    (r"^xui\.template", "Шаблон Xray"),
    (r"^xui\.settings", "Настройки панели"),
    (r"^awg", "AWG-туннели"),
]


def _name_of(x):
    for k in ("tag", "name", "email", "remark", "comment"):
        if x.get(k):
            return str(x[k])
    for k, pre in (("inboundTag", "in:"), ("ip", "ip:"), ("domain", "domain:"), ("network", "net:")):
        if x.get(k):
            v = x[k]
            return pre + (",".join(map(str, v)) if isinstance(v, list) else str(v))
    return None


def _keyed(lst):
    """Список объектов → словарь по имени (tag/name/email/…, для правил — по их условию)."""
    if not lst or not all(isinstance(x, dict) for x in lst):
        return None
    out = {}
    for x in lst:
        name = _name_of(x)
        if name is None or name in out:
            return None
        out[name] = x
    return out


def _brief(v):
    if isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False, sort_keys=True)
        return "есть" if len(s) > 90 else s
    return str(v)[:160]


def normalize_cfg(c):
    """Убрать из снимка то, что у каждого входа своё по задумке: имя входящего (vless / vless-2).
    Входящие сравниваются по протоколу и порту, у клиентов — список входящих в том же виде."""
    c = json.loads(json.dumps(c))
    x = c.get("xui") or {}
    ren, new = {}, {}
    for name, ib in (x.get("inbounds") or {}).items():
        port = str(name).rsplit(":", 1)[-1]
        key = "%s:%s" % ((ib or {}).get("protocol") or "", port)
        ren[name] = key
        new[key] = {k: v for k, v in (ib or {}).items() if k != "remark"}
    if "inbounds" in x:
        x["inbounds"] = new
    for cl in (x.get("clients") or {}).values():
        if isinstance(cl, dict) and isinstance(cl.get("inbounds"), list):
            cl["inbounds"] = sorted(ren.get(n, n) for n in cl["inbounds"])
    return c


KIND = {"Клиенты": "Клиент", "Входящие": "Входящий", "Балансировщики": "Балансировщик", "Исходящие": "Исходящий",
        "Маршрутизация": "Правило маршрутизации", "AWG-туннели": "Туннель"}


def describe(d):
    """Короткое человеческое название строки различия."""
    path, g = d["path"], d["group"]
    m = re.match(r"^(clients|inbounds)\.([^.]+)(?:\.(.+))?$", path) or re.match(r"^([\w.]*?)\[([^\]]+)\](?:\.(.+))?$", path)
    if m:
        what = "%s «%s»" % (KIND.get(g, g), m.group(2))
        return what + (": " + m.group(3) if m.group(3) else "")
    m = re.match(r"^(wg\d+)(?:\.(\w+))?$", path)
    if m:
        return "Туннель %s" % m.group(1) + (": " + m.group(2) if m.group(2) else "")
    return g + ": " + path


def diff_configs(a, b):
    res = []

    def add(path, va, vb):
        group = next((g for rx, g in GROUPS if re.match(rx, path)), "Прочее")
        short = re.sub(r"^(xui\.(template\.)?|awg\.)", "", path)
        res.append({"group": group, "path": short, "a": va, "b": vb})

    def walk(x, y, path):
        if isinstance(x, list) and isinstance(y, list):
            kx, ky = _keyed(x), _keyed(y)
            if kx is not None and ky is not None:
                common = [k for k in kx if k in ky]
                if common != [k for k in ky if k in kx]:      # в Xray порядок правил важен
                    add(path + " (порядок)", ", ".join(common), ", ".join(k for k in ky if k in kx))
                x, y = kx, ky
                path_fmt = "%s[%s]"
            elif (isinstance(x, list) and x and all(isinstance(i, dict) for i in x + y)):
                for i in range(max(len(x), len(y))):
                    p = "%s[%d]" % (path, i + 1)
                    if i >= len(y):
                        add(p, _brief(x[i]), "— нет —")
                    elif i >= len(x):
                        add(p, "— нет —", _brief(y[i]))
                    else:
                        walk(x[i], y[i], p)
                return
            else:
                if x != y:
                    add(path, _brief(x), _brief(y))
                return
        else:
            path_fmt = "%s.%s" if path else "%s%s"
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y), key=str):
                p = path_fmt % (path, k)
                if k not in y:
                    add(p, _brief(x[k]), "— нет —")
                elif k not in x:
                    add(p, "— нет —", _brief(y[k]))
                else:
                    walk(x[k], y[k], p)
        elif x != y:
            add(path, _brief(x), _brief(y))

    walk(a, b, "")
    return res


# ------------------------------------------------------------------ обновления пакетов: что затронут

PKG_RULES = [   # (шаблон имени, метка, уровень, что произойдёт)
    (r"^linux-(image|headers|modules|generic|virtual|azure|aws|gcp|kvm|oem|cloud-tools|tools|firmware)|^linux-firmware$",
     "перезагрузка", "warn", "новое ядро заработает только после перезагрузки сервера"),
    (r"^openssh-server$", "SSH", "warn",
     "SSH перезапустится. На Ubuntu 24.04 бывает, что он поднимается не сразу — панель запускает его сама"),
    (r"^amneziawg", "туннели AWG", "warn",
     "пересоберётся модуль AmneziaWG; новый заработает после перезагрузки, туннели могут коротко моргнуть"),
    (r"^(docker-ce|containerd\.io)$", "Docker", "warn",
     "перезапустится Docker — контейнеры (Amnezia на выходе) остановятся на несколько секунд"),
    (r"^(netplan\.io|libnetplan.*|netplan-generator|systemd-networkd|cloud-init)$", "сеть", "info",
     "пакет сетевой настройки; сеть обычно не перезапускается"),
    (r"^(libc6|systemd|libsystemd.*|dbus|libssl.*|openssl)$", "системное", "info",
     "системная библиотека: службы, которые её используют, перезапустятся сами"),
]


def classify_pkgs(info, srv, is_main):
    """Пометки к пакетам и общий вывод «можно ли ставить» — простыми словами."""
    items = info.get("items") or []
    tags_seen = {}
    for it in items:
        it["tags"] = []
        for rx, label, lvl, text in PKG_RULES:
            if re.search(rx, it["name"]):
                it["tags"].append({"label": label, "level": lvl})
                if not it["held"]:
                    tags_seen.setdefault(label, (lvl, text))
                break
    todo = [i for i in items if not i["held"]]
    notes = [{"level": lvl, "label": label, "text": text} for label, (lvl, text) in tags_seen.items()]
    if "Docker" in tags_seen and srv["role"] == "exit":
        notes.append({"level": "info", "label": "", "text": "пока Docker перезапускается, трафик сам уйдёт на следующий выход в цепочке"})
    if is_main and any(n["level"] == "warn" for n in notes):
        notes.append({"level": "warn", "label": "", "text": "через этот вход идёт трафик всех устройств — возможен короткий перерыв, "
                                                           "удобнее ставить, когда VPN не нужен"})
    if info.get("dpkg_busy"):
        notes.insert(0, {"level": "warn", "label": "", "text": "на сервере сейчас уже идёт apt (возможно, автообновление Ubuntu) — "
                                                             "установка подождёт, пока он закончит (до 20 минут; не дождётся — ничего не поставит, можно повторить)"})
    if not todo:
        v = {"level": "ok", "text": "ставить нечего" + (" — есть только отложенные Ubuntu" if items else "")}
    elif any(n["level"] == "warn" for n in notes if n["label"]):
        v = {"level": "warn", "text": "можно ставить, но учтите пометки ниже"}
    else:
        v = {"level": "ok", "text": "можно ставить: службы VPN это не затронет"}
    reboot_after = info.get("reboot_required") or "перезагрузка" in tags_seen
    return {"verdict": v, "notes": notes, "todo": len(todo), "security": sum(1 for i in todo if i["security"]),
            "reboot_after": bool(reboot_after)}


# ------------------------------------------------------------------ состояние и проверки

class Dash:
    def __init__(self):
        self.cfg = Config()
        self.ssh = SSHPool(self.cfg)
        self.ssh.route = self.ssh_route
        self.hist = History(lambda: int(self.cfg.settings.get("hist_days") or 30))
        self.restart_args = None    # перезапуск после обновления: аргументы нового процесса
        try:
            import updater
            self.version = updater.version()
            self.git = updater.available()
        except Exception:
            self.version, self.git = None, False
        self.on_restart = None      # как остановить текущий (ставит значок в трее)
        self.lock = threading.RLock()
        self.status = {}        # sid -> {at, ok, error, data}
        self.channels = {}      # entry sid -> [channel]
        self.results = {}       # "entry:key" -> {status, ip, ms, at, error}
        self.dc = {}            # exit sid -> {at, cells|error}
        self.reach = {}         # "entry:port" -> {ok, ms, at, error}
        self.drift = None       # {at, main, res: [{id, diffs|error}]}
        self.pkg_count = {}     # sid -> {at, n}: сколько обновлений поставится (считается редко)
        self.fw = {}            # sid -> {at, ok, error, plan}: проверка для фаервола (только чтение)
        self.fwjob = {}         # sid -> {at, do, steps: [[уровень, текст]], ok, done}: включение/выключение фаервола
        self.govjob = {}        # sid -> то же для «сетей госорганов»
        try:
            self.gov = json.loads(GOV_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.gov = {}       # {at, sha, v4, v6, bad, error, tried}: список сетей госорганов (govblock.fetch)
        self.xui_web = {}       # sid -> {port, path, https, domain, listen}: веб-панель 3X-UI (путь — только здесь, не на странице)
        self.geo = {}           # sid -> итог «как видят адрес» (ipcheck.summarize + at)
        self.nb = {}            # sid -> итог «шумные соседи» (neighbors.summarize + at)
        self.dns = {}           # sid -> итог проверки DNS (dnscheck.summarize + at)
        try:
            a = json.loads(ADDR_FILE.read_text(encoding="utf-8"))
            self.geo, self.nb, self.dns = a.get("geo") or {}, a.get("nb") or {}, a.get("dns") or {}
        except (OSError, ValueError):
            pass
        self.dpi = None         # «что режут на входах»: sites.Sites.dpi()
        self.quality = None     # последняя проверка качества: {at, secs, tests, ch, routes, pc, ...}
        self.rsess = remote.Sessions()      # удалённый доступ: сессии и защита от подбора
        import sites
        self.sites = sites.Sites(self, PROBE)   # «Сайты и обходы»
        import zapret
        self.zapret = zapret.Zapret(self, PROBE)   # «Zapret»: сайты с входа напрямую
        self.last_zap = 0
        self.remote_srv = None              # второй HTTP-сервер (порт удалённого доступа)
        self.remote_pending = None          # секрет одноразовых кодов, пока его не подтвердили кодом
        self.backup = {}        # последняя попытка: {at, ok, file, error}
        self.running = set()    # что сейчас проверяется
        self.log = []
        self.pool = cf.ThreadPoolExecutor(max_workers=8)    # запуски: «всё», «вход», «сервер», бэкап
        self.leaf = cf.ThreadPoolExecutor(max_workers=16)   # сами тесты: каналы, порты, DC
        self.last_auto = 0
        self.last_dc = 0
        BACKUP_DIR.mkdir(exist_ok=True)
        if LOG_FILE.exists():
            if LOG_FILE.stat().st_size > 2_000_000:     # журнал не растёт бесконечно: оставляем 5000 последних записей
                try:
                    LOG_FILE.write_text("\n".join(LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]) + "\n",
                                        encoding="utf-8")
                except OSError:
                    pass
            for line in LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-150:]:
                try:
                    self.log.append(json.loads(line))
                except ValueError:
                    pass

    # --- журнал

    # --- удалённый доступ (Tailscale)

    def remote_cfg(self):
        r = self.cfg.data.setdefault("remote", {})
        r.setdefault("enabled", False)
        r.setdefault("port", PORT + 1)
        return r

    def remote_creds(self):
        return {"pw": self.cfg.get_pw("_remote_pw") or "", "totp": self.cfg.get_pw("_remote_totp") or ""}

    def remote_status(self):
        rc, cr = self.remote_cfg(), self.remote_creds()
        return {"enabled": rc["enabled"], "port": rc["port"], "running": self.remote_srv is not None,
                "has_pw": bool(cr["pw"]), "has_totp": bool(cr["totp"]), "keyring": bool(keyring),
                "sessions": self.rsess.list(), "error": getattr(self, "remote_error", "")}

    def remote_apply(self):
        """Запустить или остановить порт удалённого доступа по настройке."""
        rc, cr = self.remote_cfg(), self.remote_creds()
        want = rc["enabled"] and cr["pw"] and cr["totp"]
        self.remote_error = ""
        if self.remote_srv and (not want or self.remote_srv.server_address[1] != rc["port"]):
            srv, self.remote_srv = self.remote_srv, None
            srv.shutdown()
            srv.server_close()
            self.rsess.drop()
        if want and not self.remote_srv:
            try:
                self.remote_srv = QuietServer(("127.0.0.1", int(rc["port"])), RemoteHandler)
            except OSError as e:
                self.remote_error = "порт %s занят: %s" % (rc["port"], e)
                return
            threading.Thread(target=self.remote_srv.serve_forever, daemon=True).start()

    def remote_api(self, body):
        a = body.get("action")
        rc = self.remote_cfg()
        if a == "set_pw":
            pw = str(body.get("password") or "")
            if len(pw) < 10:
                return {"error": "пароль — не короче 10 символов"}
            if not keyring:
                return {"error": "нет модуля keyring — пароль удалённого доступа негде надёжно хранить"}
            self.cfg.set_pw("_remote_pw", remote.hash_password(pw))
            self.rsess.drop()
            self.note("ok", "Удалённый доступ: пароль задан, все удалённые сессии закрыты")
        elif a == "totp_new":
            self.remote_pending = remote.new_totp_secret()
            return {"secret": self.remote_pending, "uri": remote.otpauth_uri(self.remote_pending)}
        elif a == "totp_confirm":
            if not self.remote_pending:
                return {"error": "сначала нажмите «Создать код»"}
            if remote.totp_match(self.remote_pending, body.get("code")) is None:
                return {"error": "код не подошёл — проверьте, что время на телефоне и компьютере верное, и введите свежий"}
            self.cfg.set_pw("_remote_totp", self.remote_pending)
            self.remote_pending = None
            self.rsess.drop()
            self.rsess.last_counter = -1
            self.note("ok", "Удалённый доступ: приложение для одноразовых кодов подключено, все удалённые сессии закрыты")
        elif a == "enable":
            on = bool(body.get("on"))
            cr = self.remote_creds()
            if on and not (cr["pw"] and cr["totp"]):
                return {"error": "сначала задайте пароль и подключите приложение для кодов"}
            rc["enabled"] = on
            self.cfg.save()
            self.remote_apply()
            self.note("ok" if not on else "warn", "Удалённый доступ %s" % ("включён (порт %s)" % rc["port"] if on else "выключен"))
        elif a == "test":            # проверка с домашнего компьютера: что именно не так — пароль, код или часы
            cr = self.remote_creds()
            res = {"pw_ok": bool(cr["pw"]) and remote.check_password(str(body.get("password") or ""), cr["pw"]),
                   "has_totp": bool(cr["totp"]), "skew": None, "pc_time": time.strftime("%H:%M:%S")}
            code = "".join(ch for ch in str(body.get("code") or "") if ch.isdigit())
            t = int(time.time() // 30)
            for d in sorted(range(-20, 21), key=abs):     # ±10 минут: если код подходит со сдвигом — часы расходятся
                if cr["totp"] and len(code) == 6 and remote.totp(cr["totp"], t + d) == code:
                    res["skew"] = d * 30
                    break
            res["locked_for"] = self.rsess.blocked_for()
            return {"test": res}
        elif a == "unlock":
            self.rsess.fails = []
        elif a == "logout":
            if body.get("id"):
                self.rsess.drop_by_id(str(body["id"]))
            else:
                self.rsess.drop()
        elif a != "status":
            return {"error": "action?"}
        return self.remote_status()

    # --- обходы (отдельные цепочки для сайтов)

    def bypass_api(self, body):
        import sites
        a, code = body.get("action"), str(body.get("code") or "")
        if not sites.CODE_RE.match(code):
            return {"error": "код обхода?"}
        reg = self.sites.registry()
        ents = [s for s in self.cfg.servers if s["role"] == "entry"]
        if "bypass" in self.running:
            return {"error": "уже идёт другое действие с обходами — дождитесь"}
        with self.busy("bypass"):
            if a == "recheck":
                b = reg.get(code)
                if not b:
                    return {"error": "нет такого обхода"}
                act = self.sites.active_exit(ents[0]["id"]) if ents else None
                xn = (self.cfg.by_id(act) or {"name": "?"})["name"]
                if b.get("service") == "dc5":           # DC5: нужен, пока DC5 не открывается с основного выхода
                    if act:
                        self.check_dc(act)
                    cells = (self.dc.get(act) or {}).get("cells") or []
                    ok = any(c["name"] == "DC5" and c["ok"] for c in cells)
                else:
                    r = self.sites.check(b.get("service") or (b["match"].get("domain") or ["?"])[0].replace("domain:", ""))
                    rows = [x for x in r["rows"] if x["exit_id"] == act]
                    ok = any(all(c["st"] in ("ok", "slow") for c in x["cells"] if c["st"] != "none") for x in rows)
                b["check"] = {"at": time.time(), "fine": ok,
                              "text": ("через выход %s %s снова открывается — обход больше не нужен" if ok else
                                       "через выход %s %s всё ещё не открывается — обход нужен") % (xn, b["title"])}
                self.cfg.save()
                self.note("ok" if ok else "warn", "Перепроверка обхода %s: %s" % (code, b["check"]["text"]))
                return {"ok": True, "check": b["check"]}
            chain = [str(x) for x in body.get("chain") or [] if re.match(r"^[A-Za-z0-9_.-]{1,40}$", str(x))]
            if a == "create" and body.get("target") and not body.get("match"):   # новый обход вручную, без проверки
                try:
                    svc = sites.service_for(body["target"])
                except ValueError as e:
                    return {"error": str(e)}
                if svc["code"] in reg:
                    return {"error": "обход для %s уже есть (%s) — измените цепочку у него" % (svc["title"], svc["code"])}
                code = svc["code"]
                body.update({"match": svc["match"], "title": svc["title"], "service": svc["id"],
                             "reason": "создан вручную %s" % time.strftime("%d.%m %H:%M")})
            if a == "chain":
                b = reg.get(code)
                if not b:
                    return {"error": "нет такого обхода"}
                if not chain:
                    return {"error": "в цепочке нужен хотя бы один канал"}
                on = self.sites.where().get(code, {}).get("on", {})
                log = self.sites.apply(code, [e for e in ents if on.get(e["id"])] or ents, "set", b["match"], chain)
                if all(x.get("ok") for x in log):
                    b["chain"] = chain
                    b["check"] = None
                    self.cfg.save()
            elif a == "create":
                match = body.get("match") or {}
                if not chain or not (match.get("domain") or match.get("ip")):
                    return {"error": "нет цепочки или правила"}
                match = {k: [str(v) for v in match[k]][:50] for k in ("domain", "ip") if match.get(k)}
                targets = [e for e in ents if e["id"] in (body.get("entries") or [])]
                log = self.sites.apply(code, targets, "create", match, chain)
                if any(x.get("ok") and x.get("changed") for x in log) or code not in reg:
                    reg.setdefault(code, {"title": str(body.get("title") or code)[:40], "service": str(body.get("service") or "")[:80],
                                          "match": match, "chain": chain, "reason": str(body.get("reason") or "")[:200],
                                          "created": time.time()})
                    self.cfg.save()
            elif a == "spread":
                b = reg.get(code)
                if not b:
                    return {"error": "нет такого обхода"}
                on = self.sites.where().get(code, {}).get("on", {})
                log = self.sites.apply(code, [e for e in ents if not on.get(e["id"])], "create", b["match"], b["chain"])
            elif a == "remove":
                on = self.sites.where().get(code, {}).get("on", {})
                log = self.sites.apply(code, [e for e in ents if on.get(e["id"])] or ents, "remove")
                if all(x.get("ok") for x in log):
                    reg.pop(code, None)
                    self.cfg.data.setdefault("bypass_gone", {})[code] = time.time()   # не подхватить снова по старым данным
                    self.cfg.save()
            else:
                return {"error": "action?"}
        for x in log:
            self.note("ok" if x.get("ok") else "bad", "Обход %s на %s: %s" % (code, x["entry"], x.get("msg")))
            if x.get("no_sniff"):
                self.note("warn", "Обход %s на %s: у входящего %s выключен sniffing — правило по имени сайта не сработает" % (
                    code, x["entry"], ", ".join(x["no_sniff"])))
        futs = [self.pool.submit(self.check_server, x["id"]) for x in log]   # обновить, что где стоит
        cf.wait(futs, timeout=60)
        return {"ok": all(x.get("ok") for x in log), "log": log, "code": code}

    def xui_change(self, sid, what):
        """Веб-панель 3X-UI: закрыть из интернета / открыть снова / свой путь в адресе. Только по кнопке."""
        srv = self.cfg.by_id(sid)
        if not srv or sid not in self.xui_web:
            return {"error": "сначала проверьте сервер — панель не знает, где у него 3X-UI"}
        if what == "close":
            sets, title = {"webListen": "127.0.0.1"}, "закрыть из интернета"
        elif what == "expose":
            sets, title = {"webListen": ""}, "открыть в интернет"
        elif what == "path":                    # только буквы и цифры: путь без сюрпризов в адресе
            abc = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            sets, title = {"webBasePath": "/%s/" % "".join(secrets.choice(abc) for _ in range(18))}, "свой путь"
        else:
            return {"error": "что сделать?"}
        if "xui:" + sid in self.running:
            return {"error": "уже меняю — подождите"}
        with self.busy("xui:" + sid):
            try:
                rc, out, err = self.ssh.run(srv, "python3 -", timeout=120, stdin="P = %s\n" % json.dumps({"set": sets}) + XUI_WEB_PY)
                lines = out.strip().splitlines()
                r = json.loads(lines[-1]) if lines else {"ok": False, "msg": (err.strip().splitlines() or ["код %s" % rc])[-1][:200]}
            except (CheckError, ValueError) as e:
                r = {"ok": False, "msg": str(e)}
        self.note("ok" if r.get("ok") else "bad", "%s: веб-панель 3X-UI (%s) — %s" % (srv["name"], title, r.get("msg")))
        self.check_server(sid)
        return r

    def acme_open(self, sid):
        """Открыть в ufw порт 80 для продления сертификата Let's Encrypt (acme.sh standalone) и, если продление
        уже пора, сразу продлить. Только по кнопке; больше ничего не меняет."""
        srv = self.cfg.by_id(sid)
        if not srv:
            return {"error": "нет такого сервера"}
        if "acme:" + sid in self.running:
            return {"error": "уже делаю — подождите"}
        with self.busy("acme:" + sid):
            try:
                rc, out, err = self.ssh.run(srv, "bash -s", stdin=ACME80_SH, timeout=150)
                lines = out.strip().splitlines()
                r = json.loads(lines[-1]) if lines and lines[-1].startswith("{") else \
                    {"ok": False, "msg": (err.strip().splitlines() or ["код %s" % rc])[-1][:200]}
            except (CheckError, ValueError) as e:
                r = {"ok": False, "msg": str(e)}
        self.note("ok" if r.get("ok") else "bad", "%s: порт 80 для продления сертификата — %s" % (srv["name"], r.get("msg")))
        self.check_server(sid)
        with self.lock:
            self.fw.pop(sid, None)              # план фаервола устарел
        return r

    # ------------------------------------------------------------ AmneziaWG: все туннели наглядно (только чтение)
    AWG_MUST = ("S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "HeaderProtectionKey")   # должны совпадать на обоих концах

    def awg_view(self):
        """probe MODE "awg" на всех серверах (параллельно): настройки туннелей без секретов + живое состояние;
        дальше — какой туннель входа к какому выходу и совпадают ли у концов параметры маскировки."""
        servers = [s for s in self.cfg.servers if self.cfg.get_pw(s["id"])]

        def one(s):
            try:
                rc, out, err = self.ssh.run(s, "python3 -", stdin='MODE = "awg"\n' + PROBE, timeout=40)
                if rc != 0 or not out.strip():
                    raise CheckError((err.strip().splitlines() or ["код %s" % rc])[-1][:200])
                return s["id"], json.loads(out.strip().splitlines()[-1])["awg"]
            except Exception as e:  # noqa: BLE001
                return s["id"], {"error": str(e)[:200]}
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            got = dict(ex.map(one, servers))
        byhost = {}
        for s in servers:
            byhost.setdefault(s["host"], s)
        res = []
        for s in self.cfg.servers:
            r = got.get(s["id"]) or {"error": "нет сохранённого пароля"}
            ifs = [i for i in r.get("ifaces") or [] if (i["name"].startswith("wg") if s["role"] == "entry" else i["name"].startswith("awg"))]
            res.append({"id": s["id"], "name": s["name"], "role": s["role"], "host": s["host"], "error": r.get("error"),
                        "sw": r.get("sw"), "ifaces": ifs})
        ip_of = lambda a: (a or "").split("/")[0].split(",")[0].strip()
        servers_if = {x["id"]: x for x in res}
        for x in res:                            # входы: туннель → выход, сверка параметров с его awg0
            if x["role"] != "entry":
                continue
            for i in x["ifaces"]:
                ep = next((p["params"].get("Endpoint", "") for p in i["peers"] if p["params"].get("Endpoint")), "")
                host = ep.rsplit(":", 1)[0].strip("[]")
                ex_ = byhost.get(host)
                i["exit"] = ex_ and {"id": ex_["id"], "name": ex_["name"]}
                srv_if = None
                if ex_:
                    port = ep.rsplit(":", 1)[-1]
                    cands = (servers_if.get(ex_["id"]) or {}).get("ifaces") or []
                    srv_if = next((c for c in cands if str(c["iface"].get("ListenPort") or c.get("port")) == port), cands[0] if cands else None)
                if srv_if:
                    a, b = i["iface"], srv_if["iface"]
                    i["diff"] = [k for k in self.AWG_MUST if (k in a or k in b) and a.get(k) != b.get(k)]
                    i["peer_if"] = srv_if["name"]
                    for pr in srv_if["peers"]:          # у выхода: этот пир — наш вход
                        if ip_of(pr["params"].get("AllowedIPs")) == ip_of(i["iface"].get("Address")):
                            pr["entry"] = {"id": x["id"], "name": x["name"], "iface": i["name"]}
        return {"at": now(), "servers": res}

    def check_fw(self, sid):
        """Фаервол, шаг 1: что слушает сервер и что останется открытым. Ничего не меняет."""
        import fw
        srv = self.cfg.by_id(sid)
        if not srv:
            return
        with self.busy("fw:" + sid):
            try:
                rc, out, err = self.ssh.run(srv, "python3 -", stdin='MODE = "fw"\n' + PROBE, timeout=70)
                if rc != 0 or not out.strip():
                    raise CheckError("проверочный скрипт: %s" % (err.strip().splitlines() or ["код %s" % rc])[-1][:200])
                r = {"at": now(), "ok": True, "plan": fw.plan(srv, json.loads(out)["fw"])}
            except (CheckError, ValueError, KeyError) as e:
                r = {"at": now(), "ok": False, "error": str(e)}
            with self.lock:
                self.fw[sid] = r

    def _fw_run(self, srv, P, timeout=120):
        import fw
        rc, out, err = self.ssh.run(srv, "python3 -", stdin="P = %s\n" % json.dumps(P) + fw.FW_PY, timeout=timeout)
        lines = out.strip().splitlines()
        if not lines:
            raise CheckError((err.strip().splitlines() or ["код %s" % rc])[-1][:300])
        return json.loads(lines[-1])

    def _fw_channels(self, sid):
        """Какие каналы зависят от этого сервера: на входе — все его каналы, на выходе — каналы входов через него."""
        out = []
        for e in self.cfg.servers:
            if e["role"] != "entry":
                continue
            for c in self.channels.get(e["id"], []):
                if e["id"] == sid or c.get("exit_id") == sid:
                    out.append((e["id"], c["key"]))
        return out

    def _fw_probe(self, srv, chans):
        """Сейчас: SSH заново, каналы, порты входа с этого компьютера. → (ssh_ok, {канал: ok}, {порт: ok})"""
        self.ssh.drop(srv["id"])
        try:
            rc, _, _ = self.ssh.run(srv, "true", timeout=20)
            ssh_ok = rc == 0
        except CheckError:
            ssh_ok = False
        futs = [self.leaf.submit(self.check_channel, e, k) for e, k in chans]
        cf.wait(futs, timeout=90)
        ch = {(e, k): (self.results.get("%s:%s" % (e, k)) or {}).get("status") in ("ok", "warn") for e, k in chans}
        ports = {}
        if srv["role"] == "entry":
            self.check_server(srv["id"])
            for s, port, label in self.reach_targets():
                if s["id"] == srv["id"]:
                    try:
                        socket.create_connection((s["host"], port), timeout=6).close()
                        ports[(port, label)] = True
                    except OSError:
                        ports[(port, label)] = False
        return ssh_ok, ch, ports

    def fw_enable(self, sid):
        """Фаервол, шаг 2: включить ufw по плану, проверить снаружи, при сбое — сразу выключить. На сервере — «ремень»:
        через 5 минут ufw выключится сам, если панель не подтвердит (например, потеряла связь)."""
        import fw
        srv = self.cfg.by_id(sid)
        job = {"at": now(), "do": "enable", "steps": [], "ok": None, "done": False}
        self.fwjob[sid] = job

        def step(level, text):
            job["steps"].append([level, text])

        def finish(ok, text):
            step("ok" if ok else "bad", text)
            job.update(ok=ok, done=True)
            self.note("ok" if ok else "bad", "%s: фаервол — %s" % (srv["name"], text))

        with self.busy("fwon:" + sid):
            step("info", "проверяю заново, что слушает сервер")
            self.check_fw(sid)
            r = self.fw.get(sid) or {}
            if not r.get("ok"):
                return finish(False, "проверка не прошла: %s" % r.get("error"))
            plan = r["plan"]
            if plan["state"] == "on":
                return finish(False, "ufw уже включён — ничего не менял")
            cmds = [c for c in plan["cmds"] if fw.CMD_RE.match(c)]
            if len(cmds) != len(plan["cmds"]) or not any(c.startswith("ufw allow %d/tcp" % int(srv.get("port") or 22)) for c in cmds):
                return finish(False, "в плане нет SSH или странная команда — не включаю")
            chans = self._fw_channels(sid)
            step("info", "замеряю, как всё работает сейчас (%d каналов)" % len(chans))
            ssh0, ch0, ports0 = self._fw_probe(srv, chans)
            try:
                step("info", "включаю ufw (если нужно — ставлю); «ремень»: сам выключится через 5 минут")
                res = self._fw_run(srv, {"do": "enable", "cmds": cmds, "undo_s": 300}, timeout=700)
            except CheckError as e:
                return finish(False, "не дошло до сервера: %s — если ufw успел включиться, он выключится сам через 5 минут" % e)
            if not res.get("ok"):
                return finish(False, res.get("msg") or "не вышло")
            job["undo_at"] = now() + 300
            step("info", "ufw включён — проверяю снаружи: SSH, каналы, порты")
            time.sleep(3)
            ssh1, ch1, ports1 = self._fw_probe(srv, chans)
            broke = []
            if not ssh1:
                broke.append("SSH не пускает")
            for k, was in ch0.items():
                if was and not ch1.get(k):
                    e = self.cfg.by_id(k[0]) or {"name": k[0]}
                    c = next((x for x in self.channels.get(k[0], []) if x["key"] == k[1]), {})
                    broke.append("канал %s → %s %s" % (e["name"], c.get("kind", ""), self._exit_label(c).get("exit", c.get("exit", "")) if c else k[1]))
            for k, was in ports0.items():
                if was and not ports1.get(k):
                    broke.append("порт %s (%s) не открывается с этого компьютера" % k)
            if broke:
                step("bad", "сломалось: " + "; ".join(broke))
                try:
                    self._fw_run(srv, {"do": "disable"})
                    job["undo_at"] = None
                    return finish(False, "выключил ufw обратно — всё как было")
                except CheckError:
                    return finish(False, "до сервера не достучаться — ufw выключится сам через 5 минут")
            try:
                self._fw_run(srv, {"do": "confirm"})
            except CheckError as e:
                return finish(False, "не смог подтвердить (%s) — ufw выключится сам через 5 минут" % e)
            job["undo_at"] = None
            ok_ch = sum(1 for v in ch1.values() if v)
            finish(True, "включён: SSH работает, каналов в порядке %d из %d%s. «Ремень» снят — ufw остаётся включённым "
                         "насовсем, и после перезагрузки тоже" % (ok_ch, len(ch1), ", порты входа открываются" if ports1 else ""))
            self.check_fw(sid)

    def fw_disable(self, sid):
        srv = self.cfg.by_id(sid)
        job = {"at": now(), "do": "disable", "steps": [["info", "выключаю ufw"]], "ok": None, "done": False}
        self.fwjob[sid] = job
        with self.busy("fwon:" + sid):
            try:
                r = self._fw_run(srv, {"do": "disable"})
                ok, text = r.get("ok"), r.get("msg")
            except CheckError as e:
                ok, text = False, str(e)
            job["steps"].append(["ok" if ok else "bad", text])
            job.update(ok=ok, done=True)
            self.note("ok" if ok else "bad", "%s: фаервол — %s" % (srv["name"], text))
            self.check_fw(sid)

    # --- «Сети госорганов» на входах (govblock.py): не пускать новые подключения из их подсетей

    def gov_fetch(self):
        """Скачать список с GitHub этим компьютером и проверить. Не вышло — остаётся прежний."""
        import govblock
        import urllib.request

        def get(url):
            if os.environ.get("VPN_DASH_STAND") == "1":     # стенд: готовый список (сеть стенда до GitHub не всегда достаёт)
                return Path("/etc/testbed-govblock-%s.txt" % ("v6" if url.endswith("v6.txt") else "v4")).read_text()
            rq = urllib.request.Request(url, headers={"User-Agent": "vpn-dash"})
            with urllib.request.urlopen(rq, timeout=30) as f:
                return f.read(5_000_000).decode("utf-8", "replace")
        self.gov["tried"] = now()
        try:
            g = govblock.fetch(get, local_ok=os.environ.get("VPN_DASH_STAND") == "1")
        except Exception as e:  # noqa: BLE001
            self.gov["error"] = str(e)[:200]
            self._gov_save()
            raise CheckError("список сетей госорганов не скачался: %s" % self.gov["error"])
        g["tried"] = g["at"]
        with self.lock:
            self.gov = g
        self._gov_save()
        return g

    def _gov_save(self):
        try:
            tmp = GOV_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.gov), encoding="utf-8")
            os.replace(tmp, GOV_FILE)
        except OSError:
            pass

    def gov_view(self):
        g = self.gov
        return {"at": g.get("at"), "sha": g.get("sha"), "n4": len(g.get("v4") or []), "n6": len(g.get("v6") or []),
                "error": g.get("error") if (g.get("tried") or 0) > (g.get("at") or 0) else None}

    def _gov_run(self, srv, P, timeout=120):
        import govblock
        rc, out, err = self.ssh.run(srv, "python3 -", stdin="P = %s\n" % json.dumps(P) + govblock.GOV_PY, timeout=timeout)
        lines = out.strip().splitlines()
        if not lines:
            raise CheckError((err.strip().splitlines() or ["код %s" % rc])[-1][:300])
        return json.loads(lines[-1])

    def gov_apply(self, sid, auto=False):
        """Включить (или обновить список) на входе: свои адреса — в исключения, замер до и после, «ремень» на 5 минут."""
        import govblock
        srv = self.cfg.by_id(sid)
        job = {"at": now(), "do": "update" if auto else "enable", "steps": [], "ok": None, "done": False}
        self.govjob[sid] = job

        def step(level, text):
            job["steps"].append([level, text])

        def finish(ok, text):
            step("ok" if ok else "bad", text)
            job.update(ok=ok, done=True)
            self.note("ok" if ok else "bad", "%s: сети госорганов — %s" % (srv["name"], text))
            return ok

        with self.busy("govon:" + sid):
            g = self.gov
            if not g.get("v4") or now() - (g.get("at") or 0) > 24 * 3600:
                step("info", "скачиваю список с GitHub")
                try:
                    g = self.gov_fetch()
                except CheckError as e:
                    if not g.get("v4"):
                        return finish(False, str(e))
                    step("warn", "%s — беру прежний от %s" % (e, time.strftime("%d.%m", time.localtime(g["at"]))))
            x = ((self.status.get(sid) or {}).get("data") or {}).get("entry") or {}
            ports = [ib["port"] for ib in ((x.get("xui") or {}).get("inbounds") or []) if ib.get("enable")]
            try:
                who = self._gov_run(srv, {"do": "who", "ports": ports}, timeout=60)
            except CheckError as e:
                return finish(False, "сервер не ответил: %s" % e)
            nets = g["v4"] + g["v6"]
            keep = govblock.keep_list(self.cfg.settings.get("gov_keep"))
            mine = [a for a in [who.get("me")] if a]
            for a, n in govblock.hits(nets, mine):
                step("warn", "адрес этого компьютера %s есть в списке (сеть %s) — оставляю его открытым" % (a, n))
            peers = govblock.hits(nets, who.get("peers") or [])
            for a, n in peers:
                step("warn", "к входу сейчас подключён %s из сети %s — оставляю открытым (если это не ваш, уберите в «Настройках»)" % (a, n))
            keep = sorted(set(keep + [a for a, _ in govblock.hits(nets, mine)] + [a for a, _ in peers]))
            chans = self._fw_channels(sid)
            step("info", "замеряю, как всё работает сейчас: SSH, %d каналов, порты входа с этого компьютера" % len(chans))
            ssh0, ch0, ports0 = self._fw_probe(srv, chans)
            meta = {"date": time.strftime("%Y-%m-%d", time.localtime(g["at"])), "sha": g["sha"], "n4": len(g["v4"]),
                    "n6": len(g["v6"]), "keep": keep, "at": now()}
            try:
                step("info", "ставлю таблицу nftables: %d сетей IPv4, %d IPv6; «ремень» — всё вернётся само через 5 минут"
                     % (len(g["v4"]), len(g["v6"])))
                res = self._gov_run(srv, {"do": "apply", "nft": govblock.nft_script(g["v4"], g["v6"], keep), "meta": meta,
                                          "undo_s": 300}, timeout=600)
            except CheckError as e:
                return finish(False, "не дошло до сервера: %s — если успело включиться, через 5 минут вернётся само" % e)
            if not res.get("ok"):
                return finish(False, res.get("msg") or "не вышло")
            job["undo_at"] = now() + 300
            step("info", "включено — проверяю снова")
            time.sleep(2)
            ssh1, ch1, ports1 = self._fw_probe(srv, chans)
            broke = ([] if ssh1 or not ssh0 else ["SSH не пускает"]) + \
                ["канал %s" % k[1] for k, was in ch0.items() if was and not ch1.get(k)] + \
                ["порт %s (%s) не открывается с этого компьютера" % k for k, was in ports0.items() if was and not ports1.get(k)]
            if broke:
                step("bad", "сломалось: " + "; ".join(broke))
                try:
                    self._gov_run(srv, {"do": "undo"})
                    job["undo_at"] = None
                    return finish(False, "вернул как было")
                except CheckError:
                    return finish(False, "до сервера не достучаться — через 5 минут вернётся само")
            try:
                self._gov_run(srv, {"do": "confirm"})
            except CheckError as e:
                return finish(False, "не смог подтвердить (%s) — через 5 минут вернётся как было" % e)
            job["undo_at"] = None
            self.check_server(sid)
            return finish(True, ("список обновлён (от %s)" if auto else "включено: список от %s, всё работает как раньше")
                          % time.strftime("%d.%m", time.localtime(g["at"])))

    def gov_off(self, sid):
        srv = self.cfg.by_id(sid)
        job = {"at": now(), "do": "off", "steps": [["info", "убираю таблицу nftables"]], "ok": None, "done": False}
        self.govjob[sid] = job
        with self.busy("govon:" + sid):
            try:
                r = self._gov_run(srv, {"do": "off"})
                ok, text = r.get("ok"), r.get("msg")
            except CheckError as e:
                ok, text = False, str(e)
            job["steps"].append(["ok" if ok else "bad", text])
            job.update(ok=ok, done=True)
            self.note("ok" if ok else "bad", "%s: сети госорганов — %s" % (srv["name"], text))
            self.check_server(sid)

    def gov_auto(self):
        """Раз в gov_hours: свежий список; где включено и список поменялся — обновить (с тем же замером и «ремнём»)."""
        with self.busy("govauto"):
            old = self.gov.get("sha")
            try:
                g = self.gov_fetch()
            except CheckError as e:
                self.note("warn", str(e))
                return
            for s in self.cfg.servers:
                gi = ((self.status.get(s["id"]) or {}).get("data") or {}).get("gov") or {}
                if s["role"] != "entry" or not gi.get("on") or not self.cfg.get_pw(s["id"]):
                    continue
                if (gi.get("meta") or {}).get("sha") == g["sha"] and old == g["sha"]:
                    continue
                if any(k.startswith("govon:") or k.startswith("fwon:") for k in self.running):
                    continue
                try:
                    self.gov_apply(s["id"], auto=True)
                except Exception as e:  # noqa: BLE001
                    self.note("bad", "%s: обновление списка сетей госорганов — ошибка панели: %s" % (s["name"], e))

    def xui_dups(self):
        """У каких серверов путь 3X-UI такой же, как у сервера выше в списке (входы из одного бэкапа)."""
        seen, out = {}, {}
        for s in self.cfg.servers:
            w = self.xui_web.get(s["id"])
            if not w:
                continue
            if w["path"] in seen:
                out[s["id"]] = seen[w["path"]]
            else:
                seen[w["path"]] = s["name"]
        return out

    def remove_server(self, sid):
        """Убрать сервер из панели (вместе с паролем и результатами). На самом сервере ничего не меняется."""
        with self.lock:
            self.cfg.data["servers"] = [s for s in self.cfg.servers if s["id"] != sid]
            self.cfg.save()
            self.status.pop(sid, None)
            self.channels.pop(sid, None)
            self.dc.pop(sid, None)
            for k in [k for k in self.results if k.startswith(sid + ":")]:
                self.results.pop(k)
            self.reach.clear()
        self.cfg.set_pw(sid, "")
        self.ssh.drop(sid)

    def upgrade_done(self, job):
        """Итог обновления пакетов — в журнал проверок."""
        p, r = job.params, job.result or {}
        name = p.get("name") or p.get("sid")
        if job.status != "ok":
            self.note("bad", "%s: обновление не удалось — %s" % (name, job.error))
        elif p.get("only_reboot"):
            self.note("ok", "%s: перезагружен" % name)
        else:
            self.note("ok", "%s: обновления установлены (пакетов: %s)%s%s" % (
                name, r.get("installed", "?"), ", перезагружен" if r.get("rebooted") else "",
                ", нужна перезагрузка" if r.get("reboot_required") else ""))

    def log_tail(self, n):
        """Последние n записей журнала из файла, новые сверху (для «Показать ещё»)."""
        out = []
        try:
            lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
        except OSError:
            lines = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out[::-1]

    def note(self, level, text):
        e = {"t": hhmm(), "ts": now(), "level": level, "text": text}
        with self.lock:
            self.log.append(e)
            self.log = self.log[-300:]
        try:
            with LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def busy(self, key):
        class _B:
            def __enter__(s):
                with self.lock:
                    self.running.add(key)

            def __exit__(s, *a):
                with self.lock:
                    self.running.discard(key)
        return _B()

    # --- состояние сервера

    def check_server(self, sid):
        srv = self.cfg.by_id(sid)
        if not srv:
            return
        if "srv:" + sid in self.running:      # уже проверяется — дождёмся этой проверки
            for _ in range(600):
                time.sleep(0.2)
                if "srv:" + sid not in self.running:
                    return
            return
        with self.busy("srv:" + sid):
            try:
                # число обновлений считается тяжело — раз в 6 часов (или сразу после установки), в остальное время
                # показываем прошлое
                pc = self.pkg_count.get(sid) or {}
                want = now() - pc.get("at", 0) > 6 * 3600
                rc, out, err = self.ssh.run(srv, "python3 -", stdin='MODE = "status"\nPKG_COUNT = %s\n' % want + PROBE, timeout=90)
                if rc != 0 or not out.strip():
                    raise CheckError("проверочный скрипт: %s" % (
                        "не уложился в 80 с — сервер перегружен?" if rc == 3 else (err.strip().splitlines() or ["код %s" % rc])[-1][:200]))
                data = json.loads(out)
                sysd = data.get("system") or {}
                if sysd.get("updates") is not None:
                    self.pkg_count[sid] = {"at": now(), "n": sysd["updates"]}
                else:
                    if want:                    # не посчиталось (мало памяти, долго) — следующая попытка через 6 ч
                        self.pkg_count[sid] = {"at": now(), "n": pc.get("n")}
                    sysd["updates"] = pc.get("n")
                w = data.get("web")
                if w and not w.get("error"):
                    self.xui_web[sid] = {"port": w["port"], "path": w.pop("path"), "https": w["https"],
                                         "domain": w.pop("domain", ""), "listen": w["listen"]}
                    w["openable"] = xui_path_ok(self.xui_web[sid]["path"])
                else:
                    self.xui_web.pop(sid, None)
                st = {"at": now(), "ok": True, "data": data}
                if srv["role"] == "entry":
                    self._build_channels(srv, data)
            except CheckError as e:
                st = {"at": now(), "ok": False, "error": str(e)}
            except Exception as e:
                st = {"at": now(), "ok": False, "error": "%s: %s" % (type(e).__name__, e)}
            with self.lock:
                old = self.status.get(sid)
                self.status[sid] = st
            # «нет пароля» — не сбой связи, в журнал и историю не пишем
            nopw = lambda x: str((x or {}).get("error", "")).startswith("не задан пароль")
            if not nopw(st):
                self.hist.add("srv", sid, "ok" if st["ok"] else "bad")
            if not st["ok"] and not nopw(st) and (old is None or old["ok"] or nopw(old)):
                self.note("bad", "%s: нет связи — %s" % (srv["name"], st["error"]))
            elif st["ok"] and old is not None and not old["ok"] and not nopw(old):
                self.note("ok", "%s: снова на связи" % srv["name"])

    def _build_channels(self, srv, data):
        e = data.get("entry") or {}
        awg = {a["iface"]: a for a in e.get("awg") or []}
        chain = ((e.get("xui") or {}).get("chain")) or []
        chans, used = [], set()

        def exit_of(host):
            x = self.cfg.by_host(host)
            return (x["id"], x["name"], x.get("cc", "")) if x else (None, host or "?", "")

        def add(ref, n, tag=None):
            a = awg.get(ref)
            if not a:
                return
            xid, xname, cc = exit_of(a["host"])
            chans.append({"key": "awg:" + ref, "n": n, "kind": "AWG", "exit_id": xid, "exit": xname, "cc": cc, "tag": tag,
                          "host": a["host"], "via": "%s · %s" % (ref, a.get("address", "")),
                          "iface": ref, "handshake_age": a.get("handshake_age"), "up": a.get("up")})
            used.add(ref)

        for i, c in enumerate(chain, 1):
            if c["kind"] == "AWG":
                add(c["iface"], i, c.get("tag"))
        for a in awg:                      # туннели, которых нет в цепочке
            if a not in used:
                add(a, None)
        with self.lock:
            self.channels[srv["id"]] = chans

    # --- тест канала

    def check_channel(self, sid, key):
        srv = self.cfg.by_id(sid)
        ch = next((c for c in self.channels.get(sid, []) if c["key"] == key), None)
        if not srv or not ch:
            return
        rk = "%s:%s" % (sid, key)
        with self.busy("ch:" + rk):
            st = self.cfg.settings
            url = st.get("check_url") or "https://ifconfig.me"
            tmo = int(st.get("channel_timeout") or 15)
            cmd = "curl -4 -s -m %d --interface %s -w '\\n%%{time_total}' '%s'" % (tmo, ch["iface"], url)
            res = {"at": now()}
            try:
                rc, out, err = self.ssh.run(srv, cmd, timeout=30)
                lines = out.strip().splitlines()
                ip = lines[0].strip() if len(lines) >= 2 else ""
                secs = float(lines[-1]) if lines and re.match(r"^[\d.]+$", lines[-1].strip()) else None
                if rc != 0 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    res.update(status="bad", error="нет ответа через канал" + (" (curl %d)" % rc if rc else ""))
                elif ch.get("host") and ip != ch["host"]:
                    res.update(status="bad", ip=ip, ms=secs, error="вышел не через тот сервер: %s" % ip)
                else:
                    res.update(status="warn" if secs and secs >= float(st.get("slow_s") or 2) else "ok", ip=ip, ms=secs)
                self.hist.add("ch", rk, res["status"], res.get("ms"))
            except CheckError as e:
                res.update(status="bad", error=str(e))
            prev = self.results.get(rk, {}).get("status")
            with self.lock:
                self.results[rk] = res
            if prev and prev != res["status"]:
                name = "%s → %s %s" % (srv["name"], ch["kind"], self._exit_label(ch).get("exit", ch["exit"]))
                if res["status"] == "ok":
                    self.note("ok", "%s: снова в норме (%.2f с)" % (name, res.get("ms") or 0))
                elif res["status"] == "warn":
                    self.note("warn", "%s: медленно, %.2f с" % (name, res.get("ms") or 0))
                else:
                    self.note("bad", "%s: %s" % (name, res.get("error")))

    def check_entry_channels(self, sid):
        futs = [self.leaf.submit(self.check_channel, sid, c["key"]) for c in self.channels.get(sid, [])]
        cf.wait(futs)

    # --- раздел «Zapret»

    def zapret_api(self, body):
        a, z = str(body.get("action") or ""), self.zapret
        try:
            if a == "save":
                return {"ok": True, "id": z.save_target(body)}
            if a == "delete":
                z.del_target(str(body.get("id") or ""))
                return {"ok": True}
            if a == "auto":
                t = z.targets().get(str(body.get("id") or ""))
                if not t:
                    raise ValueError("такой цели нет")
                with self.lock:
                    t["auto"] = bool(body.get("on"))
                    self.cfg.save()
                return {"ok": True}
            if a == "geosite":
                return dict(z.geosite(str(body.get("entry") or ""), body.get("domain")), ok=True)
            srv = self.cfg.by_id(str(body.get("entry") or ""))
            if not srv:
                raise ValueError("нет такого входа")
            if a == "direct":
                tid, on = str(body.get("id") or ""), bool(body.get("on"))
                st = ((z.targets().get(tid) or {}).get("ents") or {}).get(srv["id"]) or {}
                if on and not st.get("zap"):
                    raise ValueError("сначала включите zapret для этой цели на этом входе")
                if "bypass" in self.running:
                    raise ValueError("сейчас меняются обходы — подождите минуту")
                with self.busy("bypass"):
                    r = z.direct(tid, srv["id"], on)
                if r.get("ok"):
                    self.note("ok", "Zapret %s на %s: %s" % (z.targets()[tid]["name"], srv["name"],
                                                              "напрямую с входа" if on else "снова через выходы"))
                return r
            if a == "stop":                     # остановить подбор и взять найденное (или взять из журнала прерванного)
                tid = str(body.get("id") or "")
                if tid not in z.targets():
                    raise ValueError("такой цели нет")
                res = z.collect(tid, srv["id"], stop=True)
                if res is None:
                    raise ValueError("в журнале подбора на %s пока нет ни одной сработавшей стратегии" % srv["name"])
                self.note("ok", "Zapret %s на %s: подбор остановлен, найдено стратегий: %d" % (z.targets()[tid]["name"], srv["name"], len(res["strategies"])))
                return {"ok": True, "n": len(res["strategies"])}
            if a == "verify":
                return dict(z.verify(str(body.get("id") or ""), srv["id"]), ok_=True)
            return {"ok": True, "job": self.prov.start_zapret(srv, a, str(body.get("id") or "") or None, body.get("strat"))}
        except (ValueError, CheckError, RuntimeError) as e:
            return {"error": str(e)}

    # --- консоль выхода через вход

    TUN_PY = r"""
import glob, ipaddress, json, re
host = HOST
for f in sorted(glob.glob("/etc/amnezia/amneziawg/wg*.conf")):
    t = open(f).read()
    ep = re.search(r"^\s*Endpoint\s*=\s*\[?([^\]\s]+?)\]?:\d+\s*$", t, re.M)
    a = re.search(r"^\s*Address\s*=\s*([^\s,/]+)", t, re.M)
    if ep and a and ep.group(1) == host:
        print(json.dumps({"iface": f.rsplit("/", 1)[1][:-5],
                          "peer": str(ipaddress.ip_network(a.group(1) + "/24", strict=False).network_address + 1)}))
        break
"""

    def addr_save(self):
        """«Как видят» и «соседи» переживают перезапуск панели (обновление)."""
        with self.lock:
            data = json.dumps({"geo": self.geo, "nb": self.nb, "dns": self.dns}, ensure_ascii=False)
        try:
            tmp = ADDR_FILE.with_suffix(".tmp")
            tmp.write_text(data, encoding="utf-8")
            tmp.replace(ADDR_FILE)
        except OSError:
            pass

    def ssh_route(self, srv, via):
        """Куда входу подключаться к выходу: по туннелю AWG (адрес выхода в туннеле — .1 той же сети),
        а если туннеля до этого выхода нет — по интернету с самого входа. → (вход, адрес, порт, как, туннель или None)."""
        entry = self.cfg.by_id(via)
        if not entry or entry["role"] != "entry" or entry["id"] == srv["id"]:
            raise CheckError("вход для SSH не найден — выберите другой в «Серверы и пароли»")
        port = int(srv.get("port") or 22)
        aw = ((((self.status.get(entry["id"]) or {}).get("data") or {}).get("entry") or {}).get("awg")) or []
        a = next((x for x in aw if x.get("host") == srv["host"] and x.get("address")), None)
        tun = None
        if a:
            try:
                import ipaddress
                tun = {"iface": a["iface"], "peer": str(ipaddress.ip_network(a["address"].split("/")[0] + "/24", strict=False).network_address + 1)}
            except ValueError:
                tun = None
        if not tun:                       # вход ещё не проверялся — спросим у него самого
            try:
                rc, out, _ = self.ssh.run(entry, "python3 -", stdin="HOST = %r\n" % srv["host"] + self.TUN_PY, timeout=20)
                tun = json.loads(out) if out.strip() else None
            except (CheckError, ValueError):
                tun = None
        if tun:
            return entry, tun["peer"], port, "туннель " + tun["iface"], tun["iface"]
        return entry, srv["host"], port, "по интернету с входа", None

    # --- Telegram DC с выхода

    def check_dc(self, sid):
        srv = self.cfg.by_id(sid)
        if not srv:
            return
        with self.busy("dc:" + sid):
            try:
                dcs = parse_dc(self.cfg.settings.get("tg_dc")) or parse_dc(TG_DC_DEFAULT)
                rc, out, err = self.ssh.run(srv, "python3 -", stdin='MODE = "dc"\nTG_DC_OVERRIDE = %r\n' % dcs + PROBE, timeout=40)
                cells = json.loads(out)["dc"]
                r = {"at": now(), "cells": cells}
                for c in cells:
                    self.hist.add("dc", "%s:%s" % (sid, c["name"]), "ok" if c["ok"] else "bad", c.get("ms"))
            except Exception as e:
                r = {"at": now(), "error": str(e)}
            prev = self.dc.get(sid, {}).get("cells")
            with self.lock:
                self.dc[sid] = r
            if prev and r.get("cells"):
                was = {c["name"] for c in prev if c["ok"]}
                for c in r["cells"]:
                    if c["name"] in was and not c["ok"]:
                        self.note("bad", "%s: Telegram %s стал недоступен" % (srv["name"], c["name"]))
                    if c["name"] not in was and c["ok"]:
                        self.note("ok", "%s: Telegram %s снова доступен" % (srv["name"], c["name"]))

    # --- доступность входов с этого компьютера

    def reach_targets(self):
        out = []
        for s in self.cfg.servers:
            if s["role"] != "entry":
                continue
            x = ((self.status.get(s["id"], {}).get("data") or {}).get("entry") or {}).get("xui") or {}
            for ib in x.get("inbounds", []):
                if ib.get("enable"):
                    out.append((s, ib["port"], "VLESS · %s" % (ib.get("remark") or ib["port"])))
            if x.get("sub"):
                out.append((s, x["sub"]["port"], "подписка"))
            out.append((s, int(s.get("port") or 22), "SSH"))
        return out

    def check_reach(self):
        with self.busy("reach"):
            def one(t):
                s, port, label = t
                k = "%s:%s" % (s["id"], port)
                t0 = now()
                try:
                    socket.create_connection((s["host"], port), timeout=6).close()
                    r = {"ok": True, "ms": round((now() - t0) * 1000), "at": now()}
                except OSError as e:
                    r = {"ok": False, "error": str(e)[:80], "at": now()}
                self.hist.add("reach", k, "ok" if r["ok"] else "bad", r.get("ms"))
                prev = self.reach.get(k, {}).get("ok")
                with self.lock:
                    self.reach[k] = dict(r, label=label, entry=s["id"], port=port)
                if prev is True and not r["ok"]:
                    self.note("bad", "%s: порт %s (%s) не открывается с этого компьютера" % (s["name"], port, label))
                if prev is False and r["ok"]:
                    self.note("ok", "%s: порт %s (%s) снова открывается" % (s["name"], port, label))
            list(self.leaf.map(one, self.reach_targets()))

    # --- сравнение входов

    def drift_main(self):
        return next((s for s in self.cfg.servers if s["role"] == "entry"), None)

    def check_drift(self):
        """Сверка резервов: основной вход (первый в списке) против каждого другого входа."""
        entries = [s for s in self.cfg.servers if s["role"] == "entry"]
        if len(entries) < 2:
            with self.lock:
                self.drift = None
            return
        with self.busy("drift"):
            def snap(s):
                try:
                    rc, out, err = self.ssh.run(s, "python3 -", stdin='MODE = "config"\n' + PROBE, timeout=60)
                    if rc != 0 or not out.strip():
                        raise CheckError((err.strip().splitlines() or ["код %s" % rc])[-1][:200])
                    return normalize_cfg(json.loads(out)["config"]), None
                except Exception as e:
                    return None, str(e)
            snaps = dict(zip([s["id"] for s in entries], self.leaf.map(snap, entries)))
            main = entries[0]
            ma, merr = snaps[main["id"]]
            res = []
            for s in entries[1:]:
                sb, err = snaps[s["id"]]
                if merr or err:
                    res.append({"id": s["id"], "error": ("%s: %s" % (main["name"], merr)) if merr else err})
                    continue
                diffs = diff_configs(ma, sb)
                for d in diffs:
                    d["title"] = describe(d)
                res.append({"id": s["id"], "diffs": diffs})
            r = {"at": now(), "main": main["id"], "res": res}
            prev = self.drift if self.drift and self.drift.get("main") == main["id"] else None
            with self.lock:
                self.drift = r
            pn = {x["id"]: self.drift_open(x) for x in (prev or {}).get("res", [])}
            for x in res:
                srv = self.cfg.by_id(x["id"]) or {"name": x["id"]}
                n, was = self.drift_open(x), pn.get(x["id"])
                if n is None or n == was or (was is None and n == 0):
                    continue
                self.note("ok" if n == 0 else "warn", "%s и %s: %s" % (
                    main["name"], srv["name"], "настройки совпадают" if n == 0 else "отличий в настройках: %d" % n))

    def drift_ok_set(self):
        return {(o.get("p"), o.get("a"), o.get("b")) for o in self.cfg.data.get("drift_ok", [])}

    def drift_open(self, x):
        """Сколько отличий у резерва, не считая принятых как норма (None — сверить не удалось)."""
        if "diffs" not in x:
            return None
        ok = self.drift_ok_set()
        return sum(1 for d in x["diffs"] if (d["path"], str(d["a"]), str(d["b"])) not in ok)

    def drift_view(self):
        dr = self.drift
        if not dr:
            return None
        ok = self.drift_ok_set()
        res = []
        for x in dr["res"]:
            x = dict(x)
            if "diffs" in x:
                x["diffs"] = [dict(d, ok=(d["path"], str(d["a"]), str(d["b"])) in ok) for d in x["diffs"]]
            res.append(x)
        return {"at": dr["at"], "main": dr["main"], "res": res}

    # --- бэкап

    def backups_list(self):
        files = sorted(BACKUP_DIR.glob("vpn-backup-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        return [{"name": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime} for p in files]

    def request_restart(self):
        """Перезапуск после обновления — только в режиме со значком (у окна консоли так не выйдет)."""
        if not self.on_restart:
            return False
        self.restart_args = ["--tray", "--no-browser"]
        self.on_restart()
        return True

    def backup_target(self):
        """Сервер для бэкапа: из настроек, а если не выбран — первый вход."""
        srv = self.cfg.by_id(self.cfg.settings.get("backup_server") or "")
        return srv or next((s for s in self.cfg.servers if s["role"] == "entry"), None)

    def do_backup(self, sid=None):
        srv = self.cfg.by_id(sid) if sid else self.backup_target()
        if not srv:
            return
        if "backup" in self.running:
            return
        with self.busy("backup"):
            t0 = now()
            remote_script = "/root/.vpn-dash-backup.sh"
            try:
                if not BACKUP_SCRIPT.exists():
                    raise CheckError("нет vpn-backup.sh рядом с панелью")
                c = self.ssh.client(srv)
                sftp = c.open_sftp()
                try:
                    sftp.put(str(BACKUP_SCRIPT), remote_script)
                    rc, out, err = self.ssh.run(srv, "bash %s 2>&1; rm -f %s" % (remote_script, remote_script), timeout=600)
                    m = re.search(r"Готово:\s*(/root/vpn-backup-[^\s]+\.tar\.gz)", out)
                    if rc != 0 or not m:
                        tail = [x for x in out.strip().splitlines() if x.strip()][-3:]
                        raise CheckError("скрипт бэкапа: %s" % (" / ".join(tail) or "код %s" % rc))
                    remote = m.group(1)
                    name = os.path.basename(remote)
                    local = BACKUP_DIR / name
                    tmp = local.with_suffix(".part")
                    sftp.get(remote, str(tmp))
                    rsize = sftp.stat(remote).st_size
                    if tmp.stat().st_size != rsize:
                        tmp.unlink()
                        raise CheckError("архив скачался не полностью")
                    tmp.replace(local)
                    sftp.remove(remote)
                finally:
                    sftp.close()
                keep = max(1, int(self.cfg.settings.get("backup_keep") or 10))
                for old in self.backups_list()[keep:]:
                    try:
                        (BACKUP_DIR / old["name"]).unlink()
                    except OSError:
                        pass
                self.backup = {"at": now(), "ok": True, "file": name, "size": local.stat().st_size, "server": sid}
                sz = local.stat().st_size
                self.note("ok", "Бэкап %s: %s, %s за %.0f с" % (srv["name"], name, "%.1f МБ" % (sz / 2**20) if sz >= 2**20 else "%d КБ" % max(1, sz // 1024), now() - t0))
            except Exception as e:
                self.backup = {"at": now(), "ok": False, "error": str(e), "server": sid}
                self.note("bad", "Бэкап %s не удался: %s" % (srv["name"], e))

    def backup_due(self):
        h = float(self.cfg.settings.get("backup_hours") or 0)
        if h <= 0 or "backup" in self.running:
            return False
        if self.backup.get("at") and not self.backup.get("ok") and now() - self.backup["at"] < 3600:
            return False                           # после неудачи — повтор не чаще раза в час
        lst = self.backups_list()
        return not lst or now() - lst[0]["mtime"] >= h * 3600

    # --- всё сразу

    def check_all(self, with_dc=False):
        if "all" in self.running:              # полная проверка уже идёт
            return
        with self.busy("all"):
            t0 = now()
            ids = [s["id"] for s in self.cfg.servers]
            cf.wait([self.leaf.submit(self.check_server, i) for i in ids])
            entries = [s["id"] for s in self.cfg.servers if s["role"] == "entry" and self.status.get(s["id"], {}).get("ok")]
            jobs = [self.pool.submit(self.check_entry_channels, e) for e in entries]
            jobs.append(self.pool.submit(self.check_reach))
            if self.cfg.settings.get("drift_auto", True):
                jobs.append(self.pool.submit(self.check_drift))
            if with_dc:
                jobs += [self.leaf.submit(self.check_dc, s["id"]) for s in self.cfg.servers if s["role"] == "exit"]
            cf.wait(jobs)
            res = [self.results.get("%s:%s" % (e, c["key"]), {}) for e in entries for c in self.channels.get(e, [])]
            okc = sum(1 for r in res if r.get("status") == "ok")
            srv_ok = sum(1 for i in ids if self.status.get(i, {}).get("ok"))
            self.note("ok" if okc == len(res) and srv_ok == len(ids) else "warn",
                      "Проверка всего: серверов на связи %d из %d, каналов в норме %d из %d (%.0f с)"
                      % (srv_ok, len(ids), okc, len(res), now() - t0))

    def auto_loop(self):
        time.sleep(2)
        while True:
            st = self.cfg.settings
            has_pw = any(self.cfg.get_pw(s["id"]) for s in self.cfg.servers)
            due = now() - self.last_auto >= max(1, int(st.get("auto_minutes") or 5)) * 60
            due_dc = now() - self.last_dc >= max(5, int(st.get("dc_minutes") or 30)) * 60
            if (due or due_dc) and "all" not in self.running and has_pw:
                self.last_auto = now()
                if due_dc:
                    self.last_dc = now()
                try:
                    self.check_all(with_dc=due_dc)
                except Exception:
                    traceback.print_exc()
            if has_pw and now() - self.last_zap >= 300 and "zapmon" not in self.running:   # автовозврат zapret
                self.last_zap = now()

                def zapmon():
                    with self.busy("zapmon"):
                        self.zapret.monitor()
                self.pool.submit(zapmon)
            gh = int(st.get("gov_hours") or 0)
            if has_pw and gh and now() - (self.gov.get("tried") or 0) >= gh * 3600 and "govauto" not in self.running:
                self.pool.submit(self.gov_auto)
            bs = (self.backup_target() or {}).get("id")
            if has_pw and self.cfg.get_pw(bs or "") and self.backup_due():
                self.pool.submit(self.do_backup, bs)
            time.sleep(10)

    # --- общее состояние для значка в трее

    def overall(self):
        """(уровень, короткие строки): bad — вход недоступен или на нём не работает ни один канал;
        warn — что-то не так, но трафик идёт; ok — всё в норме; idle — данных ещё нет."""
        with self.lock:
            servers = list(self.cfg.servers)
            status = dict(self.status)
            chans = {k: list(v) for k, v in self.channels.items()}
            results = dict(self.results)
            drift, bk = self.drift, dict(self.backup)
        nopw = lambda st: str((st or {}).get("error", "")).startswith("не задан пароль")
        status = {k: v for k, v in status.items() if not nopw(v)}   # без пароля — не сбой, а «не настроено»
        if not any(status.get(s["id"]) for s in servers):
            return "idle", []
        bad, warn = [], []
        for s in servers:
            st = status.get(s["id"])
            if st and not st.get("ok"):
                (bad if s["role"] == "entry" else warn).append("%s: нет связи" % s["name"])
        for s in servers:
            if s["role"] != "entry" or not (status.get(s["id"]) or {}).get("ok"):
                continue
            rs = [(c, results.get("%s:%s" % (s["id"], c["key"]))) for c in chans.get(s["id"], [])]
            rs = [(c, r) for c, r in rs if r]
            if not rs:
                continue
            good = [c for c, r in rs if r.get("status") in ("ok", "warn")]
            if not good:
                bad.append("%s: не работает ни один канал" % s["name"])
                continue
            nbad = sum(1 for c, r in rs if r.get("status") == "bad")
            if nbad:
                warn.append("%s: каналов со сбоем %d из %d" % (s["name"], nbad, len(rs)))
        for x in (drift or {}).get("res", []):
            n = self.drift_open(x)
            if n:
                warn.append("%s отличается от основного входа: %d" % ((self.cfg.by_id(x["id"]) or {}).get("name", x["id"]), n))
        if bk.get("at") and not bk.get("ok"):
            warn.append("бэкап не удался")
        if bad:
            return "bad", bad + warn
        return ("warn", warn) if warn else ("ok", [])

    # --- снимок для страницы

    # --- качество каналов (только замеры, на серверах ничего не меняется)

    def quality_check(self, body):
        """Проверить выбранные маршруты «вход → выход» и связь с этого ПК до выбранных входов. Одна проверка за раз."""
        import quality
        tests = {k: bool((body.get("tests") or {}).get(k)) for k in ("base", "speed", "trace")}
        mb = (body.get("tests") or {}).get("mb")
        tests["mb"] = max(1, min(100, int(mb))) if isinstance(mb, (int, float)) and not isinstance(mb, bool) else 2
        ch = {"awg": True}
        routes = [r for r in body.get("routes") or [] if isinstance(r, list) and len(r) == 2]
        pcs = [str(x) for x in body.get("pc") or []]
        if not any(tests[k] for k in ("base", "speed", "trace")) or not (routes or pcs and (tests["base"] or tests["trace"])):
            raise ValueError("нечего проверять: выберите маршрут или вход и тест")
        if "quality" in self.running:
            raise ValueError("проверка качества уже идёт")
        t0 = time.time()
        by_entry = {}
        for eid, xid in routes:
            e, x = self.cfg.by_id(str(eid)), self.cfg.by_id(str(xid))
            if not e or not x or e["role"] != "entry" or x["role"] != "exit":
                raise ValueError("маршрут %s → %s не найден — обновите страницу" % (eid, xid))
            by_entry.setdefault(e["id"], []).append(x)
        res = {"at": now(), "tests": tests, "ch": ch, "routes": {}, "pc": {}, "errors": {}}

        def on_entry(eid):
            e = self.cfg.by_id(eid)
            chans = self.channels.get(eid) or []
            if not chans:
                raise CheckError("каналы входа ещё не прочитаны — подождите, пока панель проверит вход на «Обзоре», и повторите")
            targets = []
            for x in by_entry[eid]:
                awg = next((c for c in chans if c.get("exit_id") == x["id"] and c["kind"] == "AWG"), None)
                targets.append({"key": "%s>%s" % (eid, x["id"]), "host": x["host"], "sshport": int(x.get("port") or 22),
                                "iface": awg["iface"] if awg else None})
            if not self.cfg.get_pw(eid):
                raise CheckError("не задан пароль")
            pre = "MODE = \"quality\"\nQ_TARGETS = %r\nQ_TESTS = %r\nQ_CH = %r\n" % (targets, tests, ch)
            rc, out, err = self.ssh.run(e, "python3 -", stdin=pre + QUALITY_SRC + "\n" + PROBE, timeout=305)
            if rc != 0 or not out.strip():
                raise CheckError("не уложилась в 290 с" if rc == 3 else (err.strip().splitlines() or ["код %s" % rc])[-1][:200])
            return json.loads(out)["quality"]

        def on_pc(eid):
            e = self.cfg.by_id(eid)
            if not e or e["role"] != "entry":
                raise CheckError("вход не найден")
            x = ((self.status.get(eid, {}).get("data") or {}).get("entry") or {}).get("xui") or {}
            port = next((ib["port"] for ib in x.get("inbounds", []) if ib.get("enable")), None)
            r = quality.pc_run(e["host"], port, tests)
            r["port"] = port
            return r

        with self.busy("quality"):
            with cf.ThreadPoolExecutor(max_workers=8) as ex:
                fe = {ex.submit(on_entry, eid): eid for eid in by_entry}
                fp = {ex.submit(on_pc, eid): eid for eid in pcs}
                for f, eid in fe.items():
                    try:
                        res["routes"].update(f.result())
                    except Exception as e:  # noqa: BLE001
                        res["errors"][eid] = str(e)
                for f, eid in fp.items():
                    try:
                        res["pc"][eid] = f.result()
                    except Exception as e:  # noqa: BLE001
                        res["pc"][eid] = {"error": str(e)}
        res["secs"] = round(time.time() - t0)
        res["asked"] = {"routes": ["%s>%s" % (e, x) for e, x in routes], "pc": pcs}
        with self.lock:
            self.quality = res
        return res

    def _exit_label(self, c):
        """Имя и страна выхода — всегда из текущего списка серверов (его могли переименовать)."""
        x = self.cfg.by_id(c.get("exit_id")) if c.get("exit_id") else None
        return {"exit": x["name"], "cc": x.get("cc", "")} if x else {}

    def snapshot(self):
        with self.lock:
            servers, dups = [], self.xui_dups()
            for s in self.cfg.servers:
                servers.append(dict(s, has_password=bool(self.cfg.get_pw(s["id"])), state=self.status.get(s["id"]),
                                    xui_dup=dups.get(s["id"])))
            chans = {}
            for sid, lst in self.channels.items():
                chans[sid] = [dict(c, **self._exit_label(c), result=self.results.get("%s:%s" % (sid, c["key"]))) for c in lst]
            return {
                "now": now(), "servers": servers, "channels": chans, "dc": self.dc,
                "reach": list(self.reach.values()), "running": sorted(self.running),
                "log": self.log[-60:][::-1], "settings": self.cfg.settings,
                "keyring": bool(keyring), "slow_s": float(self.cfg.settings.get("slow_s") or 2),
                "hs_stale_s": 60 * int(self.cfg.settings.get("hs_stale_min") or 5),
                "schema": [dict(zip(("key", "default", "type", "min", "max", "group", "label", "help"), x)) for x in SETTINGS],
                "platform": os.name, "port_now": PORT, "boot": BOOT_ID, "can_restart": bool(self.on_restart),
                "version": self.version, "git": self.git,
                "hist": self.hist.summary(), "drift": self.drift_view(), "fw": self.fw, "fwjob": self.fwjob, "gov": self.gov_view(), "govjob": self.govjob, "bypasses": self.sites.view(),
                "quality": self.quality, "geo": self.geo, "nb": self.nb, "dns": self.dns, "dpi": self.dpi,
                "addrjobs": [{"id": j.id, "kind": j.kind, "sid": j.params.get("sid"), "status": j.status, "error": j.error,
                              "finished": j.finished}
                             for j in sorted(getattr(self, "prov", None).jobs.values() if getattr(self, "prov", None) else [],
                                             key=lambda j: j.started) if j.kind in ("geo", "nb", "dns") and j.params.get("sid")][-60:], "zapret": dict(self.zapret.view(), jobs=[
                    {"id": j.id, "sid": j.params.get("sid"), "action": j.params.get("action"), "tid": j.params.get("tid"),
                     "status": j.status, "started": j.started, "finished": j.finished, "error": j.error}
                    for j in sorted(getattr(self, "prov", None).jobs.values() if getattr(self, "prov", None) else [],
                                    key=lambda j: j.started) if j.kind == "zapret"][-30:]),
                "backup": {"last": self.backup, "files": self.backups_list()[:8], "dir": str(BACKUP_DIR),
                           "server": (self.backup_target() or {}).get("id")},
            }


# ------------------------------------------------------------------ WebSocket (консоль)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_frame(opcode, payload=b""):
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def ws_read(rfile):
    """Одно сообщение от браузера: (opcode, payload) или None, если соединение закрыто."""
    h = rfile.read(2)
    if len(h) < 2:
        return None
    opcode, ln = h[0] & 0x0F, h[1] & 0x7F
    if ln == 126:
        ln = struct.unpack("!H", rfile.read(2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", rfile.read(8))[0]
    if ln > 1 << 20:
        return None
    mask = rfile.read(4) if h[1] & 0x80 else b""
    data = rfile.read(ln)
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


def terminal_session(handler, srv, cols, rows, via=""):
    wlock = threading.Lock()

    def send(op, data=b""):
        with wlock:
            handler.wfile.write(ws_frame(op, data))
            handler.wfile.flush()

    own = None                 # через вход — своё соединение только для этой консоли, закроется вместе с ней
    try:
        if via:
            pw = D.cfg.get_pw(srv["id"])
            if not pw:
                raise CheckError("не задан пароль")
            own, path = D.ssh.connect(srv, pw, via)
            client = own
        else:
            client = D.ssh.client(srv)
        chan = client.get_transport().open_session()
        chan.get_pty(term="xterm-256color", width=cols, height=rows)
        chan.invoke_shell()
    except Exception as e:
        if own:
            own.close()
        send(0x1, json.dumps({"error": str(e)}, ensure_ascii=False).encode())
        send(0x8)
        return
    D.note("ok", "Консоль открыта: %s%s" % (srv["name"], " — через вход %s (%s)" % (path["via"], path["how"]) if own else ""))
    if own:
        send(0x1, json.dumps({"info": "через вход %s · %s" % (path["via"], path["how"])}, ensure_ascii=False).encode())
    closed = threading.Event()

    def pump():
        try:
            while not closed.is_set():
                data = chan.recv(32768)
                if not data:
                    break
                send(0x2, data)
        except Exception:
            pass
        finally:
            closed.set()
            try:
                send(0x8)
            except Exception:
                pass

    threading.Thread(target=pump, daemon=True).start()
    try:
        while not closed.is_set():
            msg = ws_read(handler.rfile)
            if msg is None:
                break
            op, data = msg
            if op == 0x8:
                break
            if op == 0x9:
                send(0xA, data)
            elif op == 0x2:
                chan.sendall(data)
            elif op == 0x1:
                try:
                    m = json.loads(data.decode("utf-8"))
                    if "resize" in m:
                        chan.resize_pty(width=int(m["resize"][0]), height=int(m["resize"][1]))
                    elif "input" in m:
                        chan.sendall(m["input"].encode("utf-8"))
                except (ValueError, KeyError, TypeError):
                    pass
    except Exception:
        pass
    finally:
        closed.set()
        try:
            chan.close()
        except Exception:
            pass
        if own:
            own.close()


# ------------------------------------------------------------------ веб-панель 3X-UI через SSH

esc_html = html.escape
XUI_RESERVED = ("/api/", "/static/", "/ws/", "/xui/", "/login", "/logout", "/index.html")


def xui_path_ok(path):
    """Через нашу панель можно открыть только 3X-UI со своим (секретным) путём — иначе она займёт наши адреса."""
    return len(path) > 3 and not path.startswith(XUI_RESERVED)


# Скрипт для сервера: webListen в базе 3X-UI → перезапуск x-ui → проверка; не вышло — откат. P = {"listen": "" | "127.0.0.1"}
XUI_WEB_PY = r'''
import json, os, shutil, sqlite3, ssl, subprocess, time, urllib.error, urllib.request
DB = "/etc/x-ui/x-ui.db"


def sh(c):
    return subprocess.run(c, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True).stdout


def done(ok, msg):
    print(json.dumps({"ok": ok, "msg": msg}, ensure_ascii=False))
    raise SystemExit(0)


def addrs(port):
    out = []
    for line in sh("ss -Htln 'sport = :%d'" % port).splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append(f[3].rsplit(":", 1)[0].split("%")[0])
    return out


local = lambda a: a.startswith("127.") or a == "[::1]"
con = sqlite3.connect(DB, timeout=10)
st = dict(con.execute("select key, value from settings").fetchall())
con.close()
want = dict(st, **P["set"])
port = int(want.get("webPort") or 2053)
listen = want.get("webListen") or ""
path = "/" + (want.get("webBasePath") or "/").strip("/") + "/"
had_xray = xray_running()


def answers():                      # по новому пути отвечает панель, а не 404
    host = listen if listen not in ("", "0.0.0.0", "::") else "127.0.0.1"
    https = bool(want.get("webCertFile") and want.get("webKeyFile"))
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        op.open("%s://%s:%d%s" % ("https" if https else "http", host, port, path), timeout=5)
        return True
    except urllib.error.HTTPError as e:
        return e.code < 404
    except Exception:
        return False


def good():
    a = addrs(port)
    return (bool(a) and (all(local(x) for x in a) if listen else any(not local(x) for x in a))
            and (xray_running() or not had_xray) and ("webBasePath" not in P["set"] or answers()))


if all((st.get(k) or "") == v for k, v in P["set"].items()) and good():
    done(True, "уже так, ничего не менял")
bak = DB + ".before-web-%d" % time.time()
sh("systemctl stop x-ui")
shutil.copy2(DB, bak)
con = sqlite3.connect(DB, timeout=10)
for k, v in P["set"].items():
    if con.execute("select 1 from settings where key=?", (k,)).fetchone():
        con.execute("update settings set value=? where key=?", (v, k))
    else:
        con.execute("insert into settings(key, value) values(?, ?)", (k, v))
con.commit()
con.close()
sh("systemctl start x-ui")
for _ in range(30):
    time.sleep(1)
    if good():
        break
else:
    sh("systemctl stop x-ui")
    shutil.copy2(bak, DB)
    for x in ("-wal", "-shm"):
        try:
            os.remove(DB + x)
        except OSError:
            pass
    sh("systemctl start x-ui")
    done(False, "после перезапуска x-ui панель или Xray не поднялись как надо — вернул как было (%s)" % (", ".join(addrs(port)) or "порт не слушается"))
os.remove(bak)
if "webBasePath" in P["set"]:
    done(True, "у панели теперь свой путь в адресе (логин и пароль прежние)")
done(True, "закрыта из интернета: слушает только сам сервер, открывается кнопкой «3X-UI» в панели" if listen else
     "снова открыта в интернет (порт %d)" % port)
'''
XUI_WEB_PY = probe_func("xray_running") + XUI_WEB_PY    # та же проверка «Xray запущен», что в probe.py

XUI_HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
           "proxy-authorization", "host", "content-length"}


# ------------------------------------------------------------------ HTTP

D = None
ALLOWED_HOSTS = {"127.0.0.1:%d" % PORT, "localhost:%d" % PORT}
ALLOWED_ORIGINS = {"http://" + h for h in ALLOWED_HOSTS}
STATIC_FILES = {"xterm.js": "application/javascript", "xterm.css": "text/css", "addon-fit.js": "application/javascript",
                "qrcode.js": "application/javascript"}


class Handler(BaseHTTPRequestHandler):
    server_version = "vpn-dash"
    protocol_version = "HTTP/1.1"
    remote = False          # True — запрос пришёл на порт удалённого доступа (через Tailscale)

    def _origin_ok(self):
        return self.headers.get("Origin") in ALLOWED_ORIGINS

    def log_message(self, *a):
        pass

    def _host_ok(self):
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        b = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b)

    # --- веб-панель 3X-UI через SSH: запросы на секретный путь панели идут на сам сервер (127.0.0.1:порт там)

    def _cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _xui_target(self):
        path = urlparse(self.path).path + "/"
        hits = [(sid, w) for sid, w in list(D.xui_web.items()) if xui_path_ok(w["path"]) and path.startswith(w["path"])]
        if not hits:
            return None
        want = self._cookie("xui_sid")          # у входов из одного бэкапа путь одинаковый — какой открыли последним
        return next((h for h in hits if h[0] == want), hits[0])

    def _xui_page(self, code, text):
        body = ("<!doctype html><meta charset=utf-8><title>3X-UI</title><body style='font:16px system-ui;background:#0d1117;"
                "color:#e6edf3;padding:40px'><h2>3X-UI</h2><p>%s</p><p><a style='color:#58a6ff' href='/'>← в панель каскада</a>"
                % text).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _xui_open(self, sid):
        w, srv = D.xui_web.get(sid), D.cfg.by_id(sid)
        if not w or not srv:
            return self._xui_page(404, "Панель ещё не знает, где 3X-UI на этом сервере — нажмите «проверить» у сервера.")
        if not xui_path_ok(w["path"]):
            return self._xui_page(409, "У 3X-UI на «%s» нет своего пути в адресе — через панель каскада её открыть нельзя. "
                                       "Задайте путь (webBasePath) в настройках 3X-UI." % esc_html(srv["name"]))
        self.send_response(303)
        self.send_header("Location", quote(w["path"]))
        self.send_header("Set-Cookie", "xui_sid=%s; Path=/; HttpOnly; SameSite=Strict%s" % (sid, "; Secure" if self.remote else ""))
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _xui_proxy(self, sid, w):
        srv = D.cfg.by_id(sid)
        if not srv:
            return self._xui_page(404, "Нет такого сервера.")
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self._xui_page(403, "Открывайте 3X-UI кнопкой в панели каскада.")
        ws = self.headers.get("Upgrade", "").lower() == "websocket"
        if (ws or self.command not in ("GET", "HEAD")) and not self._origin_ok():
            return self._xui_page(403, "Запрос не со страницы панели.")
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n > 0 else b""
        scheme = "https" if w["https"] else "http"
        # Host — настоящий адрес сервера: по нему 3X-UI строит ссылки подписки (иначе в них был бы 127.0.0.1)
        real = w["domain"] or srv["host"]
        host = "%s:%d" % ("[%s]" % real if ":" in real and not real.startswith("[") else real, w["port"])
        js = self.command == "GET" and urlparse(self.path).path.endswith(".js")   # в скриптах подменим адрес страницы
        dest = w["listen"] if w["listen"] not in ("", "0.0.0.0", "::", "[::]") else "127.0.0.1"
        lines = ["%s %s HTTP/1.1" % (self.command, self.path), "Host: " + host]
        for k, v in self.headers.items():
            kl = k.lower()
            if kl in XUI_HOP or kl.startswith(("x-forwarded", "x-real-ip", "tailscale-", "x-dash")) or (js and kl == "accept-encoding"):
                continue
            if kl == "cookie":                  # наши cookie (вход в панель каскада) серверу не отдаём
                v = "; ".join(c.strip() for c in v.split(";") if c.strip() and c.strip().split("=")[0] not in (remote.COOKIE, "xui_sid"))
                if not v:
                    continue
            elif kl == "origin":
                v = "%s://%s" % (scheme, host)
            elif kl == "referer":
                v = re.sub(r"^https?://[^/]+", "%s://%s" % (scheme, host), v)
            lines.append("%s: %s" % (k, v))
        lines += ["Connection: Upgrade", "Upgrade: websocket"] if ws else ["Connection: close"]
        if body or self.command in ("POST", "PUT", "PATCH"):
            lines.append("Content-Length: %d" % len(body))
        try:
            up = D.ssh.tunnel(srv, dest, w["port"])
            if w["https"]:                      # внутри SSH до самого сервера — сертификат проверять не нужно
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                up = ctx.wrap_socket(up, server_hostname=w["domain"] or None)
            up.settimeout(None if ws else 120)
            up.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + body)
            f = up.makefile("rb")
            status = f.readline(65537)
            if not status.startswith(b"HTTP/"):
                raise OSError("3X-UI не ответила" + (" — может, у неё не https?" if w["https"] else " — может, она на https?"))
            hdrs = []
            while True:
                ln = f.readline(65537)
                if ln in (b"\r\n", b"\n", b""):
                    break
                hdrs.append(ln.decode("latin-1").rstrip("\r\n"))
        except (CheckError, OSError, ssl.SSLError) as e:
            return self._xui_page(502, "Не удалось открыть 3X-UI на «%s»: %s" % (esc_html(srv["name"]), esc_html(str(e))))
        code = int((status.split() + [b"0", b"0"])[1] or 0)
        own = re.compile(r"^https?://(127\.0\.0\.1|localhost|%s%s)(:\d+)?" % (
            re.escape(srv["host"]), "|" + re.escape(w["domain"]) if w["domain"] else ""), re.I)
        out = [status.decode("latin-1").rstrip("\r\n")]
        for h in hdrs:
            k, _, v = h.partition(":")
            kl, v = k.strip().lower(), v.strip()
            if kl in ("keep-alive", "strict-transport-security") or (kl == "connection" and code != 101):
                continue
            if kl == "location":
                v = own.sub("", v) or "/"
            elif kl == "set-cookie":
                v = re.sub(r";\s*domain=[^;]*", "", v, flags=re.I)
                if not self.remote:             # страница у нас на http://127.0.0.1
                    v = re.sub(r";\s*secure(?=\s*(;|$))", "", v, flags=re.I)
            out.append("%s: %s" % (k.strip(), v))
        if js and code == 200 and not any(h.lower().startswith("content-encoding:") for h in hdrs):
            return self._xui_js(f, up, out, hdrs, real)
        if code != 101:
            out.append("Connection: close")
        self.close_connection = True
        try:
            self.wfile.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1", "replace"))
            if code == 101 and ws:
                def to_server():
                    try:
                        while True:
                            d = self.rfile.read1(65536)
                            if not d:
                                break
                            up.sendall(d)
                    except Exception:
                        pass
                    finally:
                        try:
                            up.close()
                        except Exception:
                            pass
                threading.Thread(target=to_server, daemon=True).start()
            while True:
                d = f.read1(65536)
                if not d:
                    break
                self.wfile.write(d)
        except (OSError, ssl.SSLError):
            pass
        finally:
            for x in (f, up):
                try:
                    x.close()
                except Exception:
                    pass

    def _xui_js(self, f, up, out, hdrs, real):
        """Скрипт 3X-UI: адрес в ссылках VLESS панель берёт из адреса страницы (window.location.hostname) — у нас это
        127.0.0.1 или адрес Tailscale. Подменяем на настоящий адрес сервера."""
        self.close_connection = True
        try:
            chunked = any(re.match(r"transfer-encoding:\s*chunked", h, re.I) for h in hdrs)
            body = b""
            if chunked:
                while True:
                    size = int(f.readline(1024).split(b";")[0].strip() or b"0", 16)
                    if not size:
                        break
                    body += f.read(size)
                    f.readline(1024)
            else:
                body = f.read()
            text = re.sub(r"(?<![\w.$])(?:(?:window|globalThis|self)\.)?location\.hostname\b(?!\s*=[^=])", json.dumps(real), body.decode("utf-8", "replace"))
            b = text.encode("utf-8")
            head = [out[0]] + [h for h in out[1:] if h.split(":")[0].strip().lower() not in
                               ("content-length", "transfer-encoding", "etag", "last-modified", "connection")]
            head += ["Content-Length: %d" % len(b), "Connection: close"]
            self.wfile.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1", "replace") + b)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            for x in (f, up):
                try:
                    x.close()
                except Exception:
                    pass

    def _xui_other(self):                       # HEAD/PUT/DELETE/PATCH — только для 3X-UI
        if not self._host_ok():
            return self._send(403, {"error": "host"})
        t = self._xui_target()
        return self._xui_proxy(*t) if t else self._send(405, {"error": "method"})

    do_HEAD = do_PUT = do_DELETE = do_PATCH = _xui_other

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "host"})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/xui/open":
            return self._xui_open(q.get("id", [""])[0])
        t = self._xui_target()
        if t:
            return self._xui_proxy(*t)
        if u.path in ("/", "/index.html"):
            html = INDEX.read_text(encoding="utf-8").replace("__DASH_TOKEN__", TOKEN).replace('"__DASH_REMOTE__"', "true" if self.remote else "false")
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        if u.path.startswith("/static/") and u.path[8:] in STATIC_FILES:
            return self._send(200, (STATIC / u.path[8:]).read_bytes(), STATIC_FILES[u.path[8:]])
        if u.path == "/api/state":
            return self._send(200, D.snapshot())
        if u.path == "/api/history":
            kind, key = q.get("kind", [""])[0], q.get("key", [""])[0]
            hours = max(1, min(24 * 365, int(q.get("hours", ["24"])[0])))
            return self._send(200, {"points": D.hist.series(kind, key, hours)})
        if u.path == "/ws/term":
            return self._terminal(q)
        if u.path == "/api/log":
            if self.headers.get("X-Dash") != TOKEN:
                return self._send(403, {"error": "forbidden"})
            try:
                n = max(10, min(5000, int(q.get("n", ["100"])[0])))
            except ValueError:
                n = 100
            return self._send(200, {"log": D.log_tail(n)})
        if u.path.startswith("/api/prov/"):
            # в журналах установки бывают ключи — только со страницы панели (токен), как и POST
            if self.headers.get("X-Dash") != TOKEN:
                return self._send(403, {"error": "token"})
            if u.path == "/api/prov/jobs":
                return self._send(200, {"jobs": D.prov.list()})
            if u.path == "/api/prov/job":
                j = D.prov.get(q.get("id", [""])[0], int(q.get("from", ["0"])[0] or 0))
                return self._send(200, j) if j else self._send(404, {"error": "нет такой задачи"})
        self._send(404, {"error": "not found"})

    def _terminal(self, q):
        # консоль — это root на сервере, поэтому строго: наш Origin, наш токен, наш адрес
        if (not self._origin_ok() or q.get("token", [""])[0] != TOKEN
                or self.headers.get("Upgrade", "").lower() != "websocket"):
            return self._send(403, {"error": "forbidden"})
        srv = D.cfg.by_id(q.get("id", [""])[0])
        if not srv:
            return self._send(404, {"error": "нет такого сервера"})
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        try:
            cols = max(20, min(400, int(q.get("cols", ["120"])[0])))
            rows = max(5, min(200, int(q.get("rows", ["32"])[0])))
        except ValueError:
            cols, rows = 120, 32
        via = q.get("via", [""])[0]
        if via and (srv["role"] != "exit" or not (D.cfg.by_id(via) or {}).get("role") == "entry"):
            via = ""
        terminal_session(self, srv, cols, rows, via)
        self.close_connection = True

    def do_POST(self):
        # защита от чужих сайтов: только наш адрес, наш заголовок и токен этого запуска
        if self._host_ok():
            t = self._xui_target()
            if t:                               # 3X-UI сама следит за входом; от чужих сайтов — проверка Origin
                return self._xui_proxy(*t)
        if not self._host_ok() or self.headers.get("X-Dash") != TOKEN:
            return self._send(403, {"error": "forbidden — обновите страницу"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        p = self.path
        if p == "/api/check":
            what, sid, key = body.get("what"), body.get("id"), body.get("key")
            if what == "all":
                D.pool.submit(D.check_all, True)
            elif what == "server":
                D.pool.submit(D.check_server, sid)
            elif what == "entry":
                def run_entry():
                    D.check_server(sid)
                    D.check_entry_channels(sid)
                D.pool.submit(run_entry)
            elif what == "channel":
                D.leaf.submit(D.check_channel, sid, key)
            elif what == "dc":
                for s in D.cfg.servers:
                    if s["role"] == "exit":
                        D.leaf.submit(D.check_dc, s["id"])
            elif what == "reach":
                D.pool.submit(D.check_reach)
            elif what == "drift":
                D.pool.submit(D.check_drift)
            elif what == "fw":
                for s in D.cfg.servers:
                    if not sid or s["id"] == sid:
                        D.pool.submit(D.check_fw, s["id"])
            elif what == "drift-ok":           # «это нормально» / «вернуть»: только запоминается в servers.json
                key = {"p": str(body.get("path") or ""), "a": str(body.get("a")), "b": str(body.get("b"))}
                with D.lock:
                    lst = [o for o in D.cfg.data.get("drift_ok", []) if (o.get("p"), o.get("a"), o.get("b")) != (key["p"], key["a"], key["b"])]
                    if not body.get("undo"):
                        key["at"] = int(now())
                        lst.append(key)
                    D.cfg.data["drift_ok"] = lst[-500:]
                    D.cfg.save()
            elif what == "backup":
                D.pool.submit(D.do_backup, sid)
            else:
                return self._send(400, {"error": "what?"})
            return self._send(200, {"ok": True})
        if p == "/api/password":
            sid, pw = body.get("id"), body.get("password") or ""
            srv = D.cfg.by_id(sid)
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            where = D.cfg.set_pw(sid, pw)
            D.ssh.drop(sid)
            if not pw:
                return self._send(200, {"ok": True, "where": where})
            try:
                rc, out, err = D.ssh.run(srv, "hostname", timeout=20)
                D.pool.submit(D.check_server, sid)
                return self._send(200, {"ok": True, "where": where, "hostname": out.strip()})
            except CheckError as e:
                return self._send(200, {"ok": False, "where": where, "error": str(e)})
        if p == "/api/servers":
            lst = body.get("servers")
            if not isinstance(lst, list):
                return self._send(400, {"error": "servers?"})
            clean, seen = [], set()
            for s in lst:
                sid = re.sub(r"[^a-z0-9_-]", "", str(s.get("id") or "").lower())[:24]
                host = str(s.get("host") or "").strip()
                if not sid or sid in seen or not re.match(r"^[A-Za-z0-9.\-:]+$", host):
                    return self._send(400, {"error": "у сервера нужен уникальный id и адрес: %s" % (s.get("name") or sid)})
                seen.add(sid)
                clean.append({
                    "id": sid, "name": str(s.get("name") or sid)[:40], "host": host,
                    "port": int(s.get("port") or 22), "user": str(s.get("user") or "root")[:32],
                    "role": "entry" if s.get("role") == "entry" else "exit",
                    "provider": str(s.get("provider") or "")[:60], "note": str(s.get("note") or "")[:40],
                    "cc": str(s.get("cc") or "")[:3].upper(),
                })
            olds = {o["id"]: o for o in D.cfg.servers}
            gone = [i for i in olds if i not in seen]
            added = [s["id"] for s in clean if s["id"] not in olds]
            # адрес, порт, пользователь или роль поменялись — старое соединение и результаты больше не годятся
            moved = [s["id"] for s in clean if s["id"] in olds
                     and any(olds[s["id"]].get(k) != s[k] for k in ("host", "port", "user", "role"))]
            renamed = [s["id"] for s in clean if s["id"] in olds and s["id"] not in moved
                       and any(olds[s["id"]].get(k, "") != s[k] for k in ("name", "provider", "note", "cc"))]
            with D.lock:
                for sid in gone + moved:
                    if sid in gone:
                        D.cfg.set_pw(sid, "")
                    D.ssh.drop(sid)
                    D.status.pop(sid, None)
                    D.channels.pop(sid, None)
                    D.dc.pop(sid, None)
                    for k in [k for k in D.results if k.startswith(sid + ":")]:
                        D.results.pop(k)
                if gone or moved:
                    D.reach.clear()
                D.cfg.data["servers"] = clean
                D.cfg.save()
            for sid in moved:
                o, n = olds[sid], next(x for x in clean if x["id"] == sid)
                D.note("ok", "%s: адрес изменён %s:%s → %s:%s" % (n["name"], o.get("host"), o.get("port"), n["host"], n["port"]))
            for sid in added:
                D.note("ok", "Добавлен сервер %s" % next(x["name"] for x in clean if x["id"] == sid))
            for sid in gone:
                D.note("ok", "Убран сервер %s" % olds[sid].get("name", sid))
            if moved or gone:                    # каналы входов зависят и от адресов выходов — проверим всё
                def recheck():
                    for _ in range(120):             # если полная проверка уже идёт — дождаться её
                        if "all" not in D.running:
                            break
                        time.sleep(1)
                    D.check_all(True)
                D.pool.submit(recheck)
            return self._send(200, {"ok": True, "moved": moved, "added": added, "gone": gone, "renamed": renamed})
        if p == "/api/pkgs":
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                rc, out, err = D.ssh.run(srv, "python3 -", stdin='MODE = "pkgs"\nREFRESH = %s\n' % bool(body.get("refresh")) + PROBE,
                                         timeout=300)
                if rc != 0 or not out.strip():
                    raise CheckError((err.strip().splitlines() or ["код %s" % rc])[-1][:200])
                info = json.loads(out)["pkgs"]
            except Exception as e:
                return self._send(200, {"error": "%s: %s" % (srv["name"], e)})
            main = next((s for s in D.cfg.servers if s["role"] == "entry"), None)
            info.update(classify_pkgs(info, srv, bool(main and main["id"] == srv["id"])))
            info["at"] = now()
            D.pkg_count[srv["id"]] = {"at": now(), "n": info["todo"]}
            if body.get("refresh"):
                D.pool.submit(D.check_server, srv["id"])       # число обновлений в обзоре — сразу свежее
            return self._send(200, info)
        if p == "/api/fw":
            srv = D.cfg.by_id(str(body.get("id") or ""))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            if any(k.startswith("fwon:") for k in D.running):
                return self._send(409, {"error": "фаервол уже включается на другом сервере — по одному"})
            def job(f=D.fw_enable if body.get("do") == "enable" else D.fw_disable, sid=srv["id"]):
                try:
                    f(sid)
                except Exception as e:          # чтобы окно не крутилось вечно
                    j = D.fwjob.setdefault(sid, {"steps": []})
                    j["steps"].append(["bad", "ошибка панели: %s: %s — если ufw успел включиться, он выключится сам через 5 минут" % (type(e).__name__, e)])
                    j.update(ok=False, done=True)
            D.pool.submit(job)
            return self._send(200, {"ok": True})
        if p == "/api/gov":                     # «сети госорганов» на входе: enable | off | fetch
            do = str(body.get("do") or "")
            if do == "fetch":
                try:
                    D.gov_fetch()
                    return self._send(200, {"ok": True, "gov": D.gov_view()})
                except CheckError as e:
                    return self._send(200, {"error": str(e)})
            srv = D.cfg.by_id(str(body.get("id") or ""))
            if not srv or srv["role"] != "entry":
                return self._send(404, {"error": "это не вход — список нужен только на входах"})
            if any(k.startswith(("govon:", "fwon:")) for k in D.running):
                return self._send(409, {"error": "уже идёт включение на другом сервере — по одному"})
            def gjob(f=D.gov_apply if do == "enable" else D.gov_off, sid=srv["id"]):
                try:
                    f(sid)
                except Exception as e:          # чтобы окно не крутилось вечно
                    j = D.govjob.setdefault(sid, {"steps": []})
                    j["steps"].append(["bad", "ошибка панели: %s: %s — если успело включиться, через 5 минут вернётся само" % (type(e).__name__, e)])
                    j.update(ok=False, done=True)
            D.pool.submit(gjob)
            return self._send(200, {"ok": True})
        if p == "/api/acme":
            return self._send(200, D.acme_open(str(body.get("id") or "")))
        if p == "/api/xui":
            return self._send(200, D.xui_change(str(body.get("id") or ""), str(body.get("what") or "")))
        if p == "/api/geo":                     # как базы геолокации и сервисы видят адрес сервера (только чтение)
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                return self._send(200, {"ok": True, "job": D.prov.start_geo(srv, body.get("install") if isinstance(body.get("install"), list) else None)})
            except ValueError as e:
                return self._send(409, {"error": str(e)})
        if p == "/api/awg-mimic":               # пакеты-маски на туннеле входа — по кнопке с подтверждением
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                return self._send(200, {"ok": True, "job": D.prov.start_mimic(srv, str(body.get("iface") or ""), str(body.get("profile") or ""))})
            except ValueError as e:
                return self._send(409, {"error": str(e)})
        if p == "/api/awg":                     # AmneziaWG: все туннели наглядно (только чтение, секреты не уходят с серверов)
            return self._send(200, D.awg_view())
        if p == "/api/dns":                     # DNS на сервере: кто отвечает, подменяют ли (только чтение)
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                return self._send(200, {"ok": True, "job": D.prov.start_dns(srv)})
            except ValueError as e:
                return self._send(409, {"error": str(e)})
        if p == "/api/nb":                      # «шумные соседи»: /24 сервера — с этого компьютера (только чтение)
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                return self._send(200, {"ok": True, "job": D.prov.start_nb(srv)})
            except ValueError as e:
                return self._send(409, {"error": str(e)})
        if p == "/api/migrate":                 # выход: Amnezia в Docker → AmneziaWG без Docker
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                jid = D.prov.start_migrate(srv, str(body.get("awg_net") or ""))
            except ValueError as e:
                return self._send(409, {"error": str(e)})
            return self._send(200, {"ok": True, "job": jid})
        if p == "/api/upgrade":
            srv = D.cfg.by_id(body.get("id"))
            if not srv:
                return self._send(404, {"error": "нет такого сервера"})
            try:
                jid = D.prov.start_upgrade(srv, bool(body.get("reboot")), body.get("mode") == "reboot")
            except ValueError as e:
                return self._send(409, {"error": str(e)})
            return self._send(200, {"ok": True, "job": jid})
        if p == "/api/remote":
            if self.remote:
                return self._send(403, {"error": "удалённый доступ настраивается только на домашнем компьютере"})
            return self._send(200, D.remote_api(body))
        if p == "/api/site":
            try:
                return self._send(200, D.sites.check(body.get("target")))
            except ValueError as e:
                return self._send(400, {"error": str(e)})
        if p == "/api/zapret":                  # раздел «Zapret»: цели, подсказка адресов, задачи на входах
            return self._send(200, D.zapret_api(body))
        if p == "/api/dpi":                     # что режут по пути на входах (сайты напрямую, только чтение)
            if not [s for s in D.cfg.servers if s["role"] == "entry" and D.cfg.get_pw(s["id"])]:
                return self._send(409, {"error": "нет входов с сохранённым паролем"})
            with D.lock:
                if "dpi" in D.running:
                    return self._send(409, {"error": "проверка уже идёт"})
                D.running.add("dpi")

            def job():
                try:
                    r = D.sites.dpi()
                except Exception as e:  # noqa: BLE001
                    r = {"at": time.time(), "error": str(e), "entries": [], "sites": []}
                with D.lock:
                    D.dpi = r
                    D.running.discard("dpi")
            D.pool.submit(job)
            return self._send(200, {"ok": True})
        if p == "/api/quality":
            try:
                return self._send(200, D.quality_check(body))
            except ValueError as e:
                return self._send(409, {"error": str(e)})
        if p == "/api/bypass":
            return self._send(200, D.bypass_api(body))
        if p == "/api/servers/order":
            ids = body.get("ids")
            with D.lock:
                cur = {s["id"]: s for s in D.cfg.servers}
                if not isinstance(ids, list) or sorted(map(str, ids)) != sorted(cur):
                    return self._send(409, {"error": "список серверов изменился — обновите страницу"})
                D.cfg.data["servers"] = [cur[i] for i in ids]
                D.cfg.save()
            return self._send(200, {"ok": True})
        if p == "/api/prov/start":
            kind = body.get("kind")
            if kind not in ("check", "bench", "install", "geo"):
                return self._send(400, {"error": "kind?"})
            params = body.get("params") or {}
            host = str(params.get("host") or "").strip()
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                return self._send(400, {"error": "IP нового сервера в виде 1.2.3.4"})
            params["host"] = host
            if not body.get("password"):
                return self._send(400, {"error": "нужен пароль root нового сервера"})
            try:
                return self._send(200, {"job": D.prov.start(kind, params, body["password"])})
            except ValueError as e:
                return self._send(400, {"error": str(e)})
        if p == "/api/update":
            import updater
            if body.get("action") == "check":
                return self._send(200, dict(updater.check(), version=updater.version()))
            if body.get("action") == "apply":
                r = updater.apply()
                if r.get("updated"):
                    if D.request_restart():
                        r["restarting"] = True
                    else:
                        r["note"] = "Закройте окно панели и запустите start.bat — новая версия заработает."
                return self._send(200, r)
            return self._send(400, {"error": "action?"})
        if p == "/api/settings":
            st = D.cfg.settings
            if body.get("reset"):
                for k, dflt, *_ in SETTINGS:
                    if k not in ("backup_server", "autostart", "port"):
                        st[k] = dflt
                D.cfg.save()
                return self._send(200, {"ok": True})
            new = {}
            try:
                for k, v in body.items():
                    if k in SETTINGS_BY_KEY:
                        new[k] = clean_setting(k, v, D.cfg)
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            for a, b in (("cpu_warn", "cpu_bad"), ("mem_warn", "mem_bad"), ("disk_warn", "disk_bad")):
                if new.get(a, st.get(a)) > new.get(b, st.get(b)):
                    return self._send(400, {"error": "жёлтый порог (%s) не может быть выше красного" % SETTINGS_BY_KEY[a][6].split(":")[0]})
            msg = []
            if "autostart" in new and new["autostart"] != st.get("autostart") and os.name == "nt":
                try:
                    import tray
                    tray.autostart_set(new["autostart"])
                except Exception as e:
                    return self._send(400, {"error": "автозапуск: не удалось изменить реестр (%s)" % e})
            if "port" in new and new["port"] != PORT:
                msg.append("Порт %d заработает после перезапуска панели" % new["port"])
            st.update(new)
            D.cfg.save()
            return self._send(200, {"ok": True, "notes": msg})
        self._send(404, {"error": "not found"})


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):   # обрыв соединения браузером — не ошибка
        if not isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            super().handle_error(request, client_address)


class RemoteHandler(Handler):
    """Порт удалённого доступа: сюда попадают только через `tailscale serve`. Всё — только после входа."""
    remote = True
    sess = None

    def _who(self):
        return self.headers.get("Tailscale-User-Login") or "?"

    def _ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def _host_ok(self):                 # вместо проверки адреса — вход с паролем и кодом
        return self.sess is not None

    def _origin_ok(self):
        o = self.headers.get("Origin", "")
        hosts = [h for h in (self.headers.get("X-Forwarded-Host"), self.headers.get("Host")) if h]
        return any(o in ("https://" + h, "http://" + h) for h in hosts) or bool(re.match(r"^https://[a-z0-9-]+\.[a-z0-9-]+\.ts\.net$", o))

    def _redirect(self, where, cookie=None):
        self.send_response(303)
        self.send_header("Location", where)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            return self._send(200, remote.login_page(), "text/html; charset=utf-8")
        if u.path == "/logout":
            D.rsess.drop(remote.cookie_of(self.headers))
            return self._redirect("/login", "%s=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" % remote.COOKIE)
        self.sess = D.rsess.get(remote.cookie_of(self.headers))
        if self.sess is None:
            if u.path in ("/", "/index.html", "/xui/open") or self._xui_target():
                return self._redirect("/login")
            return self._send(401, {"error": "нужен вход — обновите страницу"})
        return super().do_GET()

    def _xui_other(self):
        self.sess = D.rsess.get(remote.cookie_of(self.headers))
        return super()._xui_other()

    do_HEAD = do_PUT = do_DELETE = do_PATCH = _xui_other

    def do_POST(self):
        if urlparse(self.path).path == "/login":
            return self._login()
        self.sess = D.rsess.get(remote.cookie_of(self.headers))
        if self.sess is None:
            return self._send(401, {"error": "сессия закончилась — обновите страницу и войдите заново"})
        return super().do_POST()

    def _login(self):
        if self.headers.get("Origin") and not self._origin_ok():
            return self._send(403, remote.login_page("Вход только со страницы панели."), "text/html; charset=utf-8")
        wait = D.rsess.blocked_for()
        if wait:
            return self._send(429, remote.login_page("Слишком много неудачных попыток. Подождите %d мин." % (wait // 60 + 1)),
                              "text/html; charset=utf-8")
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 4096)
            form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        except ValueError:
            form = {}
        pw, code = (form.get("password") or [""])[0], (form.get("code") or [""])[0]
        cred = D.remote_creds()
        ok_pw = bool(cred["pw"]) and remote.check_password(pw, cred["pw"])
        counter = remote.totp_match(cred["totp"], code, last_used=D.rsess.last_counter) if ok_pw else None
        if not ok_pw or counter is None:
            D.rsess.fail()
            D.note("warn", "Удалённый доступ: неудачная попытка входа (%s, %s)" % (self._who(), self._ip()))
            return self._send(401, remote.login_page("Неверный пароль или код."), "text/html; charset=utf-8")
        D.rsess.last_counter = counter
        tok = D.rsess.new(self._who(), self._ip())
        D.note("ok", "Удалённый доступ: вход (%s, %s)" % (self._who(), self._ip()))
        return self._redirect("/", remote.set_cookie(tok))


def main():
    global D
    args = sys.argv[1:]
    if "--launch" in args:                    # из start.bat: уйти в трей и закрыть окно
        import tray
        if tray.launch(PORT):
            return
    tray_mode = "--tray" in args
    if tray_mode:
        # у pythonw нет консоли: вывод — в файл рядом (последние ~1 МБ)
        out = APP / "dash-run.log"
        try:
            if out.exists() and out.stat().st_size > 1 << 20:
                out.unlink()
        except OSError:
            pass
        sys.stdout = sys.stderr = open(out, "a", encoding="utf-8", buffering=1)
        print("\n=== %s запуск" % time.strftime("%Y-%m-%d %H:%M:%S"))
    url = "http://127.0.0.1:%d/" % PORT
    try:
        srv = QuietServer(("127.0.0.1", PORT), Handler)
    except OSError:
        msg = "Порт %d уже занят — наверное, панель уже запущена. Открываю страницу." % PORT
        print(msg)
        if "--autostart" not in args and os.environ.get("DASH_NO_BROWSER") != "1":
            webbrowser.open(url)
        return
    D = Dash()
    import provision
    D.prov = provision.Provisioner(D, APP, Path(os.environ.get("VPN_DASH_SCRIPTS") or APP / "server-scripts"),
                                   {"CheckError": CheckError, "PROBE": PROBE, "parse_dc": parse_dc, "TG_DC_DEFAULT": TG_DC_DEFAULT, "BACKUP_DIR": BACKUP_DIR})
    threading.Thread(target=D.auto_loop, daemon=True).start()
    D.remote_apply()
    if tray_mode:
        try:
            import tray
            tray.run_tray(D, srv, PORT, D.cfg.save, "--autostart" in args or "--no-browser" in args)
            srv.server_close()
            if D.restart_args:
                import updater
                updater.restart_detached(D.restart_args)
            return
        except Exception as e:
            print("Значок в трее недоступен (%s) — работаю без значка" % e)
            D.note("warn", "Значок в трее не запустился: %s. Панель работает; остановить — start.bat console и Ctrl+C или Диспетчер задач" % e)
    print("Панель каскада: %s  (остановить — Ctrl+C или закрыть это окно)" % url)
    if not keyring:
        print("ВНИМАНИЕ: нет модуля keyring — пароли будут храниться только до перезапуска")
    if os.environ.get("DASH_NO_BROWSER") != "1":
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
