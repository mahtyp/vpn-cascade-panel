"""Доступ «только чтение» для «Аналитики»: пользователь vpn-ro на серверах.

Ключ SSH панели (ECDSA) хранится в keyring, на сервер уходит только публичная часть — в authorized_keys с
`restrict,command="/usr/local/sbin/vpn-dash-ro"`: что бы ни прислали по SSH, выполнится только обёртка, а она через
sudo запускает только server-scripts/vpn-dash-ro.py (там список названных проверок). Запрет на изменения держит
сервер, а не агент: если в журналы подсунут «инструкцию», агент всё равно может лишь читать из списка.
Ставит и убирает это задача `ro` в provision.py (по кнопке, через root).
"""
import hashlib
import io
import re
import socket
import threading
from pathlib import Path

import paramiko

USER = "vpn-ro"
KR_KEY = "_ro_key"
LIB = "/usr/local/lib/vpn-dash-ro"
WRAPPER = "/usr/local/sbin/vpn-dash-ro"
TMP = "/root/.vpn-dash-ro-tmp"
HERE = Path(__file__).resolve().parent
RO_PY = HERE / "server-scripts" / "vpn-dash-ro.py"
PROBE_PY = HERE / "probe.py"


def files_sha():
    """Отпечаток файлов для журнала установки."""
    h = hashlib.sha256()
    for p in (RO_PY, PROBE_PY):
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def version():
    """Версия списка проверок (VERSION в vpn-dash-ro.py). Поднимается, только когда меняются сами проверки — обычные
    обновления панели (в том числе probe.py) не делают доступ на серверах «устаревшим»."""
    m = re.search(r'^VERSION = "(\d+)"', RO_PY.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else ""


def get_key(cfg, create=True):
    """Ключ панели для vpn-ro: из keyring; нет — создать (если create)."""
    pem = cfg.get_pw(KR_KEY)
    if pem:
        try:
            return paramiko.ECDSAKey.from_private_key(io.StringIO(pem))
        except (paramiko.SSHException, ValueError):
            pass
    if not create:
        return None
    key = paramiko.ECDSAKey.generate(bits=256)
    buf = io.StringIO()
    key.write_private_key(buf)
    cfg.set_pw(KR_KEY, buf.getvalue())
    return key


def pub_line(key):
    return 'restrict,command="%s" %s %s vpn-dash-analytics' % (WRAPPER, key.get_name(), key.get_base64())


def key_tail(key):
    """Хвост публичного ключа — probe показывает такой же, чтобы понять, наш ли ключ на сервере."""
    return ("%s %s" % (key.get_name(), key.get_base64()))[-24:]


INSTALL_SH = r"""set -eu
[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 1; }
command -v sudo >/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -q sudo >/dev/null; }
command -v python3 >/dev/null || { echo "нет python3"; exit 1; }
if ! id -u vpn-ro >/dev/null 2>&1; then
  useradd -r -m -d /var/lib/vpn-ro -s /bin/sh -c "vpn-dash read-only" vpn-ro
  echo "пользователь vpn-ro создан"
fi
usermod -p '*' -d /var/lib/vpn-ro vpn-ro    # пароля нет вовсе (вход только по ключу), но учётка не «заблокирована»
install -d -o vpn-ro -g vpn-ro -m 750 /var/lib/vpn-ro     # домашняя папка — даже если пользователь остался от прошлого раза без неё
install -d -o root -g root -m 755 /usr/local/lib/vpn-dash-ro
install -o root -g root -m 644 "$TMPD/ro.py" /usr/local/lib/vpn-dash-ro/ro.py
install -o root -g root -m 644 "$TMPD/probe.py" /usr/local/lib/vpn-dash-ro/probe.py
cat > /usr/local/sbin/vpn-dash-ro.new <<'EOF'
#!/bin/sh
# vpn-dash: вход vpn-ro попадает только сюда (command= в authorized_keys); дальше — только список проверок.
# Строка проверки идёт через stdin: в sudoers команда записана целиком, без «*» (sudo-rs в Ubuntu 26.04 их не понимает)
printf '%s' "$SSH_ORIGINAL_COMMAND" | sudo -n /usr/bin/python3 -I /usr/local/lib/vpn-dash-ro/ro.py
EOF
chown root:root /usr/local/sbin/vpn-dash-ro.new; chmod 755 /usr/local/sbin/vpn-dash-ro.new
mv -f /usr/local/sbin/vpn-dash-ro.new /usr/local/sbin/vpn-dash-ro
S=$(mktemp)
printf '%s\n' '# vpn-dash: пользователю vpn-ro — только скрипт проверок (только чтение), строка проверки — через stdin' \
  'vpn-ro ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/lib/vpn-dash-ro/ro.py' > "$S"
visudo -cf "$S" >/dev/null || { rm -f "$S"; echo "sudoers не прошёл проверку"; exit 1; }
install -o root -g root -m 440 "$S" /etc/sudoers.d/vpn-dash-ro; rm -f "$S"
install -d -o vpn-ro -g vpn-ro -m 700 /var/lib/vpn-ro/.ssh
printf '%s\n' "$PUB" > /var/lib/vpn-ro/.ssh/authorized_keys
chown vpn-ro:vpn-ro /var/lib/vpn-ro/.ssh/authorized_keys; chmod 600 /var/lib/vpn-ro/.ssh/authorized_keys
T=$(sshd -T 2>/dev/null || true)
au=$(printf '%s\n' "$T" | awk 'tolower($1)=="allowusers"{ $1=""; print }')
ag=$(printf '%s\n' "$T" | awk 'tolower($1)=="allowgroups"{ $1=""; print }')
pk=$(printf '%s\n' "$T" | awk 'tolower($1)=="pubkeyauthentication"{print $2}')
[ -n "$au" ] && ! printf '%s' " $au " | grep -q ' vpn-ro\b' && echo "SSHD-ALLOWUSERS:$au"
[ -n "$ag" ] && echo "SSHD-ALLOWGROUPS:$ag"
[ "$pk" = "no" ] && echo "SSHD-NOPUBKEY"
rm -rf "$TMPD"
echo RO-OK
"""

REMOVE_SH = r"""set -u
rm -f /var/lib/vpn-ro/.ssh/authorized_keys /etc/sudoers.d/vpn-dash-ro      # сначала — чтобы никто не вошёл заново
for i in 1 2 3 4 5; do                                                     # сессии vpn-ro (в том числе панели) — завершить
  pgrep -u vpn-ro >/dev/null 2>&1 || break; pkill -KILL -u vpn-ro 2>/dev/null; sleep 1
done
if id -u vpn-ro >/dev/null 2>&1; then userdel -r vpn-ro 2>/dev/null || userdel -f vpn-ro 2>/dev/null; fi
rm -rf /usr/local/lib/vpn-dash-ro /var/lib/vpn-ro
rm -f /usr/local/sbin/vpn-dash-ro
id -u vpn-ro >/dev/null 2>&1 && echo "RO-STILL-USER" || echo RO-REMOVED
"""


class ROPool:
    """SSH-соединения панели под vpn-ro (отдельно от root): только для «Аналитики»."""

    def __init__(self, cfg, known_hosts, check_error):
        self.cfg, self.kh, self.CheckError = cfg, known_hosts, check_error
        self.clients = {}
        self.lock = threading.Lock()

    def drop(self, sid):
        c = self.clients.pop(sid, None)
        if c:
            try:
                c.close()
            except Exception:
                pass

    def _client(self, srv):
        with self.lock:
            c = self.clients.get(srv["id"])
            if c and c.get_transport() and c.get_transport().is_active():
                return c
        key = get_key(self.cfg, create=False)
        if not key:
            raise self.CheckError("ключа панели для vpn-ro ещё нет — поставьте доступ «только чтение» в «Аналитике»")
        c = paramiko.SSHClient()
        self.kh.touch(exist_ok=True)
        c.load_host_keys(str(self.kh))
        c.set_missing_host_key_policy(paramiko.RejectPolicy())     # ключ сервера уже должен быть известен по root-проверкам
        try:
            c.connect(srv["host"], port=int(srv.get("port") or 22), username=USER, pkey=key, timeout=10,
                      banner_timeout=15, auth_timeout=15, look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException:
            raise self.CheckError("vpn-ro не пустили по ключу — доступ «только чтение» на этом сервере не поставлен или ключ сменился")
        except paramiko.BadHostKeyException:
            raise self.CheckError("ключ сервера изменился — проверьте сервер, прежде чем ему доверять")
        except paramiko.SSHException as e:
            raise self.CheckError("SSH (vpn-ro): %s" % e)
        except (socket.timeout, OSError) as e:
            raise self.CheckError("SSH (vpn-ro) не отвечает: %s" % (e or "таймаут"))
        c.get_transport().set_keepalive(30)
        with self.lock:
            self.clients[srv["id"]] = c
        return c

    def run(self, srv, line, timeout=120):
        """Выполнить проверку «имя [аргументы]» под vpn-ro. Вернуть текст вывода."""
        for attempt in (1, 2):
            try:
                c = self._client(srv)
                si, so, se = c.exec_command(line, timeout=timeout)
                out = so.read().decode("utf-8", "replace")
                err = se.read().decode("utf-8", "replace")
                rc = so.channel.recv_exit_status()
                if rc != 0 and not out.strip() and "sudo" in err:
                    raise self.CheckError("sudo на сервере не пустил vpn-ro к проверкам — переставьте доступ «только чтение»")
                return (out + (("\n" + err) if err.strip() and rc else "")).strip()
            except self.CheckError:
                raise
            except (paramiko.SSHException, OSError, EOFError) as e:
                self.drop(srv["id"])
                if attempt == 2:
                    raise self.CheckError("SSH (vpn-ro): %s" % (e or type(e).__name__))
