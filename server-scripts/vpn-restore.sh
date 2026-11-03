#!/usr/bin/env bash
# vpn-restore.sh — поднимает ещё один вход из бэкапа основного входа (горячий резерв).
#
# Что делает (по этапам):
#   sysctl    BBR и сетевые буферы, как на основном входе
#   packages  пакеты: AmneziaWG 3.x (модуль ядра), fail2ban, утилиты
#   awg       по SSH заходит на выходные серверы, создаёт там НОВОГО AWG-клиента
#             для этого сервера и поднимает wg0, wg1, ... (по одному на выход из бэкапа)
#   xui       ставит 3X-UI той же версии и подкладывает базу из бэкапа
#             (входящий, балансировщики, правило DC5 и т.д.)
#   fail2ban  правила из бэкапа
#   report    итоговая проверка и ссылки подписки для нового сервера
#
# Запуск на НОВОМ сервере от root:
#   bash vpn-restore.sh /root/vpn-backup-<...>.tar.gz
# Отдельные этапы:
#   bash vpn-restore.sh архив.tar.gz --only awg
#   bash vpn-restore.sh архив.tar.gz --skip xui
# Пересоздать AWG-клиентов (старые для этого сервера будут удалены на выходах):
#   bash vpn-restore.sh архив.tar.gz --only awg --force-awg
#
# Переменные окружения:
#   AWG_CONTAINER  имя контейнера Amnezia на выходах (по умолчанию amnezia-awg2;
#                  выходы без Docker от vpn-exit-setup.sh определяются сами)
#   SSH_PORT       порт SSH выходных серверов (по умолчанию 22)
#   XUI_VERSION    версия 3X-UI, если не определилась из бэкапа (например 3.8.5)
#   VPN_NAME       имя этого входа для AWG-клиентов на выходах (по умолчанию hostname)
#
# Пароли от выходных серверов вводятся при запуске и никуда не сохраняются.

set -euo pipefail

AWG_CONTAINER="${AWG_CONTAINER:-amnezia-awg2}"
SSH_PORT="${SSH_PORT:-22}"
AWG_DIR=/etc/amnezia/amneziawg
ALL_STAGES="sysctl packages awg xui fail2ban report"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }

# IP-адреса из сертификата (subjectAltName), по одному в строке
cert_ips() { openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | grep -oE 'IP Address:[0-9.]+' | cut -d: -f2 || true; }

# пары «сертификат<TAB>ключ» панели и подписки из x-ui.db
xui_cert_pairs() {
  python3 - <<'PY'
import sqlite3
db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
st = dict(db.execute("select key, value from settings").fetchall())
seen = set()
for p in ("web", "sub"):
    c, k = st.get(p + "CertFile") or "", st.get(p + "KeyFile") or ""
    if c and c not in seen:
        seen.add(c)
        print(c + "\t" + k)
PY
}
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

# SSH на выход. Одно соединение держится 3 минуты, поэтому пароль спрашивается один раз
# на сервер, даже если команд несколько.
# Если запускает панель, пароли выходов лежат в $VPN_PWDIR/<адрес> (файлы 600, панель удаляет их
# после установки), а порты SSH — в $VPN_PWDIR/<адрес>.port. Иначе пароль спрашивает ssh.
rssh() {   # $1 = хост, дальше команда
  local h=$1; shift
  local port=$SSH_PORT pre=()
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  if [ -n "${VPN_PWDIR:-}" ] && [ -f "$VPN_PWDIR/$h" ]; then
    command -v sshpass >/dev/null || apt-get install -y -q sshpass >/dev/null
    [ -f "$VPN_PWDIR/$h.port" ] && port=$(cat "$VPN_PWDIR/$h.port")
    pre=(sshpass -f "$VPN_PWDIR/$h")
  fi
  "${pre[@]}" ssh -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
      -o ControlMaster=auto -o "ControlPath=/root/.ssh/cm-vpn-%C" -o ControlPersist=180 \
      "root@$h" "$@"
}

# туннели AWG этого сервера (wg0, wg1, ...)
awg_ifaces() { local f; for f in "$AWG_DIR"/wg*.conf; do [ -e "$f" ] && basename "$f" .conf; done; return 0; }

# Параметры обфускации, которые переносятся с сервера в конфиг клиента
AWG_KEYS="Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies"

# ---------------------------------------------------------------- подготовка

prepare() {
  [ "$(id -u)" -eq 0 ] || die "запустите от root"
  [ -f "$ARCHIVE" ] || die "нет файла бэкапа: $ARCHIVE"
  if ! grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null; then
    warn "скрипт проверялся на Ubuntu 24.04, у вас: $(. /etc/os-release; echo "$PRETTY_NAME")"
  fi
  WORK=$(mktemp -d /root/vpn-restore.XXXXXX)
  chmod 700 "$WORK"
  trap 'rm -rf "$WORK"' EXIT
  tar -xzf "$ARCHIVE" -C "$WORK"
  SRC=$(find "$WORK" -mindepth 2 -maxdepth 2 -type d -name files | head -n1)
  [ -n "$SRC" ] || die "в архиве нет папки files — это точно бэкап от vpn-backup.sh?"
  VERS="$(dirname "$SRC")/versions.txt"
  OLD_IP=$(sed -n 's/^ip=//p' "$VERS" 2>/dev/null || true)
  OLD_XUI=$(sed -n 's/^xui=//p' "$VERS" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)
  NEW_IP=$(hostname -I | awk '{print $1}')
  ok "бэкап распакован (сервер-источник: ${OLD_IP:-неизвестен}, 3X-UI ${OLD_XUI:-?})"
  ok "этот сервер: $(hostname -s), $NEW_IP"
}

# ---------------------------------------------------------------- sysctl

stage_sysctl() {
  say "sysctl: BBR и буферы"
  if [ -f "$SRC/etc/sysctl.conf" ]; then
    # настройки памяти (swappiness и т. п.) у каждого сервера свои — их из бэкапа не переносим:
    # vm.swappiness=0 на маленьком сервере (0,5 ГБ) оставляет подкачку пустой, пока память не кончится
    grep -hvE '^[[:space:]]*(#|$)|^[[:space:]]*vm\.' "$SRC/etc/sysctl.conf" > /etc/sysctl.d/99-vpn-restore.conf || true
  fi
  if [ "$(awk '/^MemTotal/ {print $2}' /proc/meminfo)" -lt 1500000 ] && [ "$(swapon --show --noheadings | wc -l)" != 0 ]; then
    echo 'vm.swappiness=10' > /etc/sysctl.d/99-zz-vpn-swap.conf
    # /etc/sysctl.conf применяется последним и перебивает sysctl.d (у RUVDS там стоит vm.swappiness = 0)
    sed -i -E 's/^[[:space:]]*vm\.swappiness[[:space:]]*=.*/vm.swappiness = 10/' /etc/sysctl.conf 2>/dev/null || true
    ok "мало памяти — подкачка включается раньше (vm.swappiness=10)"
  fi
  grep -q 'tcp_congestion_control' /etc/sysctl.d/99-vpn-restore.conf 2>/dev/null || {
    echo 'net.core.default_qdisc=fq' >> /etc/sysctl.d/99-vpn-restore.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.d/99-vpn-restore.conf
  }
  sysctl --system >/dev/null
  ok "$(sysctl -n net.ipv4.tcp_congestion_control) включён"
}

# ---------------------------------------------------------------- пакеты
# общие функции AmneziaWG (reload_awg_module, add_amnezia_ppa) — из vpn-awg-common.sh рядом
# shellcheck source=vpn-awg-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vpn-awg-common.sh" || { echo "Рядом должен лежать vpn-awg-common.sh" >&2; exit 1; }


stage_packages() {
  apt_begin
  apt-get install -y -q curl ca-certificates openssl python3 jq software-properties-common \
    fail2ban "linux-headers-$(uname -r)"
  add_amnezia_ppa
  apt-get install -y -q amneziawg amneziawg-tools
  reload_awg_module
  ok "AmneziaWG: модуль $(modinfo -F version amneziawg), $(awg --version 2>/dev/null | head -n1)"
}

# ---------------------------------------------------------------- AWG

# Скрипт, который выполняется на выходном сервере (получает C, PUB, PSK, NAME, REPLACE в начале)
remote_body() {
cat <<'REMOTE'
set -euo pipefail
umask 077
command -v python3 >/dev/null || { echo "ERR: на сервере нет python3" >&2; exit 2; }
# Два вида выходов: Amnezia в Docker (поставлен из приложения) и AmneziaWG модулем ядра
# (поставлен vpn-exit-setup.sh, конфиг /etc/amnezia/amneziawg/awg0.conf)
# AWG_MODE=native — клиента заводим в AmneziaWG без Docker, даже если контейнер ещё работает (перевод выхода)
if [ "${AWG_MODE:-}" != native ] && command -v docker >/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$C"; then
  MODE=docker
  CONF=$(docker exec "$C" sh -c 'ls /opt/amnezia/awg/*.conf 2>/dev/null' | head -n1)
  [ -n "$CONF" ] || { echo "ERR: в контейнере нет /opt/amnezia/awg/*.conf" >&2; exit 2; }
  X() { docker exec "$C" "$@"; }
elif [ -f /etc/amnezia/amneziawg/awg0.conf ]; then
  MODE=native
  CONF=/etc/amnezia/amneziawg/awg0.conf
  X() { "$@"; }
else
  echo "ERR: на сервере нет ни контейнера $C, ни /etc/amnezia/amneziawg/awg0.conf" >&2; exit 2
fi
IF=$(basename "$CONF" .conf)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
if [ "$MODE" = docker ]; then
  docker cp "$C:$CONF" "$T/server.conf"
  docker cp "$C:/opt/amnezia/awg/clientsTable" "$T/clientsTable" 2>/dev/null || true
  HOSTPORT=$(docker port "$C" 2>/dev/null | awk -F: '/udp/ {print $NF; exit}')
else
  cp "$CONF" "$T/server.conf"
  HOSTPORT=""
fi
cp "$T/server.conf" "/root/amnezia-$IF.conf.bak-$(date +%F_%H%M%S)"
SPUB=$(X awg show "$IF" public-key)
PUB="$PUB" PSK="$PSK" NAME="$NAME" REPLACE="$REPLACE" python3 - "$T" > "$T/out" <<'PY'
import datetime, ipaddress, json, os, re, sys
T = sys.argv[1]
pub, psk, name, replace = (os.environ[k] for k in ("PUB", "PSK", "NAME", "REPLACE"))
marker = "# vpn-restore: " + name
txt = open(T + "/server.conf").read()

old_pub = ""
blk = re.compile(r"\n*\[Peer\]\n" + re.escape(marker) + r"\n.*?(?=\n\[|\Z)", re.S)
m = blk.search(txt)
if m:
    if replace != "1":
        print("ERR: на сервере уже есть клиент " + name + " (пересоздать: vpn-restore.sh --force-awg или vpn-add-exit.sh --force)", file=sys.stderr)
        sys.exit(3)
    k = re.search(r"PublicKey\s*=\s*(\S+)", m.group(0))
    old_pub = k.group(1) if k else ""
    txt = blk.sub("", txt)

iface, used, section = {}, set(), None
for line in txt.splitlines():
    s = line.strip()
    if s.startswith("["):
        section = s.lower(); continue
    if not s or s.startswith("#") or "=" not in s:
        continue
    k, v = (x.strip() for x in s.split("=", 1))
    if section == "[interface]":
        iface[k] = v
    elif section == "[peer]" and k.lower() == "allowedips":
        for a in v.split(","):
            try:
                used.add(ipaddress.ip_interface(a.strip()).ip)
            except ValueError:
                pass

addr = iface.get("Address", "").split(",")[0].strip()
if not addr:
    print("ERR: в [Interface] сервера нет Address", file=sys.stderr); sys.exit(4)
srv = ipaddress.ip_interface(addr)
ip = next((h for h in srv.network.hosts() if h != srv.ip and h not in used), None)
if ip is None:
    print("ERR: в подсети " + str(srv.network) + " нет свободных адресов", file=sys.stderr); sys.exit(4)

txt = txt.rstrip("\n") + "\n\n[Peer]\n%s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n" % (marker, pub, psk, ip)
with open(T + "/server.conf.new", "w") as f:
    f.write(txt)

ct = T + "/clientsTable"
if os.path.exists(ct):
    try:
        data = json.load(open(ct))
        if isinstance(data, list):
            data = [d for d in data if not (isinstance(d, dict) and d.get("clientId") == old_pub)]
            data.append({"clientId": pub, "userData": {
                "clientName": name,
                "creationDate": datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")}})
            with open(ct + ".new", "w") as f:
                json.dump(data, f, indent=4)
        else:
            print("WARN: clientsTable в незнакомом формате, в приложении Amnezia клиент не появится", file=sys.stderr)
    except Exception as e:
        print("WARN: clientsTable не прочитан (%s), в приложении Amnezia клиент не появится" % e, file=sys.stderr)

print("CLIENT_IP=%s" % ip)
print("OLD_PUB=%s" % old_pub)
print("LISTEN_PORT=%s" % iface.get("ListenPort", ""))
for k in os.environ.get("AWG_KEYS", "").split():
    if k in iface:
        print("P:%s = %s" % (k, iface[k]))
PY
CIP=$(sed -n 's/^CLIENT_IP=//p' "$T/out")
OLD=$(sed -n 's/^OLD_PUB=//p' "$T/out")
LP=$(sed -n 's/^LISTEN_PORT=//p' "$T/out")
printf '%s\n' "$PSK" > "$T/psk"
if [ "$MODE" = docker ]; then
  docker cp "$T/server.conf.new" "$C:$CONF"
  docker cp "$T/psk" "$C:/tmp/vpn-restore.psk"
  PSKF=/tmp/vpn-restore.psk
else
  install -m 600 "$T/server.conf.new" "$CONF"
  PSKF="$T/psk"
fi
if [ -n "$OLD" ]; then X awg set "$IF" peer "$OLD" remove; fi
X awg set "$IF" peer "$PUB" preshared-key "$PSKF" allowed-ips "$CIP/32"
if [ "$MODE" = docker ]; then
  docker exec "$C" rm -f /tmp/vpn-restore.psk
  if [ -f "$T/clientsTable.new" ]; then docker cp "$T/clientsTable.new" "$C:/opt/amnezia/awg/clientsTable"; fi
fi
grep -v '^OLD_PUB=' "$T/out" | grep -v '^LISTEN_PORT='
echo "SERVER_PUB=$SPUB"
echo "PORT=${HOSTPORT:-$LP}"
REMOTE
}

awg_add_exit() {   # $1 = интерфейс (wg0/wg1), $2 = адрес выхода
  local IFACE=$1 HOST=$2 NAME PRIV PUB PSK OUT SERVER_PUB PORT CIP PARAMS
  NAME="${VPN_NAME:-$(hostname -s)}-$IFACE"
  PRIV=$(awg genkey); PUB=$(printf '%s' "$PRIV" | awg pubkey); PSK=$(awg genpsk)
  if [ -n "${VPN_PWDIR:-}" ] && [ -f "$VPN_PWDIR/$HOST" ]; then echo "  Подключаюсь к $HOST"
  else echo "  Подключаюсь к $HOST. Если спросит пароль — введите пароль root этого сервера:"; fi
  OUT=$( {
    printf 'C=%q\nPUB=%q\nPSK=%q\nNAME=%q\nREPLACE=%q\nAWG_MODE=%q\nexport AWG_KEYS=%q\n' \
      "$AWG_CONTAINER" "$PUB" "$PSK" "$NAME" "${FORCE_AWG:-0}" "${AWG_MODE:-}" "$AWG_KEYS"
    remote_body
  } | rssh "$HOST" 'bash -s' ) \
    || die "не удалось создать клиента на $HOST (сообщение выше)"
  SERVER_PUB=$(sed -n 's/^SERVER_PUB=//p' <<<"$OUT")
  PORT=$(sed -n 's/^PORT=//p' <<<"$OUT")
  CIP=$(sed -n 's/^CLIENT_IP=//p' <<<"$OUT")
  PARAMS=$(sed -n 's/^P://p' <<<"$OUT")
  [ -n "$SERVER_PUB" ] && [ -n "$PORT" ] && [ -n "$CIP" ] || die "с $HOST пришёл неполный ответ"

  mkdir -p "$AWG_DIR"
  [ -f "$AWG_DIR/$IFACE.conf" ] && cp "$AWG_DIR/$IFACE.conf" "$AWG_DIR/$IFACE.conf.bak-$(date +%F_%H%M%S)"
  ( umask 077
    cat > "$AWG_DIR/$IFACE.conf" <<EOF
[Interface]
PrivateKey = $PRIV
Address = $CIP/32
Table = off
MTU = 1280
$PARAMS

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $HOST:$PORT
PersistentKeepalive = 25
EOF
  )
  ok "клиент $NAME создан на $HOST, адрес в туннеле $CIP"

  systemctl enable "awg-quick@$IFACE" >/dev/null 2>&1
  systemctl restart "awg-quick@$IFACE"
  sleep 4
  local HS
  HS=$(awg show "$IFACE" latest-handshakes | awk '{print $2}')
  if [ -n "$HS" ] && [ "$HS" != "0" ]; then
    ok "$IFACE: handshake есть, выход через $(curl -s -m 10 --interface "$IFACE" https://ifconfig.me || echo '?')"
  else
    warn "$IFACE: handshake пока нет — проверьте позже: awg show $IFACE"
  fi
}

stage_awg() {
  say "AmneziaWG: новые клиенты на выходах"
  command -v awg >/dev/null || die "нет awg — сначала этап packages"
  local found=0 f IFACE EP HOST
  for f in "$SRC$AWG_DIR"/wg*.conf; do
    [ -e "$f" ] || continue
    found=1
    IFACE=$(basename "$f" .conf)
    EP=$(awk -F'=' '/^[[:space:]]*Endpoint/ {gsub(/[[:space:]]/, "", $2); print $2}' "$f")
    HOST=${EP%:*}
    [ -n "$HOST" ] || { warn "$IFACE: в старом конфиге нет Endpoint — пропускаю"; continue; }
    echo
    echo "  $IFACE → $HOST"
    if [ -f "$AWG_DIR/$IFACE.conf" ] && [ "${FORCE_AWG:-0}" != "1" ]; then
      warn "$IFACE уже настроен на этом сервере — пропускаю (пересоздать: --force-awg)"
      continue
    fi
    awg_add_exit "$IFACE" "$HOST"
  done
  [ "$found" = 1 ] || warn "в бэкапе нет конфигов AWG"
}

# ---------------------------------------------------------------- 3X-UI

stage_xui() {
  say "3X-UI"
  [ -f "$SRC/etc/x-ui/x-ui.db" ] || die "в бэкапе нет x-ui.db"
  if [ ! -x /usr/local/x-ui/x-ui ]; then
    local VER="${XUI_VERSION:-$OLD_XUI}"
    [ -n "$VER" ] || read -rp "  Какая версия 3X-UI стоит на основном входе (например 3.8.5)? " VER
    VER=${VER#v}
    echo "  Ставлю 3X-UI v$VER официальным установщиком."
    echo "  На его вопросы можно отвечать как угодно: настройки панели заменятся настройками из бэкапа."
    # Без терминала (из панели) установщик идёт без вопросов; сертификат — Let's Encrypt на IP
    # этого сервера (нужен открытый порт 80), чтобы подписка по https заработала сразу.
    XUI_SSL_MODE="${XUI_SSL_MODE:-ip}" XUI_SERVER_IP="${XUI_SERVER_IP:-$NEW_IP}" \
      bash <(curl -fsSL https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh) "v$VER"
  else
    ok "3X-UI уже установлена: $( { /usr/local/x-ui/x-ui -v 2>/dev/null || true; } | head -n1)"
  fi
  systemctl stop x-ui
  sleep 1
  local TS f
  TS=$(date +%F_%H%M%S)
  # база в режиме WAL: рядом лежат x-ui.db-wal и x-ui.db-shm. Если подменить только
  # основной файл, SQLite при запуске накатит старый журнал поверх бэкапа
  for f in x-ui.db x-ui.db-wal x-ui.db-shm; do
    [ -f "/etc/x-ui/$f" ] && mv "/etc/x-ui/$f" "/etc/x-ui/$f.before-restore-$TS"
  done
  install -D -m 600 "$SRC/etc/x-ui/x-ui.db" /etc/x-ui/x-ui.db
  # сертификаты панели и подписки (пути — из базы)
  local crt key
  while IFS=$'\t' read -r crt key; do
    [ -n "$crt" ] || continue
    if [ ! -f "$SRC$crt" ]; then
      warn "в бэкапе нет $crt — панель может не открыться по HTTPS"; continue
    fi
    if [ -n "${OLD_IP:-}" ] && cert_ips "$SRC$crt" | grep -qxF "$OLD_IP"; then
      # сертификат Let's Encrypt на IP старого сервера — здесь он не подходит
      if [ -f "$crt" ] && cert_ips "$crt" | grep -qxF "$NEW_IP"; then
        ok "сертификат $crt уже выпущен для $NEW_IP — оставляю его"; continue
      fi
      warn "$crt выпущен для IP основного входа ($OLD_IP) — ставлю временно, новый нужно выпустить (см. итог)"
    fi
    install -D -m 600 "$SRC$crt" "$crt"
    [ -n "$key" ] && [ -f "$SRC$key" ] && install -D -m 600 "$SRC$key" "$key"
    ok "сертификат $crt"
  done < <(xui_cert_pairs)
  systemctl start x-ui
  sleep 3
  systemctl is-active --quiet x-ui || die "x-ui не запустилась: journalctl -u x-ui -n 50"
  # сверка: в рабочей базе те же входящие и тот же порт панели, что в бэкапе
  local cmp
  cmp=$(python3 - "$SRC/etc/x-ui/x-ui.db" <<'PY'
import sqlite3, sys
def info(path):
    db = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    n = db.execute("select count(*) from inbounds").fetchone()[0]
    port = (db.execute("select value from settings where key='webPort'").fetchone() or ["?"])[0]
    return n, port
b, l = info(sys.argv[1]), info("/etc/x-ui/x-ui.db")
print("ok" if b == l else "бэкап: входящих %s, порт панели %s; на сервере: входящих %s, порт %s" % (b + l))
PY
)
  [ "$cmp" = ok ] || die "база панели не совпадает с бэкапом ($cmp)"
  ok "панель запущена с настройками из бэкапа"
}

# ---------------------------------------------------------------- fail2ban

stage_fail2ban() {
  say "fail2ban"
  command -v fail2ban-client >/dev/null || apt-get install -y -q fail2ban
  [ -f "$SRC/etc/fail2ban/jail.local" ] && cp "$SRC/etc/fail2ban/jail.local" /etc/fail2ban/
  [ -d "$SRC/etc/fail2ban/jail.d" ] && cp -a "$SRC/etc/fail2ban/jail.d/." /etc/fail2ban/jail.d/
  systemctl enable --now fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  ok "fail2ban: $(systemctl is-active fail2ban)"
}

# ---------------------------------------------------------------- итог

stage_report() {
  say "Проверка"
  local s
  for s in x-ui $(awg_ifaces | sed 's/^/awg-quick@/') fail2ban; do
    if systemctl is-active --quiet "$s"; then ok "$s работает"; else warn "$s НЕ работает"; fi
  done
  for s in $(awg_ifaces); do
    if ip link show "$s" >/dev/null 2>&1; then
      ok "$s → $(curl -s -m 10 --interface "$s" https://ifconfig.me || echo 'нет ответа')"
    fi
  done

  say "Подписка и панель на новом сервере"
  local crt key ips
  while IFS=$'\t' read -r crt key; do
    [ -f "$crt" ] || continue
    ips=$(cert_ips "$crt" | paste -sd, -)
    if [ -n "$ips" ] && ! cert_ips "$crt" | grep -qxF "$NEW_IP"; then
      warn "сертификат $crt выпущен для $ips, а этот сервер $NEW_IP."
      warn "  Пока его не заменить, подписка по https у клиентов не обновится."
      warn "  Выпустите новый: команда x-ui → управление SSL-сертификатом → сертификат для IP-адреса."
    elif ! openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1; then
      warn "сертификат $crt просрочен — перевыпустите его в меню x-ui"
    fi
  done < <(xui_cert_pairs)
  NEW_IP="$NEW_IP" OLD_IP="${OLD_IP:-}" python3 - <<'PY'
import json, os, sqlite3
db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
st = dict(db.execute("select key, value from settings").fetchall())
new, old = os.environ["NEW_IP"], os.environ["OLD_IP"]

def table_cols(t):
    return [r[1] for r in db.execute('pragma table_info("%s")' % t)]

# адрес старого сервера где угодно в базе: настройки, входящие (externalProxy), hosts…
if old:
    hits = []
    for (t,) in db.execute("select name from sqlite_master where type='table'"):
        if t in ("sqlite_sequence", "inbound_client_ips", "node_client_ips"):
            continue
        for c in table_cols(t):
            try:
                n = db.execute('select count(*) from "%s" where cast("%s" as text) like ?' % (t, c),
                               ("%" + old + "%",)).fetchone()[0]
            except Exception:
                continue
            if n:
                where = ""
                if t == "settings":
                    where = " (" + ", ".join(k for (k,) in db.execute(
                        "select key from settings where value like ?", ("%" + old + "%",))) + ")"
                hits.append("%s.%s%s" % (t, c, where))
    for h in hits:
        print("  ! в базе остался IP старого сервера %s: %s" % (old, h))
    if hits:
        print("    Если это адрес в подписке (externalProxy, hosts, subDomain) — устройства по второй")
        print("    подписке будут ходить на старый сервер. Поправьте в панели и пришлите вывод.")
https = bool(st.get("webCertFile"))
if (st.get("webListen") or "").startswith("127."):
    print("  Панель:   закрыта из интернета (как в бэкапе) — открывается кнопкой «3X-UI» в панели каскада")
else:
    print("  Панель:   %s://%s:%s%s" % ("https" if https else "http", new, st.get("webPort", "?"), st.get("webBasePath", "/")))
print("  Логин и пароль — те же, что на основном входе.")
if st.get("subEnable", "true") == "false":
    print("  Подписка выключена в настройках панели.")
else:
    sub_https = bool(st.get("subCertFile"))
    base = st.get("subURI") or "%s://%s:%s%s" % ("https" if sub_https else "http", new, st.get("subPort", "2096"), st.get("subPath", "/sub/"))
    if not base.endswith("/"):
        base += "/"
    subs = set()
    # старые версии: клиенты внутри JSON входящего
    for (settings,) in db.execute("select settings from inbounds where enable=1"):
        try:
            for c in json.loads(settings).get("clients", []):
                if c.get("enable", True) and c.get("subId"):
                    subs.add((c.get("email", ""), c["subId"]))
        except Exception:
            pass
    # 3.8+: отдельная таблица clients
    cols = table_cols("clients") if db.execute(
        "select 1 from sqlite_master where name='clients'").fetchone() else []
    def pick(*names):
        for n in names:
            for c in cols:
                if c.lower() == n:
                    return c
    sid_c, mail_c, en_c = pick("sub_id", "subid"), pick("email", "name", "remark"), pick("enable", "enabled")
    if sid_c:
        q = 'select "%s", %s, %s from clients' % (sid_c, '"%s"' % mail_c if mail_c else "''", '"%s"' % en_c if en_c else "1")
        for sid, mail, en in db.execute(q):
            if sid and en not in (0, "0", "false", False):
                subs.add((mail or "", sid))
    for email, sid in sorted(subs):
        print("  Подписка %-12s %s%s" % (email, base, sid))
    if not subs:
        print("  Ссылки подписки не нашлись. Колонки clients: %s" % ", ".join(cols))
        print("  Возьмите ссылку с основного входа и замените в ней IP на %s." % new)
PY
  cat <<'EOF'

  Что дальше:
   1. На устройствах добавьте ссылку подписки выше как ВТОРУЮ подписку (старую оставьте).
   2. В приложении Amnezia на выходах новые клиенты видны под именами <сервер>-wg0 / <сервер>-wg1.
   3. Новый сервер — копия основного входа: если потом что-то меняете в панели одного, повторите на другом.
EOF
}

# ---------------------------------------------------------------- main

main() {
  ARCHIVE=${1:-}
  [ -n "$ARCHIVE" ] && [ "${ARCHIVE#-}" = "$ARCHIVE" ] || die "укажите файл бэкапа: bash $0 /root/vpn-backup-....tar.gz"
  shift
  local only="" skip="" st
  FORCE_AWG=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --only) only="$2"; shift 2 ;;
      --skip) skip="$skip $2"; shift 2 ;;
      --force-awg) FORCE_AWG=1; shift ;;
      *) die "непонятный параметр: $1" ;;
    esac
  done
  prepare
  for st in $ALL_STAGES; do
    [ -n "$only" ] && [[ " $only " != *" $st "* ]] && [ "$st" != report ] && continue
    [[ " $skip " == *" $st "* ]] && continue
    "stage_$st"
  done
  say "Готово"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
