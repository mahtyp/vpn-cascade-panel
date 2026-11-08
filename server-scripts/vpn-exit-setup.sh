#!/usr/bin/env bash
# vpn-exit-setup.sh — делает из чистого VPS выходной сервер каскада:
#   AmneziaWG 3.1 модулем ядра (сервер awg0, без Docker) + fail2ban для SSH.
#
# Запуск на НОВОМ выходном сервере от root (Ubuntu 24.04):
#   bash vpn-exit-setup.sh                установка
#   bash vpn-exit-setup.sh client ИМЯ     клиент AWG для телефона/ноутбука (конфиг + QR-код)
#   bash vpn-exit-setup.sh status         что работает и на каких портах
#
# После установки подключите выход к каждому входу:
#   bash vpn-add-exit.sh ИМЯ IP_ВЫХОДА
#
# Переменные окружения (необязательно):
#   AWG_SUBNET   подсеть туннеля, по умолчанию 10.9.0  (сервер 10.9.0.1)
#   AWG_PORT     UDP-порт AWG, по умолчанию случайный 20000–59999
#   SKIP_FAIL2BAN=1  не настраивать fail2ban
#   ONLY_AWG=1   только AmneziaWG (перевод выхода с Amnezia в Docker): fail2ban не трогается

set -euo pipefail

AWG_DIR=/etc/amnezia/amneziawg
IF=awg0
CONF="$AWG_DIR/$IF.conf"
NET="${AWG_SUBNET:-10.9.0}"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

rnd() { echo $(( $1 + $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % ($2 - $1 + 1) )); }
public_ip() { curl -4 -s -m 10 https://ifconfig.me || hostname -I | awk '{print $1}'; }
wan_if() { ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}'; }

# ---------------------------------------------------------------- проверки

preflight() {
  [ "$(id -u)" -eq 0 ] || die "запустите от root"
  grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null \
    || warn "скрипт проверялся на Ubuntu 24.04, у вас: $(. /etc/os-release; echo "$PRETTY_NAME")"
  local v; v=$(systemd-detect-virt 2>/dev/null || true)
  case "$v" in
    openvz|lxc|lxc-libvirt) die "виртуализация $v — модуль ядра AmneziaWG здесь не встанет, нужен KVM" ;;
  esac
  ok "$(hostname -s), $(public_ip), ядро $(uname -r), виртуализация ${v:-?}"
}

# ---------------------------------------------------------------- пакеты и ядро

# общие функции AmneziaWG (reload_awg_module, add_amnezia_ppa) — из vpn-awg-common.sh рядом
# shellcheck source=vpn-awg-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vpn-awg-common.sh" || { echo "Рядом должен лежать vpn-awg-common.sh" >&2; exit 1; }

stage_packages() {
  apt_begin
  apt-get install -y -q curl ca-certificates openssl jq python3 iputils-ping iptables fail2ban qrencode zstd \
    software-properties-common "linux-headers-$(uname -r)" \
    || die "не поставились пакеты. Если не нашлись linux-headers — обновите систему и перезагрузитесь"
  add_amnezia_ppa
  apt-get install -y -q amneziawg amneziawg-tools
  reload_awg_module
  ok "AmneziaWG: модуль $(modinfo -F version amneziawg), $(awg --version 2>/dev/null | head -n1)"
}

stage_sysctl() {
  say "Ядро: пересылка пакетов и BBR"
  cat > /etc/sysctl.d/99-vpn-exit.conf <<'EOF'
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  # файлы самого образа хостера бывают с тем, что ядро уже не примет (kernel.yama.ptrace_scope и т. п.) — не бросаем
  # установку из-за них, а свои настройки применяем отдельно и проверяем главное — пересылку пакетов
  local out
  if ! out=$(sysctl --system 2>&1 >/dev/null); then
    warn "часть настроек ядра из образа хостера не применилась (не наши, на VPN не влияют): $(printf '%s' "$out" | grep -v '^\*' | tail -2 | tr '\n' ' ')"
  fi
  sysctl -e -q -p /etc/sysctl.d/99-vpn-exit.conf >/dev/null 2>&1 || true
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || { echo "не включилась пересылка пакетов (net.ipv4.ip_forward)" >&2; exit 1; }
  ok "ip_forward=$(sysctl -n net.ipv4.ip_forward), $(sysctl -n net.ipv4.tcp_congestion_control)"
}

# ---------------------------------------------------------------- AmneziaWG

stage_awg() {
  say "AmneziaWG: сервер $IF"
  if [ -f "$CONF" ]; then
    # конфиг с S4 < 16 модуль с HeaderProtectionKey не принимает («Invalid argument»).
    # Клиентов ещё нет — можно спокойно поправить
    local s4; s4=$(awk -F'= *' '/^S4 *=/ {print $2}' "$CONF")
    if [ -n "$s4" ] && [ "$s4" -lt 16 ] && ! grep -q '^\[Peer\]' "$CONF"; then
      sed -i "s/^S4 = .*/S4 = $(rnd 16 32)/" "$CONF"
      ok "$CONF: S4 был $s4 (меньше 16 — не работает с защитой заголовков), заменён"
    fi
    ok "$CONF уже есть — оставляю как есть"
  else
    local PRIV PORT S1 S2 S3 S4 HPK WAN
    PRIV=$(awg genkey)
    PORT=${AWG_PORT:-}
    while [ -z "$PORT" ] || ss -Hlun "sport = :$PORT" | grep -q .; do PORT=$(rnd 20000 59999); done
    # размеры мусорных префиксов: S1 + 56 не должно равняться S2 (иначе пакеты различимы)
    S1=$(rnd 15 150)
    S2=$(rnd 15 150); while [ $((S1 + 56)) -eq "$S2" ]; do S2=$(rnd 15 150); done
    # S4 < 16 вместе с HeaderProtectionKey модуль не принимает («Invalid argument»): поэтому
    # S4 от 16. S3 тоже не меньше 16
    S3=$(rnd 16 64); while [ $((S3 + 64)) -eq $((S2 + 92)) ]; do S3=$(rnd 16 64); done   # размеры пакетов не должны совпасть
    S4=$(rnd 16 32)
    HPK=$(openssl rand -base64 32)
    WAN=$(wan_if); [ -n "$WAN" ] || die "не определился внешний интерфейс"
    mkdir -p "$AWG_DIR"
    ( umask 077
      cat > "$CONF" <<EOF
[Interface]
PrivateKey = $PRIV
Address = $NET.1/24
ListenPort = $PORT
MTU = 1280
Jc = 4
Jmin = 10
Jmax = 50
S1 = $S1
S2 = $S2
S3 = $S3
S4 = $S4
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = $HPK
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
PostUp = iptables -t nat -A POSTROUTING -s $NET.0/24 -o $WAN -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $NET.0/24 -o $WAN -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT
EOF
    )
    ok "конфиг $CONF создан: UDP $PORT, подсеть $NET.0/24, параметры маскировки случайные"
  fi
  systemctl enable "awg-quick@$IF" >/dev/null 2>&1
  if ! systemctl restart "awg-quick@$IF"; then
    journalctl -u "awg-quick@$IF" -n 20 --no-pager >&2 || true
    die "awg0 не поднялся (лог выше)"
  fi
  awg show "$IF" | grep -q 'header protection key' \
    || warn "awg show не показывает header protection key — возможно, старые awg-tools"
  ok "$IF работает, UDP $(awg show "$IF" listen-port)"
}

# ---------------------------------------------------------------- fail2ban

stage_fail2ban() {
  say "fail2ban (SSH)"
  cat > /etc/fail2ban/jail.d/sshd-vpn.local <<'EOF'
[sshd]
enabled  = true
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  ok "fail2ban: $(systemctl is-active fail2ban)"
}

# ---------------------------------------------------------------- клиент для устройства

cmd_client() {
  local NAME=${1:-}
  [ -n "$NAME" ] || die "укажите имя клиента: bash $0 client iPhone"
  [ -f "$CONF" ] || die "сначала установка: bash $0"
  grep -qF "# vpn-client: $NAME" "$CONF" && die "клиент $NAME уже есть (файл /root/awg-client-$NAME.conf)"
  local PRIV PUB PSK SPUB PORT IP T OUT
  PRIV=$(awg genkey); PUB=$(printf '%s' "$PRIV" | awg pubkey); PSK=$(awg genpsk)
  SPUB=$(awg show "$IF" public-key); PORT=$(awg show "$IF" listen-port)
  IP=$(python3 - "$CONF" <<'PY'
import ipaddress, re, sys
txt = open(sys.argv[1]).read()
srv = ipaddress.ip_interface(re.search(r"^Address\s*=\s*([^,\s]+)", txt, re.M).group(1))
used = {ipaddress.ip_interface(a.strip()).ip
        for v in re.findall(r"^AllowedIPs\s*=\s*(.+)$", txt, re.M) for a in v.split(",")}
print(next(h for h in srv.network.hosts() if h != srv.ip and h not in used))
PY
)
  T=$(mktemp); printf '%s\n' "$PSK" > "$T"
  cp "$CONF" "$CONF.bak-$(date +%F_%H%M%S)"
  printf '\n[Peer]\n# vpn-client: %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n' \
    "$NAME" "$PUB" "$PSK" "$IP" >> "$CONF"
  awg set "$IF" peer "$PUB" preshared-key "$T" allowed-ips "$IP/32"
  rm -f "$T"
  OUT="/root/awg-client-$NAME.conf"
  ( umask 077
    {
      printf '[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1280\n' "$PRIV" "$IP"
      sed -n '/^\[Interface\]/,/^\[/p' "$CONF" \
        | grep -E '^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)[[:space:]]*='
      printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n' \
        "$SPUB" "$PSK" "$(public_ip)" "$PORT"
    } > "$OUT"
  )
  ok "клиент $NAME: адрес $IP, конфиг $OUT"
  echo "  Отсканируйте QR в приложении AmneziaVPN («Добавить» → «QR-код»)"
  echo "  или скачайте файл $OUT через SFTP и импортируйте его."
  qrencode -t ansiutf8 < "$OUT" || warn "QR не вывелся — используйте файл"
}

# ---------------------------------------------------------------- статус

cmd_status() {
  say "Выход $(hostname -s), $(public_ip)"
  local s
  for s in "awg-quick@$IF" fail2ban; do
    if systemctl is-active --quiet "$s"; then ok "$s работает"; else warn "$s НЕ работает"; fi
  done
  [ -f "$CONF" ] && ok "AWG: UDP $(awg show "$IF" listen-port 2>/dev/null), клиентов $(grep -c '^\[Peer\]' "$CONF")"
  return 0
}

# ---------------------------------------------------------------- main

main() {
  case "${1:-}" in
    client) preflight >/dev/null; cmd_client "${2:-}" ;;
    status) cmd_status ;;
    "")
      preflight
      stage_packages
      stage_sysctl
      stage_awg
      if [ "${ONLY_AWG:-0}" = 1 ]; then
        ok "AmneziaWG без Docker готов: UDP $(awg show "$IF" listen-port). fail2ban не трогал (ONLY_AWG=1)"
        return 0
      fi
      if [ "${SKIP_FAIL2BAN:-0}" = 1 ]; then warn "fail2ban пропущен (SKIP_FAIL2BAN=1)"; else stage_fail2ban; fi
      cmd_status
      cat <<EOF

  Готово. Теперь подключите этот выход к каждому входу. На каждом входе:
    bash /root/vpn-add-exit.sh ИМЯ $(public_ip)
  (ИМЯ латиницей, например Frankfurt; скрипт спросит пароль root этого сервера)
EOF
      ;;
    *) die "непонятная команда: $1 (можно: client ИМЯ, status)" ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
