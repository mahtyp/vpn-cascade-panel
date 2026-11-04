#!/usr/bin/env bash
# Тестовый стенд для панели: «5 серверов» на одной Linux-машине (только для разработки!).
# Ставит фейковые 3X-UI/AWG, заглушки awg/curl/systemctl в /usr/local/sbin и sshd на :2222.
# Все «серверы» — это 127.0.0.2…6:2222 с паролем root из $TB_PASS. Не запускать на настоящем сервере.
#   sudo bash dev/testbed.sh up      — поднять стенд и dev/stand/servers.json
#   sudo bash dev/testbed.sh down    — убрать заглушки и остановить sshd
#   bash dev/testbed.sh run [порт]   — запустить панель на стенде (копия в dev/stand/app)
#   bash dev/testbed.sh stop         — остановить эту панель
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(dirname "$HERE"); ST=$HERE/stand
TB_PASS=${TB_PASS:-testpass123}

up() {
  [ "$(id -u)" = 0 ] || { echo "нужен root"; exit 1; }
  [ -e /etc/x-ui/x-ui.db ] && [ ! -e /etc/x-ui/.testbed ] && { echo "/etc/x-ui уже есть и это не стенд — стоп"; exit 1; }
  mkdir -p "$ST" /etc/x-ui /usr/local/x-ui/bin /etc/amnezia/amneziawg /run/sshd
  touch /etc/x-ui/.testbed
  python3 - <<'PY'
import json, sqlite3, os
exits = [("EU1", "wg0", "127.0.0.3"), ("EU2", "wg1", "127.0.0.4"), ("EU3", "wg2", "127.0.0.5")]
obs, chain = [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}], []
for name, wg, ip in exits:
    obs.append({"tag": "AWG-" + name, "protocol": "freedom", "streamSettings": {"sockopt": {"interface": wg, "tcpMaxSeg": 1240}}})
    chain += ["AWG-" + name]
bals, rules = [], []
names = ["Bal-%d-%s" % (i, t) for i, t in enumerate(chain, 1)]
for i, (n, t) in enumerate(zip(names, chain)):
    bals.append({"tag": n, "selector": [t], "fallbackTag": "_bl_" + names[i + 1] if i + 1 < len(names) else ""})
for n in names[1:]:
    obs.append({"tag": "_bl_" + n, "protocol": "loopback", "settings": {"inboundTag": "_bl_" + n}})
    rules.append({"type": "field", "inboundTag": ["_bl_" + n], "balancerTag": n})
rules.append({"type": "field", "ip": ["91.108.56.0/22", "149.154.171.0/24"], "outboundTag": "AWG-EU2", "comment": "DC5TG"})
rules.append({"type": "field", "network": "tcp,udp", "balancerTag": names[0]})
tpl = {"log": {"loglevel": "warning"}, "outbounds": obs, "routing": {"rules": rules, "balancers": bals},
       "burstObservatory": {"subjectSelector": chain[:-1], "pingConfig": {"destination": "https://www.google.com/generate_204", "interval": "30s"}}}
p = "/etc/x-ui/x-ui.db"
if os.path.exists(p): os.remove(p)
db = sqlite3.connect(p)
db.executescript("""
create table settings(id integer primary key, key text, value text);
create table inbounds(id integer primary key, user_id integer, up integer, down integer, total integer, remark text, enable integer,
  expiry_time integer, listen text, port integer, protocol text, settings text, stream_settings text, tag text, sniffing text);
create table clients(id integer primary key, email text, uuid text, sub_id text, enable integer, up integer, down integer, flow text);
create table client_inbounds(client_id integer, inbound_id integer);""")
for k, v in [("xrayTemplateConfig", json.dumps(tpl)), ("webPort", "15263"), ("subPort", "2096"), ("subEnable", "true"), ("webBasePath", "/stand-panel-path/"), ("subCertFile", "/root/cert/ip/fullchain.pem")]:
    db.execute("insert into settings(key, value) values(?, ?)", (k, v))
db.execute("insert into inbounds values(1,1,0,0,0,'vless',1,0,'',1935,'vless',?,?,'inbound-1935','{}')",
           (json.dumps({"clients": [{"id": "uuid-1", "email": "phone"}], "decryption": "none"}),
            json.dumps({"network": "tcp", "security": "reality", "realitySettings": {"dest": "www.example.com:443", "privateKey": "TEST", "shortIds": ["ab"]}})))
for i, e in enumerate(["phone", "laptop", "tablet"], 1):
    db.execute("insert into clients values(?,?,?,?,1,0,0,'xtls-rprx-vision')", (i, e, "uuid-%d" % i, "sub%d" % i))
    db.execute("insert into client_inbounds values(?,1)", (i,))
db.commit()
for name, wg, ip in exits:
    open("/etc/amnezia/amneziawg/%s.conf" % wg, "w").write(
        "[Interface]\nPrivateKey = TEST\nAddress = 10.8.%s.2/32\nJc = 4\nS1 = 33\nH1 = 1\nTable = off\n\n"
        "[Peer]\nPublicKey = TEST\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\n" % (wg[-1], ip))
PY
  printf '#!/bin/bash\necho "3X-UI v3.8.5"\n' > /usr/local/x-ui/x-ui
  printf '#!/bin/bash\necho "Xray 26.9.9 (Xray, Penetrates Everything.)"\n' > /usr/local/x-ui/bin/xray-linux-amd64
  cat > /usr/local/sbin/awg <<'S'
#!/usr/bin/env python3
# заглушка awg для стенда: ключи, show, set — по конфигам в /etc/amnezia/amneziawg
import base64, glob, hashlib, os, re, sys, time
a, D = sys.argv[1:], "/etc/amnezia/amneziawg"
def conf(i):
    try: return open("%s/%s.conf" % (D, i)).read()
    except OSError: return ""
def pub(priv): return base64.b64encode(hashlib.sha256(priv.strip().encode()).digest()).decode()
def key(t, k):
    m = re.search(r"^%s\s*=\s*(\S+)" % k, t, re.M); return m.group(1) if m else ""
now = int(time.time())
if a[:1] in (["genkey"], ["genpsk"]): print(base64.b64encode(os.urandom(32)).decode())
elif a[:1] == ["pubkey"]: print(pub(sys.stdin.read()))
elif a[:1] == ["--version"]: print("awg-tools v1.0.0 (стенд)")
elif a[:3] == ["show", "all", "latest-handshakes"]:
    for f in sorted(glob.glob(D + "/wg*.conf")): print("%s\tY\t%d" % (os.path.basename(f)[:-5], now - 30))
elif a[:3] == ["show", "all", "dump"]:
    print("awg0\tS\tS\t49366\toff"); print("awg0\tPUB1\t(none)\t127.0.0.2:40000\t10.9.0.2/32\t%d\t1000\t9000\t0" % (now - 30))
elif a[:1] == ["show"] and len(a) >= 3:
    t = conf(a[1])
    if a[2] == "public-key": print(pub(key(t, "PrivateKey")))
    elif a[2] == "listen-port": print(key(t, "ListenPort") or "0")
    elif a[2] == "latest-handshakes":   # /etc/testbed-awg-mimic-bad: с пакетами-масками (I1) выход «не узнаёт» вход
        print("PEER\t%d" % (0 if os.path.exists("/etc/testbed-awg-mimic-bad") and re.search(r"(?m)^\s*I1\s*=", t) else now - 5))
elif a[:1] == ["show"]: print("interface: %s\n  header protection key: (hidden)" % (a[1] if len(a) > 1 else "awg0"))
elif a[:1] == ["set"]: pass
S
  cat > /usr/local/sbin/curl <<'S'
#!/usr/bin/env python3
# заглушка curl для стенда: «выход» через wgN отвечает IP из конфига, остальное — настоящий curl
import os, re, sys, time
args = " ".join(sys.argv[1:])
ip = None
m = re.search(r"--interface (wg\d+)", args)
if m:
    try: ip = re.search(r"^Endpoint\s*=\s*([\d.]+):", open("/etc/amnezia/amneziawg/%s.conf" % m.group(1)).read(), re.M).group(1)
    except Exception: ip = None
if "github.com/bol-van/zapret2/releases/download/" in args:              # стенд: zapret2 из кэша (скачан при up)
    import shutil
    try: shutil.copy("/var/cache/testbed-zapret2.tgz", sys.argv[sys.argv.index("-o") + 1]); sys.exit(0)
    except Exception: sys.exit(22)
QF = "/etc/testbed-quality.json"   # «качество»: {"IP выхода": {"awg_mbps": …, "awg_stall_kb": …}}
if "size_download" in args:        # замер 2 МБ
    import json
    try: q = json.load(open(QF)).get(ip or "", {})
    except Exception: q = {}
    mw = re.search(r"bytes=(\d+)", args); want = int(mw.group(1)) if mw else 2000000
    if q.get("awg_stall_kb"):
        time.sleep(3); sys.stdout.write("000 %d 0 4.0" % (q["awg_stall_kb"] * 1024)); sys.exit(28)
    mbps = q.get("awg_mbps", 80)
    t = want * 8 / mbps / 1e6 / 10          # стенд: в 10 раз быстрее, чтобы не ждать
    time.sleep(min(3, t)); sys.stdout.write("200 %d %d %.2f" % (want, mbps * 1e6 / 8, t)); sys.exit(0)
if "http_code" in args:   # проверка сайта: ответы задаёт /etc/testbed-sites.json {"IP выхода": {"часть имени": код}}
    import json
    url = sys.argv[-1]
    mres = re.search(r"--resolve ([^: ]+):443", args)
    host = mres.group(1) if mres else re.sub(r"^https?://([^/:]+).*$", r"\1", url)
    via = ip or ((os.environ.get("SSH_CONNECTION") or "").split()[2:3] or [""])[0]
    try: rules = json.load(open("/etc/testbed-sites.json")).get(via, {})
    except Exception: rules = {}
    code = next((v for k, v in rules.items() if k in host), 200)
    time.sleep(0.3)
    if not code:
        sys.stdout.write("000 10.0 "); sys.exit(28)
    sys.stdout.write("%d 0.%d 10.0.0.1" % (code, 30 + len(via) % 40)); sys.exit(0)
if ip:
    time.sleep(0.2)
    sys.stdout.write("%s\n0.%d" % (ip, 25 + len(ip) % 20) if "time_total" in args else ip); sys.exit(0)
if "--interface" in args and "ifconfig.me" in args: sys.exit(7)
if "ppa.launchpadcontent.net" in args:   # в контейнере стенда PPA недоступен — делаем вид, что открылся
    sys.stdout.write("200"); sys.exit(0)
os.execv("/usr/bin/curl", ["curl"] + sys.argv[1:])
S
  cat > /usr/local/sbin/ping <<'S'
#!/usr/bin/env python3
# заглушка ping для стенда: адреса 127.0.0.x и туннели wgN «отвечают» с задержкой, потерями и разбросом
# из /etc/testbed-quality.json {"IP или wgN": {"ms": …, "loss": %, "jit": мс}}; остальное — настоящий ping
import json, os, random, re, sys, time
a = sys.argv[1:]
def opt(k, d):
    return a[a.index(k) + 1] if k in a else d
host, iface = a[-1], opt("-I", None)
if not (host.startswith("127.") or iface or host.startswith("10.")): os.execv("/usr/bin/ping", ["ping"] + a)
try: cfg = json.load(open("/etc/testbed-quality.json"))
except Exception: cfg = {}
key = iface or host
if iface:
    try: host = re.search(r"^Endpoint\s*=\s*([\d.]+):", open("/etc/amnezia/amneziawg/%s.conf" % iface).read(), re.M).group(1)
    except Exception: print("ping: SO_BINDTODEVICE %s: No such device" % iface); sys.exit(2)
q = dict(cfg.get(host, {}), **(cfg.get(key, {}) if iface else {}))
n, iv = int(opt("-c", 4)), float(opt("-i", 1))
base = q.get("ms", 15 + int(host.rsplit(".", 1)[1]) * 9 + (6 if iface else 0))
got = 0
for i in range(1, n + 1):
    if random.random() * 100 >= q.get("loss", 0):
        got += 1
        print("64 bytes from %s: icmp_seq=%d ttl=64 time=%.1f ms" % (host, i, max(0.1, base + random.uniform(-1, 1) * q.get("jit", 2))), flush=True)
    time.sleep(iv)
print("%d packets transmitted, %d received" % (n, got)); sys.exit(0 if got else 1)
S
  chmod +x /usr/local/sbin/ping
  # «сертификат Let's Encrypt на IP» (~6 дней, как у 3X-UI) и «acme.sh», который его продлевает
  if [ ! -e /root/.acme.sh/acme.sh ] || [ -e /root/.acme.sh/.testbed ]; then
    mkdir -p /root/cert/ip /root/.acme.sh/127.0.0.2_ecc && touch /root/.acme.sh/.testbed
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 6 -subj /CN=127.0.0.2 \
      -keyout /root/cert/ip/privkey.pem -out /root/cert/ip/fullchain.pem >/dev/null 2>&1
    printf "Le_Domain='127.0.0.2'\nLe_Webroot='no'\nLe_RealFullChainPath='/root/cert/ip/fullchain.pem'\nLe_NextRenewTime='%s'\n" \
      "$(( $(date +%s) + 4*86400 ))" > /root/.acme.sh/127.0.0.2_ecc/127.0.0.2.conf
    printf '#!/bin/bash\n# стенд: acme.sh — «продление» только печатает\necho "[стенд] Skipping. Next renewal time is: later"\n' > /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
  fi
  command -v /usr/bin/ping >/dev/null || apt-get install -y -qq iputils-ping >/dev/null 2>&1 || true
  echo '{"wg1": {"loss": 4, "jit": 30}, "127.0.0.5": {"loss": 6, "jit": 25}, "127.0.0.3": {"awg_stall_kb": 16}, "127.0.0.4": {"awg_mbps": 9}}' > /etc/testbed-quality.json
  echo '{"127.0.0.3": {"youtube": 0, "googlevideo": 0, "ytimg": 0}, "127.0.0.5": {"claude": 403, "anthropic": 403}}' > /etc/testbed-sites.json
  # zapret2: релиз кэшируется (в контейнере стенда интернета нет), подбор стратегий — готовый итог
  [ -s /var/cache/testbed-zapret2.tgz ] || /usr/bin/curl -fsSL https://github.com/bol-van/zapret2/releases/download/v1.0.6/zapret2-v1.0.6.tar.gz -o /var/cache/testbed-zapret2.tgz || rm -f /var/cache/testbed-zapret2.tgz
  cp "$HERE/fake-blockcheck.txt" /etc/testbed-blockcheck.txt
  # база geosite, как у 3X-UI (подсказка адресов в «Zapret»)
  [ -s /var/cache/testbed-geosite.dat ] || /usr/bin/curl -fsSL https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat -o /var/cache/testbed-geosite.dat || rm -f /var/cache/testbed-geosite.dat
  [ -s /var/cache/testbed-geosite.dat ] && mkdir -p /usr/local/x-ui/bin && cp /var/cache/testbed-geosite.dat /usr/local/x-ui/bin/geosite.dat
  # «что режут на входах»: готовые итоги по входам (сеть стенда до этих сайтов не достаёт)
  echo '{"127.0.0.2": {"youtube.com": "sni", "redirector.googlevideo.com": "stall", "instagram.com": "sni", "facebook.com": "sni", "x.com": "ip", "discord.com": "sni", "linkedin.com": "spoof", "rutracker.org": "spoof", "flibusta.is": "dns", "rezka.ag": "stub", "amnezia.org": "sni", "getoutline.org": "sni", "digitalocean.com": "stall", "mailfence.com": "sni"},
        "127.0.0.6": {"i.ytimg.com": "http", "www.youtube.com": "sni", "redirector.googlevideo.com": "stall", "youtube.com": "sni", "instagram.com": "sni", "x.com": "ip", "rutracker.org": "spoof", "github.com": "stall", "raw.githubusercontent.com": "stall", "play.google.com": "slow"}}' > /etc/testbed-dpi.json
  cat > /usr/local/sbin/systemctl <<'S'
#!/bin/bash
A=" x-ui fail2ban awg-quick@wg0 awg-quick@wg1 awg-quick@wg2 awg-quick@awg0 "
U=/etc/testbed-units   # zapret2: «unit=active|inactive»
st() { sed -n "s/^$1=//p" "$U" 2>/dev/null | tail -n1; }
put() { grep -v "^$1=" "$U" 2>/dev/null > "$U.t"; echo "$1=$2" >> "$U.t"; mv "$U.t" "$U"; }
u2=${2%.service}; [ "$2" = --quiet ] || [ "$2" = --now ] && u2=${3%.service}
if [ "$u2" = zapret2 ]; then   # zapret2 на стенде: только состояние, сеть не трогаем; отказ — /etc/testbed-zapret-bad
  s=$(st zapret2)
  case "$1" in
    is-active) [ "$s" = active ] && { [ "$2" = --quiet ] || echo active; exit 0; }; [ "$2" = --quiet ] || echo inactive; exit 3 ;;
    start|restart) [ -e /etc/testbed-zapret-bad ] && { put zapret2 inactive; echo "Job for zapret2.service failed" >&2; exit 1; }; put zapret2 active; exit 0 ;;
    stop) put zapret2 inactive; exit 0 ;;
    disable) [ "$2" = --now ] && put zapret2 inactive; exit 0 ;;
    *) exit 0 ;;
  esac
fi
if [ "$1" = is-active ]; then [ "$2" = --quiet ] && shift; u=${2%.service}; [[ "$A" == *" $u "* ]] && { echo active; exit 0; } || { echo inactive; exit 3; }; fi
if [ "$1" = list-unit-files ]; then u=${2%.service}; [[ "$A" == *" $u "* ]] && echo "$u.service enabled enabled"; exit 0; fi
if [ "${2%.service}" = x-ui ]; then   # «веб-панель 3X-UI»: перечитывает порт/адрес/путь из базы при старте
  case "$1" in
    stop) pkill -x x-ui-web; exit 0 ;;
    start|restart) pkill -x x-ui-web; sleep 0.3; nohup /usr/local/x-ui/x-ui-web /usr/local/x-ui/fake-web.py </dev/null >/dev/null 2>&1 & exit 0 ;;
  esac
fi
exit 0
S
  chmod +x /usr/local/x-ui/x-ui /usr/local/x-ui/bin/xray-linux-amd64 /usr/local/sbin/{awg,curl,systemctl}
  # «Xray»: процесс с xray в имени слушает порт входящего — так vpn-add-exit.sh видит, что Xray поднялся
  pgrep -x xray-linux-srv >/dev/null || cp "$(readlink -f "$(command -v python3)")" /usr/local/x-ui/bin/xray-linux-srv   # занятый файл не перезаписать
  pgrep -x x-ui-web >/dev/null || cp "$(readlink -f "$(command -v python3)")" /usr/local/x-ui/x-ui-web
  cp "$HERE/fake-xui-web.py" /usr/local/x-ui/fake-web.py
  cp "$HERE/fake-ipregion.json" /etc/testbed-ipregion.json; cp "$HERE/fake-ipregion-mm.json" /etc/testbed-ipregion-mm.json; cp "$HERE/fake-ipregion-rep.json" /etc/testbed-ipregion-rep.json; cp "$HERE/fake-ipregion-ai.json" /etc/testbed-ipregion-ai.json; cp "$HERE/fake-neighbors.json" /etc/testbed-neighbors.json; cp "$HERE/fake-dns.json" /etc/testbed-dns.json   # «как видят адрес»
  cp "$HERE/fake-govblock-v4.txt" /etc/testbed-govblock-v4.txt; cp "$HERE/fake-govblock-v6.txt" /etc/testbed-govblock-v6.txt   # «сети госорганов»
  rm -f /etc/testbed-units
  cp "$HERE/fake-ufw.py" /usr/local/sbin/ufw && chmod +x /usr/local/sbin/ufw && rm -f /etc/testbed-ufw.json /etc/testbed-ufw-break
  if ! pgrep -x x-ui-web >/dev/null; then
    nohup /usr/local/x-ui/x-ui-web /usr/local/x-ui/fake-web.py </dev/null >/dev/null 2>&1 &
  fi
  if ! pgrep -x xray-linux-srv >/dev/null; then   # -x: -f совпал бы с командной строкой самой оболочки
    nohup /usr/local/x-ui/bin/xray-linux-srv -c \
      'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 1935)); s.listen(); time.sleep(10**9)' \
      </dev/null >/dev/null 2>&1 &
  fi
  grep -q 'ppa.launchpadcontent.net # testbed' /etc/hosts || echo '127.0.0.1 ppa.launchpadcontent.net # testbed' >> /etc/hosts
  [ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
  printf 'Port 2222\nListenAddress 0.0.0.0\nPermitRootLogin yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nHostKey /etc/ssh/ssh_host_ed25519_key\nSubsystem sftp internal-sftp\n' > "$ST/sshd_config"
  echo "root:$TB_PASS" | chpasswd
  pgrep -f "sshd -f $ST" >/dev/null || /usr/sbin/sshd -f "$ST/sshd_config" -E "$ST/sshd.log"
  # адреса выходов внутри туннелей (10.8.N.1 — как .1 у awg0 на выходе): SSH «через вход» идёт на них
  for n in 0 1 2; do ip addr show dev lo | grep -q "10.8.$n.1/32" || ip addr add "10.8.$n.1/32" dev lo; done
  # «DC Telegram» 127.0.1.1…5:443 с настоящим первым шагом MTProto; DC5 молчит
  [ -f /etc/testbed-mtproto.json ] || echo '{"127.0.1.5": "silent"}' > /etc/testbed-mtproto.json
  if ! { [ -f /run/testbed-mtproto.pid ] && kill -0 "$(cat /run/testbed-mtproto.pid)" 2>/dev/null; }; then
    nohup python3 "$HERE/fake-mtproto.py" </dev/null >/dev/null 2>&1 & echo $! > /run/testbed-mtproto.pid
  fi
  python3 - "$ST/servers.json" <<'PY'
import json, sys
S = [("en1", "Вход-1", "127.0.0.2", "entry", "вход · основной", ""), ("en2", "Вход-2", "127.0.0.6", "entry", "вход · резерв", ""),
     ("ex1", "EU-1", "127.0.0.3", "exit", "", "EU"), ("ex2", "EU-2", "127.0.0.4", "exit", "", "EU"), ("ex3", "EU-3", "127.0.0.5", "exit", "", "EU")]
json.dump({"settings": {"backup_hours": 0, "tg_dc": "\n".join("DC%d 127.0.1.%d" % (i, i) for i in range(1, 6))}, "servers": [{"id": i, "name": n, "host": h, "port": 2222, "user": "root", "role": r,
           "provider": "стенд", "note": note, "cc": cc} for i, n, h, r, note, cc in S]}, open(sys.argv[1], "w"), ensure_ascii=False, indent=1)
PY
  echo "Стенд готов: 127.0.0.2…6:2222, пароль $TB_PASS. Панель: bash dev/testbed.sh run"
}

stop() { [ -f "$ST/app/dash.pid" ] && kill "$(cat "$ST/app/dash.pid")" 2>/dev/null; rm -f "$ST/app/dash.pid"; echo "панель стенда остановлена"; }

down() {
  stop >/dev/null
  [ -f /run/testbed-mtproto.pid ] && kill "$(cat /run/testbed-mtproto.pid)" 2>/dev/null; rm -f /run/testbed-mtproto.pid
  rm -f /etc/testbed-units
  rm -f /usr/local/sbin/awg /usr/local/sbin/curl /usr/local/sbin/systemctl /usr/local/sbin/ufw /usr/local/sbin/docker /usr/local/sbin/ping /etc/testbed-quality.json /etc/testbed-ipregion.json /etc/testbed-ipregion-mm.json /etc/testbed-ipregion-rep.json /etc/testbed-ipregion-ai.json /etc/testbed-neighbors.json /etc/testbed-dns.json /etc/testbed-awg-mimic-bad /etc/testbed-sites.json /etc/testbed-ufw.json /etc/testbed-ufw-break /etc/testbed-docker.json /etc/testbed-mtproto.json /etc/testbed-dpi.json /etc/testbed-blockcheck.txt /etc/testbed-blockcheck-pace /etc/testbed-zapret-bad /etc/testbed-zapret-nohelp
  rm -rf /opt/zapret2 /etc/systemd/system/zapret2.service /root/vpn-zapret.sh
  nft delete table inet vpn_dash_gov 2>/dev/null; rm -rf /etc/vpn-dash /etc/systemd/system/vpn-dash-govblock.service /etc/testbed-govblock-v4.txt /etc/testbed-govblock-v6.txt /root/.vpn-dash-gov-undo*
  pkill -x sshd || true
  for n in 0 1 2; do ip addr del "10.8.$n.1/32" dev lo 2>/dev/null; done
  sshopen all >/dev/null
  pkill -x xray-linux-srv || true
  pkill -x x-ui-web || true
  sed -i '/# testbed$/d' /etc/hosts
  rm -rf /root/.vpn-dash-job /root/vpn-*.sh /root/awg-client-*.conf
  [ -e /root/.acme.sh/.testbed ] && rm -rf /root/.acme.sh /root/cert/ip
  [ -e /etc/x-ui/.testbed ] && rm -rf /etc/x-ui /usr/local/x-ui /etc/amnezia
  echo "Стенд убран"
}

# SSH к «выходу» напрямую с ПК не проходит (как если бы его резали), а через вход и туннель — проходит
sshblock() {
  local ip=${1:?адрес выхода, например 127.0.0.3}
  iptables -C INPUT -d "$ip" -p tcp --dport 2222 -m comment --comment testbed-ssh -j DROP 2>/dev/null \
    || iptables -I INPUT -d "$ip" -p tcp --dport 2222 -m comment --comment testbed-ssh -j DROP
  echo "SSH напрямую к $ip закрыт; через вход (10.8.N.1) — открыт. Вернуть: bash dev/testbed.sh sshopen $ip"
}
sshopen() {
  local ip=${1:-all} r
  iptables -S INPUT 2>/dev/null | grep -- '--comment testbed-ssh' | while read -r r; do
    case "$ip" in all) ;; *) echo "$r" | grep -q -- "-d $ip/32" || continue ;; esac
    eval "iptables ${r/-A/-D}"
  done
  echo "SSH напрямую открыт: $ip"
}

run() {
  local port=${1:-8790} A=$ST/app
  mkdir -p "$A"
  tar -C "$ROOT" --exclude=./dev --exclude=./.git --exclude=./servers.json --exclude=./history.db --exclude=./backups \
      --exclude=./known_hosts --exclude=./__pycache__ --exclude=./jobs --exclude=./secrets -cf - . | tar -C "$A" -xf -
  [ -f "$A/servers.json" ] || cp "$ST/servers.json" "$A/"
  cd "$A"
  # установка нового выхода на стенде: vpn-exit-setup.sh подменяется быстрой имитацией (без apt и сборки ядра),
  # остальные скрипты — настоящие
  mkdir -p "$ST/scripts"; cp "$ROOT"/server-scripts/*.sh "$ST/scripts/"; cp "$HERE/fake-exit-setup.sh" "$ST/scripts/vpn-exit-setup.sh"
  [ -f dash.pid ] && kill "$(cat dash.pid)" 2>/dev/null && sleep 1
  VPN_DASH_STAND=1 VPN_DASH_SCRIPTS=$ST/scripts DASH_PORT=$port DASH_NO_BROWSER=1 nohup python3 dash.py </dev/null > dash.out 2>&1 &
  echo $! > dash.pid
  sleep 1.5
  local T; T=$(curl -s "http://127.0.0.1:$port/" | grep -o 'const TOKEN = "[^"]*"' | cut -d'"' -f2)
  for id in en1 en2 ex1 ex2 ex3; do
    curl -s -X POST -H "X-Dash: $T" -d "{\"id\":\"$id\",\"password\":\"$TB_PASS\"}" "http://127.0.0.1:$port/api/password" >/dev/null
  done
  curl -s -X POST -H "X-Dash: $T" -d '{"what":"all"}' "http://127.0.0.1:$port/api/check" >/dev/null
  echo "Панель на стенде: http://127.0.0.1:$port/ (пароли заданы, проверка запущена; лог: $A/dash.out)"
}

case "${1:-}" in up) up ;; down) down ;; stop) stop ;; sshblock) shift; sshblock "$@" ;; sshopen) shift; sshopen "$@" ;; run) shift; run "$@" ;; *) sed -n 2,8p "$0"; exit 1 ;; esac
