"""«Сети госорганов»: на входах не пускать новые подключения из подсетей госорганов РФ (РКН, ведомства, их подрядчики).

Список — github.com/C24Be/AS_Network_List (BSD-2-Clause, обновляется раз в сутки), скачивается ЭТИМ компьютером
и проверяется здесь: только адреса сетей, без частных и слишком крупных. На сервере — своя таблица nftables
`inet vpn_dash_gov`, отдельно от ufw/fail2ban/Docker: `ct state new` из списка → drop. Ответы на подключения самого
сервера (Xray «напрямую» на госуслуги и т. п.) проходят: это уже не новые соединения. Свои адреса (этот компьютер, кто
сейчас подключён к входу, список из «Настроек») — в наборе keep, он проверяется первым.
Включение — с «ремнём», как у ufw: через undo_s секунд прежнее состояние вернётся само, если панель не подтвердит.
"""
import hashlib
import ipaddress
import re
import time

SRC = "https://github.com/C24Be/AS_Network_List"
URLS = {"v4": "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt",
        "v6": "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v6.txt"}
MIN_PREFIX = {4: 12, 6: 24}     # крупнее /12 (IPv4) и /24 (IPv6) — подозрительно, такую строку не берём
MIN_V4, MAX_V4 = 200, 20000     # сколько сетей IPv4 считаем нормальным списком
TABLE = "vpn_dash_gov"


def parse(text, ver, local_ok=False):
    """Текст списка → (сети, сколько строк отброшено). Пустые строки и комментарии пропускаются.
    local_ok — стенд: там «серверы» живут на 127.0.0.x."""
    nets, bad = [], 0
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        try:
            n = ipaddress.ip_network(s, strict=False)
        except ValueError:
            bad += 1
            continue
        if n.version != ver or n.prefixlen < MIN_PREFIX[ver] or not (n.is_global or local_ok and n.is_loopback):
            bad += 1
            continue
        nets.append(n)
    return [str(n) for n in ipaddress.collapse_addresses(nets)] if nets else [], bad


def check_list(v4, v6, bad):
    """Похоже ли на нормальный список. → None или текст, почему не берём."""
    if not MIN_V4 <= len(v4) <= MAX_V4:
        return "в списке %d сетей IPv4 — непохоже на обычный список (ждём %d–%d)" % (len(v4), MIN_V4, MAX_V4)
    if bad > (len(v4) + len(v6)) * 0.05 + 5:
        return "в списке много непонятных строк (%d) — не беру" % bad
    return None


def fetch(get, local_ok=False):
    """get(url) → текст. → {at, sha, v4, v6, bad} или ValueError с понятным текстом."""
    t4, t6 = get(URLS["v4"]), get(URLS["v6"])
    v4, b4 = parse(t4, 4, local_ok)
    v6, b6 = parse(t6, 6, local_ok)
    err = check_list(v4, v6, b4 + b6)
    if err:
        raise ValueError(err)
    sha = hashlib.sha256(("\n".join(v4) + "|" + "\n".join(v6)).encode()).hexdigest()[:16]
    return {"at": time.time(), "sha": sha, "v4": v4, "v6": v6, "bad": b4 + b6}


def keep_list(text):
    """Свои адреса из «Настроек» (по строке или через пробел/запятую): IP или сеть. → список строк."""
    out = []
    for s in re.split(r"[\s,;]+", str(text or "")):
        if not s:
            continue
        try:
            out.append(str(ipaddress.ip_network(s, strict=False)))
        except ValueError:
            pass
    return out


def hits(nets, addrs):
    """Какие из адресов попадают в список. → [(адрес, сеть)]"""
    idx = [ipaddress.ip_network(n) for n in nets]
    out = []
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        n = next((x for x in idx if x.version == ip.version and ip in x), None)
        if n:
            out.append((a, str(n)))
    return out


def nft_script(v4, v6, keep):
    """Файл для `nft -f`: заменяет таблицу целиком за один раз (или не меняет ничего, если в нём ошибка)."""
    k4 = [k for k in keep if ":" not in k]
    k6 = [k for k in keep if ":" in k]

    def st(name, typ, items):
        el = (" elements = { %s }" % ", ".join(items)) if items else ""
        return "  set %s { type %s; flags interval; auto-merge;%s }\n" % (name, typ, el)
    return ("table inet %s\ndelete table inet %s\n" % (TABLE, TABLE)
            + "table inet %s {\n" % TABLE
            + st("gov4", "ipv4_addr", v4) + st("gov6", "ipv6_addr", v6)
            + st("keep4", "ipv4_addr", k4) + st("keep6", "ipv6_addr", k6)
            + "  chain input {\n    type filter hook input priority -5; policy accept;\n"
            + "    ct state != new accept\n"
            + "    ip saddr @keep4 accept\n    ip6 saddr @keep6 accept\n"
            + "    ip saddr @gov4 counter drop comment \"gov4\"\n    ip6 saddr @gov6 counter drop comment \"gov6\"\n  }\n}\n")


def nft_update(v4, v6, keep):
    """Для `nft -f` поверх уже включённой таблицы: только новые списки сетей. Правила и их счётчики не трогаются
    (вся замена — одна транзакция: либо целиком, либо ничего)."""
    k4 = [k for k in keep if ":" not in k]
    k6 = [k for k in keep if ":" in k]
    out = ""
    for name, items in (("gov4", v4), ("gov6", v6), ("keep4", k4), ("keep6", k6)):
        out += "flush set inet %s %s\n" % (TABLE, name)
        if items:
            out += "add element inet %s %s { %s }\n" % (TABLE, name, ", ".join(items))
    return out


# ------------------------------------------------------------------ на сервере (python3 -)
# P = {"do": "apply", "nft": текст, "meta": {...}, "undo_s": 300} | {"do": "confirm"} | {"do": "undo"} | {"do": "off"} | {"do": "who", "ports": [...]}
# apply: ставит nftables (только пакет, его службу не включает), прежнее состояние — в .prev, «ремень» его вернёт.

GOV_PY = r'''
import json, os, shutil, signal, subprocess
D = "/etc/vpn-dash"
NFT, META, PREV, PREVM = D + "/govblock.nft", D + "/govblock.json", D + "/govblock.nft.prev", D + "/govblock.json.prev"
UNIT = "/etc/systemd/system/vpn-dash-govblock.service"
UNDO, UNDO_SH = "/root/.vpn-dash-gov-undo", "/root/.vpn-dash-gov-undo.sh"
TABLE = "vpn_dash_gov"


def sh(c, t=300):
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
        os.killpg(int(open(UNDO).read().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    for f in (UNDO, UNDO_SH):
        try:
            os.remove(f)
        except OSError:
            pass


def on():
    return sh("nft list table inet %s >/dev/null 2>&1" % TABLE)[0] == 0


if P["do"] == "who":                 # кто сейчас подключён к входу и откуда зашла панель
    me = (os.environ.get("SSH_CONNECTION") or "").split()[:1]
    peers = set()
    ports = set(int(p) for p in P.get("ports") or [])
    for line in sh("ss -Htn state established")[1].splitlines():
        f = line.split()
        if len(f) >= 4:
            lp, rp = f[2].rsplit(":", 1), f[3].rsplit(":", 1)
            if lp[-1].isdigit() and int(lp[-1]) in ports:
                peers.add(rp[0].strip("[]").replace("::ffff:", ""))
    done(True, "", me=me[0] if me else "", peers=sorted(peers))
if P["do"] == "confirm":
    cancel_undo()
    for f in (PREV, PREVM):
        try:
            os.remove(f)
        except OSError:
            pass
    sh("systemctl daemon-reload; systemctl enable vpn-dash-govblock >/dev/null 2>&1")
    done(True, "оставлено включённым, и после перезагрузки тоже", on=on())
if P["do"] == "undo":                # вернуть прежнее сейчас, не дожидаясь «ремня»
    if not os.path.exists(UNDO_SH):
        done(False, "возвращать нечего", on=on())
    try:
        os.killpg(int(open(UNDO).read().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    rc, out = sh("sh %s" % UNDO_SH, 60)
    done(rc == 0, "вернул как было" if rc == 0 else out.strip()[-300:], on=on())
if P["do"] == "off":
    cancel_undo()
    sh("systemctl disable vpn-dash-govblock >/dev/null 2>&1")
    sh("nft delete table inet %s 2>/dev/null" % TABLE)
    for f in (NFT, META, PREV, PREVM):
        try:
            os.remove(f)
        except OSError:
            pass
    done(not on(), "выключено: сети госорганов снова пускаются" if not on() else "таблица не удалилась", on=on())

# apply
if not shutil.which("nft"):
    was = sh("systemctl is-enabled nftables 2>/dev/null")[1].strip()
    env = "DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=300 "
    rc, out = sh(env + "install nftables")
    if rc != 0:
        sh(env + "update")
        rc, out = sh(env + "install nftables")
    if rc != 0 or not shutil.which("nft"):
        done(False, "не удалось поставить nftables: " + out.strip()[-300:])
    if was != "enabled":             # служба nftables при старте чистит все правила (и ufw, и Docker) — не включаем её
        sh("systemctl disable --now nftables >/dev/null 2>&1")
os.makedirs(D, exist_ok=True)
tmp = NFT + ".new"
with open(tmp, "w") as f:
    f.write(P["nft"])
rc, out = sh("nft -c -f %s" % tmp, 60)
if rc != 0:
    os.remove(tmp)
    done(False, "nftables не принял список (ничего не менял): " + out.strip()[-300:])
cancel_undo()
had = os.path.exists(NFT) and on()
run = tmp                            # уже включено — меняем только списки в той же таблице, счётчик остаётся
if had and P.get("upd"):
    with open(NFT + ".upd", "w") as f:
        f.write(P["upd"])
    if sh("nft -c -f %s.upd" % NFT, 60)[0] == 0:
        run = NFT + ".upd"
if had:
    shutil.copy(NFT, PREV)
    if os.path.exists(META):
        shutil.copy(META, PREVM)
    back = "nft -f %s && mv -f %s %s; [ -f %s ] && mv -f %s %s" % (PREV, PREV, NFT, PREVM, PREVM, META)
else:
    back = "nft delete table inet %s 2>/dev/null; systemctl disable vpn-dash-govblock >/dev/null 2>&1; rm -f %s %s" % (TABLE, NFT, META)
with open(UNDO_SH, "w") as f:
    f.write("#!/bin/sh\n%s\nrm -f %s %s\n" % (back, UNDO, UNDO_SH))
os.chmod(UNDO_SH, 0o700)
p = subprocess.Popen(["sh", "-c", "sleep %d; sh %s" % (int(P["undo_s"]), UNDO_SH)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
open(UNDO, "w").write(str(p.pid))
rc, out = sh("nft -f %s" % run, 60)
if run != tmp:
    os.remove(run)
if rc != 0:
    os.remove(tmp)
    cancel_undo()
    done(False, "nftables не принял список: " + out.strip()[-300:], on=on())
os.replace(tmp, NFT)
with open(META, "w") as f:
    json.dump(P["meta"], f)
with open(UNIT, "w") as f:
    f.write("[Unit]\nDescription=vpn-dash: не пускать сети госорганов (таблица nftables %s)\nAfter=network-pre.target\n\n"
            "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s -f %s\nExecStop=-%s delete table inet %s\n\n"
            "[Install]\nWantedBy=multi-user.target\n" % (TABLE, shutil.which("nft"), NFT, shutil.which("nft"), TABLE))
done(True, "включено; если панель не подтвердит, через %d с всё вернётся как было" % int(P["undo_s"]), on=on(),
     inplace=run != tmp)
'''

