"""Проверка входа с этого компьютера: как телефон, через настоящую дорогу до входа.

Панель запускает у себя клиент Xray (скачивается с GitHub XTLS один раз, сверяется sha256 из .dgst), он подключается
к входу VLESS Reality, и через него открывается страница Cloudflare — она отвечает адресом и страной выхода.
Вместе со сквозной проверкой с самого сервера это отвечает на вопрос «сломался вход или дорога до него».
Параметры клиента (UUID и т. п.) берутся из статуса входа, живут только в памяти панели и на страницу не уходят.
"""
import hashlib, io, json, os, platform, shutil, socket, ssl, subprocess, tempfile, time, urllib.request, zipfile

URL = "https://www.cloudflare.com/cdn-cgi/trace"
REL = "https://github.com/XTLS/Xray-core/releases/download/v%s/%s"


def asset():
    m = platform.machine().lower()
    arm = m in ("arm64", "aarch64")
    if os.name == "nt":
        return "Xray-windows-arm64-v8a.zip" if arm else "Xray-windows-64.zip"
    return "Xray-linux-arm64-v8a.zip" if arm else "Xray-linux-64.zip"


def ensure_xray(ver, home):
    """Путь к xray нужной версии в папке tools; нет — скачать с GitHub и сверить сумму."""
    exe = "xray.exe" if os.name == "nt" else "xray"
    d = os.path.join(home, "tools", "xray-" + ver)
    path = os.path.join(d, exe)
    if os.path.exists(path):
        return path
    a = asset()
    get = lambda u, t: urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "vpn-dash"}), timeout=t).read()
    z = get(REL % (ver, a), 180)
    dg = get(REL % (ver, a + ".dgst"), 30).decode("utf-8", "replace")
    want = next((l.split("=", 1)[1].strip().lower() for l in dg.splitlines() if l.startswith("SHA2-256=")), "")
    if not want or hashlib.sha256(z).hexdigest() != want:
        raise RuntimeError("Xray %s с GitHub не прошёл проверку суммы" % ver)
    os.makedirs(d, exist_ok=True)
    tmp = path + ".part"
    with zipfile.ZipFile(io.BytesIO(z)) as zf, open(tmp, "wb") as f:
        f.write(zf.read(exe))
    os.chmod(tmp, 0o755)
    os.replace(tmp, path)
    return path


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def client_config(v, address, port):
    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}}],
            "outbounds": [{"protocol": "vless",
                           "settings": {"vnext": [{"address": address, "port": v["port"],
                                                   "users": [{"id": v["id"], "encryption": "none", "flow": v.get("flow") or ""}]}]},
                           "streamSettings": {"network": "tcp", "security": "reality",
                                              "realitySettings": {"serverName": v["sni"], "fingerprint": "chrome",
                                                                  "publicKey": v["pbk"], "shortId": v.get("sid") or ""}}}]}


def fetch(hp, url, timeout, ctx=None):
    """GET через HTTP-прокси клиента Xray (CONNECT вручную: системные исключения прокси не мешают)."""
    host = url.split("/")[2]
    path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
    deadline = time.time() + timeout
    s = socket.create_connection(("127.0.0.1", hp), timeout)
    try:
        s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            s.settimeout(max(0.5, deadline - time.time()))
            c = s.recv(4096)
            if not c:
                raise OSError("Xray закрыл соединение")
            head += c
        if b" 200" not in head.split(b"\r\n", 1)[0]:
            raise OSError("Xray: " + head.split(b"\r\n", 1)[0].decode("latin-1"))
        t = (ctx or ssl.create_default_context()).wrap_socket(s, server_hostname=host)
        t.settimeout(max(0.5, deadline - time.time()))
        t.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vpn-dash\r\nConnection: close\r\n\r\n" % (path, host)).encode())
        b = b""
        while len(b) < 65536:
            t.settimeout(max(0.5, deadline - time.time()))
            c = t.recv(8192)
            if not c:
                break
            b += c
        st, _, rest = b.partition(b"\r\n\r\n")
        if b" 200" not in st.split(b"\r\n", 1)[0]:
            raise OSError("страница ответила: " + st.split(b"\r\n", 1)[0].decode("latin-1")[:60])
        return rest.decode("utf-8", "replace")
    finally:
        s.close()


def run(xbin, v, address, url=URL, timeout=12, ctx=None):
    """Один заход через вход. → {ok, ip, loc, ms} или {ok: False, err}."""
    t0 = time.time()
    hp = free_port()
    d = tempfile.mkdtemp(prefix="vpn-dash-pce2e-")
    p = None
    try:
        cfg = os.path.join(d, "c.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(client_config(v, address, hp), f)
        kw = {"creationflags": 0x08000000} if os.name == "nt" else {"start_new_session": True}   # без окна консоли
        p = subprocess.Popen([xbin, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)
        for _ in range(50):
            if p.poll() is not None:
                return {"ok": False, "err": "клиент Xray на этом компьютере не запустился: "
                        + (p.stderr.read() or b"").decode("utf-8", "replace")[-200:].strip()}
            try:
                socket.create_connection(("127.0.0.1", hp), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        try:
            body = fetch(hp, url, timeout, ctx)
        except socket.timeout:
            return {"ok": False, "err": "нет ответа за %d с" % timeout, "ms": int((time.time() - t0) * 1000)}
        except Exception as e:
            m = str(e)
            m = "соединение сброшено — вход не пустил или по дороге режут" if "reset" in m.lower() or "104" in m or "10054" in m else m[:120]
            return {"ok": False, "err": "через вход не открылось: " + (m or type(e).__name__),
                    "ms": int((time.time() - t0) * 1000)}
        kv = dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
        if not kv.get("ip"):
            return {"ok": False, "err": "ответ без адреса", "ms": int((time.time() - t0) * 1000)}
        return {"ok": True, "ip": kv["ip"], "loc": kv.get("loc", ""), "ms": int((time.time() - t0) * 1000)}
    finally:
        if p is not None:
            try:
                p.kill()
            except OSError:
                pass
            try:
                p.wait(5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)
