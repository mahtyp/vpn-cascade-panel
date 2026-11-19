#!/usr/bin/env python3
"""Чистый первый запуск в временном каталоге без servers.json и каких-либо настоящих VPS."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
PORT = 8791

def main():
    with tempfile.TemporaryDirectory(prefix="vpn-public-fresh-") as tmp:
        dest = Path(tmp) / "app"
        dest.mkdir()
        raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        for path in (p.decode() for p in raw.split(b"\0") if p):
            if path.startswith(("dev/", ".github/")) or path.startswith(".git"):
                continue
            src = ROOT / path
            if not src.is_file():
                continue
            dst = dest / path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        assert not (dest / "servers.json").exists(), "Конфигурация уже существует"
        env = dict(os.environ, DASH_NO_BROWSER="1", DASH_PORT=str(PORT),
                   PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8", VPN_DASH_STAND="1")
        proc = subprocess.Popen([sys.executable, "-u", "dash.py"],
                                cwd=dest, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace")
        try:
            for _ in range(45):
                if proc.poll() is not None:
                    raise RuntimeError("Панель завершилась до открытия HTTP: " +
                                       proc.stdout.read()[-1200:])
                try:
                    with urlopen("http://127.0.0.1:%d/api/state" % PORT,
                                 timeout=2) as response:
                        state = json.load(response)
                    break
                except (OSError, ValueError):
                    time.sleep(0.2)
            else:
                raise RuntimeError("HTTP не ответил после чистого запуска")
            assert state.get("servers") == [], "Должен быть пустой список серверов"
            assert isinstance(state.get("schema"), list), "Нет формы настроек"
            with urlopen("http://127.0.0.1:%d/" % PORT, timeout=3) as response:
                html = response.read().decode("utf-8")
            assert '<main id="main">' in html, "Нет страницы панели"
            print("PASS: чистая панель без servers.json, пустые серверы, настройки и HTML")
        finally:
            proc.terminate()
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()

if __name__ == "__main__":
    main()
