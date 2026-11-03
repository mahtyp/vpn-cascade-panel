"""Обновление панели из GitHub (git pull), если папка панели — это клон репозитория.

Работает только с кодом: servers.json, known_hosts, история, журнал и бэкапы в .gitignore
и при обновлении не трогаются.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent
NO_WINDOW = 0x08000000 if os.name == "nt" else 0     # CREATE_NO_WINDOW: без мигающих окон консоли


def _git(*args, timeout=60):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    p = subprocess.run(["git", "-C", str(APP), *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout, env=env, creationflags=NO_WINDOW,
                       stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def available():
    return bool(shutil.which("git")) and (APP / ".git").exists()


def version():
    """{'commit', 'date', 'subject'} текущей версии или None, если это не клон."""
    if not available():
        return None
    rc, out, _ = _git("log", "-1", "--format=%h%x1f%cd%x1f%s", "--date=format:%d.%m.%Y %H:%M")
    if rc != 0 or not out:
        return None
    h, d, s = (out.split("\x1f") + ["", "", ""])[:3]
    return {"commit": h, "date": d, "subject": s}


def check():
    """Скачать сведения о новых версиях. {'behind': N, 'changes': [...]} или {'error': ...}."""
    if not available():
        return {"error": "панель установлена не из GitHub (нет git или папки .git) — обновляйте архивом"}
    rc, _, err = _git("fetch", "--quiet", "origin", timeout=90)
    if rc != 0:
        return {"error": "не удалось связаться с GitHub: " + (err.splitlines() or ["?"])[-1][:200]}
    rc, out, err = _git("rev-list", "--count", "HEAD..@{u}")
    if rc != 0:
        return {"error": (err.splitlines() or ["?"])[-1][:200]}
    n = int(out or 0)
    _, log, _ = _git("log", "--format=%s", "HEAD..@{u}")
    return {"behind": n, "changes": [x for x in log.splitlines() if x][:15]}


def apply():
    """git pull; если поменялись библиотеки — доустановить. {'ok', 'updated', 'changes'} или {'error'}."""
    c = check()
    if "error" in c:
        return c
    if not c["behind"]:
        return {"ok": True, "updated": False, "changes": []}
    _, old, _ = _git("rev-parse", "HEAD")
    rc, out, err = _git("pull", "--ff-only", "--quiet", timeout=120)
    if rc != 0:
        msg = (err or out).splitlines()
        return {"error": "git pull не прошёл: " + (msg[-1] if msg else "?")[:300] +
                " — возможно, файлы панели правили вручную; пришлите это сообщение"}
    _, changed, _ = _git("diff", "--name-only", old, "HEAD")
    if "requirements.txt" in changed.split():
        py = Path(sys.executable)
        if py.name.lower() == "pythonw.exe":
            py = py.with_name("python.exe")
        subprocess.run([str(py), "-m", "pip", "install", "--disable-pip-version-check",
                        "--no-warn-script-location", "-q", "-r", str(APP / "requirements.txt")],
                       capture_output=True, creationflags=NO_WINDOW, timeout=600)
    return {"ok": True, "updated": True, "changes": c["changes"]}


def restart_detached(args):
    """Запустить панель заново (после того, как текущая освободит порт)."""
    exe = Path(sys.executable)
    flags = (0x00000008 | 0x00000200) if os.name == "nt" else 0   # DETACHED_PROCESS | NEW_PROCESS_GROUP
    subprocess.Popen([str(exe), str(APP / "dash.py"), *args], cwd=str(APP), creationflags=flags,
                     close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=(os.name != "nt"))
