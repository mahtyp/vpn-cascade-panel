"""Значок панели в трее Windows и автозапуск вместе с Windows.

dash.py --launch   — так запускает start.bat: проверяет, что всё на месте, и стартует панель
                     без окна (pythonw) со значком в трее, после чего окно start.bat закрывается.
dash.py --tray     — сама панель со значком (её и прописывает автозапуск).

Цвет значка: зелёный — всё в норме; жёлтый — есть замечание, но трафик идёт;
красный — вход недоступен или на нём не работает ни один канал; серый — данных ещё нет.
"""
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

APP = Path(__file__).resolve().parent
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "vpn-dash"
COLORS = {"ok": (52, 199, 89), "warn": (245, 166, 35), "bad": (235, 77, 75), "idle": (128, 138, 152)}
TITLES = {"ok": "в норме", "warn": "есть замечания", "bad": "проблема", "idle": "нет данных"}


def message_box(text, title="Панель каскада"):
    """Окно с сообщением — у панели без консоли другого способа сказать об ошибке нет."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x40)
    except Exception:
        print(text)


# ------------------------------------------------------------------ автозапуск (реестр текущего пользователя)

def pythonw():
    p = Path(sys.executable).with_name("pythonw.exe")
    return p if p.exists() else None


def autostart_cmd():
    exe = pythonw() or Path(sys.executable)
    return '"%s" "%s" --tray --autostart' % (exe, APP / "dash.py")


def autostart_get():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            return winreg.QueryValueEx(k, RUN_NAME)[0]
    except (ImportError, OSError):
        return None


def autostart_set(on):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, autostart_cmd())
        else:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except FileNotFoundError:
                pass


# ------------------------------------------------------------------ запуск из start.bat

def launch(port):
    """Стартует панель без окна. Если она уже работает — просто открывает страницу."""
    url = "http://127.0.0.1:%d/" % port
    if os.name != "nt":
        return False
    try:
        import pystray  # noqa: F401
        import PIL  # noqa: F401
    except Exception as e:
        print("Значок в трее недоступен (%s) — запускаю в этом окне." % e)
        return False
    if port_busy(port):
        print("Панель уже запущена — открываю страницу.")
        webbrowser.open(url)
        return True
    exe = pythonw()
    if not exe:
        return False
    flags = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([str(exe), str(APP / "dash.py"), "--tray"], cwd=str(APP), creationflags=flags,
                     close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Панель запущена: значок в трее, страница откроется сама. Это окно можно закрыть.")
    return True


def port_busy(port):
    import socket
    s = socket.socket()
    try:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


# ------------------------------------------------------------------ значок

def make_icon(level):
    from PIL import Image, ImageDraw
    n = 64
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = COLORS.get(level, COLORS["idle"])
    d.rounded_rectangle((1, 1, n - 2, n - 2), radius=14, fill=c + (255,))
    w = (255, 255, 255, 255)
    # каскад: устройство → вход → два выхода
    d.line([(12, 32), (30, 32)], fill=w, width=5)
    d.line([(30, 32), (50, 17)], fill=w, width=5)
    d.line([(30, 32), (50, 47)], fill=w, width=5)
    for x, y, r in ((12, 32, 6), (30, 32, 8), (50, 17, 6), (50, 47, 6)):
        d.ellipse((x - r, y - r, x + r, y + r), fill=w)
    return img


def run_tray(D, srv, port, cfg_save, autostart_flag):
    """Значок в главном потоке, веб-сервер — в фоновом (так требует Windows для значков)."""
    import pystray
    url = "http://127.0.0.1:%d/" % port
    st = D.cfg.settings

    # первый запуск со значком — сразу включаем автозапуск; путь обновляем, если папку перенесли
    first = "autostart" not in st
    if os.name == "nt":
        try:
            if first:
                st["autostart"] = True
                cfg_save()
            if st.get("autostart"):
                if autostart_get() != autostart_cmd():
                    autostart_set(True)
            elif autostart_get():
                autostart_set(False)
        except OSError as e:
            D.note("warn", "Автозапуск: не удалось записать в реестр (%s)" % e)
    st.setdefault("tray_notify", True)

    def open_page(icon=None, item=None):
        webbrowser.open(url)

    def check_all(icon, item):
        D.pool.submit(D.check_all, True)

    def backup(icon, item):
        D.pool.submit(D.do_backup)

    def open_backups(icon, item):
        p = APP / "backups"
        p.mkdir(exist_ok=True)
        os.startfile(str(p)) if os.name == "nt" else None

    def toggle_notify(icon, item):
        st["tray_notify"] = not st.get("tray_notify")
        cfg_save()

    def toggle_autostart(icon, item):
        on = not st.get("autostart")
        try:
            autostart_set(on)
        except OSError as e:
            icon.notify("Не удалось изменить автозапуск: %s" % e, "Панель каскада")
            return
        st["autostart"] = on
        cfg_save()

    def quit_(icon, item):
        icon.visible = False
        icon.stop()

    def update(icon, item):
        def work():
            import updater
            icon.notify("Проверяю обновления…", "Панель каскада")
            r = updater.apply()
            if "error" in r:
                icon.notify(r["error"][:200], "Обновление не удалось")
            elif not r["updated"]:
                icon.notify("У вас последняя версия.", "Панель каскада")
            else:
                icon.notify("Обновил: " + "; ".join(r["changes"][:3])[:180] + ". Перезапускаюсь…", "Панель каскада")
                time.sleep(2)
                D.request_restart()
        threading.Thread(target=work, daemon=True).start()

    D.on_restart = lambda: (setattr(icon, "visible", False), icon.stop())

    menu = pystray.Menu(
        pystray.MenuItem("Открыть панель", open_page, default=True),
        pystray.MenuItem("Проверить всё", check_all),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Сделать бэкап", backup),
        pystray.MenuItem("Открыть папку бэкапов", open_backups),
        pystray.MenuItem("Обновить панель", update),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Уведомления о сбоях", toggle_notify, checked=lambda i: bool(st.get("tray_notify"))),
        pystray.MenuItem("Запускать вместе с Windows", toggle_autostart, checked=lambda i: bool(st.get("autostart"))),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Выход", quit_),
    )
    icon = pystray.Icon("vpn-dash", make_icon("idle"), "Панель каскада: запускаюсь…", menu)

    def watcher():
        last = None
        while True:
            try:
                level, lines = D.overall()
                tip = ("Каскад: " + TITLES[level] + ("\n" + "\n".join(lines) if lines else ""))
                if len(tip) > 120:
                    tip = tip[:118] + "…"
                if level != last:
                    icon.icon = make_icon(level)
                if icon.title != tip:
                    icon.title = tip
                # уведомление: стало хуже или снова в норме (первое состояние после запуска не объявляем)
                rank = {"idle": 0, "ok": 1, "warn": 2, "bad": 3}
                if last not in (None, "idle") and level != "idle" and level != last and st.get("tray_notify"):
                    loud = st.get("notify_warn", True)   # выкл. — только о красном и о выходе из красного
                    if rank[level] > rank[last] and (level == "bad" or loud):
                        icon.notify("\n".join(lines[:3]) or TITLES[level], "Каскад: " + TITLES[level])
                    elif level == "ok" and (last == "bad" or loud):
                        icon.notify("Всё снова в норме", "Каскад")
                    elif level == "warn" and last == "bad":
                        icon.notify("\n".join(lines[:3]) or "Остались замечания", "Каскад: стало лучше")
                last = level
            except Exception as e:  # значок не должен ронять панель
                print("tray:", e)
            time.sleep(5)

    def setup(ic):
        ic.visible = True
        threading.Thread(target=watcher, daemon=True).start()
        if first and os.name == "nt":
            ic.notify("Панель работает в трее и будет запускаться вместе с Windows. "
                      "Выключить — правой кнопкой по значку.", "Панель каскада")

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    if not autostart_flag and os.environ.get("DASH_NO_BROWSER") != "1":
        threading.Timer(1.0, open_page).start()
    try:
        icon.run(setup=setup)
    finally:
        srv.shutdown()   # «Выход» из меню; при ошибке значка dash.py продолжит без него
