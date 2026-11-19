#!/usr/bin/env python3
"""Проверить синтаксис всех встроенных JavaScript-блоков index.html через Node.js."""
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
html = (root / "index.html").read_text(encoding="utf-8")
pattern = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script\s*>", re.IGNORECASE)
checked = 0
with tempfile.TemporaryDirectory(prefix="vpn-dash-jscheck-") as tmp:
    for n, match in enumerate(pattern.finditer(html), 1):
        attrs, code = match.groups()
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE) or not code.strip():
            continue
        path = pathlib.Path(tmp) / ("script_%s.js" % n)
        path.write_text(code, encoding="utf-8")
        completed = subprocess.run(["node", "--check", str(path)],
                                   capture_output=True, text=True)
        if completed.returncode:
            raise SystemExit("Ошибка синтаксиса JS-блока %s: %s" %
                             (n, completed.stderr[:2500]))
        checked += 1
if checked < 2:
    raise SystemExit("Ожидались два inline JS-блока, найдено %s" % checked)
print("OK: встроенных JS-блоков проверено: %s" % checked)
