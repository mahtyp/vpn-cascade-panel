"""Вывод скрипта с сервера → последняя строка JSON (скрипты печатают итог одной строкой в конце)."""
import json


def last_json(out):
    for line in reversed((out or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    return None
