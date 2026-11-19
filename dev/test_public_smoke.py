#!/usr/bin/env python3
"""Smoke-тест локального Linux-стенда; не обращается к внешним серверам."""
import json
import time
import urllib.request

URL = "http://127.0.0.1:8790/api/state"
EXPECTED = {"Вход-A", "Вход-B", "Выход-A", "Выход-B", "Выход-C"}
TAGS = {"AWG-ExitA", "Sudoku-ExitA", "AWG-ExitB", "Sudoku-ExitB", "AWG-ExitC", "Sudoku-ExitC"}

def main():
    last = "нет ответа"
    for _ in range(35):
        try:
            with urllib.request.urlopen(URL, timeout=4) as response:
                state = json.loads(response.read())
            names = {s["name"] for s in state.get("servers", [])}
            channels = state.get("channels") or {}
            tags_by_entry = {
                name: {c.get("tag") for c in channels.get(name, [])}
                for name in ("en1", "en2")
            }
            complete = all(TAGS <= tags for tags in tags_by_entry.values())
            if EXPECTED <= names and complete:
                print("OK: 5 анонимных серверов; AWG и Sudoku на обоих входах")
                print("Каналов: вход-1 = %d; вход-2 = %d" %
                      (len(channels.get("en1", [])), len(channels.get("en2", []))))
                return
            last = "серверов %d/5, проверенных каналов: %d/6 и %d/6" % (
                len(EXPECTED & names),
                len(TAGS & tags_by_entry["en1"]),
                len(TAGS & tags_by_entry["en2"]))
        except Exception as error:
            last = type(error).__name__
        time.sleep(2)
    raise SystemExit("FAIL: локальный стенд не поднялся: " + last)

if __name__ == "__main__":
    main()
