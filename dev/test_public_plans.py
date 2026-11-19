#!/usr/bin/env python3
"""Проверка планов операций без записи конфигурации на стенде."""
import json
import re
import time
import urllib.request

BASE = "http://127.0.0.1:8790"

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=90) as r:
        return json.load(r)

def post(path, body, token):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=data, headers={
        "X-Dash": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def main():
    with urllib.request.urlopen(BASE + "/", timeout=10) as r:
        html = r.read().decode("utf-8")
    token = re.search(r'const TOKEN = "([^"]+)"', html)
    if not token:
        raise AssertionError("Не найден токен локальной панели")
    token = token.group(1)
    state = {}
    for _ in range(40):
        state = get("/api/state")
        c = state.get("channels") or {}
        if (len(c.get("en1", [])) == 6 and
                all((s.get("state") or {}).get("ok") for s in
                    state.get("servers", []) if s.get("id") in ("en1", "ex1"))):
            break
        time.sleep(1)
    else:
        raise AssertionError("Состояние тестовых серверов не готово для планов")
    chain = sorted((c for c in state["channels"]["en1"] if c.get("n") and c.get("tag")),
                   key=lambda c: c["n"])
    order = [c["tag"] for c in chain]
    assert len(order) == 6 and order[0] != order[-1], "Нет ожидаемой цепочки"

    plan = post("/api/reorder-plan", {"entry": "en1", "order": list(reversed(order))}, token)
    assert plan.get("ok") is True and plan.get("steps"), "Не сформирован план смены порядка"
    invalid = post("/api/reorder-plan", {"entry": "en1", "order": order[:-1]}, token)
    assert invalid.get("ok") is False and invalid.get("errors"), "Допущена неполная цепочка"
    print("PASS: перестановка 6 звеньев планируется, неполная цепочка запрещена")

    unlink = post("/api/unlink-plan", {"entry": "en1", "exit": "ex1", "proto": "sudoku"}, token)
    assert unlink.get("ok") is True and unlink.get("steps"), "Нет плана отвязки Sudoku"
    duplicate = post("/api/link-plan", {"entry": "en1", "exit": "ex1", "proto": "awg"}, token)
    assert duplicate.get("ok") is False and duplicate.get("errors"), "Дублирование AWG не запрещено"
    unsupported = post("/api/link-plan", {"entry": "en1", "exit": "ex1", "proto": "random"}, token)
    assert unsupported.get("ok") is False and unsupported.get("errors"), "Неподдерживаемый протокол принят"
    print("PASS: план отвязки Sudoku и блокировка дубликата AWG/неизвестного протокола")

    after = get("/api/state")
    before_tags = {eid: [c.get("tag") for c in lst] for eid, lst in state["channels"].items()}
    after_tags = {eid: [c.get("tag") for c in lst] for eid, lst in after["channels"].items()}
    assert before_tags == after_tags, "План изменил каналы"
    print("PASS: только чтение, конфигурация каналов не изменилась")

if __name__ == "__main__":
    main()
