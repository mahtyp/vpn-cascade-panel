#!/usr/bin/env python3
"""Скриншоты только с изолированного публичного стенда. Никаких настоящих VPS."""
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

BASE = "http://127.0.0.1:8790/"
DEST = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
DEST.mkdir(parents=True, exist_ok=True)


def route(page, name, heading):
    page.goto(BASE + "#/" + name, wait_until="domcontentloaded")
    expect(page.locator("#main h1")).to_have_text(heading, timeout=45000)


def save(page, name, full=False):
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_timeout(1200)
    output = DEST / (name + ".png")
    page.screenshot(path=str(output), full_page=full, animations="disabled")
    if output.stat().st_size < 3000:
        raise RuntimeError("Подозрительно маленький снимок: " + str(output))
    print("CAPTURE", output.name, output.stat().st_size, "bytes")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 960},
                                device_scale_factor=1, locale="ru-RU",
                                color_scheme="light")
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)[:150]))
        route(page, "", "Обзор")
        expect(page.locator('a[data-page="awg"]')).to_be_visible()
        expect(page.locator("#main")).to_contain_text("Каналы до выходов", timeout=40000)
        save(page, "overview", full=True)

        route(page, "servers", "Серверы и пароли")
        expect(page.locator(".srv")).to_have_count(5, timeout=20000)
        save(page, "servers", full=True)

        route(page, "awg", "Протоколы")
        tab = page.locator('[data-act="proto-tab"][data-tab="sudoku"]')
        expect(tab).to_be_visible(timeout=90000)
        tab.click()
        expect(page.locator("#main")).to_contain_text("Входы — прокси Mihomo до Sudoku", timeout=35000)
        save(page, "sudoku", full=True)

        page.locator('[data-act="proto-tab"][data-tab="map"]').click()
        expect(page.locator("#mp .mp-n").first).to_be_visible(timeout=30000)
        save(page, "schema", full=True)

        route(page, "ai", "Аналитика")
        expect(page.locator("#main")).to_contain_text("Ключ API", timeout=20000)
        save(page, "analytics", full=True)
        if errors:
            raise RuntimeError("Ошибки JavaScript: " + " | ".join(errors[:5]))
        browser.close()


if __name__ == "__main__":
    main()
