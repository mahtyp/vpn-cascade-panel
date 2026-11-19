#!/usr/bin/env python3
"""Проверка реального Chromium UI на локальных фиктивных серверах. Никаких записей на VPS."""
from playwright.sync_api import sync_playwright, expect

BASE = "http://127.0.0.1:8790/"


def go(page, path, title):
    page.goto(BASE + "#/" + path, wait_until="domcontentloaded")
    h1 = page.locator("#main h1")
    expect(h1).to_have_text(title, timeout=45000)


def main():
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            channel="chrome", headless=True, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on("pageerror", lambda error: errors.append(str(error)[:300]))
        go(page, "", "Обзор")
        expect(page.locator('a[data-page="awg"]')).to_be_visible()
        print("PASS: начальная страница и навигация")

        go(page, "servers", "Серверы и пароли")
        expect(page.locator(".srv")).to_have_count(5, timeout=20000)
        page.locator('[data-act="add-server"]').first.click()
        expect(page.locator(".srv")).to_have_count(6)
        page.locator('[data-act="undo-servers"]').first.click()
        expect(page.locator(".srv")).to_have_count(5)
        print("PASS: добавление и отмена нового сервера без сохранения")

        go(page, "settings", "Настройки")
        theme = page.locator('[data-act="theme"][data-v="dark"]')
        theme.click()
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        page.locator('[data-act="theme"][data-v="light"]').click()
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        print("PASS: настройки и переключение темы")

        go(page, "awg", "Протоколы")
        sudoku = page.locator('[data-act="proto-tab"][data-tab="sudoku"]')
        expect(sudoku).to_be_visible(timeout=90000)
        sudoku.click()
        expect(page.locator("#main")).to_contain_text("Входы — прокси Mihomo до Sudoku",
                                                      timeout=35000)
        print("PASS: страница Sudoku и Mihomo")

        page.locator('[data-act="proto-tab"][data-tab="map"]').click()
        expect(page.locator("#mp")).to_be_visible(timeout=30000)
        expect(page.locator("#mp .mp-n").first).to_be_visible()
        for mode in ("whatif", "trace"):
            page.locator('[data-act="map-mode"][data-v="%s"]' % mode).click()
            expect(page.locator('[data-act="map-mode"][data-v="%s"]' % mode)
                   ).to_have_attribute("aria-pressed", "true")
        print("PASS: интерактивная схема и режимы")

        go(page, "sites", "Сайты и обходы")
        expect(page.locator("#main")).to_contain_text("AWG и Sudoku", timeout=12000)
        go(page, "ai", "Аналитика")
        expect(page.locator("#main")).to_contain_text("Ключ API", timeout=12000)
        print("PASS: сайты и аналитика")

        if errors:
            raise AssertionError("JavaScript pageerror: " + " | ".join(errors[:8]))
        print("PASS: без необработанных ошибок JavaScript")
        browser.close()


if __name__ == "__main__":
    main()
