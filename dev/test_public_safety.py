#!/usr/bin/env python3
"""Безопасные тесты блокировок публичной версии; только временные репозитории."""
import pathlib
import subprocess
import tempfile
import unittest

import public_safety as guard


class PublicSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="public-check-")
        self.root = pathlib.Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.orig = guard.ROOT
        guard.ROOT = self.root

    def tearDown(self):
        guard.ROOT = self.orig
        self.tmp.cleanup()

    def add(self, path, text):
        f = self.root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "--", path],
                       check=True, capture_output=True)

    def test_missing_readme_screenshot_is_blocked(self):
        self.add("README.md", "# Example")
        missing = guard.screenshot_problems()
        self.assertTrue(any(p[0] == "docs/screenshots/overview.png" for p in missing))

    def test_missing_third_party_license_is_blocked(self):
        self.add("LICENSE", "MIT License")
        missing = guard.license_problems()
        self.assertTrue(any(p[0] == "static/qrcode-LICENSE.txt" for p in missing))

    def test_documentation_ip_passes(self):
        self.add("sample.txt", "Документация: 192.0.2.10 и DNS 1.1.1.1")
        errors, warnings = guard.scan(strict_ip=True)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_tracked_server_config_is_blocked(self):
        self.add("servers.json", '{"servers":[]}')
        errors, _ = guard.scan()
        self.assertTrue(errors)

    def test_api_token_is_blocked(self):
        token = "ghp_" + ("X" * 32)
        self.add("example.txt", "token=" + token)
        errors, _ = guard.scan()
        self.assertTrue(any("API-токен" in e[2] for e in errors))

    def test_real_looking_ip_requires_manual_review(self):
        ip = "11.22" + ".33.44"
        self.add("example.txt", ip)
        errors, warnings = guard.scan(strict_ip=False)
        self.assertEqual(errors, [])
        self.assertTrue(warnings)
        errors, _ = guard.scan(strict_ip=True)
        self.assertTrue(errors)


    def test_personal_example_name_is_blocked(self):
        self.add("example.txt", "Пример настройки: сервер " + "Мос" + "ква")
        errors, _ = guard.scan()
        self.assertTrue(any("персональные примеры" in e[2] for e in errors))

    def test_normal_russian_words_are_not_personal_hosts(self):
        self.add("example.txt", "показано сказано указано")
        errors, _ = guard.scan()
        self.assertEqual(errors, [])

    def test_local_windows_user_path_is_blocked(self):
        path = "C:" + chr(92) + "Users" + chr(92) + "ExamplePerson" + chr(92) + "config"
        self.add("example.txt", path)
        errors, _ = guard.scan()
        self.assertTrue(any("Windows" in e[2] for e in errors))


if __name__ == "__main__":
    unittest.main()
