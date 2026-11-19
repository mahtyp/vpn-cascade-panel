#!/usr/bin/env python3
"""Проверка публичного дерева перед релизом. Без сетевых запросов и изменений файлов."""
import argparse
import ipaddress
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DENY_NAMES = {"servers.json", "servers.tmp", "known_hosts", "history.db",
              ".env", "id_rsa", "id_ed25519", "credentials.json"}
DENY_PREFIXES = ("backups/", "secrets/", "jobs/", ".ssh/")
DENY_SUFFIXES = (".db", ".db-wal", ".db-shm", ".pem", ".p12", ".pfx", ".key", ".zip", ".rar")
BINARY_ALLOW = {"static/fonts/golos-cyrillic.woff2", "static/fonts/golos-latin.woff2",
                "static/fonts/jbmono-cyrillic.woff2", "static/fonts/jbmono-latin.woff2",
                "docs/screenshots/overview.png", "docs/screenshots/servers.png",
                "docs/screenshots/sudoku.png", "docs/screenshots/schema.png",
                "docs/screenshots/analytics.png"}
PATTERNS = [
    ("персональные примеры серверов", re.compile(
        r"\b(?:Моск[а-яё]*|Казан[а-яё]*|Новосибир[а-яё]*|Стокгольм[а-яё]*|"
        r"Хельсинк[а-яё]*|Барселон[а-яё]*|Париж[а-яё]*|"
        r"Stockholm|Kazan|Moscow|Novosibirsk|Helsinki|Paris|Barcelona|"
        r"Aeza|Clouding|AdminVPS|SolusVM)\b", re.I)),
    ("приватный ключ", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("API-токен", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|"
        r"sk-ant-[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{12,}|"
        r"xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[A-Z0-9]{16})\b")),
    ("локальный профиль Windows", re.compile(r"C:\\Users\\(?!<|\\|%)[A-Za-z0-9._-]{2,}\\", re.I)),
    ("другой репозиторий владельца", re.compile(r"github\.com/mahtyp/(?!vpn-cascade-panel(?:\b|\.git))[\w.-]+", re.I)),
]
IP4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SERVICE_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
               "94.140.14.14", "77.88.8.8", "95.161.64.40"}
SERVICE_PREFIXES = ("91.108.", "149.154.", "185.76.151.", "95.161.64.")
FIXTURE_ALLOW = {"dev/fake-govblock-v4.txt", "dev/fake-neighbors.json"}
REQUIRED_LICENSE_FILES = (
    "LICENSE",
    "static/qrcode-LICENSE.txt",
    "static/xterm-LICENSE.txt",
    "static/fonts/GolosText-OFL.txt",
    "static/fonts/JetBrainsMono-OFL.txt",
    "server-scripts/third_party/ipregion.LICENSE",
)


def tracked_files():
    data = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [pathlib.PurePosixPath(x.decode("utf-8")) for x in data.split(b"\0") if x]


def license_problems():
    """Проверить, что лицензии всех встроенных сторонних библиотек отслеживаются Git."""
    paths = {p.as_posix() for p in tracked_files()}
    return [(p, 0, "нет лицензии обязательного компонента")
            for p in REQUIRED_LICENSE_FILES if p not in paths]


def scan(strict_ip=False):
    problems, warnings = [], []
    for rel in tracked_files():
        name = rel.as_posix()
        low = name.lower()
        if (rel.name.lower() in DENY_NAMES or
                low.startswith(DENY_PREFIXES) or low.endswith(DENY_SUFFIXES)):
            problems.append((name, 0, "файл с возможными чувствительными данными"))
            continue
        data = (ROOT / name).read_bytes()
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            if name not in BINARY_ALLOW:
                problems.append((name, 0, "неразрешённый двоичный файл"))
            continue
        for n, line in enumerate(content.splitlines(), 1):
            for label, pattern in PATTERNS:
                # Названия в regex-правиле нужны для работы самого сканера;
                # все остальные категории (токены, пути, IP) проверяются и здесь.
                if name == "dev/public_safety.py" and label == "персональные примеры серверов":
                    continue
                if pattern.search(line):
                    problems.append((name, n, label))
            if name in FIXTURE_ALLOW:
                continue  # тестовые публичные IP-блоки требуют отдельной ручной ревизии
            for match in IP4.finditer(line):
                raw = match.group(0)
                try:
                    ip = ipaddress.IPv4Address(raw)
                except ipaddress.AddressValueError:
                    continue
                if not ip.is_global or raw in SERVICE_IPS or raw.startswith(SERVICE_PREFIXES):
                    continue
                (problems if strict_ip else warnings).append(
                    (name, n, "публичный IPv4: требуется ручная проверка"))
    return problems, warnings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict-ip", action="store_true",
                        help="считать неизвестные публичные IPv4 блокирующими")
    args = parser.parse_args()
    problems, warnings = scan(strict_ip=args.strict_ip)
    problems.extend(license_problems())
    # Не печатать сами совпавшие секреты и IP!
    for name, line, label in problems:
        print("ERROR %s:%s: %s" % (name, line, label))
    for name, line, label in warnings[:30]:
        print("REVIEW %s:%s: %s" % (name, line, label))
    if len(warnings) > 30:
        print("REVIEW и ещё %s совпадений (список сокращён)" % (len(warnings) - 30))
    print("Public safety scan: %s блокирующих, %s для ручной проверки" %
          (len(problems), len(warnings)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
