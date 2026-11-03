#!/usr/bin/env bash
# vpn-awg-common.sh — общие функции AmneziaWG для vpn-exit-setup.sh и vpn-restore.sh (подключается через source,
# сам по себе не запускается). Ждёт от вызывающего скрипта say/ok/warn/die.

# В памяти может сидеть старый модуль AmneziaWG (поставленный когда-то раньше, его же использует
# контейнер Amnezia): новый файл модуля есть, а загружен старый — и awg0 с параметрами 3.1 не поднимается
# («Unable to modify interface: Invalid argument»). Перезагружаем модуль; если он занят контейнером
# Amnezia — останавливаем контейнер на эти секунды и запускаем снова (уже на новом модуле).
reload_awg_module() {
  local want have cs="" c
  want=$(modinfo -F version amneziawg 2>/dev/null || true)
  have=$(cat /sys/module/amneziawg/version 2>/dev/null || true)
  if [ -z "$have" ] || [ "$have" = "$want" ]; then modprobe amneziawg; return 0; fi
  warn "в памяти старый модуль AmneziaWG $have (установлен $want) — перезагружаю модуль"
  if ! rmmod amneziawg 2>/dev/null; then
    command -v docker >/dev/null && cs=$(docker ps --format '{{.Names}}' 2>/dev/null | grep '^amnezia-awg' || true)
    [ -n "$cs" ] || die "старый модуль AmneziaWG занят ($(ip -o link show type amneziawg 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')) — перезагрузите сервер и запустите снова"
    echo "  модуль занят контейнером Amnezia ($cs) — останавливаю его на несколько секунд"
    for c in $cs; do docker stop "$c" >/dev/null; done
    if ! rmmod amneziawg 2>/dev/null; then
      for c in $cs; do docker start "$c" >/dev/null || true; done
      die "старый модуль AmneziaWG не выгружается даже без контейнера — перезагрузите сервер и запустите снова"
    fi
    modprobe amneziawg
    for c in $cs; do docker start "$c" >/dev/null || warn "контейнер $c не запустился снова"; done
    ok "контейнер Amnezia снова запущен (на новом модуле)"
  else
    modprobe amneziawg
  fi
  ok "загружен модуль AmneziaWG $(cat /sys/module/amneziawg/version 2>/dev/null)"
}

# Репозиторий Amnezia. add-apt-repository ходит в API Launchpad и падает, если на сервере сломан IPv6
# (или API на минуту не ответил) — тогда подключаем сами: отпечаток ключа из API по IPv4, ключ с keyserver.
add_amnezia_ppa() {
  grep -rqs 'amnezia/ppa' /etc/apt/sources.list.d/ && return 0
  if [ -z "$(ip -6 route show default 2>/dev/null)" ]; then       # IPv6 нет — apt пусть идёт только по IPv4
    echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99vpn-force-ipv4
  fi
  local i
  for i in 1 2; do
    timeout 120 add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 && { apt-get update -q; return 0; }
    rm -f /etc/apt/sources.list.d/amnezia-ubuntu-ppa*
    sleep 5
  done
  echo "  add-apt-repository не смог (сеть до Launchpad) — подключаю репозиторий Amnezia вручную"
  local fp code
  fp=$(curl -4 -fsS -m 30 https://api.launchpad.net/1.0/~amnezia/+archive/ubuntu/ppa | jq -r '.signing_key_fingerprint // empty') \
    || true
  [[ "$fp" =~ ^[0-9A-Fa-f]{40}$ ]] || die "не узнал ключ репозитория Amnezia (api.launchpad.net не отвечает по IPv4)"
  code=$(. /etc/os-release; echo "$VERSION_CODENAME")
  mkdir -p /etc/apt/keyrings
  curl -4 -fsS -m 30 "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$fp" \
    | gpg --dearmor > /etc/apt/keyrings/amnezia-ppa.gpg || die "не скачался ключ репозитория Amnezia с keyserver.ubuntu.com"
  gpg --show-keys --with-colons /etc/apt/keyrings/amnezia-ppa.gpg 2>/dev/null | grep -qi "^fpr:.*:$fp:" \
    || die "ключ с keyserver не совпал с отпечатком из Launchpad — не подключаю"
  echo "deb [signed-by=/etc/apt/keyrings/amnezia-ppa.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu $code main" \
    > /etc/apt/sources.list.d/amnezia-ppa.list
  apt-get update -q
  ok "репозиторий Amnezia подключён вручную (ключ $fp)"
}

apt_begin() {   # начало шага «Пакеты»: apt без вопросов и свежие списки пакетов
  say "Пакеты"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  apt-get update -q
}
