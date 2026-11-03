#!/usr/bin/env bash
# vpn-zapret.sh — zapret2 (github.com/bol-van/zapret2) на входе: обход ТСПУ для отдельных сайтов, которые
# 3X-UI пускает напрямую с входа. Кнопками из панели каскада, раздел «Zapret».
#
#   bash vpn-zapret.sh install <ссылка на zapret2-vX.tar.gz> <тег>   поставить в /opt/zapret2, служба ВЫКЛЮЧЕНА
#   bash vpn-zapret.sh check "<адреса через пробел>"                подбор стратегий (blockcheck2), только TLS 1.3, IPv4
#   bash vpn-zapret.sh apply <файл настроек>                        включить с этими стратегиями (не поднялся — назад)
#   bash vpn-zapret.sh off                                          выключить (zapret остаётся, правила сети убраны)
#   bash vpn-zapret.sh remove                                       выключить и удалить совсем
#
# Zapret трогает только соединения к адресам из своих списков (hostlist) — туннели и клиентов входа
# не касается. Подбор временно ставит свои правила только на адреса проверяемого сайта и убирает их сам.
# STAND=1 — стенд панели: blockcheck2 и сеть не трогаются, ответы готовые.
set -uo pipefail

Z=/opt/zapret2
UNIT=/etc/systemd/system/zapret2.service
say() { echo "== $*"; }
ok()  { echo "  ✓ $*"; }
die() { echo "  ✗ $*" >&2; exit 1; }
stand() { [ "${STAND:-}" = 1 ]; }
running() { stand && systemctl is-active --quiet zapret2 && return 0; pgrep -x nfqws2 >/dev/null; }

case "${1:-}" in
install)
  URL=${2:?ссылка}; TAG=${3:?тег}
  case "$URL" in https://github.com/bol-van/zapret2/releases/download/*) ;; *) die "ссылка не на релиз zapret2: $URL" ;; esac
  say "Zapret2 $TAG: скачать"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  curl -fsSL --connect-timeout 15 --max-time 300 "$URL" -o "$TMP/z.tgz" || die "не скачалось: $URL"
  tar -xzf "$TMP/z.tgz" -C "$TMP" || die "архив повреждён"
  SRC=$(find "$TMP" -maxdepth 2 -type f -name blockcheck2.sh -printf '%h\n' | head -n1)
  [ -n "$SRC" ] || die "в архиве нет zapret2"
  ok "архив разобран"
  if [ -d "$Z" ]; then
    say "Уже стоит $(cat $Z/.vpn-dash-ver 2>/dev/null || echo '?') — обновляю файлы, настройки и списки сохраняю"
    systemctl stop zapret2 >/dev/null 2>&1 || true
    mkdir -p "$TMP/keep"; for f in config ipset/vpn-dash-*.txt; do [ -e "$Z/$f" ] && cp -p "$Z"/$f "$TMP/keep/" 2>/dev/null; done
    rm -rf "$Z"
  fi
  cp -a "$SRC" "$Z" || die "не скопировалось в $Z"
  [ -d "$TMP/keep" ] && { [ -f "$TMP/keep/config" ] && cp -p "$TMP/keep/config" "$Z/config"; cp -p "$TMP"/keep/vpn-dash-*.txt "$Z/ipset/" 2>/dev/null; }
  say "Программы под этот сервер"
  sh "$Z/install_bin.sh" >/dev/null 2>&1 || die "install_bin.sh: нет подходящих программ для $(uname -m)"
  "$Z/nfq2/nfqws2" --version 2>/dev/null | head -n1 | sed 's/^/  /'
  if ! command -v nft >/dev/null 2>&1; then
    say "Ставлю nftables (нужен zapret)"
    stand || DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >/dev/null 2>&1 || die "nftables не поставился"
  fi
  if ! command -v hexdump >/dev/null 2>&1; then   # подбору нужен для случайного выбора адреса сайта
    say "Ставлю hexdump (нужен подбору)"
    stand || DEBIAN_FRONTEND=noninteractive apt-get install -y bsdextrautils >/dev/null 2>&1 \
      || DEBIAN_FRONTEND=noninteractive apt-get install -y bsdmainutils >/dev/null 2>&1 || echo "  ! hexdump не поставился — подбор будет работать, но адрес сайта будет выбирать не случайно"
  fi
  [ -f "$Z/config" ] || { cp "$Z/config.default" "$Z/config"; sed -i 's/^NFQWS2_ENABLE=.*/NFQWS2_ENABLE=0/' "$Z/config"; }
  cp "$Z/init.d/systemd/zapret2.service" "$UNIT"
  systemctl daemon-reload
  echo "$TAG" > "$Z/.vpn-dash-ver"
  ok "zapret2 $TAG в $Z; служба выключена — ничего не изменилось, пока не нажмёте «Включить»"
  ;;
check)
  DOMS=${2:?адреса}
  [ -x "$Z/blockcheck2.sh" ] || die "zapret2 не установлен"
  echo "$DOMS" | grep -Eq '^[a-z0-9.\ /_-]+$' || die "странные адреса: $DOMS"
  command -v hexdump >/dev/null 2>&1 || { DEBIAN_FRONTEND=noninteractive apt-get install -y bsdextrautils >/dev/null 2>&1 || true; }
  running && echo "  ! zapret сейчас включён — подбор идёт с ним вместе, результаты могут быть неточными"
  say "Подбор стратегий для: $DOMS (TLS 1.3, IPv4, это долго — 10–40 минут)"
  if stand; then
    for d in $DOMS; do echo "* curl_test_https_tls13 ipv4 $d"; echo "- checking without DPI bypass"; echo "  UNAVAILABLE code=28"; sleep 1; done
    pace=$(cat /etc/testbed-blockcheck-pace 2>/dev/null || echo 1)   # стенд: секунд на каждую найденную стратегию
    while IFS= read -r line; do echo "$line"; case "$line" in '!!!!!'*) sleep "$pace" ;; esac; done < /etc/testbed-blockcheck.txt
    exit 0
  fi
  cd "$Z" || exit 1
  # DoH — сначала по IP: у некоторых российских хостеров имена cloudflare-dns.com, dns.google не находятся (DNS перехвачен),
  # а https://1.1.1.1 отвечает. Без рабочего DoH blockcheck2 при подмене DNS прекращает подбор
  DOH_SERVERS="https://1.1.1.1/dns-query https://8.8.8.8/dns-query https://9.9.9.9/dns-query https://cloudflare-dns.com/dns-query https://dns.google/dns-query" \
  CURL_MAX_TIME_DOH=${CURL_MAX_TIME_DOH:-5} \
  BATCH=1 DOMAINS="$DOMS" IPVS=4 ENABLE_HTTP=0 ENABLE_HTTPS_TLS12=0 ENABLE_HTTPS_TLS13=1 ENABLE_HTTP3=0 \
    REPEATS=${REPEATS:-3} SCANLEVEL=${SCANLEVEL:-veryquick} CURL_HTTPS_GET=1 CURL_MAX_TIME=${CURL_MAX_TIME:-3} SKIP_IPBLOCK=0 \
    sh "$Z/blockcheck2.sh" 2>&1 < /dev/null
  ;;
apply)
  NEW=${2:?файл настроек}        # только наши переменные: дописываются после config.default и перекрывают его
  [ -f "$Z/config.default" ] || die "zapret2 не установлен"
  [ -f "$NEW" ] || die "нет файла $NEW"
  say "Проверка настроек"
  # zapret — только на внешнем интерфейсе. Xray ходит на выходы сам, через туннели wgN к тем же адресам YouTube:
  # без этого zapret «дурил» бы и эти соединения внутри туннеля, и сайт через выходы начинал тормозить
  WAN=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  [ -n "$WAN" ] || die "не нашёлся внешний интерфейс (нет маршрута по умолчанию)"
  case "$WAN" in wg*|awg*|tun*) die "маршрут по умолчанию идёт через $WAN — zapret тут ставить нельзя" ;; esac
  { cat "$Z/config.default" "$NEW"; echo "IFACE_WAN=$WAN"; } > "$Z/config.vpn-dash-new"
  ( . "$Z/config.vpn-dash-new"; [ "${NFQWS2_ENABLE:-0}" = 1 ] ) || die "в настройках не включён nfqws2"
  if ! stand; then
    # --dry-run проверяет параметры и файлы списков (Lua — только при запуске); раскрытие — как в скриптах zapret
    OPT=$(. "$Z/config.vpn-dash-new"; echo "$NFQWS2_OPT" | tr '\n' ' ')
    set -f
    OUT=$("$Z/nfq2/nfqws2" --dry-run --qnum=200 --lua-init=@$Z/lua/zapret-lib.lua --lua-init=@$Z/lua/zapret-antidpi.lua \
          --lua-init=@$Z/lua/zapret-auto.lua $OPT 2>&1) || { echo "$OUT" | tail -5; rm -f "$Z/config.vpn-dash-new"; die "nfqws2 не принимает эти стратегии — ничего не менял"; }
    set +f
  fi
  ok "стратегии принимаются; zapret только на $WAN (туннели до выходов не трогает)"
  say "Включение"
  cp -p "$Z/config" "$Z/config.before-vpn-dash" 2>/dev/null
  mv "$Z/config.vpn-dash-new" "$Z/config"
  systemctl enable zapret2 >/dev/null 2>&1
  systemctl restart zapret2
  sleep 2
  if running; then
    ok "zapret2 работает"
  else
    journalctl -u zapret2 -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
    cp -p "$Z/config.before-vpn-dash" "$Z/config"
    if grep -q '^NFQWS2_ENABLE=1' "$Z/config"; then systemctl restart zapret2; else systemctl disable --now zapret2 >/dev/null 2>&1; fi
    die "zapret2 не запустился — вернул прежние настройки"
  fi
  ;;
off)
  say "Выключаю zapret2"
  systemctl disable --now zapret2 >/dev/null 2>&1 || true
  [ -f "$Z/config" ] && sed -i 's/^NFQWS2_ENABLE=.*/NFQWS2_ENABLE=0/' "$Z/config"
  sleep 1
  running && die "nfqws2 всё ещё работает — проверьте вручную: systemctl status zapret2"
  ok "выключен; программы остались в $Z"
  ;;
remove)
  say "Удаляю zapret2"
  systemctl disable --now zapret2 >/dev/null 2>&1 || true
  [ -x "$Z/init.d/sysv/zapret2" ] && "$Z/init.d/sysv/zapret2" stop >/dev/null 2>&1
  rm -f "$UNIT"; systemctl daemon-reload
  rm -rf "$Z"
  ok "удалён"
  ;;
*)
  echo "использование: $0 install <url> <tag> | check \"<адреса>\" | apply <файл> | off | remove" >&2; exit 2 ;;
esac
