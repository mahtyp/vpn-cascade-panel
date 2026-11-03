#!/usr/bin/env bash
# vpn-remove-client.sh — убирает с ЭТОГО выхода AWG-клиентов входа (например, тестового сервера,
# который больше не нужен). Клиенты, созданные vpn-restore.sh / vpn-add-exit.sh, называются
# <имя входа>-wg0, <имя входа>-wg1 и т.д.
#
# Запуск на выходе от root:
#   bash vpn-remove-client.sh Entry3         убрать всех клиентов Entry3-wg*
#   bash vpn-remove-client.sh Entry3 --dry    только показать, что будет удалено
# Работает и с AmneziaWG без Docker (awg0.conf), и с Amnezia в Docker (контейнер amnezia-awg2).
# Перед правкой конфиг копируется рядом (.bak-ДАТА).
set -euo pipefail
NAME=${1:-}; DRY=${2:-}
[ -n "$NAME" ] || { echo "Использование: bash $0 ИМЯ_ВХОДА [--dry]"; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || { echo "ИМЯ — латиница, цифры, - _ ."; exit 1; }
C="${AWG_CONTAINER:-amnezia-awg2}"
if command -v docker >/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$C"; then
  CONF=$(docker exec "$C" sh -c 'ls /opt/amnezia/awg/*.conf 2>/dev/null' | head -n1)
  X() { docker exec "$C" "$@"; }
  T=$(mktemp); docker cp "$C:$CONF" "$T"
elif [ -f /etc/amnezia/amneziawg/awg0.conf ]; then
  CONF=/etc/amnezia/amneziawg/awg0.conf
  X() { "$@"; }
  T=$(mktemp); cp "$CONF" "$T"
else
  echo "На этом сервере нет ни контейнера $C, ни /etc/amnezia/amneziawg/awg0.conf"; exit 1
fi
IF=$(basename "$CONF" .conf)
OUT=$(python3 - "$T" "$NAME" <<'PY'
import re, sys
path, name = sys.argv[1], sys.argv[2]
txt = open(path).read()
blk = re.compile(r"\n*\[Peer\]\n# vpn-restore: " + re.escape(name) + r"-wg\d+\n.*?(?=\n\[|\Z)", re.S)
keys = [m.group(1) for b in blk.findall(txt) for m in [re.search(r"PublicKey\s*=\s*(\S+)", b)] if m]
names = re.findall(r"# vpn-restore: (" + re.escape(name) + r"-wg\d+)", txt)
open(path + ".new", "w").write(blk.sub("\n", txt).rstrip("\n") + "\n")
print(" ".join(names)); print(" ".join(keys))
PY
)
NAMES=$(sed -n 1p <<<"$OUT"); KEYS=$(sed -n 2p <<<"$OUT")
if [ -z "$NAMES" ]; then echo "Клиентов $NAME-wg* на этом сервере нет — ничего не делаю"; rm -f "$T" "$T.new"; exit 0; fi
echo "Найдены клиенты: $NAMES"
if [ "$DRY" = "--dry" ]; then rm -f "$T" "$T.new"; exit 0; fi
if [ "${CONF#/opt/}" != "$CONF" ]; then
  docker cp "$C:$CONF" "/root/amnezia-$IF.conf.bak-$(date +%F_%H%M%S)"
  docker cp "$T.new" "$C:$CONF"
else
  cp "$CONF" "$CONF.bak-$(date +%F_%H%M%S)"
  install -m 600 "$T.new" "$CONF"
fi
for k in $KEYS; do X awg set "$IF" peer "$k" remove; done
rm -f "$T" "$T.new"
echo "Удалено: $NAMES (конфиг до правки сохранён рядом, .bak-*)"
