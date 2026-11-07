# Панель каскада (vpn-dash)

Локальная веб-панель для VPN-каскада «вход (3X-UI) → выход (AmneziaWG)»: Windows-ПК дома, Python 3, без сборки.
Пользователи — не программисты; все тексты интерфейса, README и сообщения — по-русски, простыми словами.

## Устройство
- `dash.py` — всё серверное: HTTP на 127.0.0.1 (stdlib ThreadingHTTPServer), SSH через paramiko,
  пароли в keyring (Диспетчер учётных данных Windows), история в SQLite `history.db`,
  WebSocket-консоль (написан вручную), бэкап, сравнение входов, настройки (`SETTINGS` — схема,
  из неё строится страница «Настройки»; значения в `servers.json` → `settings`).
- `probe.py` — отправляется на сервер через `python3 -` (stdin) с префиксом `MODE = "status"|"dc"|"config"`;
  только читает. Секреты в режиме config заменяются отпечатками (`SECRET_RE`).
- `index.html` — вся страница (vanilla JS, без фреймворков), `static/` — xterm.js.
- `tray.py` — значок в трее (pystray), автозапуск (HKCU\...\Run), `--launch` из start.bat.
- `updater.py` — обновление из GitHub (`git pull --ff-only`) и перезапуск.
- Обновления пакетов: `classify_pkgs` в dash.py (пометки и вывод), задача `upgrade` в provision.py
  (`UPGRADE_SH` через detached, перезагрузка по галочке, потом check_all). На стенде apt имитируется.
- `provision.py` — мастер «Новый сервер»: задачи check/bench/install в фоне, журнал в `jobs/`,
  итоги в `secrets/`. Долгие шаги идут на сервере через nohup (`/root/.vpn-dash-job/`), панель
  дочитывает лог. Пароль нового сервера — только в памяти задачи (`srv["_pw"]`). Входам пароль
  выхода передаётся файлом в `/root/.vpn-dash-job/pw/` (rssh в vpn-restore.sh берёт его через
  sshpass) и удаляется в finally. Ставятся роли «выход» (vpn-exit-setup.sh + vpn-add-exit.sh на входах)
  и «вход из бэкапа» (vpn-restore.sh с VPN_NAME, XUI_SSL_MODE=ip; установщик 3X-UI без TTY идёт
  без вопросов). Замена выхода — роль «выход» с `params.replace` = id старого: на входах
  `REPLACE=IP_старого vpn-add-exit.sh` переводит исходящие старого на новый туннель и
  переименовывает теги во всём шаблоне (места в цепочках, включая DC5TG, сохраняются), затем
  выключает старый wgN; старый сервер убирается из панели (`Dash.remove_server`).
- `sites.py` — «Сайты и обходы»: проверка сайта (probe MODE "site": curl через --interface wgN / напрямую
  с выхода + разбор SNI/TCP/DNS), вывод, обходы — правила 3X-UI с comment=код и цепочкой балансировщиков `<код>-N-<тег>`
  (как DC5TG), ставятся/меняются (режим set — новая цепочка, правило на месте)/убираются скриптом `BYPASS_PY` на входах (копия базы, откат), реестр в `servers.json` → `bypasses`.
  Автоматически ничего не создаётся и не перепроверяется.
  «Что режут на входах» — `Sites.dpi` (`/api/dpi`, в фоне, снимок `dpi`): probe MODE "dpi" `dpi_check(DPI_SITES)` на каждом входе —
  curl напрямую, при сбое разбор dns/spoof (DoH 1.1.1.1/8.8.8.8)/ip/sni (TLS с чужим именем)/stall/tls/stub. На стенде — `/etc/testbed-dpi.json`.
- Telegram DC (`dc_check` в probe): TCP 443 + первый шаг MTProto (obfuscated2 + req_pq_multi, AES-CTR через `openssl enc`, как censorcheck);
  `tcp` без `mt` — «молчит». На стенде — `dev/fake-mtproto.py` на 127.0.1.1…5:443 (настройка tg_dc стенда), молчащий DC — `/etc/testbed-mtproto.json`.
- Консоль выхода «через вход»: меню у кнопки «Консоль» → `/ws/term?via=<вход>` → `SSHPool.connect(srv, pw, via)`: с входа на адрес выхода
  в туннеле через `RELAY_PY` (python3 на входе, SO_BINDTODEVICE wgN — у туннелей Table = off, маршрутов нет, direct-tcpip не дойдёт) (`Dash.ssh_route`: .1 сети из Address wgN, у которого Endpoint = IP выхода; нет туннеля — IP выхода),
  ключ проверяется по обычному адресу в known_hosts; соединение только для этой консоли. Проверки панели — напрямую.
  На стенде — 10.8.N.1 на lo и `testbed.sh sshblock|sshopen <IP>` (закрыть SSH напрямую).
- `zapret.py` — раздел «Zapret»: цели в `servers.json` → `zapret.targets` (имя, адреса, адреса для подбора, `ents[вход]`:
  found/chosen/zap/direct/last/auto_off). `GEOSITE_PY` — подсказка адресов по geosite.dat входа (свой разбор protobuf).
  Задачи `zapret` в provision.py (`start_zapret`: install/check/apply/disable/off/remove) → `server-scripts/vpn-zapret.sh`
  (релиз zapret2 `ZAP_TAG` только с GitHub bol-van, blockcheck2 в BATCH через detached, apply — config.default + наш файл + `IFACE_WAN` (интерфейс маршрута по умолчанию: Xray ходит на выходы через wgN к тем же
  адресам, их zapret трогать не должен),
  `nfqws2 --dry-run`, не поднялся — назад). `parse_blockcheck` — раздел SUMMARY, без него — `parse_progress` по журналу; стратегии только по `STRAT_RE`.
  «Остановить и взять найденное» — `Zapret.collect(stop=True)`: TERM группе процессов zapcheck, журнал с сервера.
  «Напрямую» — `Sites.apply` с кодом `Z-<id>`, своё исходящее `Z-<id>-out` (freedom, sockopt.domainStrategy UseIPv4) и записи
  DNS Xray: адреса цели — через `DOH_SERVERS` (https+local 1.1.1.1/8.8.8.8, skipFallback, метка `full:z-<id>.vpn-dash.invalid`),
  иначе «localhost»; match domain + network tcp (в списке обходов не показываются). На некоторых входах DNS хостера и обычные
  запросы к 1.1.1.1/8.8.8.8 перехвачены — без DoH напрямую не открывается. verify: «нет в DNS», но по адресу от DoH открылось — ок.
  Автовозврат — `Zapret.monitor` из auto_loop раз в 5 мин: probe MODE "dpi" по адресам подбора, 2 провала — direct off.
  На стенде: релиз и geosite.dat кэшируются при `up`, подбор — `dev/fake-blockcheck.txt`, systemctl-заглушка для zapret2
  (`/etc/testbed-zapret-bad` — не запускается), `/etc/testbed-zapret-nohelp` — zapret «не помогает».
- Веб-панель 3X-UI через SSH: probe `web_info()` даёт порт/путь/где слушает; путь хранится только в `Dash.xui_web`
  (на страницу не уходит). Запросы на секретный путь панели Handler проксирует через `SSHPool.tunnel` (direct-tcpip
  на 127.0.0.1:порт сервера), включая WebSocket; наши cookie серверу не отдаются, POST/WS — только с нашим Origin.
  Host к 3X-UI — настоящий адрес сервера (по нему строится subURI); в .js подменяется `location.hostname` (адрес в ссылках VLESS).
  Одинаковый путь у входов из одного бэкапа — подсказка «путь как у …» (`xui_dups`) и кнопка «свой путь»; до тех пор сервер выбирает cookie `xui_sid`. На стенде — `dev/fake-xui-web.py`.
- `fw.py` — фаервол, шаг 1 (только чтение): probe MODE "fw" (ss, awg listen-port, Docker, sshd -T, правила iptables/ufw)
  → `fw.plan()`: какие порты оставить (SSH — всегда и порт панели, входящие 3X-UI, подписка, AWG), что
  закроется, заметки и команды ufw. Страница «Фаервол», `Dash.check_fw`, в снимке `fw`. Шаг 2 — `Dash.fw_enable`:
  замер (SSH заново, каналы через сервер, порты входа с ПК) → `fw.FW_PY` enable (ставит ufw, «ремень» — фоновый
  `sleep 300; ufw --force disable`, pid в /root/.vpn-dash-fw-undo) → замер снова → confirm (снять ремень) или disable.
  Команды — только из плана и только по `fw.CMD_RE`; SSH-порт панели обязателен. Если acme.sh продлевает сертификат через standalone (IP-сертификат 3X-UI ~6 дней), порт 80 в плане остаётся открытым. По одному серверу. На стенде — `dev/fake-ufw.py`.
- «Сети госорганов» на входах — `govblock.py` (страница «Фаервол», строка у входа): список C24Be/AS_Network_List
  (`URLS`, BSD-2) качает ПК (`Dash.gov_fetch`, проверка `parse`/`check_list`, кэш `govblock.json` в .gitignore), на сервере `GOV_PY`:
  своя таблица `inet vpn_dash_gov` (`ct state != new accept`, keep4/keep6, gov4/gov6 → drop с counter), файл /etc/vpn-dash/govblock.nft,
  юнит `vpn-dash-govblock` (`nft -f`), nftables ставится пакетом, его служба не включается. `Dash.gov_apply`: who (адрес панели из
  SSH_CONNECTION + кто подключён к входящим) → keep, замер `_fw_probe` → apply с «ремнём» (`.prev` / delete table) → замер → confirm
  или undo. Автообновление `gov_auto` раз в `gov_hours` — только где включено и sha списка поменялся (второе автоматическое
  изменение на серверах). На стенде — `/etc/testbed-govblock-v4/v6.txt` (выдуманный список из адресов 127.x, `local_ok`).
- Перевод выхода Docker → без Docker: задача `migrate` в provision.py (`start_migrate`, `/api/migrate`): на выходе
  `ONLY_AWG=1 vpn-exit-setup.sh` (только awg0), ufw allow + route allow; на входах `MIGRATE=1 vpn-add-exit.sh` —
  тот же wgN на новый awg0 (`AWG_MODE=native` в awg_add_exit/remote_body), проверка выхода через wgN, иначе откат
  конфига; потом `docker rm -f` контейнера. На стенде — `dev/fake-docker.py` (ставится вручную, см. «Стенд»).
- Версии: probe `sw_versions()` (AmneziaWG: dpkg/apt-cache и модуль /sys/module vs modinfo, протокол по конфигам
  `awg_proto`: 1.0/1.5 (I1–I5)/2.0 (S3/S4, диапазоны H)/3.x (HeaderProtectionKey, ContentPaddingAddition…)) в `data.sw` — в чипе AWG у сервера.
- `ipcheck.py` — «как видят адрес»: на сервер шлётся `RUNNER` с base64 копии `server-scripts/third_party/ipregion.sh`
  (vernette/ipregion, проверенный коммит — см. README там; обновлять только прочитав diff), запуск `runuser -u nobody --json -4`,
  заменители `column`/`nslookup`, владелец сети — MaxMind. `summarize()` → пометки. ИИ (ChatGPT/Claude/Copilot/Grok — коды ответов API без ключа, Gemini — из ipregion) и
  хостинг/VPN (ip-api demo, ipinfo widget, proxycheck) — свой код в `RUNNER` по образцу XaksFlaX/ipregion-fixed, `ai`/`net`. Задача `geo` (`start_geo`, `/api/geo`; в мастере —
  `/api/prov/start` kind geo), итог в `Dash.geo` → снимок `geo`. На стенде — готовый ответ `/etc/testbed-ipregion*.json` (ИИ и хостинг/VPN — `-ai.json`). Без jq: `mv /usr/bin/jq /usr/bin/jq.testbed-off` — кнопка установки на стенде его возвращает.
- Раздел «Качество» (`#/addr`, `renderAddr`): у каждого сервера «как видят» (geo) и «соседи» (nb), итоги `Dash.geo`/`Dash.nb`
  хранятся в `addrcheck.json` (.gitignore), в снимке `geo`, `nb`, `addrjobs`. `neighbors.py` — «шумные соседи»: /24 сервера
  сканируется С ЭТОГО ПК (`scan`: 443 без SNI, сертификат через `ssl._ssl._test_decode_cert`/свой DER, DoH 1.1.1.1 — настоящий
  ли сайт, для своих — TLS 1.3+h2 с проверкой сертификата), с сервера только `reality_script` (serverNames/target из x-ui.db и проверка сайта маскировки).
  `summarize`: чужие (BRANDS) / настоящие / прочее, шум, наша маскировка. Сайт маскировки: probe `reality_mask()` (в статусе входа
  `entry.mask`: TLS к target с SNI, проверка сертификата, TLS 1.3/h2, срок) → метка у сервера «маскировка: …» (ведёт в «Качество»);
  тот же код уходит в задачу nb (`neighbors.reality_script`): мёртвый сайт — note bad, живой не в /24 — warn. На стенде — `dev/fake-mask-site.py`
  (mask.testbed → 127.0.1.20:443, свой CA в системных), `/etc/testbed-mask-dead` — «сайт пропал». Задача `nb` (`start_nb`, `/api/nb`). На стенде —
  `/etc/testbed-neighbors.json` вместо скана.
  «DNS» (dns): `dnscheck.py` — `DNS_PY` на сервере (свои пакеты DNS: UDP 53, DoT 853 и DoH POST на IP с SNI и проверкой
  сертификата имени сервиса; подмена — ответы системного DNS и UDP 1.1.1.1/8.8.8.8 по TEST_DOMAINS против первого рабочего DoH),
  `summarize`, задача `dns` (`start_dns`, `/api/dns`), `Dash.dns`. На стенде — `/etc/testbed-dns.json` (по адресу сервера, «*» — остальные).
- Раздел «AmneziaWG» (`#/awg`, `renderAwg`, только чтение): probe MODE "awg" `awg_view()` — конфиги wgN/awgN (PrivateKey/
  PresharedKey не уходят с сервера, HeaderProtectionKey — только отпечаток), пиры с именами из комментариев, `awg show all dump`.
  `Dash.awg_view` (`/api/awg`, все серверы параллельно, не хранится): у входа туннель → выход по Endpoint, сверка `AWG_MUST`
  (S1–S4, H1–H4, ключ заголовков) с awgN выхода, пир выхода ↔ вход по AllowedIPs = Address. Страница сама обновляется раз в 30 с.
  Пакеты-маски — `awgmimic.py`: `generate(quic|stun|dns)` → строка I1 только из тегов `<b 0x…>`/`<r N>`; задача `mimic`
  (`start_mimic`, `/api/awg-mimic`, только туннели wgN входов, одна за раз) → `APPLY_PY`: копия `.before-mimic-*`, I1–I5 в
  [Interface], `systemctl restart awg-quick@wgN`, ping -I wgN .1 и рукопожатие новее старта ≤40 с, иначе копия назад.
  На стенде — `/etc/testbed-awg-mimic-bad`: с I1 заглушка awg отдаёт рукопожатие 0 (проверка отката).
- `quality.py` — раздел «Связь» (`#/quality`, качество каналов): замеры без изменений на серверах. На входе — исходник quality.py шлётся перед probe.py
  (MODE "quality", `entry_run`: ping напрямую/`-I wgN` до .1 туннеля, при отсутствии ответа — TCP к порту SSH;
  `ss -tin` живые соединения; 2 МБ с speed.cloudflare.com; трассировка своими ICMP с TTL). С ПК — `pc_run` (ping/tracert
  на Windows, TCP к порту VLESS). `Dash.quality_check` (`/api/quality`, одна за раз), итог в снимке `quality`. Набор маршрутов
  хранится в браузере. На стенде — заглушка ping и ветки curl, цифры задаёт `/etc/testbed-quality.json`.
- `server-scripts/` — bash-скрипты для серверов (бэкап/восстановление входа, развёртывание выхода,
  цепочки резерва). `vpn-backup.sh` оттуда же использует кнопка бэкапа.
  `vpn-awg-common.sh` — общие функции AmneziaWG (`apt_begin`, `add_amnezia_ppa`, `reload_awg_module`) для
  `vpn-exit-setup.sh` и `vpn-restore.sh`: `Provision.put` кладёт его рядом сам. `vpn-pin-chain.sh` берёт из `vpn-add-exit.sh`
  `xui_db_backup` / `xui_start_or_rollback` (копия базы 3X-UI и откат, если Xray не поднялся).
- Общее без повторов: `jsonline.last_json` — итог скрипта с сервера (последняя строка JSON) для ipcheck/neighbors/dnscheck;
  `ipcheck.abuse_parse` (её текст уходит и в RUNNER); `quality.run_bg`; `provision.first_steps`; `dash.probe_func(имя)` — текст функции из probe.py для маленьких скриптов на сервер.

Каскад: устройство → вход (3X-UI/Xray, VLESS Reality) → выходы через AmneziaWG (wg0, wg1, …, исходящие
`AWG-ИМЯ` — freedom с sockopt.interface); цепочка резерва — балансировщики 3X-UI с fallbackTag
через loopback-исходящие `_bl_*`.

## Правила
- Никаких реальных IP, паролей, ключей, ссылок подписок в репозитории. Всё личное — в
  `servers.json`, `known_hosts`, `history.db`, `backups/` (они в .gitignore).
- Защита страницы: проверка Host, токен `X-Dash` на POST, Origin+токен на WebSocket. Не ослаблять.
- Удалённый доступ (`remote.py`, `RemoteHandler`): отдельный порт PORT+1 только на 127.0.0.1, наружу — только
  `tailscale serve` (не funnel). Всё на этом порту — только после входа: пароль (pbkdf2) + TOTP, оба в keyring
  (`_remote_pw`, `_remote_totp`); сессия — cookie HttpOnly/Secure/SameSite=Strict, 12 ч без действий;
  5 ошибок за 15 мин — пауза. Настройка (`/api/remote`) — только с домашнего порта, не удалённо.
- Панель ничего не меняет на серверах, кроме бэкапа (временный скрипт и архив в /root, сразу удаляются),
  того, что пользователь сам набирает в консоли, и действий по кнопке с подтверждением: мастер «Новый
  сервер», «Обновления» (apt-get upgrade / перезагрузка, одна задача за раз), обходы, закрыть/открыть веб-панель 3X-UI
  из интернета и свой путь (`XUI_WEB_PY`: webListen/webBasePath, перезапуск x-ui, проверка, откат), включить/выключить
  фаервол (ufw, с замером до/после и автооткатом), перевод выхода с Docker на AmneziaWG без Docker, пакеты-маски AmneziaWG (I1) на туннеле входа (с откатом), zapret2 на входе (установка, подбор, включение, «напрямую»; автоматическое
  изменение — автовозврат цели на выходы, включается галочкой у цели), «сети госорганов» на входах (не пускать новые
  подключения из их подсетей; обновление списка раз в сутки — автоматически, только где включено, с замером и откатом), открыть порт 80
  для продления сертификата Let's Encrypt (`ACME80_SH`: `ufw allow 80/tcp` + `acme.sh --renew` только того, чему уже пора, без --cron — он обновляет сам acme.sh; probe `acme_info` видит, что ufw его закрыл). поставить jq/curl/iproute2 для «как видят», если их нет (кнопка «Поставить … и проверить заново», `ipcheck.install_cmd`). Окно обновлений до кнопки
  только читает (`MODE = "pkgs"`; «Проверить заново» = apt-get update).
- `start.bat` — CRLF, UTF-8, `chcp 65001`.
- Каждое изменение — проверить на стенде и в браузере (Playwright, Chromium предустановлен),
  коммит с понятным русским описанием (его пользователь видит в «Проверить обновления»).

## Стенд для проверки
`sudo bash dev/testbed.sh up` — фейковые 3X-UI/AWG, заглушки awg/curl/systemctl и sshd :2222;
«серверы» 127.0.0.2…6. `bash dev/testbed.sh run 8790` — панель на стенде с заданными паролями.
`sudo bash dev/testbed.sh down` — убрать. Нельзя запускать на настоящем сервере.
Мастер на стенде: «новый выход» — 127.0.0.7:2222; `vpn-exit-setup.sh` подменяется на
`dev/fake-exit-setup.sh`, обновление системы пропускается (`VPN_DASH_STAND=1`), остальные скрипты
настоящие; «новый вход» — 127.0.0.8/9, vpn-restore.sh идёт с `--only awg --force-awg`.
После `apt upgrade` в контейнере старый sshd стенда сбрасывает соединения — `pkill -x sshd` и `up`. Остановить панель стенда — `bash dev/testbed.sh stop`.
Выход в Docker на стенде: `cp dev/fake-docker.py /usr/local/sbin/docker && chmod +x …`, `echo '{"containers": {"amnezia-awg2": {"port": 43437}}}' > /etc/testbed-docker.json`, убрать `/etc/amnezia/amneziawg/awg0.conf`.
Осторожно с `pkill -f`/`pgrep -f <шаблон>`: шаблон совпадает и с собственной командной строкой
оболочки (это уже убивало сессию). Останавливать процессы — по pid-файлу или `pkill -x имя`.
