# Панель каскада (vpn-dash)

Локальная веб-панель для VPN-каскада — самостоятельный продукт для сторонних пользователей:
Windows-ПК, Python 3, без сборки. Интерфейс и документация — по-русски, простым языком.
Sudoku и Mihomo — постоянные полноценные компоненты наравне с AmneziaWG.

## Устройство
- `dash.py` — всё серверное: HTTP на 127.0.0.1 (stdlib ThreadingHTTPServer), SSH через paramiko,
  пароли в keyring (Диспетчер учётных данных Windows), история в SQLite `history.db`,
  WebSocket-консоль (написан вручную), бэкап, сравнение входов, настройки (`SETTINGS` — схема,
  из неё строится страница «Настройки»; значения в `servers.json` → `settings`).
- `probe.py` — отправляется на сервер через `python3 -` (stdin) с префиксом `MODE = "status"|"dc"|"config"`;
  только читает. Секреты в режиме config заменяются отпечатками (`SECRET_RE`).
- `index.html` — вся страница (vanilla JS, без фреймворков), `static/` — xterm.js и шрифты (`static/fonts`: Golos Text и JetBrains Mono, OFL; в `STATIC_FILES`).
  Вид — Hallmark, тема Grid (швейцарский стиль, app screen): токены в `:root` (светлый лист — по умолчанию) и `[data-theme="dark"]`,
  выбор в «Настройках» → «Оформление» (localStorage `vd-theme`: нет = светлое, dark, auto; ставится до отрисовки скриптом в `<head>`).
  `--field` (ультрамарин) — где идёт трафик и что выбрано, `--bad`/`--mark` (красный) — беда и знак; без рамок, теней и скруглений;
  шрифт 13/15/17/18/24/28/44, плитки Обзора: `field` / `alarm`; цвета только через токены; без «·» в подписях; `alert()` → `toast()`.
  Обзор внизу: журнал проверок и справа «Бэкапы» (`backupCard`); «Схема входов» — внизу «Серверы и пароли» (`driftCard`, `#drift-box`
  обновляется в `render()`): `Dash.principle()` по живому трафику — клиент → вход (проверка с ПК + клиенты основного по отпечаткам UUID
  `clients_fp`, только в памяти `client_fps`), российское напрямую (`e2e.ru`: тот же клиент открывает `E2E_RU_URLS` (ip.mail.ru, yandex.ru/internet — HTML, в нём ищется адрес входа или выхода)),
  зарубежное через выход (`e2e`); нарушения — в `overall()` и «замечания». Сравнение настроек поле за полем (`check_drift`) — только по кнопке
  «Сравнить» в свёрнутом блоке, без пометок и журнала.
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
  без вопросов; `xray_match` — Xray той же версии, что `xray=` в versions.txt бэкапа, с GitHub XTLS по sha256 из .dgst). Вход «с нуля» (source kind fresh, `_install_entry_fresh`) — отдельная связка: `server-scripts/vpn-entry-new.sh` (берёт этапы из vpn-restore.sh; Mihomo свежий с GitHub и пустой конфиг; 3X-UI той же версии, что у основного входа: `x-ui setting` логин/порт/путь/listen 127.0.0.1, шаблон = config.json без входящих + правила RU direct/IPv6 и private в блок + burstObservatory; вход VLESS Reality через API с токеном `x-ui setting -getApiToken`, отпечаток firefox — большое приветствие chrome (с ML-KEM, 2 пакета) ТСПУ рвёт; итог в `$RESULT` 600, панель забирает и удаляет), сервер получает `group` = свой id; выход с `params.group` подключается только ко входам связки, первый выход создаёт цепочку и общее правило (vpn-add-exit.sh, пустой `balancers`). Связки не участвуют в сверке резервов и бэкапе по умолчанию. На стенде — `dev/fake-entry-new.sh`. Замена выхода — роль «выход» с `params.replace` = id старого: на входах
  `REPLACE=IP_старого vpn-add-exit.sh` переводит исходящие старого на новый туннель/SOCKS и
  переименовывает теги во всём шаблоне (места в цепочках, включая DC5TG, сохраняются), затем
  выключает старый wgN и прокси Mihomo; старый сервер убирается из панели (`Dash.remove_server`).
- `sites.py` — «Сайты и обходы»: проверка сайта (probe MODE "site": curl через --interface wgN / SOCKS Mihomo / напрямую
  с выхода + разбор SNI/TCP/DNS), вывод, обходы — правила 3X-UI с comment=код и цепочкой балансировщиков `<код>-N-<тег>`
  (как DC5TG), ставятся/меняются (режим set — новая цепочка, правило на месте)/убираются скриптом `BYPASS_PY` на входах (копия базы, откат), реестр в `servers.json` → `bypasses`.
  Автоматически ничего не создаётся и не перепроверяется.
  «Что режут на входах» — `Sites.dpi` (`/api/dpi`, в фоне, снимок `dpi`): probe MODE "dpi" `dpi_check(DPI_SITES)` на каждом входе —
  curl напрямую, при сбое разбор dns/spoof (DoH 1.1.1.1/8.8.8.8)/ip/sni (TLS с чужим именем)/stall/tls/stub. На стенде — `/etc/testbed-dpi.json`.
- Сквозная проверка входа — probe `xray_e2e()` в статусе (`entry.e2e`): временный клиент Xray (бинарник 3X-UI, `xray run -c` во временной папке, socks на 127.0.0.1)
  подключается к своему VLESS Reality (клиент без limitIp, publicKey из realitySettings.settings или `xray x25519 -i`, отпечаток — как в подписке, `fp`) и открывает `E2E_URL` (cloudflare trace) — ip/loc выхода;
  curl с `--noproxy ''`. В dash — `e2e_fail`, `exit`/`direct`; 2 провала подряд — тревога в `overall()` и баннер на Обзоре. На стенде — `/etc/testbed-e2e.json` (`-bad.json` — сбой).
- Проверка входа с ПК — `pce2e.py` (`check_pc_e2e` в check_all, настройка `pc_e2e`): параметры клиента приходят в `entry.e2e.pc` и сразу
  вынимаются в `Dash.e2e_params` (только память); Xray той же версии, что на входе, — `ensure_xray` в `tools/xray-<ver>/` (GitHub XTLS, sha256 из .dgst,
  .gitignore), клиент с http-входом, CONNECT вручную (`fetch`: системные исключения прокси не мешают). Итог — снимок `pce2e`; сквозная с сервера ок,
  а с ПК 2 провала — «режется дорога до входа» (баннер, warn в overall). На стенде — `/etc/testbed-pc-e2e.json` (`-bad.json`).
- Диагностика — кнопка у сервера → `/api/diag` → probe MODE "diag" (`diag()`: службы, xray fd/conntrack, туннели, наружу через wgN/SOCKS, журналы x-ui
  и Mihomo, error.log Xray, маршрутизация, dmesg, фаервол) + что видит панель; `Dash._redact`: адреса серверов → [имя], прочие → [адрес-N], UUID/ключи скрыты.
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
  иначе «localhost»; match domain + network tcp (в списке обходов не показываются). У некоторых провайдеров DNS хостера и обычные
  запросы к 1.1.1.1/8.8.8.8 перехвачены — без DoH напрямую не открывается. verify: «нет в DNS», но по адресу от DoH открылось — ок.
  Автовозврат — `Zapret.monitor` из auto_loop раз в 5 мин: probe MODE "dpi" по адресам подбора, 2 провала — direct off.
  На стенде: релиз и geosite.dat кэшируются при `up`, подбор — `dev/fake-blockcheck.txt`, systemctl-заглушка для zapret2
  (`/etc/testbed-zapret-bad` — не запускается), `/etc/testbed-zapret-nohelp` — zapret «не помогает».
- Веб-панель 3X-UI через SSH: probe `web_info()` даёт порт/путь/где слушает; путь хранится только в `Dash.xui_web`
  (на страницу не уходит). Запросы на секретный путь панели Handler проксирует через `SSHPool.tunnel` (direct-tcpip
  на 127.0.0.1:порт сервера), включая WebSocket; наши cookie серверу не отдаются, POST/WS — только с нашим Origin.
  Host к 3X-UI — настоящий адрес сервера (по нему строится subURI); в .js подменяется `location.hostname` (адрес в ссылках VLESS).
  Открыть/закрыть из интернета заодно разрешает/убирает порт панели в ufw (`ufw_sync` в `XUI_WEB_PY`, правило с comment «vpn-dash: 3x-ui web»);
  слушает все адреса, но ufw не пускает — `web.fw_blocked` (probe `ufw_port_open`) → пометка «3X-UI: порт закрыт фаерволом» (xui-allow). Одинаковый путь у входов из одного бэкапа — подсказка «путь как у …» (`xui_dups`) и кнопка «свой путь»; до тех пор сервер выбирает cookie `xui_sid`. На стенде — `dev/fake-xui-web.py`.
- `fw.py` — фаервол, шаг 1 (только чтение): probe MODE "fw" (ss, awg listen-port, Docker, sshd -T, правила iptables/ufw)
  → `fw.plan()`: какие порты оставить (SSH — всегда и порт панели, входящие 3X-UI, подписка, AWG, Sudoku), что
  закроется, заметки и команды ufw. Страница «Фаервол», `Dash.check_fw`, в снимке `fw`. Шаг 2 — `Dash.fw_enable`:
  замер (SSH заново, каналы через сервер, порты входа с ПК) → `fw.FW_PY` enable (ставит ufw, «ремень» — фоновый
  `sleep 300; ufw --force disable`, pid в /root/.vpn-dash-fw-undo) → замер снова → confirm (снять ремень) или disable.
  Команды — только из плана и только по `fw.CMD_RE`; SSH-порт панели обязателен. Если acme.sh продлевает сертификат через standalone (IP-сертификат 3X-UI ~6 дней), порт 80 в плане остаётся открытым. По одному серверу. На стенде — `dev/fake-ufw.py`.
- «Сети госорганов» на входах — `govblock.py` (страница «Фаервол», строка у входа): список C24Be/AS_Network_List
  (`URLS`, BSD-2) качает ПК (`Dash.gov_fetch`, проверка `parse`/`check_list`, кэш `govblock.json` в .gitignore), на сервере `GOV_PY`:
  своя таблица `inet vpn_dash_gov` (`ct state != new accept`, keep4/keep6, gov4/gov6 → drop с counter), файл /etc/vpn-dash/govblock.nft,
  юнит `vpn-dash-govblock` (`nft -f`), nftables ставится пакетом, его служба не включается. `Dash.gov_apply`: who (адрес панели из
  SSH_CONNECTION + кто подключён к входящим) → keep, замер `_fw_probe` → apply с «ремнём» (`.prev` / delete table) → замер → confirm
  или undo. Где уже включено — `nft_update` (flush/add element в тех же наборах, счётчики правил целы; кнопка «Обновить список» = `/api/gov` do update, fresh). Счётчик через перезагрузки копит панель (`_gov_count`, `govdrops.json`). Автообновление `gov_auto` раз в `gov_hours` — только где включено и sha списка поменялся (второе автоматическое
  изменение на серверах). На стенде — `/etc/testbed-govblock-v4/v6.txt` (копия списка + 127.0.0.0/12, `local_ok`).
- Перевод выхода Docker → без Docker: задача `migrate` в provision.py (`start_migrate`, `/api/migrate`): на выходе
  `ONLY_AWG=1 vpn-exit-setup.sh` (только awg0), ufw allow + route allow; на входах `MIGRATE=1 vpn-add-exit.sh` —
  тот же wgN на новый awg0 (`AWG_MODE=native` в awg_add_exit/remote_body), проверка выхода через wgN, иначе откат
  конфига; потом `docker rm -f` контейнера. На стенде — `dev/fake-docker.py` (ставится вручную, см. «Стенд»).
- Sudoku через sing-box → обычный: задача `sudoku` в provision.py (`start_sudoku_direct`, `/api/sudoku-direct`, чип
  «Sudoku через sing-box»): `server-scripts/vpn-sudoku-direct.sh switch` (свежий sudoku с GitHub, `-test` конфига, юнит как у
  установщика, versions.env) → проверка каналов Sudoku со входов (только тех, что работали до) → иначе `rollback`; потом `finish`.
  На стенде — `sudo bash dev/testbed.sh singbox` (заглушки `dev/fake-sudoku.py`, `/etc/testbed-units`; отказ канала —
  `/etc/testbed-sudoku-chan-bad`, плохой конфиг — `/etc/testbed-sudoku-bad`).
- Запасной канал Sudoku к выходу связки: задача `sudokubk` (`start_sudoku_backup`, `/api/sudoku-backup`, чип «нет запасного канала» у выхода
  с `group`, если со входов связки нет канала Sudoku до него): на выходе `ONLY_SUDOKU=1 vpn-exit-setup.sh` (только Sudoku, без обновления системы,
  AWG, sysctl, fail2ban; 3X-UI не трогается), на входах `SUDOKU_ONLY=1 vpn-add-exit.sh` — прокси Mihomo + `Sudoku-ИМЯ`; цепочки нет, а общее
  правило ведёт прямо на исходящее (например, `sub1-…` из подписки 3X-UI) — оно оборачивается в `Bal-N-<тег>` → запасной `Bal-N+1-Sudoku-ИМЯ`
  (все правила на это исходящее → на цепочку, тег в burstObservatory); есть цепочка — Sudoku звеном на POSITION. Проверено Xray 26.10.31 (-test и
  переключение). На стенде — связка «Друг/ДругВыход» (пароли им задать вручную), `dev/fake-exit-setup.sh` понимает ONLY_SUDOKU.
- Версии: probe `sw_versions()` (Sudoku из versions.env, Mihomo `-v` + путь из юнита, AmneziaWG: dpkg/apt-cache и модуль
  /sys/module vs modinfo, протокол по конфигам `awg_proto`: 1.0/1.5 (I1–I5)/2.0 (S3/S4, диапазоны H)/3.x (HeaderProtectionKey, ContentPaddingAddition…)) в `data.sw` — в чипе AWG у сервера; `Dash.fetch_sw_latest` (GitHub API с ПК раз в 12 ч, на стенде — заданные теги) →
  `sw_latest`. Обновление — задача `swupdate` (`start_sw_update`, `/api/sw-update`): `server-scripts/vpn-sw-update.sh sudoku|mihomo`
  (только ссылки на релизы GitHub, `-test`/`-t` конфига, замена, перезапуск, порт) → проверка каналов Sudoku → иначе `*-rollback`.
- `ipcheck.py` — «как видят адрес»: на сервер шлётся `RUNNER` с base64 копии `server-scripts/third_party/ipregion.sh`
  (vernette/ipregion, проверенный коммит — см. README там; обновлять только прочитав diff), запуск `runuser -u nobody --json -4`,
  заменители `column`/`nslookup`, владелец сети — MaxMind. `summarize()` → пометки. ИИ (ChatGPT/Claude/Copilot/Grok — коды ответов API без ключа, Gemini — из ipregion) и
  хостинг/VPN (ip-api demo, ipinfo widget, proxycheck) — свой код в `RUNNER` по образцу XaksFlaX/ipregion-fixed, `ai`/`net`. AbuseIPDB — только с ПК по API с ключом (`ipcheck.abuse_api`, keyring `_abuseipdb_key`, «Настройки» → `/api/abusekey`; без ключа строки нет; стенд — `/etc/testbed-abuseipdb.json`). Задача `geo` (`start_geo`, `/api/geo`; в мастере —
  `/api/prov/start` kind geo), итог в `Dash.geo` → снимок `geo`. На стенде — готовый ответ `/etc/testbed-ipregion*.json` (ИИ и хостинг/VPN — `-ai.json`). Без jq: `mv /usr/bin/jq /usr/bin/jq.testbed-off` — кнопка установки на стенде его возвращает.
- Раздел «Качество» (`#/addr`, `renderAddr`): у каждого сервера «как видят» (geo) и «соседи» (nb), итоги `Dash.geo`/`Dash.nb`
  хранятся в `addrcheck.json` (.gitignore), в снимке `geo`, `nb`, `addrjobs`. `neighbors.py` — «шумные соседи»: /24 сервера
  сканируется С ЭТОГО ПК (`scan`: 443 без SNI, сертификат через `ssl._ssl._test_decode_cert`/свой DER, DoH Яндекс/Google/Cloudflare (`doh_ips`) — настоящий
  ли сайт, для своих — TLS 1.3+h2 с проверкой сертификата), с сервера только `reality_script` (serverNames/target из x-ui.db и проверка сайта маскировки).
  `summarize`: чужие (BRANDS) / настоящие / прочее, шум, наша маскировка. Кандидаты для маскировки перепроверяются с сервера (`FIT_PY`,
  `apply_server_fit`: не открылся оттуда — «с сервера не открывается», в подсказки не попадает; стенд — `/etc/testbed-fit.json`). Сайт маскировки: probe `reality_mask()` (в статусе входа
  `entry.mask`: TLS к target с SNI, проверка сертификата, TLS 1.3/h2, срок) → метка у сервера «маскировка: …» (ведёт в «Качество»);
  тот же код уходит в задачу nb (`neighbors.reality_script`): мёртвый сайт — note bad, живой не в /24 — warn, «переехал» — адрес с сервера не в /24 ни одного ответа `doh_ips` (`pub_ips`/`pub_by`). На стенде — `dev/fake-mask-site.py`
  (mask.testbed → 127.0.1.20:443, свой CA в системных), `/etc/testbed-mask-dead` — «сайт пропал». Задача `nb` (`start_nb`, `/api/nb`). На стенде —
  `/etc/testbed-neighbors.json` вместо скана.
  «DNS» (dns): `dnscheck.py` — `DNS_PY` на сервере (свои пакеты DNS: UDP 53, DoT 853 и DoH POST на IP с SNI и проверкой
  сертификата имени сервиса; подмена — ответы системного DNS и UDP 1.1.1.1/8.8.8.8 по TEST_DOMAINS против первого рабочего DoH),
  `summarize`, задача `dns` (`start_dns`, `/api/dns`), `Dash.dns`. На стенде — `/etc/testbed-dns.json` (по адресу сервера, «*» — остальные).
- Раздел «Протоколы» (`#/awg`, `renderAwg`, только чтение; бывший «AmneziaWG») — вкладки `protoTabs()`: «Схема» (по умолчанию), «Связи», по вкладке на каждый
  понятный протокол, который есть на серверах (AmneziaWG; Sudoku — `protoSudokuHtml`: сервер Sudoku на выходе (`sudoku`: служба, порт, версия,
  настройки без ключей через `_plain`) и прокси Mihomo на входах (`mproxies`), сверка порта и шифра; VLESS/Trojan/Shadowsocks/… — `protoXrayHtml`:
  входящие 3X-UI этого протокола и исходящие до других серверов, сверка порта/имени/flow с входящим на той стороне), «Что ещё стоит». «Связи»: probe MODE "proto" `proto_view()`
  (исходящие из работающего config.json — в нём и подписки 3X-UI, — основная цепочка `main`, правила `pins`, входящие, Mihomo, кто слушает порты,
  Docker; внутри же `awg_view()`), `Dash.proto_view` (`/api/proto`, `_probe_all`) → `proto.links()`: путь = протокол + куда (сервер панели или
  адрес «не в панели») + место в цепочке / правило; таблица «вход × выход» и пути по входам. Проверка каждого пути отдельно — probe MODE
  "prototest" `proto_test()` (временный Xray с теми же исходящими, у каждого свой локальный вход, страница `E2E_URL`), `Dash.proto_test`
  (`/api/proto-test`, итог в памяти `proto_tests`); на стенде — `/etc/testbed-proto.json` (по тегу, «*» — остальные). «Что ещё стоит»:
  `proto.inventory()` — наша схема / известная программа не из схемы (`OTHER`) / неизвестное / системное; «Спросить Аналитику» подставляет
  вопрос и сервер в «Аналитику» (запуск там по кнопке). «Схема» (`protoMapHtml`, `MAP`, `mapAfter`/`mapDraw`) — плитки и линии без библиотек
  (div + SVG, сдвиг/масштаб колесом, плитки тащатся за заголовок, места — localStorage `vd-map-pos` по виду; пока не двигал — вписывается сама):
  «Все серверы» — входы (пути по порядку цепочки) → выходы (что принимают: awg, Sudoku, входящие 3X-UI); «вход» — входящие 3X-UI → правила
  (`proto.rules`: probe `rules`/`plain`/`first_out`, имена «Россия», «IPv6», «Telegram»…, соседние одинаковые склеены; нет общего — неявное «всё
  остальное» на первое исходящее) → цепочки (основная = `main`) / напрямую / блок → выходы. Линия: синяя — где сейчас трафик (первый живой путь
  основной цепочки), серая — запасной рабочий, красная — не работает, пунктир — не проверялся/не используется.
  Кнопка «Во весь экран» (`mapFullscreen`, флаг `MAP.fs`): обёртка `#mp-full` (кнопки входов/режимов + поле + легенда)
  получает `.fs` — fixed на всё окно, z-index 45 (модалки 50 и тосты 80 остаются поверх), поле `.mp` тянется на свободную
  высоту; плюс `requestFullscreen` у documentElement (перерисовки `renderAwg` его не сбрасывают, отказ браузера не мешает —
  остаётся режим «на всё окно»). Выход — той же кнопкой или Esc (`fullscreenchange` / keydown); при входе и выходе схема
  вписывается заново (`MAP.fit`).
  Режимы схемы (`MAP.mode`): «Настройка» (по умолчанию) — правки в черновик `MAP.draft` (на серверы — только «Применить» после плана, по одному:
  порядок цепочек → связи → отвязки, `mapDraftApply`): «+» у входа протянуть на выход/строку протокола (на другой вход — только VLESS) = link,
  щелчок по пути (строка или линия, `data-un`) = unlink, перетаскивание звена основной цепочки за ⠿ в схеме входа = order
  (`Provisioner.reorder_plan`/`start_reorder`, задача `reorder`, `/api/reorder(-plan)` → `server-scripts/vpn-reorder.sh ТЕГ1,ТЕГ2,…`: те же Bal-N,
  меняются fallbackTag/петли `_bl_`, общее правило и DNS — на новое начало; отказ, если на середину цепочки ведут свои правила).
  «Что если» (`mapSim`, `MAP.fail`: x:ID / ext:адрес / p:вход:тег) — понарошку выключить выход/путь, куда уйдёт трафик, правила без пути,
  «проверка на прочность» (каждый выход по одному и пары). «Куда пойдёт» — `proto.ROUTE_PY` (`/api/route`, `Dash.route_trace`): правила
  работающего config.json по порядку как у Xray (domain:/full:/regexp:/keyword:/geosite: и geoip:/подсети из .dat входа, domainStrategy AsIs/
  IPIfNonMatch/IPOnDemand), `proto.rules` отдаёт `ix` — номера правил probe; путь — первый живой. «Нагрузка» — скорость по счётчикам awg
  (`mapRates`, раз в 10 с). «Перемотка» — 48 получасов из `S.hist` (`mapPastState`), переключения на резерв за сутки. Связь по VLESS
  (`LINK_PROTO` vless): клиент `vpn-dash-<id входа>` во входящем VLESS Reality цели через API 3X-UI (`VLESS_CLIENT_PY` find/add/rm, токен
  `x-ui setting -getApiToken`, после — перевыпуск), параметры — файлом `/root/.vpn-dash-job/vless.json` 600 → `VLESS_ONLY=1 vpn-add-exit.sh`
  (исходящее `VLESS-ИМЯ`, отпечаток firefox), проверка — `proto_test`; отвязать — `vpn-unlink.sh VLESS ИМЯ` + rm клиента (только `VLESS-…`).
  На стенде: API 3X-UI в `dev/fake-xui-web.py` (токен stand-api-token), geoip.dat, растущие счётчики туннелей, `python3 dev/fake-history.py`
  — сутки истории для «Перемотки». Действия, меняющие серверы (вкладка «Настройка» удалена, всё делается на «Схеме», `MAP_EDIT = true`): «Связать» вход с выходом по AmneziaWG или Sudoku — `Provisioner.link_plan` (`/api/link-plan`, ничего не меняет: ошибки,
  предупреждения, шаги по серверам; связь уже есть, не вход/выход, нет Mihomo, разные связки → `cross`, нужна отдельная галочка) →
  `start_link`/`_link` (задача `link`, `/api/link`): на выходе только нужный протокол — `ONLY_AWG=1` (без fail2ban, с sysctl пересылки/BBR;
  ufw — порт и route allow) или `ONLY_SUDOKU=1`, уже стоит — не трогается; на входе `AWG_ONLY=1`/`SUDOKU_ONLY=1 vpn-add-exit.sh` с `POSITION`
  (end/first/after:тег; цепочки нет — общий путь оборачивается, как у `sudokubk`); проверка каналов до/после. Имя в тегах — `_link_name`
  (то же, если вход уже связан с этим выходом другим протоколом). «Отвязать» — `Provisioner.unlink_plan` (`/api/unlink-plan`) → `start_unlink`/`_unlink`
  (задача `unlink`, `/api/unlink`): на входе `server-scripts/vpn-unlink.sh AWG|Sudoku ИМЯ|@wgN|@порт` (сначала `CHECK=1`): звено вынимается из цепочки,
  соседи сшиваются (fallbackTag предыдущего → следующий, правила — на следующее звено), исходящее и наблюдатель убираются; отказ, если путь
  в других цепочках/правилах или единственный с правилами; копия базы и откат; потом `drop_old` (туннель → .removed, прокси Mihomo — если больше
  никому не нужен) и `UNLINK-PEER=<ключ>` → на выходе `PEER_RM_PY` убирает этого клиента из awg0 (копия `.before-unlink-*`). Sudoku на выходе не трогается.
  Правки мышкой на схеме включены (`MAP_EDIT = true`): связать/отвязать/порядок цепочки/VLESS — только на «Схеме»,
  черновик → «Показать план» → «Применить». Вкладки «Настройка» больше нет (код protoSetupHtml/LS удалён).
  Вкладка «AmneziaWG» — прежний вид: probe MODE "awg" `awg_view()` — конфиги wgN/awgN (PrivateKey/
  PresharedKey не уходят с сервера, HeaderProtectionKey — только отпечаток), пиры с именами из комментариев, `awg show all dump`.
  `Dash.awg_view` (`/api/awg`, все серверы параллельно, не хранится): у входа туннель → выход по Endpoint, сверка `AWG_MUST`
  (S1–S4, H1–H4, ключ заголовков) с awgN выхода, пир выхода ↔ вход по AllowedIPs = Address. Страница сама обновляется раз в 30 с.
  Пакеты-маски — `awgmimic.py`: `generate(quic|stun|dns)` → строка I1 только из тегов `<b 0x…>`/`<r N>`; задача `mimic`
  (`start_mimic`, `/api/awg-mimic`, только туннели wgN входов, одна за раз) → `APPLY_PY`: копия `.before-mimic-*`, I1–I5 в
  [Interface], `systemctl restart awg-quick@wgN`, ping -I wgN .1 и рукопожатие новее старта ≤40 с, иначе копия назад.
  На стенде — `/etc/testbed-awg-mimic-bad`: с I1 заглушка awg отдаёт рукопожатие 0 (проверка отката).
- `quality.py` — раздел «Связь» (`#/quality`, качество каналов): замеры без изменений на серверах. На входе — исходник quality.py шлётся перед probe.py
  (MODE "quality", `entry_run`: ping напрямую/`-I wgN` до .1 туннеля, при отсутствии ответа — TCP к порту Sudoku; curl через
  SOCKS; `ss -tin` живые соединения; 2 МБ с speed.cloudflare.com; трассировка своими ICMP с TTL). С ПК — `pc_run` (ping/tracert
  на Windows, TCP к порту VLESS). `Dash.quality_check` (`/api/quality`, одна за раз), итог в снимке `quality`. Набор маршрутов
  хранится в браузере. На стенде — заглушка ping и ветки curl, цифры задаёт `/etc/testbed-quality.json`.
- «Аналитика» (`#/ai`, `renderAi`): `analyst.py` — агент на Claude API (Messages + tool use, urllib, `anthropic-version: 2023-06-01`,
  кэш промпта на system/tools/последнем сообщении). Инструменты: `panel_overview` (что видит панель: статусы, каналы — в норме одной строкой, остальные подробно с доступностью за сутки,
  e2e, схема, маски, DC, версии; не обрезается до `OVERVIEW_CHARS`), `panel_events` (журнал), `server_check` (проверки под vpn-ro),
  `all_servers_check` (одна проверка из `ALL_CHECKS` на всех серверах параллельно, по `ALL_CHARS` от каждого — общий обход за шаг), `submit_report` (level ok/warn/bad, summary,
  body Markdown). «Свой вопрос» (trigger `ask`, колонки `question`/`scope` в `reports`): `start(question, servers)` — ответ в свободной форме,
  инструменты и обзор — только по выбранным серверам (`servers()`, `_foreign`), ответ можно скачать .md; настройки Xray — проверка `xray-config`
  (config.json, исходящие/правила/цепочки/входящие без секретов, вывод до `BIG_CHECKS`). Всё, что уходит в модель, — через `redactor()` (адреса → имена/[адрес-N] на весь прогон, UUID/ключи скрыты), вывод проверки
  обрезан до `TOOL_CHARS`. Ключ API — keyring `_anthropic_key`, меняется только с домашнего порта (`/api/ai` key/clearkey). Лимиты: шагов,
  $ за прогон и за месяц (`cost()` по `MODELS` из usage). Отчёты — `history.db` → `reports` (180 дней). Запуск: кнопка; `tick()` из auto_loop —
  ежедневно с часа `ai_hour` (догоняет, если ПК был выключен), при переходе `overall()` в bad (не чаще раза в 2 ч). Настройки `ai_*` в `settings`
  (страница «Аналитика», не «Настройки»). На стенде ключ «stand» — `Analyst.fake` (сценарий из 4 шагов, включая запрещённую проверку).
  Доступ «только чтение» — `readonly.py`: пользователь vpn-ro, ключ панели ECDSA в keyring `_ro_key`, в authorized_keys
  `restrict,command="/usr/local/sbin/vpn-dash-ro"` → `printf %s "$SSH_ORIGINAL_COMMAND" | sudo -n python3 -I /usr/local/lib/vpn-dash-ro/ro.py` (строка
  проверки — через stdin; в sudoers ровно эта команда без «*» и без Defaults: sudo-rs в Ubuntu 26.04 не понимает подстановок в аргументах и requiretty). `server-scripts/vpn-dash-ro.py` — список названных проверок (`CHECKS`, аргументы по регуляркам, `clean()` вырезает секреты на сервере),
  рядом копия probe.py (MODE "lib" — как библиотека). Ставит/убирает задача `ro` (`start_ro`, `/api/ai` ro/ro_all) через root: INSTALL_SH, затем
  проверка под vpn-ro (version, system, «id; touch» → отказ). probe `ro_info()` → `data.ro` (VERSION из ro.py на сервере, хвост ключа) против `readonly.version()` — VERSION поднимать, только когда меняются сами проверки.
- `server-scripts/` — bash-скрипты для серверов (бэкап/восстановление входа, развёртывание выхода,
  цепочки резерва). `vpn-backup.sh` оттуда же использует кнопка бэкапа.
  `vpn-awg-common.sh` — общие функции AmneziaWG (`apt_begin`, `add_amnezia_ppa`, `reload_awg_module`) для
  `vpn-exit-setup.sh` и `vpn-restore.sh`: `Provision.put` кладёт его рядом сам. `vpn-pin-chain.sh` берёт из `vpn-add-exit.sh`
  `xui_db_backup` / `xui_start_or_rollback` (копия базы 3X-UI и откат, если Xray не поднялся).
- Общее без повторов: `jsonline.last_json` — итог скрипта с сервера (последняя строка JSON) для ipcheck/neighbors/dnscheck;
  `quality.run_bg`; `provision.first_steps`, `Provision.working_now`
  (каналы, что работали до изменения); `dash.probe_func(имя)` — текст функции из probe.py для маленьких скриптов на сервер.
- Этот проект — универсальный продукт, а не персональная конфигурация разработчика.
  Sudoku, Mihomo и AmneziaWG никогда не удалять из публичной версии.
  Нельзя публиковать локальные настройки, секреты, ключи, реальные примеры серверов или историю
  приватного проекта. Тестовые данные — вымышленные; проверки должны запрещать выпуск
  при подозрении на утечку. Перед публикацией — полный аудит диффа и стендовые тесты.

Каскад: устройство → вход (3X-UI/Xray, VLESS Reality) → выходы через AmneziaWG (wg0, wg1, …)
и Sudoku через Mihomo SOCKS (1080, 1081, …); цепочка резерва — балансировщики 3X-UI с fallbackTag
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
  из интернета (и её порт в ufw) и свой путь (`XUI_WEB_PY`: webListen/webBasePath, перезапуск x-ui, проверка, откат), включить/выключить
  фаервол (ufw, с замером до/после и автооткатом), перевод выхода с Docker на AmneziaWG без Docker, перевод Sudoku с sing-box на обычный, запасной канал Sudoku к выходу связки, «Связать»/«Отвязать» вход и выход по AmneziaWG/Sudoku/VLESS и порядок цепочки («Протоколы» → «Схема», после плана), пакеты-маски AmneziaWG (I1) на туннеле входа (с откатом), обновление Sudoku/Mihomo до релиза с GitHub, zapret2 на входе (установка, подбор, включение, «напрямую»; автоматическое
  изменение — автовозврат цели на выходы, включается галочкой у цели), «сети госорганов» на входах (не пускать новые
  подключения из их подсетей; обновление списка раз в сутки — автоматически, только где включено, с замером и откатом), открыть порт 80
  для продления сертификата Let's Encrypt (`ACME80_SH`: `ufw allow 80/tcp` + `acme.sh --renew` только того, чему уже пора, без --cron — он обновляет сам acme.sh; probe `acme_info` видит, что ufw его закрыл). поставить jq/curl/iproute2 для «как видят», если их нет (кнопка «Поставить … и проверить заново», `ipcheck.install_cmd`), поставить/убрать пользователя vpn-ro для «Аналитики» (только чтение, проверки из списка; сам агент ничего не меняет). Окно обновлений до кнопки
  только читает (`MODE = "pkgs"`; «Проверить заново» = apt-get update).
- Панелью пользуются только с ПК: под телефон ничего не делать и не проверять.
- `start.bat` — CRLF, UTF-8, `chcp 65001`.
- Каждое изменение — проверить на стенде и в браузере (Playwright, Chromium предустановлен),
  коммит с понятным русским описанием (его пользователь видит в «Проверить обновления»).

## Стенд для проверки
`sudo bash dev/testbed.sh up` — фейковые 3X-UI/Mihomo/AWG, заглушки awg/curl/systemctl и sshd :2222;
«серверы» 127.0.0.2…6. `bash dev/testbed.sh run 8790` — панель на стенде с заданными паролями.
`sudo bash dev/testbed.sh down` — убрать. Нельзя запускать на настоящем сервере.
Мастер на стенде: «новый выход» — 127.0.0.7:2222; `vpn-exit-setup.sh` подменяется на
`dev/fake-exit-setup.sh`, обновление системы пропускается (`VPN_DASH_STAND=1`), остальные скрипты
настоящие; «новый вход» — 127.0.0.8/9, vpn-restore.sh идёт с `--only awg --force-awg`.
После `apt upgrade` в контейнере старый sshd стенда сбрасывает соединения — `pkill -x sshd` и `up`. Остановить панель стенда — `bash dev/testbed.sh stop`.
Выход в Docker на стенде: `cp dev/fake-docker.py /usr/local/sbin/docker && chmod +x …`, `echo '{"containers": {"amnezia-awg2": {"port": 43437}}}' > /etc/testbed-docker.json`, убрать `/etc/amnezia/amneziawg/awg0.conf`.
Осторожно с `pkill -f`/`pgrep -f <шаблон>`: шаблон совпадает и с собственной командной строкой
оболочки (это уже убивало сессию). Останавливать процессы — по pid-файлу или `pkill -x имя`.
