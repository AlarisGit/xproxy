# xproxy

Небольшой watchdog поверх [xray](https://github.com/XTLS/Xray-core), который:

- регулярно обновляет список серверов из подписки;
- фильтрует серверы по `conf/country.lst` и сортирует по приоритету стран;
- скачивает актуальные `geosite.dat` / `geoip.dat` для маршрутизации с экспоненциальным бэкоффом и валидацией формата;
- сам чистит routing/DNS от ссылок на отсутствующие `geosite:*`/`geoip:*` категории, чтобы `xray -test` не падал из-за несовпадения `.dat` и `routing.json`;
- постоянно следит за тем, что трафик реально идёт через xray;
- **если** интернет жив, но проксируемый трафик не проходит N раз подряд — переключается на следующий рабочий сервер, регенерируя `config.json` и рестартуя xray.

Работает на macOS (`brew services restart xray`, `/opt/homebrew/etc/xray/config.json`) и Linux (`sudo systemctl restart xray`, `/usr/local/etc/xray/config.json`).

## Структура

```
xproxy/            пакет
  settings.py      все тайминги/пути
  platform_utils.py детект платформы + команды рестарта/записи
  env_config.py    чтение .env с валидацией
  subscription.py  загрузка и кэш подписки
  servers.py       парсинг vless://, страна, сортировка, TCP-проба
  routing.py       конвертер conf/routing.json → xray routing/dns/fakedns
                   + strip-missing-geo (вырезает ссылки на отсутствующие категории)
  geo.py           скачивание geosite.dat / geoip.dat:
                   atomic replace, Content-Length + format validation,
                   exponential backoff, persistent state, self-heal от битых файлов
  xray_config.py   сборка итогового config.json
  xray_control.py  запись/рестарт xray
  healthcheck.py   приоритизированные пробы через прокси и напрямую
  state.py         состояние демона (активный сервер, счётчики)
  notifier.py      уведомления в Telegram (SOCKS → direct)
  autoupdate.py    git pull --ff-only, валидация, безопасный рестарт
  daemon.py        главный цикл + one-shot
conf/              шаблоны и справочники (версионируются)
  config.tmpl      базовый xray-конфиг (log + inbounds); остальное добавляется
  subscription.tmpl ссылка подписки с плейсхолдерами
  country.lst      разрешённые страны в порядке приоритета (сверху = лучше)
  routing.json     маршрутная конфигурация (Hiddify-like)
state/             кэш и состояние (в .gitignore)
                   active.json       — текущий активный сервер
                   servers.json      — последняя успешная подписка
                   geo_state.json    — успехи/попытки/failure-счётчики по .dat
                   xray_config.backup.json — последний рабочий xray config
deploy/            systemd/launchd/sudoers + install.sh
main.py            CLI-entrypoint
```

## Установка зависимостей

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`PySocks` **обязателен** — без него проба прокси всегда будет падать.

## Логи

Пишутся в `/var/log/xproxy/xproxy.log` с ротацией 100 КБ × 3 файла (итого ≤ 400 КБ на диск). Также дублируются в stderr. Директория создаётся `deploy/install.sh` (потребует `sudo` один раз) и сразу передаётся текущему пользователю, так что дальнейшая работа — без sudo. Если директории нет/нет прав — файловый хендлер молча отключается, остаётся только stderr.

## Запуск

```bash
python main.py --once --dry-run   # одна диагностическая итерация, не трогает xray
python main.py --once             # одна итерация с реальной ротацией, если нужно
python main.py --daemon           # постоянный цикл
```

Флаг `-v` включает DEBUG.

Перед первым запуском скопируйте `.env.example` → `.env` и заполните `SUBSCR_UUID`. Опционально добавьте `TELEGRAM_BOT_TOKEN` / `TELEGRAM_ALERTS_USER_ID` для уведомлений.

## Telegram-уведомления

Если в `.env` заданы оба ключа `TELEGRAM_BOT_TOKEN` и `TELEGRAM_ALERTS_USER_ID`, демон шлёт сообщения в ключевых точках:

Формат сообщения: `hostname/public_ip: <текст>` (префикс добавляется автоматически).

- **Старт** — `🟢 xproxy started (active: Германия (...))`
- **Остановка** — `🛑 xproxy stopped (signal SIGTERM, last active: ...)`
- **Ротация** — `🔄 switched Германия → Австрия (host:port) reason=proxy-failing`
- **State-machine active/standby**:
  - `🟢 standby READY: ... — ready_ttl=Ns usable_ttl=Ns slot=...` — слот стал готовым после пустого/невалидного состояния или фактически заменил прежнее содержимое;
  - плановый цикл `READY → PRE_STALE → READY` для того же standby-конфига не отправляет Telegram-уведомление;
  - `🔴 standby FAILED: ... reason=...` — promotion не прошла проверку или подбор кандидата падает, пока active уже ждёт standby;
  - `🟠 active WAITING_FOR_STANDBY: ... reason=...` — боевой сервер признан проблемным, готового резерва пока нет;
  - `🔄 active PROMOTING: ... — next=...` и `🔄 standby PROMOTING: ...` — начинается быстрая promotion;
  - `🟢 active OK: ... reason=...` — активный канал снова в рабочем состоянии после recovery/switch/promotion.
- **Проблема с подпиской**:
  - `⚠️ subscription unavailable: ...` — подписка недоступна (даже кэш пуст)
  - `🔴 subscription stale for Nh — live fetch keeps failing` — подписка не обновлялась живым фетчем более 24ч (критично)
  - Кэш-фетч вместо живого — только в лог, без Telegram (штатная ситуация, демон восстановится сам)
- **Автоапдейт** (успехи):
  - `🆙 xproxy updating abc1234 → def5678, restarting` (ок, pull + restart; отправляется **blocking**, чтобы сообщение успело уйти до `os.execv`)
  - `⚠️ autoupdate pulled ..., but requirements.txt changed` (нужен ручной pip install)
- **Автоапдейт** (неудачи):
  - `⚠️ autoupdate failed: fetch failed — <error>` (git fetch не прошёл)
  - `⚠️ autoupdate failed: pull failed — <error>` (git pull ff-only отклонён)
  - `⚠️ autoupdate paused: too many recent restarts (rate-limit)` (сработал лимит перезапусков)
  - `⚠️ autoupdate failed (check_and_pull exception): ...` (неожиданное исключение)
  - `🔴 autoupdate: new code failed import check` (откат на старый)
- **Автоапдейт** (стабильные no-op, без уведомлений): `up to date`, `working tree not clean`, `no upstream`, `detached HEAD`, `not a git repo`.
- **Нет рабочего сервера** — `🔴 no working server found (tried N of M, K in penalty box, reason=...)` (отправляется **blocking**, чтобы максимизировать шанс доставки при сломанном прокси).
- **Geo-файлы**:
  - `⚠️ geo download error (geosite.dat: ...); working copy kept, next retry in Ns` — скачивание не прошло (HTTP ошибка, обрыв соединения, битый ответ); боевая копия на диске не тронута.
  - `⚠️ routing: dropped entries referencing missing geo categories (N total): ...` — в `routing.json` указаны `geosite:*` / `geoip:*` категории, которых нет в свежескачанных `.dat`. Эти правила вырезаны, чтобы `xray -test` не падал. Отправляется только при **изменении** набора выкинутых записей (не спамит).
- **Тупик** — `🔴 xproxy stuck: rotation needed (...) but geo assets unreadable ...` (отправляется **blocking**, **urgent**). Срабатывает, если одновременно нужно переключить сервер И все `.dat`, на которые опирается текущий `routing.json`, нечитаемы. Дедуплицируется: следующее уведомление уйдёт, только когда geo-assets снова станут валидными и ситуация повторится.
- **Суточный heartbeat** (раз в сутки, после `HEARTBEAT_HOUR=12:00` локально) — `💚 daily heartbeat: active=..., proxy=ok, uptime=2d 3h, rotations_today=N`. Если heartbeat перестал приходить — значит инстанс умер или потерял оба канала.

Защиты:

- **Маршрут**: сначала пробуем через xray SOCKS-прокси (во многих юрисдикциях `api.telegram.org` заблокирован на прямом канале — это одна из основных причин, почему вы используете xproxy), при неудаче — fallback на direct.
- Каждое сообщение автоматически префиксируется `hostname/public_ip:`. Внешний IP определяется через **consensus** из нескольких `IP_CHECK_URLS` (защита от сервисов, возвращающих IP upstream-провайдера вместо реального source-IP), **без прокси**, и кэшируется на `NOTIFIER_IDENTITY_TTL` (6 часов).
- Одинаковые сообщения не повторяются чаще 60 секунд (throttle). `urgent=True` в коде обходит throttle.
- Отправка в daemon-треде с таймаутом 6 сек — не блокирует основной цикл.
- Токен никогда не логируется (автоматически редактируется в любых сообщениях об ошибках).
- Если любой из ключей не задан — функция молча ничего не делает.

## Автозапуск

Универсальный скрипт: `deploy/install.sh`. Он рендерит шаблоны (подставляет `$HOME`, пользователя, путь проекта, `python3`) и печатает команды установки.

### macOS (LaunchAgent)

```bash
./deploy/install.sh
launchctl load -w ~/Library/LaunchAgents/com.xproxy.daemon.plist
# чтобы xray видел кастомные geo-файлы:
launchctl setenv XRAY_LOCATION_ASSET "$HOME/.config/xproxy/geo"
brew services restart xray
```

Управление сервисом:

```bash
# Статус
launchctl list | grep xproxy          # PID и exit-код

# Логи
tail -f /var/log/xproxy/xproxy.log

# Перезапуск (отправляет SIGTERM, ждёт завершения, затем стартует)
launchctl stop com.xproxy.daemon && launchctl start com.xproxy.daemon
# Или одной командой:
launchctl kickstart gui/$(id -u)/com.xproxy.daemon

# Полная перезагрузка конфига
launchctl unload ~/Library/LaunchAgents/com.xproxy.daemon.plist
launchctl load -w ~/Library/LaunchAgents/com.xproxy.daemon.plist
```

### Linux (systemd)

```bash
./deploy/install.sh      # напечатает готовые команды
# Установить unit:
sudo install -m 0644 /tmp/tmp.XXXX /etc/systemd/system/xproxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now xproxy.service

# Разрешить рестарт xray и запись config.json без пароля:
sudo install -m 0440 /tmp/tmp.YYYY /etc/sudoers.d/xproxy
sudo visudo -c

# Сделать так, чтобы xray использовал наши geo-файлы:
sudo systemctl edit xray
# добавить:
# [Service]
# Environment=XRAY_LOCATION_ASSET=/var/lib/xproxy/geo
sudo systemctl daemon-reload
sudo systemctl restart xray
```

Управление сервисом:

```bash
# Статус
sudo systemctl status xproxy.service

# Логи
tail -f /var/log/xproxy/xproxy.log
# или через journalctl:
journalctl -u xproxy.service -f

# Перезапуск
sudo systemctl restart xproxy.service

# Полная перезагрузка (если меняли unit-файл):
sudo systemctl daemon-reload
sudo systemctl restart xproxy.service
```

## Fail-safe и geo-файлы

Перед каждой записью `config.json` xproxy прогоняет `xray -test` на временном файле. Проверка выполняется дважды: сначала с asset-каталогом xproxy (`XRAY_LOCATION_ASSET=GEO_DIR`), затем с `XRAY_LOCATION_ASSET`, который виден продовому xray-сервису (`systemctl show xray ...` на Linux или launchd/Homebrew plist + `launchctl getenv` на macOS). Если любой тест не прошёл — боевой `/etc/xray/config.json` **не меняется**, xray продолжает работать со старым конфигом. Сломать работающий xray нельзя, даже если мы ошибёмся в шаблоне, подписка выдаст странный URI или продовый xray не видит свежие geo-файлы.

Если сгенерированный конфиг бит-в-бит совпадает с текущим на диске — запись и рестарт xray пропускаются (`ConfigUnchanged`). Это нужно, чтобы post-download rebuild или startup-rebuild не рвали живые соединения, если на самом деле ничего не изменилось.

Важно: `ConfigUnchanged` проверяется только после `xray -test`. Если уже опубликованный файл совпадает с новым, но больше не проходит prod-проверку (например, у `xray.service` потерялся `XRAY_LOCATION_ASSET`), xproxy не будет маскировать это как no-op.

После записи и рестарта xproxy обязательно ждёт локальный listener xray (`127.0.0.1:10808`). Если listener не поднялся за `BOOT_GRACE`, это считается аварией запуска xray, а не нерабочим сервером: ротация останавливается на первом таком кандидате, в лог пишется диагностика (`xray_running`, prod `XRAY_LOCATION_ASSET`, повторный prod `xray -test`, хвост error-log), и следующий конфиг не публикуется.

На время теста пути `log.access` / `log.error` в копии конфига заменяются на `"none"` — иначе `xray -test`, запущенный из-под пользователя xproxy, пытался бы открыть боевой `/var/log/xray/*.log` (принадлежит root) и падал бы с `permission denied`, хотя сам конфиг валиден. Боевой файл на диске пишется с оригинальными путями.

### systemd-sandbox: `ReadWritePaths`

Юнит `xproxy.service` использует `ProtectSystem=full` — `/usr`, `/boot`, `/efi` делаются read-only для процесса в приватном mount namespace. Это хорошая практика безопасности, но у неё есть ловушка: **любая запись в `/usr/local/etc/xray/config.json` вернёт `[Errno 30] EROFS`**, даже если файл принадлежит вашему пользователю, даже через sudo (дочерние процессы наследуют namespace юнита).

Поэтому в юните обязательно есть:

```
ReadWritePaths=/usr/local/etc/xray
```

Если xray на вашей системе читает конфиг из другого пути (например `/etc/xray/config.json` при установке из deb/rpm), поменяйте значение соответственно — иначе демон будет штрафовать все серверы с ошибкой `Read-only file system`, хотя FS на самом деле read-write.

Запись `config.json` атомарна: сначала пишется соседний временный файл, затем выполняется rename поверх боевого файла. На Linux sudo-fallback делает то же самое через `sudo tee` во временный файл и `sudo mv -f` в целевой путь. Для совместимости первого автообновления со старыми `/etc/sudoers.d/xproxy` оставлен fallback на прежний `sudo tee config.json`, если запись во временный файл не разрешена; после применения нового `deploy/sudoers.xproxy` используется атомарный путь.

Перед записью также сохраняется бэкап текущего `config.json` в `state/xray_config.backup.json`. Откатиться можно вручную или через Python:

```python
from xproxy.xray_control import restore_backup
restore_backup()
```

### Безопасное скачивание geo-файлов

Custom `geosite.dat`/`geoip.dat` (с расширенным набором ru-категорий из `GeositeUrl`/`GeoipUrl` в `routing.json`) скачиваются в shared-каталог и читаются xray-ом через переменную `XRAY_LOCATION_ASSET`, которая прописывается один раз при установке (см. «Автозапуск»).

Сетевой маршрут скачивания предсказуемый: сначала прямой HTTPS без учёта `HTTP_PROXY`/`HTTPS_PROXY` из окружения, затем явный fallback через локальный HTTP inbound xray (`http://127.0.0.1:10809`). Это помогает при проблемах с прямым доступом к GitHub `release-assets.githubusercontent.com`, но не создаёт скрытой зависимости от случайных proxy-переменных shell/systemd/launchd.

Для стабильности xray мы **никогда** не заменяем боевой `.dat`, пока не убедились, что новый geo-набор полноценный и совместим с текущим routing/config:

1. Скачивание идёт в staging-директорию `.geo-staging.*` внутри `GEO_DIR`. Файлы, которые не обновляются в этот проход, копируются туда из текущего live-набора, чтобы проверялся полный будущий `XRAY_LOCATION_ASSET`.
2. После загрузки проверяется:
   - `Content-Length` (если сервер его вернул) должен совпадать с реально прочитанным числом байт;
   - размер файла не меньше 1 КБ (отсекает HTML-страницы ошибок от CDN, отдаваемые с HTTP 200);
   - содержимое разбирается собственным protobuf-парсером v2ray-geodata, ожидается минимум одна запись. HTML/мусор не пройдёт проверку.
3. Staging-набор проверяется strict-режимом: все `geosite:*`/`geoip:*`, которые нужны `routing.json`, `direct.lst` и синтетическим DNS-правилам, должны реально присутствовать. Отсутствующая категория блокирует публикацию всего набора.
4. xproxy собирает config с категориями из staging-набора и прогоняет `xray -test` с `XRAY_LOCATION_ASSET=<staging-dir>`. Если нет ни активного сервера, ни кандидата из подписки для сборки тестового config — публикация geo-набора откладывается.
5. Только после успешных проверок выполняется `os.replace(staged, target)` для live `.dat`. При ошибке публикации уже заменённые файлы откатываются из staging backup.
6. При старте и на каждой итерации live-файл на диске проверяется тем же парсером: если уже лежит битый `.dat` (например, опубликованный старой версией кода до введения валидации), он принудительно перескачивается, не дожидаясь `GEO_REFRESH`.

### Бэкофф и планирование

Максимальный интервал между успешными скачиваниями — `GEO_REFRESH` (6 часов). При ошибках используется экспоненциальный бэкофф из `GEO_RETRY_SCHEDULE`: `10с → 1м → 5м → 30м → 1ч → 6ч`; после каждого успеха счётчик неудач сбрасывается. Состояние (`last_success`, `last_attempt`, `failures` по каждому файлу) сохраняется в `state/geo_state.json` и переживает рестарты.

Планировщик в демоне перечитывает `.dat` ровно тогда, когда это нужно: первая успешная попытка после ошибки запланирована через очередной интервал из schedule, а не через 6 часов. Это даёт быстрое восстановление без лишних обращений к CDN.

### Geo-aware routing: strip_missing_geo

`routing.json` может содержать ссылки на категории (`geosite:vk`, `geoip:ru`, `geosite:category-ru` и т. п.), которых может не быть в конкретном `.dat`. Для публикации новых geo-файлов действует strict-режим: отсутствующая категория блокирует замену live `.dat`. Для уже опубликованных live-файлов `build_xray_sections()` умеет мягко деградировать:

- парсит `.dat` и собирает множество реально доступных категорий по каждому kind'у;
- проходит по всем группам правил (`BlockIp/Sites`, `DirectIp/Sites`, `ProxyIp/Sites`) и по DNS (`domains`, `expectIPs`), вырезая `geosite:*`/`geoip:*` ссылки на отсутствующие категории;
- не-geo записи (CIDR, обычные домены) всегда сохраняются;
- факт вырезаний логируется; **пользователь уведомляется один раз** на каждый уникальный набор выкинутых записей (`_last_removed_geo_sig`), без спама.

### Различие «нет категории» и «файл нечитаем»

Это два разных состояния с разной семантикой:

- **Staged `.dat`, категория отсутствует** → новый geo-набор не публикуется.
- **Live `.dat`, категория отсутствует** → ссылка вырезается из routing/DNS (runtime-деградация без падения `xray -test`).
- **Файл отсутствует/битый/не парсится** → мы **не** вырезаем ссылки: текущая маршрутизация сохраняется as-is. Иначе временная проблема с FS или CDN превратилась бы в живую деградацию трафика.

В этом случае `build_xray_sections()` возвращает `geo_readable=False` и `unreadable_needed=['geosite', ...]`, а демон **не трогает live-config xray**: ни post-download rebuild, ни startup rebuild, ни ротация не выполняются. xray продолжает работать с последним валидным конфигом.

Гибкость: проверяется читаемость только тех kind'ов, на которые реально ссылается итоговый построенный `routing+dns`. Пример: если `geoip.dat` отсутствует, но в `routing.json` нет ни одной `geoip:*` ссылки и нет Domestic DNS с `expectIPs=[geoip:ru]` — rebuild разрешён, отсутствие `geoip.dat` не блокирует.

### Тупиковая ситуация

Если одновременно (а) нужно ротировать (xray упал или прокси не отвечает), и (б) нужные `.dat` нечитаемы, демон не может подменить сервер, не потеряв live-config. Это логируется как `STUCK: rotation blocked ... AND geo assets unreadable` и отправляется отдельное blocking-urgent уведомление. Дедуплицируется: следующее сообщение придёт, только когда geo-assets восстановятся и снова деградируют.

Пути платформо-специфичные:

- **Linux**: `/var/lib/xproxy/geo/` — каталог создаётся `deploy/install.sh` с правами `0755`, владелец — пользователь xproxy. xray-сервис (обычно от `nobody`) может читать эту директорию, потому что она не прячется внутри `$HOME`.
- **macOS**: `~/.config/xproxy/geo/` — на macOS `brew services` запускает xray от текущего пользователя, home-директории по умолчанию world-executable, проблем с доступом нет.

**Почему именно так, а не `~/.config/xproxy/geo/` на Linux:**

`$HOME` на большинстве Linux-дистрибутивов имеет права `0750`, а `~/.config/` — `0700`. Пользователь `nobody`, под которым systemd обычно запускает xray-сервис, **не может войти** в эту цепочку директорий, даже если сами файлы world-readable — `open()` возвращает `permission denied`. Выносить geo-файлы в `/var/lib/xproxy/geo/` проще и безопаснее, чем менять права на `$HOME`.

**Почему не `/usr/local/share/xray/`:**

- Требует sudo и whitelist в sudoers для конкретных путей.
- Ломается на системах с read-only системными каталогами (NixOS, immutable rootfs, squashfs-пакеты).

Если `XRAY_LOCATION_ASSET` **не** задан у xray — xray возьмёт устаревшие geo-файлы, пришедшие с его пакетом, и правила маршрутизации `geosite:...`/`geoip:...` могут работать не так, как ожидается. Начиная с prod-env проверки такой конфиг не будет опубликован, если он не проходит `xray -test` в окружении самого xray-сервиса.

## Автоматическое обновление из git

Раз в `GIT_PULL_INTERVAL` (час по умолчанию) демон пробует обновить свой код:

1. Проверяет, что это git-репо, working tree чист и есть настроенный upstream. Иначе skip.
2. `git fetch` → если нет новых коммитов — skip.
3. `git pull --ff-only` (только fast-forward, никаких мёрджей).
4. Если изменился `requirements.txt`, демон сам выполняет `python -m pip install -r requirements.txt` через тот же интерпретатор, под которым работает xproxy. Если установка зависимостей не прошла — новый код не запускается, git откатывается на прежний commit.
5. Если изменились deploy-файлы (`deploy/sudoers.xproxy`, `deploy/xproxy.service`, `deploy/com.xproxy.daemon.plist`), логируем/уведомляем, но продолжаем self-update: runtime-код должен сохранять обратную совместимость с уже установленным окружением.
6. Запускает в подпроцессе `python -c "import xproxy.daemon; ..."` — валидация нового кода. Если импорт падает → остаёмся на старом коде в памяти, логируем ERROR, не рестартим.
7. Иначе — `os.execv(sys.executable, sys.argv)`. PID сохраняется, systemd/launchd не видят «падения», логи/порты продолжают работать.

Защиты:

- **`fast-forward only`** — никаких авто-мёрджей, никаких переписываний истории.
- **Чистый tree** — локальные изменения никогда не затрагиваются.
- **Валидация импорта** — сломанный код не ломает живой демон.
- **Rate-limit рестартов** — если за `AUTOUPDATE_RESTARTS_WINDOW` (10 мин) случилось `AUTOUPDATE_RESTARTS_LIMIT` (3) перезапусков — автоапдейт приостанавливается до следующего окна, чтобы не уйти в pull-restart-pull-restart цикл.
- **Выключается одной строкой**: `GIT_PULL_INTERVAL = 0` в `xproxy/settings.py`.

После успешного рестарта демон пишет `process started after autoupdate restart (...)` в лог, так что в истории видно, когда именно он обновился.

## Happ routing link

Чтобы передать мобильному приложению VPN обновлённую маршрутизацию, можно собрать ссылку из базового `conf/routing.json` и дополнительных записей `conf/direct.lst`:

```bash
python main.py --routing-link
```

Инструмент разделяет строки `direct.lst` на IP/CIDR и домены: IP-сети добавляются в `DirectIp`, домены — в `DirectSites`. IP-адреса валидируются через стандартный парсер Python, дубли с базовым `routing.json` не добавляются. Итоговый JSON сериализуется компактно, кодируется в base64 и печатается как `happ://routing/onadd/<base64>`.

## Логика healthcheck

Каждые `HEALTH_INTERVAL` (15 с) демон проверяет, проходит ли трафик через xray.

### Приоритизированный обход URL

Пробы IP-чекеров идут **по порядку**, а не случайно. `IP_CHECK_URLS` в `settings.py` отсортирован от самых быстрых/надёжных к медленным/резервным:

1. `icanhazip.com` — стабильно быстрый, почти не таймаутит через прокси
2. `ifconfig.me/ip` — стабильно быстрый
3. `api.ipify.org` — иногда медленный через CDN
4. `ipecho.net/plain` — резерв, чаще таймаутит

`_any_probe()` пробует URL по порядку, останавливаясь после первого успеха. Это минимизирует число ложных 1/3-фейлов, когда случайный shuffle подкидывает медленный чекер первым.

### Таймаут пробы

`HEALTH_TIMEOUT = 10` с — увеличен с 5 с, чтобы CDN-ноды с холодным коннектом успевали ответить. Ранее с 5 с таймаутом ~30% проб завершались `ReadTimeout`, генерируя ложные `probe failed (1/3)`.

### Анти-флаппинг

Единичный фейл пробы не триггерит ротацию — нужен набор из `FAIL_THRESHOLD` (3) подряд-фейлов. `ROTATION_COOLDOWN` (60 с) не даёт ротировать чаще раза в минуту.

## Логика ротации (кратко)

1. Каждые `HEALTH_INTERVAL` (15 с) — проверка здоровья.
2. Если `xray` не запущен — сразу подбираем первый рабочий сервер (`reason=xray-not-running`).
3. Если прямой интернет мёртв — пропускаем итерацию.
4. Если прокси отвечает, но активный сервер неизвестен (`active=None`) — ротируем, чтобы взять управление (`reason=active-unknown`). Это происходит, когда xproxy стартует, а xray уже сконфигурирован вручную или `state/active.json` утерян.
5. Если прокси отвечает и активный сервер известен — обнуляем счётчик фейлов.
6. Если прокси не отвечает: растим счётчик. При `FAIL_THRESHOLD` (3) подряд-фейлах — ротация:
   - текущий активный штрафуется на `SERVER_PENALTY_DURATION` (5 мин) и уходит в конец очереди;
   - идём по `next_candidates()`: сначала «чистые» серверы, затем штрафники (с раньше истекающим штрафом — раньше); активный всегда в конце своей группы;
   - для каждого кандидата — быстрый TCP-probe → рендер конфига → запись → рестарт → проверка прокси;
   - если кандидат падает на любом шаге — тоже уходит в штрафной бокс;
   - первый прошедший становится активным (его штраф сбрасывается при `set_active`).
7. `ROTATION_COOLDOWN` (60 с) защищает от флаппинга.
8. **Penalty box не блокирует навсегда**: если все серверы в штрафе — мы всё равно проходим по ним (второй шанс), что важно для коротких списков серверов в подписке.
9. Если после полного прохода ни один сервер не работает — отправляется blocking-уведомление `🔴 no working server found`.
10. **Geo-guard**: перед любым rebuild/rotation проверяется, что в построенном routing+dns не осталось ссылок на нечитаемые `.dat`. Если остались — rebuild/rotation пропускаются, live-config xray сохраняется (см. раздел «Fail-safe и geo-файлы» → «Различие "нет категории" и "файл нечитаем"»).

Все тайминги — в `xproxy/settings.py`.

## Целевая архитектура standby-режима

Этот раздел описывает standby-режим: xproxy поддерживает два рабочих конфига —
один применён в боевом xray, второй заранее проверен и готов к немедленному
применению. Балансировка средствами xray (`routing.balancers`, `observatory`)
намеренно не входит в этот этап: standby остаётся управляемым на стороне xproxy
через подготовку конфига и быструю promotion-операцию.

Текущий первый этап реализации хранит standby slot в памяти процесса. Persistent
cache `state/standby.json` описан ниже как следующий шаг, но пока не является
источником данных после рестарта демона.

### Основные роли

**Active Guard** — быстрый контур реакции. Он не подбирает серверы и не делает
долгий перебор кандидатов. Его задача — быстро определить, что боевой xray
перестал доставлять трафик к критичным внешним ресурсам при живом прямом
интернете, и применить уже готовый standby.

**Standby Worker** — медленный контур подготовки резерва. Он выбирает кандидата,
собирает production-конфиг, тщательно проверяет его и поддерживает состояние
`standby_slot` пригодным для promotion (`READY` или `PRE_STALE`). Этот процесс
может занимать время и не должен блокировать быстрый healthcheck боевого xray.

На уровне реализации это могут быть потоки/задачи внутри одного daemon-процесса,
а не отдельные OS-процессы. Важнее не способ запуска, а разделение обязанностей
и синхронизация доступа к общему состоянию.

### Слоты конфигурации

В нормальном состоянии демон стремится держать два рабочих слота:

- `active_slot` — сервер и production-конфиг, который сейчас применён в xray.
- `standby_slot` — другой сервер и production-конфиг, который прошёл проверку,
  но ещё не применён.

`standby_slot` хранит не только JSON-конфиг, но и метаданные:

- ключ сервера (`server.key()`), страна, display name;
- время подготовки (`created_at`) и последней успешной проверки (`last_ok_at`);
- время перехода из `READY` в `PRE_STALE` (`pre_stale_at`) и окончательный
  срок годности (`expires_at`);
- hash/fingerprint входов, из которых собран конфиг: сервер, `routing.json`,
  `direct.lst`, `config.tmpl`, geo-набор, service `XRAY_LOCATION_ASSET`;
- статус слота: `EMPTY`, `READY`, `PRE_STALE`, `PROMOTING`, `STALE`.

Если routing, geo-файлы, шаблон, подписка или service-env изменились так, что
fingerprint больше не совпадает, standby нельзя использовать как fast path: он
становится `STALE`, а Standby Worker должен подготовить новый.

Для защиты от гонок у standby-подготовки есть generation/epoch. Любое изменение
входов standby (`subscription`, geo/routing/template/service-env invalidation)
инкрементит generation. Worker захватывает текущую generation перед долгой
проверкой кандидата и публикует результат только если generation не изменилась.
Сам `config_text` тоже защищён fixed-point проверкой fingerprint: fingerprint
снимается до сборки/валидации и после end-to-end проверки, и кандидат
отбрасывается, если входы изменились в середине подготовки. Отдельный
waiting-generation защищает от поздней promotion: если active успел
восстановиться и вышел из `WAITING_FOR_STANDBY`, результат worker'а остаётся
готовым standby, но не применяется автоматически.

`PREPARING` не является статусом опубликованного standby slot. Это внутреннее
состояние Standby Worker: он может долго собирать и проверять нового кандидата,
но уже опубликованный `READY`/`PRE_STALE` slot при этом остаётся доступным для
Active Guard.

Жизненный цикл пригодного слота разделён на два интервала:

- `READY` — свежий standby, promotion разрешена, refresh ещё не нужен;
- `PRE_STALE` — refresh уже нужен, но promotion всё ещё разрешена;
- `STALE` — fast promotion запрещена, нужен новый проверенный standby.

### Синхронизация и персистентность

Общее состояние слотов должно обновляться под одним lock. Для связи между
контурами достаточно `Condition`/`Event` внутри daemon-процесса:

- Standby Worker публикует `standby_slot=READY` и отправляет `StandbyReady`;
- Active Guard реагирует на `StandbyReady`, если всё ещё находится в
  `WAITING_FOR_STANDBY`; параллельный cold fallback может восстановить active
  раньше;
- после promotion Active Guard очищает standby slot и отправляет worker'у
  wakeup на подготовку следующего резерва;
- refresh подписки bump'ит generation для in-flight worker'ов, но сохраняет
  опубликованный standby, если endpoint остался в новом ranked и fingerprint
  совпадает; geo-update и rebuild routing/template инвалидируют standby через
  fingerprint и тоже будят Standby Worker.

Персистентный `state/standby.json` полезен как cache между рестартами, но не
должен быть безусловным источником истины. При старте демон может загрузить
standby snapshot, проверить fingerprint/TTL и, если нужно, быстро перепроверить
его end-to-end перед переводом в `READY`. Если проверка не пройдена — slot
считается `EMPTY`, а Standby Worker начинает обычный подбор.

### Проверка standby

Standby Worker подготавливает кандидата по конвейеру. Если текущий slot перешёл
в `PRE_STALE`, worker сначала перепроверяет именно сохранённый в slot сервер.
Если он всё ещё проходит end-to-end проверку, slot возвращается в `READY`, а
поиск нового сервера не запускается.

1. Выбрать следующий сервер из `next_candidates()`, если slot `EMPTY`/`STALE`
   или перепроверка `PRE_STALE` slot провалилась. Текущий active исключается.
   Кандидаты из страны текущего active не запрещены, но понижаются в приоритете:
   Standby Worker сначала пробует другие страны и только затем same-country
   fallback.
2. Выполнить быстрый `tcp_probe(candidate.address, candidate.port)`.
3. Собрать production config тем же кодом, который будет использоваться при
   promotion.
4. Прогнать `xray -test` через `validate_config_for_service()`.
5. Выполнить end-to-end проверку через временный xray:
   - заменить inbounds на свободные локальные standby-порты, например
     `127.0.0.1:11808` для SOCKS и `127.0.0.1:11809` для HTTP;
   - заменить `log.access` и `log.error` на `"none"`;
   - оставить outbound, routing, dns и geo окружение эквивалентными будущему
     production-конфигу;
   - запустить `xray` дочерним процессом с временным config.json;
   - дождаться локального standby SOCKS listener;
   - выполнить IP-check и `TARGET_CHECK_URLS` через standby SOCKS;
   - остановить временный xray и убрать временный конфиг.
6. Если все проверки прошли, атомарно опубликовать `standby_slot=READY` и
   разбудить Active Guard событием `StandbyReady`.

Временный xray нужен именно для end-to-end проверки: `xray -test` и TCP-проба
не доказывают, что VLESS/TLS/Reality handshake проходит и критичные ресурсы
доступны через конкретный сервер. Постоянно держать вторую копию xray не нужно:
достаточно периодически запускать её на время проверки и обновлять TTL standby.

Публикация нового standby сравнивает содержимое слота по `(server.key(),
fingerprint)`. Если worker перепроверил тот же конфиг в цикле
`READY → PRE_STALE → READY`, Telegram-уведомление не отправляется. Если slot был
`EMPTY`/`STALE` или содержимое изменилось, отправляется `standby READY`.

### Быстрый контур Active Guard

Active Guard делает только дешёвые проверки:

1. Проверить прямой интернет без proxy/env-переменных. Если прямой интернет
   недоступен, ничего не переключать: это не блокировка VPN-сервера.
2. Проверить боевой xray через SOCKS (`proxy_alive`) и критичные ресурсы
   (`target_alive`).
3. Проба `proxy_alive()` уже делает несколько приоритизированных попыток по
   IP-check URL. Отдельный confirm-probe можно добавить позже, если быстрый
   standby threshold окажется слишком чувствительным к одиночным таймаутам.
4. Если active действительно не работает, а `standby_slot=READY` или
   `standby_slot=PRE_STALE`, выполнить promotion.
5. Если standby ещё `EMPTY`/`STALE`, перейти в
   `WAITING_FOR_STANDBY`, разбудить Standby Worker и запустить осторожный
   cold-rotation fallback. В `--once` это единственный путь реальной замены,
   потому что Standby Worker в этом режиме не живёт фоном.
6. Если active сам восстановился (`proxy_alive` и `target_alive` снова OK),
   сбросить `WAITING_FOR_STANDBY`, чтобы поздний `StandbyReady` не переключил
   здоровый active.

Если standby пригоден (`READY` или `PRE_STALE`), используется отдельный быстрый порог
`STANDBY_FAIL_THRESHOLD` (по умолчанию 1 подряд-фейл) вместо обычного
`FAIL_THRESHOLD`. Это уменьшает время реакции: дорогой перебор уже сделан
Standby Worker'ом заранее. `ROTATION_COOLDOWN` не задерживает promotion уже
проверенного standby; cooldown относится только к дорогостоящему cold fallback.
Cooldown учитывает и последнюю успешную ротацию, и последнюю попытку cold
fallback, даже если она закончилась `no working server found`.

Promotion — это не буквальный swap файлов. Старый active после блокировки
становится `penalized`/`suspect`, а standby однонаправленно продвигается в
active:

```text
standby_slot READY/PRE_STALE -> active_slot
standby_slot EMPTY
old active -> penalty/suspect
Standby Worker wakeup -> prepare next standby
```

Promotion должна быть атомарной с точки зрения shared-state и применения
боевого xray config:

1. Под lock пометить standby как `PROMOTING`, чтобы Standby Worker не заменил
   его во время применения.
2. Взять общий apply-lock, который также использует cold rotation, чтобы две
   ветки не писали `config.json` и не рестартили xray одновременно.
3. Записать standby production-config в боевой путь `config.json`.
4. Перезапустить xray и дождаться listener `SOCKS_HOST:SOCKS_PORT`.
5. Выполнить быстрый post-promotion healthcheck.
6. При успехе сохранить новый active, очистить standby slot и разбудить Standby
   Worker для подготовки следующего резерва.
7. Если config уже был применён, но xray не стартовал или post-promotion
   healthcheck не прошёл, попытаться откатить `config.json` через последний
   backup. Если rollback не удался, daemon явно помечает applied standby как
   failed active, чтобы live-конфиг и состояние daemon не расходились молча.
8. При ошибке promotion — штрафовать этот standby, очистить slot, вернуться в
   `WAITING_FOR_STANDBY` или в аварийный cold-rotation fallback.

### Сценарий ожидания standby

Если основной сервер уже признан заблокированным, но standby ещё не готов,
Active Guard фиксирует состояние `WAITING_FOR_STANDBY`, будит Standby Worker и
параллельно использует cold-rotation fallback. Если worker раньше опубликует
`READY`, Active Guard может забрать standby в promotion после повторной проверки
active; если быстрее найдётся кандидат через cold rotation, active обновляется
прежним осторожным путём.

Когда Standby Worker публикует новый `READY` slot, он отправляет событие
`StandbyReady`. Если Active Guard всё ещё находится в `WAITING_FOR_STANDBY`, он
перепроверяет, что active всё ещё не доставляет трафик, и только затем забирает
этот standby в promotion. Если active уже восстановился, waiting-state
сбрасывается, а опубликованный standby остаётся готовым. Standby Worker после
promotion продолжает работу и подбирает следующий резерв, пока снова не
восстановится целевое состояние: `active_slot` работает, `standby_slot=READY`.
Если в waiting-режиме кандидаты подряд проваливают подготовку, worker делает
один проход по списку без повторов, затем ждёт `STANDBY_RETRY_INTERVAL` или
нового wakeup-события.

Telegram-уведомления standby намеренно отправляются только при полезном
изменении содержимого slot: новый usable standby после `EMPTY`/`STALE` или
замена сервера/fingerprint. Внутренние события Standby Worker (`PREPARING`,
`VALIDATING`, плановый refresh того же slot) остаются в логах.

### Инварианты

- Active Guard применяет standby только если slot `READY` или `PRE_STALE`.
- Standby Worker никогда не выбирает текущий active как standby.
- При `PRE_STALE` Standby Worker сначала перепроверяет текущий standby slot и
  возвращает его в `READY`, если он всё ещё работает.
- Standby Worker понижает приоритет страны текущего active только при реальной
  замене standby: другой endpoint в той же стране допустим как fallback.
- Старый active после сбоя не становится standby автоматически.
- `standby_slot=READY` всегда означает, что конфиг прошёл `xray -test` и
  end-to-end проверку через временный xray.
- `standby_slot=PRE_STALE` всё ещё можно promoted; это сигнал worker'у
  подготовить свежую замену без потери fast path.
- Любое изменение geo/routing/template/service-env инвалидирует standby через
  fingerprint.
- Refresh подписки сохраняет usable standby, если сервер всё ещё присутствует
  в ranked и fingerprint совпадает; если сервер удалён из подписки, slot
  инвалидируется.
- Подготовка нового кандидата не очищает текущий usable standby slot.
- Результат подготовки standby, начатой на старой generation, не публикуется и
  не штрафует кандидата.
- Promotion забирает standby под lock, явно помечает `PROMOTING` на всё время
  применения и через общий apply-lock не допускает параллельной записи
  `config.json` со стороны cold rotation.
- Если promotion не удалась, кандидат штрафуется и не переиспользуется без
  новой проверки.
- Standby Worker не штрафует кандидата, если за время проверки он стал текущим
  active.
- При отсутствии готового standby сохраняется текущий fail-safe принцип:
  не публиковать непроверенный конфиг только ради скорости.

### Отношение к текущей cold rotation

Текущая `_rotate_until_working()` остаётся полезной как fallback: при пустом
standby, ошибке promotion или первом запуске без подготовленного резерва демон
может использовать прежний осторожный перебор кандидатов. Однако штатный путь
после внедрения standby должен быть таким:

1. Standby Worker заранее держит `standby_slot=READY` или `PRE_STALE`.
2. Active Guard при блокировке делает быструю promotion.
3. Standby Worker сразу готовит новый standby.

Так достигается целевая конфигурация: два рабочих конфига одновременно известны
xproxy, один применён в xray, второй проверен и готов к применению.

## Что дальше (возможные улучшения)

- Поддержка VMess/Trojan/Shadowsocks в подписке (сейчас только VLESS — подписка их не даёт).
- `If-Modified-Since` / ETag при скачивании geo-файлов (экономия трафика при неизменном upstream).
- Автодеплой `geosite.dat`/`geoip.dat` в системную директорию xray через `sudo cp` вместо правки юнита.
- Метрики/prometheus endpoint.
