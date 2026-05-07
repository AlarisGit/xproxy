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

## Что дальше (возможные улучшения)

- Поддержка VMess/Trojan/Shadowsocks в подписке (сейчас только VLESS — подписка их не даёт).
- `If-Modified-Since` / ETag при скачивании geo-файлов (экономия трафика при неизменном upstream).
- Автодеплой `geosite.dat`/`geoip.dat` в системную директорию xray через `sudo cp` вместо правки юнита.
- Метрики/prometheus endpoint.
