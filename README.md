# xproxy

Небольшой watchdog поверх [xray](https://github.com/XTLS/Xray-core), который:

- регулярно обновляет список серверов из подписки;
- фильтрует серверы по `conf/country.lst` и сортирует по приоритету стран;
- скачивает актуальные `geosite.dat` / `geoip.dat` для маршрутизации;
- постоянно следит за тем, что трафик реально идёт через xray;
- **если** интернет жив, но проксируемый трафик не проходит N раз подряд — переключается на следующий рабочий сервер, регенерируя `config.json` и рестартуя xray.

Работает на macOS (`brew services restart xray`, `/opt/homebrew/etc/xray/config.json`) и Linux (`sudo systemctl restart xray`, `/usr/local/etc/xray/config.json`).

## Структура

```
xproxy/            пакет
  settings.py      все тайминги/пути
  platform_utils.py детект платформы + команды рестарта/записи
  subscription.py  загрузка и кэш подписки
  servers.py       парсинг vless://, страна, сортировка, TCP-проба
  routing.py       конвертер conf/routing.json → xray routing/dns/fakedns
  geo.py           скачивание geosite.dat / geoip.dat
  xray_config.py   сборка итогового config.json
  xray_control.py  запись/рестарт xray
  healthcheck.py   пробы через прокси и напрямую
  state.py         состояние демона (активный сервер, счётчики)
  daemon.py        главный цикл + one-shot
conf/              шаблоны и справочники (версионируются)
  config.tmpl      базовый xray-конфиг (log + inbounds); остальное добавляется
  subscription.tmpl ссылка подписки с плейсхолдерами
  country.lst      разрешённые страны в порядке приоритета (сверху = лучше)
  routing.json     маршрутная конфигурация (Hiddify-like)
state/             кэш и состояние (в .gitignore)
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
- **Проблема с подпиской** — `⚠️ subscription unavailable: ...` / `⚠️ using cached subscription`
- **Автоапдейт** (успехи):
  - `🆙 xproxy updating abc1234 → def5678, restarting` (ок, pull + restart)
  - `⚠️ autoupdate pulled ..., but requirements.txt changed` (нужен ручной pip install)
- **Автоапдейт** (неудачи):
  - `⚠️ autoupdate failed: fetch failed — <error>` (git fetch не прошёл)
  - `⚠️ autoupdate failed: pull failed — <error>` (git pull ff-only отклонён)
  - `⚠️ autoupdate paused: too many recent restarts (rate-limit)` (сработал лимит перезапусков)
  - `⚠️ autoupdate failed (check_and_pull exception): ...` (неожиданное исключение)
  - `🔴 autoupdate: new code failed import check` (откат на старый)
- **Автоапдейт** (стабильные no-op, без уведомлений): `up to date`, `working tree not clean`, `no upstream`, `detached HEAD`, `not a git repo`.
- **Нет рабочего сервера** — `🔴 no working server found (tried N of M, K in penalty box, reason=...)` (отправляется **blocking**, чтобы максимизировать шанс доставки при сломанном прокси).
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
# Environment=XRAY_LOCATION_ASSET=/home/<user>/.config/xproxy/geo
sudo systemctl daemon-reload
sudo systemctl restart xray
```

## Fail-safe и geo-файлы

Перед каждой записью `config.json` xproxy прогоняет `xray -test` на временном файле. Если тест не прошёл — боевой `/etc/xray/config.json` **не меняется**, xray продолжает работать со старым конфигом. Сломать работающий xray нельзя, даже если мы ошибёмся в шаблоне или подписка выдаст странный URI.

Перед записью также сохраняется бэкап текущего `config.json` в `state/xray_config.backup.json`. Откатиться можно вручную или через Python:

```python
from xproxy.xray_control import restore_backup
restore_backup()
```

Custom `geosite.dat`/`geoip.dat` (с расширенным набором ru-категорий из `GeositeUrl` в `routing.json`) копируются в asset-dir xray:

- macOS: `/opt/homebrew/share/xray/` (прямой `cp`, без sudo).
- Linux: `/usr/local/share/xray/` (через `sudo -n install`, нужна запись в sudoers — см. `deploy/sudoers.xproxy`).

Копирование идемпотентное: если файл совпадает по sha256 — повторная запись пропускается.

## Автоматическое обновление из git

Раз в `GIT_PULL_INTERVAL` (час по умолчанию) демон пробует обновить свой код:

1. Проверяет, что это git-репо, working tree чист и есть настроенный upstream. Иначе skip.
2. `git fetch` → если нет новых коммитов — skip.
3. `git pull --ff-only` (только fast-forward, никаких мёрджей).
4. Запускает в подпроцессе `python -c "import xproxy.daemon; ..."` — валидация нового кода. Если импорт падает → остаёмся на старом коде в памяти, логируем ERROR, не рестартим.
5. Если `requirements.txt` изменился — **не** рестартимся автоматически (нужен `pip install`), только предупреждаем в WARNING.
6. Иначе — `os.execv(sys.executable, sys.argv)`. PID сохраняется, systemd/launchd не видят «падения», логи/порты продолжают работать.

Защиты:

- **`fast-forward only`** — никаких авто-мёрджей, никаких переписываний истории.
- **Чистый tree** — локальные изменения никогда не затрагиваются.
- **Валидация импорта** — сломанный код не ломает живой демон.
- **Rate-limit рестартов** — если за `AUTOUPDATE_RESTARTS_WINDOW` (10 мин) случилось `AUTOUPDATE_RESTARTS_LIMIT` (3) перезапусков — автоапдейт приостанавливается до следующего окна, чтобы не уйти в pull-restart-pull-restart цикл.
- **Выключается одной строкой**: `GIT_PULL_INTERVAL = 0` в `xproxy/settings.py`.

После успешного рестарта демон пишет `process started after autoupdate restart (...)` в лог, так что в истории видно, когда именно он обновился.

## Логика ротации (кратко)

1. Каждые `HEALTH_INTERVAL` (15 с) — проверка здоровья.
2. Если `xray` не запущен — сразу подбираем первый рабочий сервер.
3. Если прямой интернет мёртв — пропускаем итерацию.
4. Если прокси отвечает — обнуляем счётчик фейлов.
5. Если прокси не отвечает: растим счётчик. При `FAIL_THRESHOLD` (3) подряд-фейлах — ротация:
   - текущий активный штрафуется на `SERVER_PENALTY_DURATION` (5 мин) и уходит в конец очереди;
   - идём по `next_candidates()`: сначала «чистые» серверы, затем штрафники (с раньше истекающим штрафом — раньше); активный всегда в конце своей группы;
   - для каждого кандидата — быстрый TCP-probe → рендер конфига → запись → рестарт → проверка прокси;
   - если кандидат падает на любом шаге — тоже уходит в штрафной бокс;
   - первый прошедший становится активным (его штраф сбрасывается при `set_active`).
6. `ROTATION_COOLDOWN` (60 с) защищает от флаппинга.
7. **Penalty box не блокирует навсегда**: если все серверы в штрафе — мы всё равно проходим по ним (второй шанс), что важно для коротких списков серверов в подписке.
8. Если после полного прохода ни один сервер не работает — отправляется blocking-уведомление `🔴 no working server found`.

Все тайминги — в `xproxy/settings.py`.

## Что дальше (возможные улучшения)

- Поддержка VMess/Trojan/Shadowsocks в подписке (сейчас только VLESS — подписка их не даёт).
- Более умное скачивание geo-файлов с `If-Modified-Since`.
- Автодеплой `geosite.dat`/`geoip.dat` в системную директорию xray через `sudo cp` вместо правки юнита.
- Метрики/prometheus endpoint.
