"""Общие настройки и пути проекта.

Все тайминги и параметры поведения собраны здесь, чтобы легко менять.
"""
from __future__ import annotations

import platform as _platform
from pathlib import Path

# ---------- Пути проекта ----------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
CONF_DIR: Path = PROJECT_ROOT / "conf"
STATE_DIR: Path = PROJECT_ROOT / "state"

# Логи — системная директория с ротацией (см. deploy/install.sh).
LOG_DIR: Path = Path("/var/log/xproxy")
LOG_FILE: Path = LOG_DIR / "xproxy.log"
LOG_MAX_BYTES: int = 100 * 1024       # 100 КБ на файл
LOG_BACKUP_COUNT: int = 3             # +3 ротированных файла

ENV_FILE: Path = PROJECT_ROOT / ".env"

CONFIG_TMPL: Path = CONF_DIR / "config.tmpl"
SUBSCRIPTION_TMPL: Path = CONF_DIR / "subscription.tmpl"
COUNTRY_LIST: Path = CONF_DIR / "country.lst"
ROUTING_JSON: Path = CONF_DIR / "routing.json"

SERVERS_CACHE: Path = STATE_DIR / "servers.json"
ACTIVE_STATE: Path = STATE_DIR / "active.json"

# Директория для geosite.dat / geoip.dat (XRAY_LOCATION_ASSET).
#
# Linux: /var/lib/xproxy/geo — системный shared-кеш.
#   Причина: на Linux xray-сервис обычно запущен под отдельным пользователем
#   (обычно `nobody`). Он не может войти в /home/<user>/.config/, потому что
#   $HOME на большинстве дистрибутивов имеет права 0750, а ~/.config — 0700.
#   /var/lib/xproxy/geo с правами 0755 читается всеми, а пишется владельцем
#   демона (sergey) без sudo. Директорию создаёт deploy/install.sh.
#
# macOS: ~/.config/xproxy/geo — xray под brew services работает от текущего
#   пользователя, home-директории традиционно 0755, никаких проблем с доступом.
if _platform.system().lower() == "linux":
    GEO_DIR: Path = Path("/var/lib/xproxy/geo")
else:
    GEO_DIR: Path = Path.home() / ".config" / "xproxy" / "geo"

# ---------- Локальный xray ----------
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 10808
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 10809

# ---------- Тайминги (секунды) ----------
HEALTH_INTERVAL = 15          # как часто проверяем прокси
SUBSCR_REFRESH = 30 * 60      # обновление подписки
GEO_REFRESH = 24 * 3600       # обновление geosite/geoip
GIT_PULL_INTERVAL = 3600      # 0 = выключить autoupdate
BOOT_GRACE = 10               # ожидание после рестарта xray
HEALTH_TIMEOUT = 5            # таймаут HTTP-пробы
TCP_PROBE_TIMEOUT = 3         # таймаут TCP-pre-probe сервера

# ---------- Autoupdate ----------
AUTOUPDATE_RESTARTS_WINDOW = 600   # окно (сек) для подсчёта рестартов
AUTOUPDATE_RESTARTS_LIMIT = 3      # если рестартов в окне >= лимита — пауза

# ---------- Notifier ----------
NOTIFIER_IDENTITY_TTL = 6 * 3600   # как часто освежать внешний IP для префикса

# ---------- Анти-флаппинг ----------
FAIL_THRESHOLD = 3            # сколько подряд-фейлов прокси нужно до ротации
ROTATION_COOLDOWN = 60        # не ротируем чаще, чем раз в минуту
SERVER_PENALTY_DURATION = 5 * 60   # на сколько уводим упавший сервер в конец списка

# ---------- Heartbeat ----------
HEARTBEAT_HOUR = 12           # локальный час суток, когда шлём суточный статус (0..23)

# ---------- Jitter / анти-thundering-herd ----------
# Несколько инстансов xproxy на разных хостах не знают друг о друге, поэтому
# их периодические задачи (subscription, geo, git pull) легко попадают в одну
# и ту же секунду — и бьют в один и тот же внешний сервис одновременно.
# Jitter размазывает события по времени.
#
# SCHEDULE_JITTER_RATIO: ±% к очередному интервалу после КАЖДОГО события
#   (интервал 1800s, ratio 0.15 → реальный период в диапазоне 1530..2070s,
#   перерисовывается заново после каждого успешного fetch).
SCHEDULE_JITTER_RATIO = 0.15

# STARTUP_JITTER: при старте демона — случайная пауза 0..N секунд ПЕРЕД
# первым обращением к внешним ресурсам (подписка, geo). Особенно важно,
# если все хосты одновременно ребутятся по команде или после сбоя сети.
STARTUP_JITTER = 30

# HEARTBEAT_JITTER_MIN: heartbeat уходит в HEARTBEAT_HOUR:MM, где MM —
# случайное число минут 0..N, зафиксированное при старте процесса
# (чтобы не дрейфовать внутри дня).
HEARTBEAT_JITTER_MIN = 60

# ---------- Источники для проверок ----------
# ВНИМАНИЕ: ipinfo.io/ip исключён намеренно — он возвращает IP upstream-провайдера
# по peering/anycast таблицам, а не реальный source-IP соединения. На сетях с CGNAT
# или Tier-2 ISP это приводит к расхождению с остальными IP-чекерами.
IP_CHECK_URLS = (
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://ipecho.net/plain",
    "https://icanhazip.com",
)

# ---------- HTTP ----------
USER_AGENT = "xproxy/0.1 (+https://github.com/AlarisGit/xproxy)"
