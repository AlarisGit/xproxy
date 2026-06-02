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
DIRECT_LIST: Path = CONF_DIR / "direct.lst"

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
GEO_REFRESH = 6 * 3600        # максимальный интервал между успешными скачиваниями geosite/geoip
# Экспоненциальный бэкофф повторов при ошибках скачивания geo (секунды).
# Каждая следующая неудачная попытка ждёт следующий интервал из списка;
# после последнего значения остаёмся на нём до первого успеха.
GEO_RETRY_SCHEDULE = (10, 60, 5 * 60, 30 * 60, 60 * 60, 6 * 3600)
GIT_PULL_INTERVAL = 3600      # 0 = выключить autoupdate
BOOT_GRACE = 10               # ожидание после рестарта xray
HEALTH_TIMEOUT = 8            # таймаут HTTP-пробы
TCP_PROBE_TIMEOUT = 3         # таймаут TCP-pre-probe сервера

# ---------- Autoupdate ----------
AUTOUPDATE_RESTARTS_WINDOW = 600   # окно (сек) для подсчёта рестартов
AUTOUPDATE_RESTARTS_LIMIT = 3      # если рестартов в окне >= лимита — пауза

# ---------- Notifier ----------
NOTIFIER_IDENTITY_TTL = 6 * 3600   # как часто освежать внешний IP для префикса

# ---------- Stale subscription ----------
STALE_SUBSCRIPTION_SEC = 24 * 3600  # подписка считается устаревшей через 24ч без live-фетча

# ---------- Анти-флаппинг ----------
FAIL_THRESHOLD = 5            # сколько подряд-фейлов прокси нужно до ротации
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
# Порядок важен: быстрые/надёжные источники идут первыми и пробуются
# приоритизированно. Медленные или нестабильные — в резерве.
# _any_probe() использует приоритизированный обход, а не случайный shuffle.
IP_CHECK_URLS = (
    "https://icanhazip.com",       # стабильно быстрый, почти не таймаутит
    "https://ifconfig.me/ip",      # стабильно быстрый
    "https://api.ipify.org",       # иногда медленный через CDN
    "https://ipecho.net/plain",    # резерв — чаще таймаутит через прокси
)

# ---------- Целевые ресурсы (target checks) ----------
# Ресурсы, доступность которых критична для работы xproxy.
# Проверяются ПОСЛЕ proxy_alive(): если прокси формально работает (IP-чекер
# проходит), но целевой ресурс недоступен — сервер штрафуется.
#
# Проверка — простой GET с ожиданием 200. Telegram API возвращает 401 для
# ботов без токена, это тоже считается успехом (серло доступен, TLS работает).
# Используем /bot<invalid>/getMe — минимальный эндпоинт, который вернёт 401.
TARGET_CHECK_URLS = (
    "https://api.telegram.org/bot0000000000:AAHw000000000000000000000000/getMe",
)

TARGET_CHECK_TIMEOUT = 10  # таймаут пробы целевого ресурса (секунды)

# ---------- HTTP ----------
USER_AGENT = "xproxy/0.1 (+https://github.com/AlarisGit/xproxy)"
