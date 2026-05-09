"""Уведомления в Telegram через очередь с персистентностью и ретраями.

Поведение:
- Если TELEGRAM_BOT_TOKEN или TELEGRAM_ALERTS_USER_ID не заданы — функция молча
  ничего не делает (локальная работа без Telegram полностью поддерживается);
- Одинаковый текст не повторяется чаще THROTTLE_SEC;
- Отправка идёт через in-memory очередь + фоновый sender-тред;
- При неудаче (нет сети, Telegram недоступен) — retry с exponential backoff;
- Очередь сохраняется на диск (state/notify_queue.json) при любом изменении
  состава (success, drop, retry, shutdown), чтобы пережить restart процесса;
- При старте — восстанавливается незавершённая очередь с диска;
- В текст сообщения всегда добавляется timestamp события `[HH:MM:SS]`
  в локальной TZ, чтобы время отправки не путалось со временем события;
- Failed-сообщения уходят в конец очереди — новые urgent-сообщения не ждут;
- Перед отправкой проверяется интернет через internet_alive();
- Маршрут: сначала SOCKS-прокси (через локальный xray), при неудаче — direct;
- `trust_env=False` везде: env-переменные не переопределяют маршрут;
- Токен автоматически скрабится в логируемых сообщениях.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import traceback
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import requests

from .env_config import get as env_get
from .fs_utils import secure_write
from .logger import get_logger
from .settings import NOTIFIER_IDENTITY_TTL, SOCKS_HOST, SOCKS_PORT, USER_AGENT

log = get_logger("xproxy.notifier")

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
_TIMEOUT = 6
_THROTTLE_SEC = 60
_MAX_LEN = 3500   # лимит Telegram — 4096, оставим запас
_MAX_ATTEMPTS = 10  # макс. попыток отправки одного сообщения
_RETRY_BASE = 30    # базовый интервал retry (секунды)
_RETRY_CAP = 1800   # максимальный интервал retry (30 минут)
_QUEUE_FILE = Path(__file__).resolve().parent.parent / "state" / "notify_queue.json"
_DRAIN_TIMEOUT = max(5.0, _TIMEOUT * 2 + 1)  # SOCKS+direct = до 12с, + запас

# Локальная таймзона для человекочитаемых timestamp'ов.
_LOCAL_TZ = datetime.now().astimezone().tzinfo

_last_sent: dict[str, float] = {}
_lock = threading.Lock()

# Кэш идентификатора хоста: (expires_at, "hostname/1.2.3.4").
_identity_cache: tuple[float, str] = (0.0, "")
_identity_lock = threading.Lock()

# Провайдер статуса: вызывается при каждой отправке сообщения.
# Кэширование медленных hardware-метрик — внутри провайдера (hardware_status).
# None — не добавлять статус к сообщениям.
_status_provider: Optional[Callable[[], Optional[str]]] = None


# ──────────────────────────────────────────────────────────────
# Pending notification dataclass
# ──────────────────────────────────────────────────────────────

@dataclass
class _PendingNotify:
    text: str               # текст БЕЗ prefix/timestamp (для throttle-dedup)
    event_time: float       # time.time() момента события
    attempts: int = 0       # сколько попыток отправки было
    next_retry: float = 0.0  # когда следующая попытка (0 = немедленно)

    def retry_delay(self) -> float:
        """Exponential backoff: BASE * 2^(attempts-1), с потолком CAP."""
        delay = _RETRY_BASE * (2 ** min(self.attempts, 8))
        return min(delay, _RETRY_CAP)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> _PendingNotify:
        return cls(
            text=d["text"],
            event_time=d["event_time"],
            attempts=d.get("attempts", 0),
            next_retry=d.get("next_retry", 0.0),
        )


def _format_ts(ts: float) -> str:
    """Человекочитаемый timestamp: `[HH:MM:SS]` в локальной TZ."""
    return datetime.fromtimestamp(ts, tz=_LOCAL_TZ).strftime("[%H:%M:%S]")


# ──────────────────────────────────────────────────────────────
# Notification queue (singleton)
# ──────────────────────────────────────────────────────────────

class _NotificationQueue:
    """Очередь уведомлений с фоновым sender-тредом и персистентностью."""

    def __init__(self) -> None:
        self._queue: deque[_PendingNotify] = deque()
        self._cond = threading.Condition()
        self._sender: Optional[threading.Thread] = None
        self._stopping = False
        self._loaded = False

    def start(self) -> None:
        """Запустить sender-тред (один раз, при старте демона)."""
        if not is_configured():
            return
        self._load_from_disk()
        with self._cond:
            if self._sender is not None and self._sender.is_alive():
                return
            self._stopping = False
            self._sender = threading.Thread(
                target=self._sender_loop,
                name="notify-sender",
                daemon=True,
            )
            self._sender.start()
        log.info("notification queue started (%d pending)", len(self._queue))

    def enqueue(self, text: str, *, urgent: bool = False) -> None:
        """Поставить сообщение в очередь."""
        if not is_configured():
            return

        # throttle проверяем по сырым текстам (без prefix/timestamp),
        # чтобы `🛑 stopped` не дедуплицировался из-за разницы во времени
        if not urgent and _is_throttled(text):
            return

        pending = _PendingNotify(text=text, event_time=time.time())
        with self._cond:
            self._queue.append(pending)
            self._cond.notify()
        # Персистентность сразу — чтобы не потерять при crash / os.execv
        # до того, как sender-тред доберётся до элемента.
        self._save_to_disk()
        log.debug("queued notification: %.60s", text[:60])

    def enqueue_blocking(self, pending: _PendingNotify) -> None:
        """Поставить уже сформированное сообщение в очередь (blocking-путь)."""
        with self._cond:
            self._queue.append(pending)
        self._save_to_disk()

    def drain(self, timeout: float = _DRAIN_TIMEOUT) -> None:
        """Попытаться отправить все отложенные сообщения перед выходом.

        Вызывается при shutdown. Sender-тред получит флаг _stopping
        и сделает финальные попытки. То, что не ушло — сохранится на диск.
        Timeout по умолчанию учитывает максимальное время отправки
        одного сообщения (SOCKS + direct ≈ 12с + запас).
        """
        if not is_configured():
            return
        with self._cond:
            self._stopping = True
            self._cond.notify_all()
        if self._sender is not None and self._sender.is_alive():
            self._sender.join(timeout=timeout)
        # Страховка: если что-то осталось — сохраняем на диск
        self._save_to_disk()

    # ── internals ──

    def _rotate_to_back(self) -> None:
        """Переместить head в конец очереди, чтобы не блокировать новые сообщения."""
        # Вызывается под self._cond или из sender-треда (единственный consumer).
        if len(self._queue) > 1:
            item = self._queue.popleft()
            self._queue.append(item)

    def _sender_loop(self) -> None:
        """Фоновый цикл: забирает из очереди, шлёт, ретраит."""
        while True:
            with self._cond:
                # Ждём, пока не появится что-нибудь или не скажут останавливаться
                while not self._queue and not self._stopping:
                    self._cond.wait(timeout=1.0)
                if self._stopping and not self._queue:
                    return

            # ── peek под локом ──
            with self._cond:
                item = self._queue[0]
                peek_retry = item.next_retry
            now = time.time()

            # Если время retry ещё не наступило — переносим в конец,
            # чтобы не блокировать более свежие сообщения (head-of-line)
            if peek_retry > now:
                with self._cond:
                    self._rotate_to_back()
                    self._cond.wait(timeout=min(peek_retry - now, 5.0))
                continue

            # Не тратим попытки, если интернета нет — просто отложим.
            # Ленивый импорт, чтобы избежать цикла на уровне модуля.
            from .healthcheck import internet_alive
            if not internet_alive():
                log.debug("skip notification send: no internet")
                with self._cond:
                    item.next_retry = now + item.retry_delay()
                    self._rotate_to_back()
                    self._cond.wait(timeout=min(item.retry_delay(), 30.0))
                continue

            # Резолвим identity прямо перед отправкой (в sender-треде,
            # можно блокировать на HTTP). Это восстанавливает public IP
            # в prefix'е, который ранее терялся при placeholder.
            prefix = _identity()
            full = f"{_format_ts(item.event_time)} {prefix}: {item.text}"
            suffix = _get_status_suffix()
            if suffix:
                full += f"\n{suffix}"
            if len(full) > _MAX_LEN:
                full = full[:_MAX_LEN - 3] + "..."

            # Пробуем отправить
            token = env_get("TELEGRAM_BOT_TOKEN") or ""
            chat_id = env_get("TELEGRAM_ALERTS_USER_ID") or ""
            if not token or not chat_id:
                # Конфигурация пропала — отбрасываем
                with self._cond:
                    self._queue.popleft()
                self._save_to_disk()
                continue

            ok = _send_sync(token, chat_id, full)
            if ok:
                with self._cond:
                    self._queue.popleft()
                log.debug("notification sent: %.60s", item.text[:60])
                self._save_to_disk()
            else:
                # Отметить попытку, запланировать retry
                with self._cond:
                    item.attempts += 1
                    if item.attempts >= _MAX_ATTEMPTS:
                        self._queue.popleft()
                        drop = True
                    else:
                        item.next_retry = now + item.retry_delay()
                        self._rotate_to_back()
                        drop = False
                if drop:
                    log.warning(
                        "dropping notification after %d attempts: %.60s",
                        item.attempts, item.text[:60],
                    )
                else:
                    log.info(
                        "notification retry #%d in %.0fs: %.60s",
                        item.attempts, item.next_retry - now, item.text[:60],
                    )
                self._save_to_disk()

            # При stopping — быстрый выход после обработки текущего
            if self._stopping:
                with self._cond:
                    if not self._queue:
                        return
                    # Если все оставшиеся — в будущем, сохраняем и выходим
                    soonest = min(it.next_retry for it in self._queue)
                    if soonest > time.time():
                        self._save_to_disk()
                        return

    def _load_from_disk(self) -> None:
        """Восстановить очередь из файла при старте."""
        if self._loaded:
            return
        self._loaded = True
        try:
            if not _QUEUE_FILE.exists():
                return
            data = json.loads(_QUEUE_FILE.read_text(encoding="utf-8"))
            items = [_PendingNotify.from_dict(d) for d in data]
            with self._cond:
                self._queue.extend(items)
            if items:
                log.info("restored %d pending notifications from disk", len(items))
        except Exception:  # noqa: BLE001
            log.exception("failed to load notification queue from disk")

    def _save_to_disk(self) -> None:
        """Сохранить очередь на диск через secure_write (атомарно, 0600)."""
        with self._cond:
            items = list(self._queue)
        try:
            if not items:
                # Пустая очередь — удалить файл, если он есть
                try:
                    _QUEUE_FILE.unlink(missing_ok=True)
                except OSError:
                    pass
                return
            payload = json.dumps([it.to_dict() for it in items], ensure_ascii=False)
            secure_write(_QUEUE_FILE, payload)
        except Exception:  # noqa: BLE001
            log.exception("failed to save notification queue to disk")


# ──────────────────────────────────────────────────────────────
# Module-level queue instance (lazy)
# ──────────────────────────────────────────────────────────────

_queue: Optional[_NotificationQueue] = None
_queue_lock = threading.Lock()


def _get_queue() -> _NotificationQueue:
    """Получить (или создать) синглтон очереди."""
    global _queue
    with _queue_lock:
        if _queue is None:
            _queue = _NotificationQueue()
        return _queue


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

def is_configured() -> bool:
    return bool(env_get("TELEGRAM_BOT_TOKEN")) and bool(env_get("TELEGRAM_ALERTS_USER_ID"))


def notify(text: str, *, urgent: bool = False, blocking: bool = False) -> None:
    """Отправить сообщение в Telegram через очередь.

    К тексту автоматически добавляется префикс `hostname/public_ip: `
    и timestamp события `[HH:MM:SS]` в локальной TZ.

    - `urgent=True` — обходит 60-секундный throttle.
    - `blocking=True` — дождаться отправки (для shutdown).
      В контексте очереди blocking=True делает sync-попытку прямо в текущем
      треде, а при неудаче — ставит в очередь.
    """
    if not is_configured():
        return

    # blocking-режим: shutdown — отправляем напрямую, а если не вышло — в очередь
    if blocking:
        token = env_get("TELEGRAM_BOT_TOKEN") or ""
        chat_id = env_get("TELEGRAM_ALERTS_USER_ID") or ""
        now = time.time()
        # В blocking-режиме резолвим identity синхронно (процесс сейчас выйдёт)
        prefix = _identity()
        full = f"{_format_ts(now)} {prefix}: {text}"
        suffix = _get_status_suffix()
        if suffix:
            full += f"\n{suffix}"
        if len(full) > _MAX_LEN:
            full = full[:_MAX_LEN - 3] + "..."
        ok = _send_sync(token, chat_id, full)
        if ok:
            return
        # Не удалось — запланируем в очередь на следующий старт
        log.warning("blocking notify failed, enqueuing for later delivery")
        pending = _PendingNotify(text=text, event_time=now, attempts=1)
        _get_queue().enqueue_blocking(pending)
        return

    _get_queue().enqueue(text, urgent=urgent)


def start_queue() -> None:
    """Запустить фоновый sender-тред. Вызывать один раз при старте демона."""
    _get_queue().start()


def drain_queue(timeout: float = _DRAIN_TIMEOUT) -> None:
    """Drain очереди при shutdown. Вызывать перед выходом процесса."""
    _get_queue().drain(timeout=timeout)


def refresh_identity() -> None:
    """Принудительно сбросить кэш идентификатора (следующий notify переснимет IP)."""
    global _identity_cache
    with _identity_lock:
        _identity_cache = (0.0, "")


def set_status_provider(provider: Optional[Callable[[], Optional[str]]]) -> None:
    """Установить провайдер статуса (вызывается при каждой отправке).

    Провайдер должен вернуть строку статуса или None.
    Медленные метрики кэшируются внутри провайдера.
    """
    global _status_provider
    _status_provider = provider


def _get_status_suffix() -> Optional[str]:
    """Получить суффикс статуса. Вызывает провайдер при каждой отправке.

    Провайдер отвечает за собственное кэширование медленных частей.
    """
    if _status_provider is None:
        return None
    try:
        return _status_provider()
    except Exception:  # noqa: BLE001
        log.debug("status provider failed, skipping status suffix")
        return None


# ──────────────────────────────────────────────────────────────
# Internals: message building, throttle, send
# ──────────────────────────────────────────────────────────────

def _identity() -> str:
    """`hostname/public_ip` с TTL-кэшем. При недоступном IP — только hostname.

    Может блокировать на HTTP-запросах при холодном/просроченном кэше.
    """
    global _identity_cache
    now = time.time()
    with _identity_lock:
        expires, cached = _identity_cache
        if cached and now < expires:
            return cached

    hostname = _short_hostname()
    try:
        from .healthcheck import direct_public_ip
        ip = direct_public_ip()
    except Exception:  # noqa: BLE001
        ip = None

    identity = f"{hostname}/{ip}" if ip else hostname
    with _identity_lock:
        _identity_cache = (now + NOTIFIER_IDENTITY_TTL, identity)
    return identity


def _cached_identity() -> Optional[str]:
    """Вернуть кэшированный identity, если валиден; иначе None. Не блокирует."""
    now = time.time()
    with _identity_lock:
        expires, cached = _identity_cache
        if cached and now < expires:
            return cached
    return None


def _short_hostname() -> str:
    try:
        name = socket.gethostname()
    except OSError:
        return "host"
    return name.split(".", 1)[0] or "host"


def _is_throttled(text: str) -> bool:
    """Проверить, не слишком ли рано повторять такое же сообщение."""
    now = time.time()
    with _lock:
        last = _last_sent.get(text, 0.0)
        if now - last < _THROTTLE_SEC:
            return True
        _last_sent[text] = now
        if len(_last_sent) > 200:
            cutoff = now - _THROTTLE_SEC * 10
            for k in [k for k, t in _last_sent.items() if t < cutoff]:
                _last_sent.pop(k, None)
    return False


def _scrub(s: str, token: str) -> str:
    """Удалить любые вхождения токена из строки (в т.ч. в traceback-подобных)."""
    if not s or not token:
        return s
    tail = token[-4:] if len(token) > 8 else ""
    return s.replace(token, f"<TOKEN…{tail}>")


def _make_session(proxies: Optional[dict]) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    if proxies:
        session.proxies.update(proxies)
    return session


def _socks_proxies() -> dict:
    socks = f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
    return {"http": socks, "https": socks}


def _send_sync(token: str, chat_id: str, text: str) -> bool:
    """Отправить в Telegram. Маршрут: SOCKS → direct (последовательно).

    sendMessage не идемпотентен — параллельная отправка через оба маршрута
    может привести к дублированию уведомлений. Поэтому при успешном SOCKS
    direct-маршрут не пробуется.
    """
    url = _TELEGRAM_API.format(token=token)
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    routes = (
        ("proxy", _socks_proxies()),
        ("direct", None),
    )
    errors: list[str] = []
    for label, proxies in routes:
        session = _make_session(proxies)
        try:
            resp = session.post(url, data=payload, timeout=_TIMEOUT)
            if resp.status_code == 200:
                log.debug("telegram sent via %s", label)
                return True
            errors.append(f"via {label}: http={resp.status_code} "
                          f"body={_scrub(resp.text[:200], token)}")
        except requests.RequestException as exc:
            errors.append(f"via {label}: {_scrub(str(exc), token)}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"via {label}: {_scrub(''.join(traceback.format_exception_only(type(exc), exc)).strip(), token)}")
    log.warning("telegram send failed on all routes: %s", "; ".join(errors))
    return False