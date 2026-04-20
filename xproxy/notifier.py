"""Уведомления в Telegram. Fire-and-forget, не блокируют основной цикл.

Поведение:
- если TELEGRAM_BOT_TOKEN или TELEGRAM_ALERTS_USER_ID не заданы — функция молча
  ничего не делает (локальная работа без Telegram полностью поддерживается);
- одинаковый текст не повторяется чаще THROTTLE_SEC;
- отправка выполняется в daemon-треде с коротким таймаутом;
- маршрут: сначала пробуем **через xray SOCKS-прокси** (api.telegram.org во
  многих юрисдикциях заблокирован на прямом канале), при неудаче — fallback
  на direct;
- `trust_env=False` везде: не позволяем env-переменным шелла неявно
  переопределять маршрут;
- токен автоматически редактируется в любых логируемых сообщениях (и stack
  traces тоже, см. _scrub).
"""
from __future__ import annotations

import socket
import threading
import time
import traceback
from typing import Optional

import requests

from .env_config import get as env_get
from .logger import get_logger
from .settings import NOTIFIER_IDENTITY_TTL, SOCKS_HOST, SOCKS_PORT, USER_AGENT

log = get_logger("xproxy.notifier")

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
_TIMEOUT = 6
_THROTTLE_SEC = 60
_MAX_LEN = 3500   # лимит Telegram — 4096, оставим запас

_last_sent: dict[str, float] = {}
_lock = threading.Lock()

# Кэш идентификатора хоста: (expires_at, "hostname/1.2.3.4").
_identity_cache: tuple[float, str] = (0.0, "")
_identity_lock = threading.Lock()


def is_configured() -> bool:
    return bool(env_get("TELEGRAM_BOT_TOKEN")) and bool(env_get("TELEGRAM_ALERTS_USER_ID"))


def notify(text: str, *, urgent: bool = False, blocking: bool = False) -> None:
    """Отправить сообщение в Telegram.

    К тексту автоматически добавляется префикс `hostname/public_ip: `.

    - `urgent=True` — обходит 60-секундный throttle (одинаковые сообщения).
    - `blocking=True` — ждать завершения отправки в текущем треде. Нужен при
      shutdown, когда демон-тред будет убит выходом процесса.
    """
    token = env_get("TELEGRAM_BOT_TOKEN")
    chat_id = env_get("TELEGRAM_ALERTS_USER_ID")
    if not token or not chat_id:
        return

    full = f"{_identity()}: {text}"
    if len(full) > _MAX_LEN:
        full = full[:_MAX_LEN - 3] + "..."

    if not urgent and _is_throttled(full):
        return

    if blocking:
        _send_sync(token, chat_id, full)
        return

    threading.Thread(
        target=_send_sync,
        args=(token, chat_id, full),
        name="telegram-notify",
        daemon=True,
    ).start()


def _identity() -> str:
    """`hostname/public_ip` с TTL-кэшем. При недоступном IP — только hostname."""
    global _identity_cache
    now = time.time()
    with _identity_lock:
        expires, cached = _identity_cache
        if cached and now < expires:
            return cached

    hostname = _short_hostname()
    # Ленивый импорт, чтобы избежать цикла healthcheck → notifier.
    try:
        from .healthcheck import direct_public_ip
        ip = direct_public_ip()
    except Exception:  # noqa: BLE001
        ip = None

    identity = f"{hostname}/{ip}" if ip else hostname
    with _identity_lock:
        _identity_cache = (now + NOTIFIER_IDENTITY_TTL, identity)
    return identity


def refresh_identity() -> None:
    """Принудительно сбросить кэш идентификатора (следующий notify переснимет IP)."""
    global _identity_cache
    with _identity_lock:
        _identity_cache = (0.0, "")


def _short_hostname() -> str:
    try:
        name = socket.gethostname()
    except OSError:
        return "host"
    return name.split(".", 1)[0] or "host"


# ---------- internals ----------

def _is_throttled(text: str) -> bool:
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
    # В API URL токен отделяется "bot" префиксом и следующим "/"; заменяем по подстрокам.
    return s.replace(token, f"<TOKEN…{tail}>")


def _make_session(proxies: Optional[dict]) -> requests.Session:
    session = requests.Session()
    session.trust_env = False   # env HTTP_PROXY игнорируется
    session.headers.update({"User-Agent": USER_AGENT})
    if proxies:
        session.proxies.update(proxies)
    return session


def _socks_proxies() -> dict:
    socks = f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
    return {"http": socks, "https": socks}


def _send_sync(token: str, chat_id: str, text: str) -> None:
    """Отправить в Telegram. Маршрут: SOCKS → direct, на успехе — выход."""
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
        try:
            session = _make_session(proxies)
            resp = session.post(url, data=payload, timeout=_TIMEOUT)
            if resp.status_code == 200:
                log.debug("telegram sent via %s", label)
                return
            errors.append(f"via {label}: http={resp.status_code} "
                          f"body={_scrub(resp.text[:200], token)}")
        except requests.RequestException as exc:
            errors.append(f"via {label}: {_scrub(str(exc), token)}")
        except Exception as exc:  # noqa: BLE001
            # На случай, если where-то внутри стек попадёт token — сразу скрабим.
            errors.append(f"via {label}: {_scrub(''.join(traceback.format_exception_only(type(exc), exc)).strip(), token)}")
    log.warning("telegram send failed on all routes: %s", "; ".join(errors))
