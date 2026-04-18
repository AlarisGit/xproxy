"""Загрузка подписки: через локальный прокси → без прокси → кэш на диске."""
from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Optional

import requests

from .env_config import EnvConfigError, require as env_require
from .logger import get_logger
from .settings import (
    SERVERS_CACHE,
    SOCKS_HOST,
    SOCKS_PORT,
    STATE_DIR,
    SUBSCRIPTION_TMPL,
    USER_AGENT,
)

log = get_logger("xproxy.subscription")

_HTTP_TIMEOUT = 15


class SubscriptionError(RuntimeError):
    pass


def read_uuid() -> str:
    """UUID подписки из .env (ключ SUBSCR_UUID)."""
    try:
        return env_require("SUBSCR_UUID")
    except EnvConfigError as exc:
        raise SubscriptionError(str(exc)) from exc


def build_subscription_url() -> str:
    uuid = read_uuid()
    uuid2 = uuid.replace("-", "")
    tmpl = SUBSCRIPTION_TMPL.read_text(encoding="utf-8").strip()
    return tmpl.replace("[SUBSCR_UUID]", uuid).replace("[SUBSCR_UUID2]", uuid2)


def redact_url(url: str) -> str:
    """Скрыть чувствительные части (UUID/UUID2) в URL подписки для логов."""
    try:
        uuid = read_uuid()
    except Exception:  # noqa: BLE001
        return url
    uuid2 = uuid.replace("-", "")
    masked = uuid[:4] + "…" + uuid[-4:] if len(uuid) > 8 else "…"
    masked2 = uuid2[:4] + "…" + uuid2[-4:] if len(uuid2) > 8 else "…"
    return url.replace(uuid, masked).replace(uuid2, masked2)


def _decode_base64(body: str) -> str:
    """Декодирует base64 из подписки. Добавляет padding при необходимости."""
    data = "".join(body.split())  # убрать пробелы/переносы
    pad = (-len(data)) % 4
    data += "=" * pad
    try:
        return base64.b64decode(data, validate=False).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as exc:
        raise SubscriptionError(f"base64 decode failed: {exc}") from exc


def _fetch(url: str, proxies: Optional[dict]) -> str:
    # trust_env=False: не позволяем HTTP_PROXY/HTTPS_PROXY/ALL_PROXY из шелла
    # переопределять наш выбор маршрута (иначе "direct" лукаво пойдёт через xray).
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    if proxies:
        session.proxies.update(proxies)
    resp = session.get(url, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def fetch_subscription_text() -> tuple[str, str]:
    """Скачать подписку. Возвращает (source, decoded_text).

    source: "proxy" | "direct" | "cache"
    """
    url = build_subscription_url()
    log.info("fetch subscription: %s", redact_url(url))

    socks_proxy = f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
    attempts = (
        ("proxy", {"http": socks_proxy, "https": socks_proxy}),
        ("direct", None),
    )
    last_err: Exception | None = None
    for label, proxies in attempts:
        try:
            body = _fetch(url, proxies)
            decoded = _decode_base64(body)
            if not decoded.strip():
                raise SubscriptionError("empty subscription body")
            _save_cache(decoded)
            log.info("subscription fetched via %s (%d bytes decoded)", label, len(decoded))
            return label, decoded
        except Exception as exc:  # noqa: BLE001
            # Сообщения requests нередко включают полный URL — маскируем на выходе.
            log.warning("subscription fetch via %s failed: %s",
                        label, redact_url(str(exc)))
            last_err = exc

    cached = _load_cache()
    if cached is not None:
        log.warning("using cached subscription from %s", SERVERS_CACHE)
        return "cache", cached

    raise SubscriptionError(
        f"no subscription available: {redact_url(str(last_err)) if last_err else 'unknown'}"
    )


def _save_cache(decoded: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    SERVERS_CACHE.write_text(decoded, encoding="utf-8")


def _load_cache() -> Optional[str]:
    if not SERVERS_CACHE.exists():
        return None
    try:
        data = SERVERS_CACHE.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("cannot read cache %s: %s", SERVERS_CACHE, exc)
        return None
    return data if data.strip() else None
