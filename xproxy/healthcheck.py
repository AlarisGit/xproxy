"""Проверки здоровья: живой ли интернет, проходит ли трафик через прокси.

ВАЖНО: и direct-, и proxy-пробы делаются через `requests.Session(trust_env=False)`,
чтобы env-переменные HTTP_PROXY/HTTPS_PROXY/ALL_PROXY в шелле пользователя
НЕ утекали в наши вызовы. Иначе «direct» пошёл бы через xray и при любой
заминке xray мы получали бы ложное «no direct internet».
"""
from __future__ import annotations

import random
from typing import Iterable, Optional

import requests

from .logger import get_logger
from .settings import (
    HEALTH_TIMEOUT,
    IP_CHECK_URLS,
    SOCKS_HOST,
    SOCKS_PORT,
    USER_AGENT,
)

log = get_logger("xproxy.healthcheck")

_HEADERS = {"User-Agent": USER_AGENT}


def _make_session(proxies: Optional[dict]) -> requests.Session:
    session = requests.Session()
    session.trust_env = False   # игнорируем HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY
    session.headers.update(_HEADERS)
    if proxies:
        session.proxies.update(proxies)
    return session


def _probe(session: requests.Session, url: str, via: str) -> Optional[str]:
    try:
        resp = session.get(url, timeout=HEALTH_TIMEOUT)
    except requests.RequestException as exc:
        log.debug("probe %s fail (%s): %s", url, via, exc)
        return None
    if resp.status_code != 200:
        log.debug("probe %s (%s) status=%s", url, via, resp.status_code)
        return None
    return resp.text.strip()


def _any_probe(urls: Iterable[str], proxies: Optional[dict],
               attempts: int = 2) -> Optional[str]:
    """Случайный обход — один успех → True. Возвращает тело ответа."""
    pool = list(urls)
    random.shuffle(pool)
    via = "proxy" if proxies else "direct"
    session = _make_session(proxies)
    tried = 0
    for url in pool:
        if tried >= attempts:
            break
        tried += 1
        body = _probe(session, url, via)
        if body:
            return body
    return None


def _socks_proxies() -> dict:
    socks = f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
    return {"http": socks, "https": socks}


def internet_alive() -> bool:
    """Живой ли прямой интернет-канал (в обход env-прокси)."""
    return _any_probe(IP_CHECK_URLS, proxies=None) is not None


def proxy_alive() -> bool:
    """Живой ли xray-прокси."""
    return _any_probe(IP_CHECK_URLS, proxies=_socks_proxies()) is not None


def public_ips() -> tuple[Optional[str], Optional[str]]:
    """Вернуть (direct_ip, proxy_ip) для диагностических логов."""
    direct = _any_probe(IP_CHECK_URLS, proxies=None)
    via = _any_probe(IP_CHECK_URLS, proxies=_socks_proxies())
    return direct, via


def direct_public_ip() -> Optional[str]:
    """Внешний IP без прокси: consensus из нескольких сервисов.

    Опрашиваем до 3 случайных чекеров. Возвращаем значение, которое встретилось
    >= 2 раз. Если единодушия нет — берём первый успешный ответ. Это страхует
    от отдельных сервисов, которые возвращают IP upstream-провайдера вместо
    реального source-IP (типа ipinfo.io).
    """
    pool = list(IP_CHECK_URLS)
    random.shuffle(pool)
    session = _make_session(None)
    results: list[str] = []
    counts: dict[str, int] = {}
    for url in pool[:3]:
        body = _probe(session, url, "direct")
        if not body:
            continue
        results.append(body)
        counts[body] = counts.get(body, 0) + 1
        if counts[body] >= 2:
            return body
    return results[0] if results else None
