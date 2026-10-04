"""Проверки здоровья: живой ли интернет, проходит ли трафик через прокси.

HTTP-пробы делаются через `requests.Session(trust_env=False)`,
чтобы env-переменные HTTP_PROXY/HTTPS_PROXY/ALL_PROXY в шелле пользователя
НЕ утекали в наши вызовы. Иначе «direct» пошёл бы через xray и при любой
заминке xray мы получали бы ложное «no direct internet». Базовая проверка
сначала использует ICMP по публичным IP, без DNS и зависимости от xray.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, Optional

import requests

from .logger import get_logger
from .settings import (
    HEALTH_TIMEOUT,
    INTERNET_HTTP_TIMEOUT,
    INTERNET_HTTP_URLS,
    INTERNET_PING_IPS,
    INTERNET_PING_TIMEOUT,
    IP_CHECK_URLS,
    SOCKS_HOST,
    SOCKS_PORT,
    TARGET_CHECK_TIMEOUT,
    TARGET_CHECK_URLS,
    USER_AGENT,
    UPSTREAM_PROBE_PORT,
    STREAM_CHECK_URL, STREAM_CHECK_TIMEOUT, STREAM_CHECK_BYTES,
)

log = get_logger("xproxy.healthcheck")

_HEADERS = {"User-Agent": USER_AGENT}


def _bounded_http(url: str, proxies: dict | None, kind: str, timeout: float,
                  *, size: int = 65536) -> Optional[str]:
    """A wall-clock bound including DNS, SOCKS, TLS and the entire response.

    Requests' read timeout alone permits indefinitely trickling responses.
    A child also makes cancellation finite without leaking timed-out threads.
    """
    spec = dict(url=url, proxies=proxies, kind=kind, timeout=timeout, bytes=size)
    try:
        result = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).with_name("http_probe.py"))],
            input=json.dumps(spec), capture_output=True, text=True,
            timeout=timeout,
        )
        body = json.loads(result.stdout) if result.returncode == 0 else {}
        return str(body.get("value", "ok")) if body.get("ok") else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def transfer_alive(*, socks_host: str = SOCKS_HOST, socks_port: int = SOCKS_PORT) -> bool:
    from .env_config import get
    url = get("XPROXY_STREAM_CHECK_URL", STREAM_CHECK_URL)
    return bool(url) and _bounded_http(url, _socks_proxies(socks_host, socks_port),
                                      "transfer", STREAM_CHECK_TIMEOUT,
                                      size=STREAM_CHECK_BYTES) is not None


def _make_session(proxies: Optional[dict]) -> requests.Session:
    session = requests.Session()
    session.trust_env = False   # игнорируем HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY
    session.headers.update(_HEADERS)
    if proxies:
        session.proxies.update(proxies)
    return session


def _probe(session: requests.Session, url: str, via: str) -> Optional[str]:
    if via == "proxy":
        return _bounded_http(url, session.proxies, "ip", HEALTH_TIMEOUT, size=128)
    try:
        resp = session.get(url, timeout=HEALTH_TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        log.warning("probe %s fail (%s): %s", url, via, exc)
        return None
    if resp.status_code != 200:
        log.info("probe %s (%s) status=%s", url, via, resp.status_code)
        return None
    try:
        return str(ipaddress.ip_address(resp.text.strip()))
    except ValueError:
        log.info("probe %s (%s) returned an invalid IP response", url, via)
        return None


def _any_probe(urls: Iterable[str], proxies: Optional[dict],
               attempts: int = 2, should_continue=None) -> Optional[str]:
    """Первые attempts URL: через прокси параллельно, напрямую по порядку."""
    pool = list(urls)
    via = "proxy" if proxies else "direct"
    session = _make_session(proxies)
    tried = 0
    try:
        if proxies:
            if should_continue is not None and not should_continue():
                return None
            # Independent destinations share one deadline rather than adding
            # two read timeouts. Each child is reaped before this returns.
            with ThreadPoolExecutor(max_workers=2) as pool_executor:
                results = list(pool_executor.map(lambda url: _probe(session, url, via),
                                                  pool[:attempts]))
            if should_continue is not None and not should_continue():
                return None
            return next((value for value in results if value), None)
        for url in pool:
            if should_continue is not None and not should_continue():
                return None
            if tried >= attempts:
                break
            tried += 1
            body = _probe(session, url, via)
            if body:
                return body
        return None
    finally:
        session.close()


def _socks_proxies(host: str = SOCKS_HOST, port: int = SOCKS_PORT) -> dict:
    socks = f"socks5h://{host}:{port}"
    return {"http": socks, "https": socks}


def _active_probe_port() -> int:
    # Compatibility with a config from before this upgrade. The next verified
    # rebuild adds the dedicated forced-upstream listener.
    from .platform_utils import detect_platform
    try:
        cfg = json.loads(detect_platform().xray_config.read_text())
        if any(i.get("tag") == "xproxy-upstream-probe" and i.get("port") == UPSTREAM_PROBE_PORT
               for i in cfg.get("inbounds", [])):
            return UPSTREAM_PROBE_PORT
    except (OSError, ValueError, TypeError):
        pass
    return SOCKS_PORT


def internet_alive() -> bool:
    """Базовый прямой интернет: ICMP по IP, затем HTTPS без прокси.

    Успех любого адреса достаточен. Отказ ICMP не означает offline: ping
    может отсутствовать или быть запрещён сетью/правами процесса. HTTPS
    проверяет получение заголовков, не скачивает тело и не требует ответа
    с внешним IP. Эта проверка не обращается к VLESS/SSH или локальному xray.
    """
    # launchd PATH обычно не содержит /sbin, где macOS устанавливает ping.
    search_path = os.pathsep.join((os.environ.get("PATH", ""), "/sbin", "/usr/sbin"))
    ping = shutil.which("ping", path=search_path)
    if ping:
        for address in INTERNET_PING_IPS:
            if _internet_ping(ping, address):
                return True
    session = _make_session(None)
    try:
        for url in INTERNET_HTTP_URLS:
            if _internet_http_probe(session, url):
                return True
        return False
    finally:
        session.close()


def _internet_ping(binary: str, address: str) -> bool:
    try:
        # -n / -c совместимы с macOS и Linux. -W у них имеет разные единицы;
        # общий timeout задаёт Python, который завершает и забирает процесс.
        result = subprocess.run(
            [binary, "-n", "-c", "1", address],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=INTERNET_PING_TIMEOUT,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("internet ping %s unavailable: %s", address, type(exc).__name__)
        return False


def _internet_http_probe(session: requests.Session, url: str) -> bool:
    try:
        with session.get(url, timeout=INTERNET_HTTP_TIMEOUT, allow_redirects=False,
                         stream=True, verify=True) as response:
            # Даже 403/500 подтверждает DNS → TCP → TLS → HTTP. Работоспособность
            # сайта или прокси проверяется отдельно; переходить по redirect не надо.
            return 200 <= response.status_code < 600
    except requests.RequestException as exc:
        log.debug("internet HTTPS %s unavailable: %s", url, type(exc).__name__)
        return False


def proxy_alive(
    *,
    socks_host: str = SOCKS_HOST,
    socks_port: int | None = None,
    should_continue=None,
) -> bool:
    """Живой ли xray-прокси."""
    return _any_probe(
        IP_CHECK_URLS,
        proxies=_socks_proxies(socks_host, socks_port if socks_port is not None else _active_probe_port()),
        should_continue=should_continue,
    ) is not None


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
    try:
        for url in pool[:3]:
            body = _probe(session, url, "direct")
            if not body:
                continue
            results.append(body)
            counts[body] = counts.get(body, 0) + 1
            if counts[body] >= 2:
                return body
        return results[0] if results else None
    finally:
        session.close()


def _target_probe(session: requests.Session, url: str) -> Optional[str]:
    """Проба целевого ресурса через прокси.

    В отличие от _probe(), считает успехом ЛЮБОЙ HTTP-ответ (включая 401, 403),
    потому что это означает: DNS → TLS handshake → сервер ответил.
    Таймаут и сетевые ошибки — провал.
    Возвращает краткое описание результата или None при провале.
    """
    return _bounded_http(url, session.proxies, "target", TARGET_CHECK_TIMEOUT)


def target_alive(
    *,
    socks_host: str = SOCKS_HOST,
    socks_port: int | None = None,
    should_continue=None,
) -> tuple[bool, str]:
    """Проверка доступности целевых ресурсов через прокси.

    Возвращает (ok, detail):
      ok=True  — все целевые ресурсы доступны
      ok=False — хотя бы один ресурс недоступен, detail = какой именно

    Если TARGET_CHECK_URLS пуст — пропускаем проверку, возвращаем (True, "").
    """
    if not TARGET_CHECK_URLS:
        return True, ""

    proxies = _socks_proxies(socks_host, socks_port if socks_port is not None else _active_probe_port())
    session = _make_session(proxies)
    try:
        for url in TARGET_CHECK_URLS:
            if should_continue is not None and not should_continue():
                return False, "cancelled"
            result = _target_probe(session, url)
            if result is None:
                return False, url
        return True, ""
    finally:
        session.close()
