"""DNS-резолвинг имён хостов в список IP-адресов.

Используется для расширения списка серверов: один hostname может резолвиться
в несколько IP, и каждый (hostname, IP) становится отдельным кандидатом
на подключение. Это позволяет штрафовать конкретный нерабочий IP, а не
весь сервер целиком.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from .logger import get_logger

log = get_logger("xproxy.dns_resolver")

# Таймаут на один DNS-запрос (в секундах).
_PER_HOST_TIMEOUT = 5.0

# Долгоживущий пул потоков для DNS-резолвинга.
# Фиксированный размер гарантирует, что зависшие getaddrinfo никогда
# не создадут больше _MAX_WORKERS зомби-потоков. Потоки переиспользуются
# между вызовами resolve_host / resolve_hosts — ничего не накапливается.
_MAX_WORKERS = 8
_pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="dns")


def _resolve_one(host: str) -> List[str]:
    """Резолвить один hostname. Вызывается в потоке из _pool."""
    try:
        addrs = socket.getaddrinfo(
            host, None, socket.AF_INET, socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return []
    seen: set[str] = set()
    result: List[str] = []
    for _family, _type, _proto, _canonname, sockaddr in addrs:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def resolve_host(host: str, timeout: float = _PER_HOST_TIMEOUT) -> List[str]:
    """Резолвить один hostname в список IPv4-адресов.

    Использует общий долгоживущий пул потоков.
    При таймауте возвращает [] — но getaddrinfo продолжает работать
    в фоне, переиспользуя тот же поток из _pool.
    """
    if not host:
        return []
    try:
        socket.inet_aton(host)
        return [host]
    except OSError:
        pass

    try:
        future = _pool.submit(_resolve_one, host)
        ips = future.result(timeout=timeout)
    except Exception:  # noqa: BLE001
        log.warning("DNS resolve timeout (%.1fs) for %s", timeout, host)
        return []
    if not ips:
        log.debug("DNS resolve: no IPv4 addresses for %s", host)
    return ips


def resolve_hosts(
    hosts: List[str],
    overall_timeout: float = 30.0,
) -> Dict[str, List[str]]:
    """Параллельно резолвить список hostnames в IPv4-адреса.

    Возвращает словарь {hostname: [ip1, ip2, ...]}.
    Hostnames, которые не резолвятся или истекают по таймауту,
    получают пустой список — вызывающий код решает, что делать.

    overall_timeout — жёсткий верхний предел: функция гарантированно
    возвращается не позднее overall_timeout секунд. Зависшие getaddrinfo
    потоки продолжают работать в _pool, но не блокируют вызывающий код
    и не накапливаются сверх _MAX_WORKERS.
    """
    if not hosts:
        return {}

    result: Dict[str, List[str]] = {}

    # Предрезолвленные IP-адреса — не отправляем в пул.
    to_resolve: List[str] = []
    for host in hosts:
        try:
            socket.inet_aton(host)
            result[host] = [host]
        except OSError:
            to_resolve.append(host)

    if not to_resolve:
        return result

    resolved = 0
    failed = 0

    futures = {}
    for host in to_resolve:
        futures[_pool.submit(_resolve_one, host)] = host

    try:
        for future in as_completed(futures, timeout=overall_timeout):
            host = futures[future]
            try:
                ips = future.result(timeout=0)  # уже завершён
            except Exception:  # noqa: BLE001
                ips = []
            result[host] = ips
            if ips:
                resolved += 1
            else:
                failed += 1
    except TimeoutError:
        # Часть futures не завершилась за overall_timeout.
        # Помечаем их как failed. Потоки продолжат работу в _pool,
        # но результат будет отброшен — никто его не ждёт.
        for future, host in futures.items():
            if host not in result:
                result[host] = []
                failed += 1
        # cancel() не прервёт уже выполняющийся getaddrinfo, но
        # отменит pending-задачи в очереди пула.
        for future in futures:
            future.cancel()

    log.info("batch DNS resolve: %d hosts, %d resolved, %d failed "
             "(%.1fs budget)", len(to_resolve), resolved, failed,
             overall_timeout)
    return result