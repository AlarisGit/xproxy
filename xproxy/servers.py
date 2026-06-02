"""Парсинг VLESS URI, извлечение страны, фильтрация/сортировка, TCP-проба."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field, asdict
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .dns_resolver import resolve_hosts
from .logger import get_logger
from .settings import COUNTRY_LIST, TCP_PROBE_TIMEOUT

log = get_logger("xproxy.servers")


@dataclass
class Server:
    """Описание одного vless-сервера из подписки.

    Поля host и resolved_ip:
      - host — оригинальное имя хоста из подписки (например,
        'cdn9-33.vk-cdnvideo.com'). Используется как serverName
        в TLS/Reality-настройках xray (SNI).
      - resolved_ip — если host был резолвирован в IP-адрес, это конкретный
        IP для подключения. Если None, host используется напрямую как address
        в xray (старое поведение, для доменов которые не резолвили).

    Ключ для ротации (penalty box) — (resolved_ip или host, port). Это
    позволяет штрафовать конкретный IP без исключения всего hostname.
    """
    uri: str                        # исходная строка
    protocol: str                   # "vless"
    uuid: str
    host: str                       # оригинальное hostname или IP из подписки
    port: int
    params: dict = field(default_factory=dict)   # type, security, alpn, sni, path, pbk, fp, …
    fragment: str = ""              # человекочитаемое имя после '#'
    country: Optional[str] = None   # извлечённое русское название страны
    rank: int = 10**6               # чем меньше — тем приоритетнее (индекс в country.lst)
    resolved_ip: Optional[str] = None  # конкретный IP для address в xray

    @property
    def address(self) -> str:
        """Адрес для поля address в xray outbound.

        Если сервер был резолвирован, используем конкретный IP,
        иначе — оригинальное имя хоста.
        """
        if self.resolved_ip is not None:
            return self.resolved_ip
        return self.host

    @property
    def display_name(self) -> str:
        """Человекочитаемое имя для логов.

        Для резолвленных серверов: 'cdn9-33.vk-cdnvideo.com:8443 (82.202.156.248)'
        Для обычных: 'cdn9-33.vk-cdnvideo.com:8443'
        """
        if self.resolved_ip and self.resolved_ip != self.host:
            return f"{self.host}:{self.port} ({self.resolved_ip})"
        return f"{self.host}:{self.port}"

    def key(self) -> tuple[str, int]:
        """Ключ для penalty box и сравнения серверов.

        Резолвленные серверы с разными IP — разные ключи, чтобы
        штрафовать конкретный IP, а не весь hostname.
        """
        return (self.address, self.port)

    def to_dict(self) -> dict:
        return asdict(self)


def parse_vless(uri: str) -> Optional[Server]:
    """Распарсить vless:// URI. Возвращает None при ошибке."""
    uri = uri.strip()
    if not uri.lower().startswith("vless://"):
        return None
    try:
        parsed = urlparse(uri)
    except ValueError:
        return None
    if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.port:
        return None
    uuid = unquote(parsed.username or "")
    if not uuid:
        return None

    # parse_qs даёт list значений, мы берём первое.
    raw_params = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: v[0] for k, v in raw_params.items() if v}
    fragment = unquote(parsed.fragment or "").strip()
    country = _country_from_fragment(fragment)

    return Server(
        uri=uri,
        protocol="vless",
        uuid=uuid,
        host=parsed.hostname,
        port=parsed.port,
        params=params,
        fragment=fragment,
        country=country,
    )


def parse_subscription(decoded: str) -> List[Server]:
    servers: List[Server] = []
    for line in decoded.splitlines():
        line = line.strip()
        if not line:
            continue
        srv = parse_vless(line)
        if srv is None:
            log.debug("skip non-vless or malformed line: %r", line[:80])
            continue
        servers.append(srv)
    log.info("parsed %d vless servers from subscription", len(servers))
    return servers


def expand_servers(servers: List[Server]) -> List[Server]:
    """Резолвить hostname каждого сервера и создать по кандидату на каждый IP.

    Для каждого сервера в списке:
      - Если host — уже IP-адрес, сервер пропускается без изменений.
      - Если DNS-резолвинг не дал результатов, сервер пропускается без изменений
        (xray будет резолвить hostname сам — старое поведение).
      - Если DNS-резолвинг дал 1 IP, в сервер устанавливается resolved_ip
        (и адрес подключения сменится на IP при генерации конфига xray).
      - Если DNS-резолвинг дал >1 IP, для каждого IP создаётся отдельный
        сервер-кандидат с установленным resolved_ip. Оригинальный сервер
        при этом удаляется.

    Функция сохраняет порядок, ранги и страны. Серверы с одинаковым
    hostname, но разными IP, идут подряд — это упрощает отладку.
    """
    # Собираем уникальные hostnames для пакетного резолвинга.
    hostnames = set()
    for srv in servers:
        try:
            socket.inet_aton(srv.host)
        except OSError:
            hostnames.add(srv.host)

    # Пакетный DNS-резолвинг с общим бюджетом 30с.
    dns_map = resolve_hosts(list(hostnames)) if hostnames else {}

    expanded: List[Server] = []
    total_resolved = 0
    total_multi = 0

    for srv in servers:
        # Уже IP-адрес — пропускаем без изменений.
        try:
            socket.inet_aton(srv.host)
            expanded.append(srv)
            continue
        except OSError:
            pass

        ips = dns_map.get(srv.host, [])
        if not ips:
            # DNS не резолвится — оставляем как есть, xray будет резолвить сам.
            log.debug("DNS resolve: no IPs for %s, keeping as-is", srv.host)
            expanded.append(srv)
            continue

        total_resolved += 1

        if len(ips) == 1:
            # Один IP — просто устанавливаем resolved_ip на месте.
            srv.resolved_ip = ips[0]
            expanded.append(srv)
        else:
            # Несколько IP — отдельный кандидат на каждый IP.
            total_multi += 1
            for ip in ips:
                from dataclasses import replace
                new_srv = replace(srv, resolved_ip=ip)
                expanded.append(new_srv)
            # Оригинальный сервер (без resolved_ip) не добавляем —
            # каждый IP уже представлен отдельным кандидатом.

    if total_resolved:
        log.info("resolved %d hostnames (%d with multiple IPs), "
                  "expanded %d → %d server candidates",
                  total_resolved, total_multi, len(servers), len(expanded))
    return expanded


def _country_from_fragment(fragment: str) -> Optional[str]:
    """Фрагмент имеет вид '🇩🇪 Берлин, Германия, Extra'. Берём вторую запятую."""
    if not fragment:
        return None
    parts = [p.strip() for p in fragment.split(",")]
    if len(parts) >= 2 and parts[1]:
        return parts[1]
    # fallback: если запятых нет, вернуть всё после первого пробела (убрать флаг).
    tail = fragment.split(" ", 1)
    return tail[1].strip() if len(tail) == 2 else fragment


def load_country_ranks() -> dict[str, int]:
    """Читает country.lst, возвращает {страна: ранг}. Меньше = важнее."""
    ranks: dict[str, int] = {}
    for idx, line in enumerate(COUNTRY_LIST.read_text(encoding="utf-8").splitlines()):
        name = line.strip()
        if name and name not in ranks:
            ranks[name] = idx
    return ranks


def filter_and_sort(servers: Iterable[Server], ranks: dict[str, int]) -> List[Server]:
    """Оставить только сервера из разрешённых стран и отсортировать по rank."""
    kept: List[Server] = []
    for srv in servers:
        if srv.country is None:
            continue
        rank = ranks.get(srv.country)
        if rank is None:
            continue
        srv.rank = rank
        kept.append(srv)
    # Стабильная сортировка: сначала по rank, затем по address для детерминизма.
    kept.sort(key=lambda s: (s.rank, s.address, s.port))
    log.info("kept %d servers after country filtering", len(kept))
    return kept


def tcp_probe(host: str, port: int, timeout: float = TCP_PROBE_TIMEOUT) -> bool:
    """Быстрая проверка доступности tcp host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False