"""Парсинг VLESS URI, извлечение страны, фильтрация/сортировка, TCP-проба."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field, asdict
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .logger import get_logger
from .settings import COUNTRY_LIST, TCP_PROBE_TIMEOUT

log = get_logger("xproxy.servers")


@dataclass
class Server:
    """Описание одного vless-сервера из подписки."""
    uri: str                        # исходная строка
    protocol: str                   # "vless"
    uuid: str
    host: str
    port: int
    params: dict = field(default_factory=dict)   # type, security, alpn, sni, path, pbk, fp, ...
    fragment: str = ""              # человекочитаемое имя после '#'
    country: Optional[str] = None   # извлечённое русское название страны
    rank: int = 10**6               # чем меньше — тем приоритетнее (индекс в country.lst)

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
    # Стабильная сортировка: сначала по rank, затем по host для детерминизма.
    kept.sort(key=lambda s: (s.rank, s.host, s.port))
    log.info("kept %d servers after country filtering", len(kept))
    return kept


def tcp_probe(host: str, port: int, timeout: float = TCP_PROBE_TIMEOUT) -> bool:
    """Быстрая проверка доступности tcp host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
