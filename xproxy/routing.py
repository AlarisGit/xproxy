"""Конвертер conf/routing.json (Hiddify-like) → нативные xray-секции.

Возвращает словарь с ключами:
    routing  — dict, всегда присутствует
    dns      — dict, всегда присутствует (DNS-сплит)
    fakedns  — list | None (если FakeDns=true)
    enable_sniffing — bool (включать sniffing во входящих)
    removed_geo — list[tuple[str, str]] — (group, entry) пары, выкинутые
                  из-за отсутствующих категорий в geosite.dat/geoip.dat.
                  Нужен, чтобы вышестоящий код мог уведомить пользователя
                  одним сообщением.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .logger import get_logger
from .settings import DIRECT_LIST, ROUTING_JSON

log = get_logger("xproxy.routing")


_IPV4_CANDIDATE_RE = re.compile(r"^[0-9.]+$")


@dataclass
class DirectExtras:
    ips: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)


def load_routing() -> dict:
    return json.loads(ROUTING_JSON.read_text(encoding="utf-8"))


def load_direct_extras(path: Path = DIRECT_LIST) -> DirectExtras:
    """Прочитать direct.lst и разделить IP/CIDR и доменные маршруты.

    Пустые строки и строки, начинающиеся с #, игнорируются.
    Файл может отсутствовать — возвращается пустой список.
    """
    if not path.exists():
        return DirectExtras()
    extras = DirectExtras()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kind, value = _classify_direct_entry(stripped, lineno=lineno)
        if kind == "ip":
            extras.ips.append(value)
        else:
            extras.sites.append(value)
    if extras.ips or extras.sites:
        log.debug("direct.lst: %d extra IP entries, %d extra domain entries",
                  len(extras.ips), len(extras.sites))
    return extras


def merge_routing_with_direct_extras(
    cfg: dict,
    extras: DirectExtras,
) -> dict:
    """Return routing config with direct.lst entries merged and deduplicated."""
    merged = dict(cfg)
    merged["DirectIp"] = _merge_unique(cfg.get("DirectIp") or [], extras.ips)
    merged["DirectSites"] = _merge_unique(
        cfg.get("DirectSites") or [],
        extras.sites,
    )
    return merged


def _merge_unique(base: list, extra: list[str]) -> list:
    out: list = []
    seen: set[str] = set()
    for item in [*base, *extra]:
        if not isinstance(item, str):
            out.append(item)
            continue
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _classify_direct_entry(entry: str, *, lineno: int) -> tuple[str, str]:
    if "/" in entry:
        return "ip", _validate_ip_network(entry, lineno=lineno)
    try:
        return "ip", str(ipaddress.ip_address(entry))
    except ValueError:
        if ":" in entry or _IPV4_CANDIDATE_RE.fullmatch(entry):
            raise ValueError(f"direct.lst:{lineno}: invalid IP address: {entry}")
        return "site", entry


def _validate_ip_network(entry: str, *, lineno: int) -> str:
    try:
        return str(ipaddress.ip_network(entry, strict=False))
    except ValueError as exc:
        raise ValueError(f"direct.lst:{lineno}: invalid IP/CIDR: {entry}") from exc


def build_xray_sections(
    categories: dict[str, set[str] | None] | None = None,
) -> dict:
    cfg = load_routing()
    direct_extras = load_direct_extras()
    # Загружаем доступные категории из .dat-файлов. Ленивый импорт,
    # чтобы избежать циклической зависимости routing ↔ geo.
    from .geo import load_geo_categories, required_geo_kinds
    if categories is None:
        categories = load_geo_categories()

    removed: list[tuple[str, str]] = []
    routing, removed_r = _build_routing(cfg, direct_extras, categories)
    removed.extend(removed_r)
    dns, removed_dns = _build_dns(cfg, direct_extras, categories)
    removed.extend(removed_dns)

    # geo_readable считаем по ФАКТУ: сканируем уже построенные routing+dns
    # и смотрим, остались ли в них ссылки на нечитаемые .dat. Это точнее,
    # чем «все .dat должны быть на диске»:
    #   1) Если routing.json вовсе не ссылается на какой-то kind, отсутствие
    #      соответствующего .dat допустимо (пример: есть только geosite:*).
    #   2) `_build_dns` синтезирует `geoip:ru` / `geosite:category-ru`
    #      поверх cfg — значит нужно смотреть на построенный результат,
    #      а не на raw routing.json.
    # strip_missing_geo уже оставил в routing+dns только те geo-ссылки,
    # которые либо валидны, либо относятся к нечитаемым ассетам (в отсутствие
    # .dat мы не трогаем правила, см. fix #2 ранее). Если таких «висящих»
    # ссылок не осталось — xray -test пройдёт, и rebuild безопасен.
    needed_kinds = required_geo_kinds({"routing": routing, "dns": dns})
    unreadable_needed = [k for k in needed_kinds if categories.get(k) is None]
    geo_readable = not unreadable_needed

    if removed:
        summary = ", ".join(f"{g}:{e}" for g, e in removed[:10])
        tail = f" (+{len(removed) - 10} more)" if len(removed) > 10 else ""
        log.warning(
            "dropped %d routing entries referring to missing geo categories: %s%s",
            len(removed), summary, tail,
        )
    if unreadable_needed:
        log.warning("geo assets unreadable/missing (%s) — routing references "
                    "them, rebuild will be blocked until they recover",
                    ", ".join(sorted(unreadable_needed)))

    return {
        "routing": routing,
        "dns": dns,
        "fakedns": _build_fakedns(cfg),
        "enable_sniffing": bool(cfg.get("FakeDns")),
        "removed_geo": removed,
        "geo_readable": geo_readable,
        "unreadable_needed": sorted(unreadable_needed),
    }


def validate_geo_categories_for_routing(
    categories: dict[str, set[str] | None],
) -> list[tuple[str, str]]:
    """Strict-check geo categories against the config xproxy would generate.

    Unlike normal runtime building, this is a publish gate for new geo assets:
    if routing/DNS would need to drop a `geosite:*`/`geoip:*` entry, or if a
    required asset kind is unreadable, the staged geo set must not replace live.
    """
    sections = build_xray_sections(categories=categories)
    missing = list(sections.get("removed_geo") or [])
    for kind in sections.get("unreadable_needed") or []:
        missing.append(("geo-assets", f"{kind}:<unreadable>"))
    return missing


# ---------- routing ----------

def _build_routing(
    cfg: dict,
    direct_extras: DirectExtras | None,
    categories: dict[str, set[str] | None],
) -> tuple[dict, list[tuple[str, str]]]:
    from .geo import strip_missing_geo

    rules: list[dict] = []
    removed: list[tuple[str, str]] = []

    # Порядок правил из RouteOrder, напр. "block-direct-proxy".
    order_key = str(cfg.get("RouteOrder") or "block-direct-proxy").lower()
    order = order_key.split("-")
    known = {"block", "direct", "proxy"}
    order = [p for p in order if p in known]
    if not order:
        order = ["block", "direct", "proxy"]

    direct_ips = list(cfg.get("DirectIp") or [])
    direct_sites = list(cfg.get("DirectSites") or [])
    if direct_extras:
        direct_ips = _merge_unique(direct_ips, direct_extras.ips)
        direct_sites = _merge_unique(direct_sites, direct_extras.sites)

    groups = {
        "block": (cfg.get("BlockIp"), cfg.get("BlockSites")),
        "direct": (direct_ips or None, direct_sites or None),
        "proxy": (cfg.get("ProxyIp"), cfg.get("ProxySites")),
    }

    for group in order:
        ips, sites = groups[group]
        ips_kept, ips_removed = strip_missing_geo(ips, categories)
        sites_kept, sites_removed = strip_missing_geo(sites, categories)
        removed.extend((group, e) for e in ips_removed)
        removed.extend((group, e) for e in sites_removed)
        rules.extend(_group_rules(ips_kept or None, sites_kept or None, group))

    # Глобальный catchall на прокси, если GlobalProxy.
    if cfg.get("GlobalProxy", True):
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})

    out = {
        "domainStrategy": cfg.get("DomainStrategy") or "IPIfNonMatch",
        "rules": rules,
    }
    log.debug("routing: %d rules (%d removed)", len(rules), len(removed))
    return out, removed


def _group_rules(ips: Optional[list], sites: Optional[list], tag: str) -> list[dict]:
    result: list[dict] = []
    if ips:
        result.append({"type": "field", "ip": list(ips), "outboundTag": tag})
    if sites:
        result.append({"type": "field", "domain": list(sites), "outboundTag": tag})
    return result


# ---------- dns ----------

def _dns_address(cfg: dict, prefix: str) -> Optional[str]:
    dns_type = (cfg.get(f"{prefix}DNSType") or "DoU").upper()
    ip = cfg.get(f"{prefix}DNSIp")
    domain = cfg.get(f"{prefix}DNSDomain")
    if dns_type == "DOH":
        return domain or (f"https://{ip}/dns-query" if ip else None)
    if dns_type == "DOT":
        return f"tls://{ip}" if ip else None
    if dns_type == "DOQ":
        return f"quic://{ip}" if ip else None
    # DoU — обычный UDP
    return ip


def _build_dns(
    cfg: dict,
    direct_extras: DirectExtras | None,
    categories: dict[str, set[str] | None],
) -> tuple[dict, list[tuple[str, str]]]:
    from .geo import strip_missing_geo

    servers: list[Any] = []
    removed: list[tuple[str, str]] = []

    remote = _dns_address(cfg, "Remote")
    domestic = _dns_address(cfg, "Domestic")

    # Локальный (домашний) DNS — только для домашних доменов/geoip:ru.
    ru_domains: list[str] = []
    ru_domains.extend(cfg.get("DirectSites") or [])
    if direct_extras:
        ru_domains = _merge_unique(ru_domains, direct_extras.sites)
    if not any(isinstance(d, str) and d.startswith("geosite:") and "ru" in d
               for d in ru_domains):
        ru_domains.append("geosite:category-ru")

    ru_domains_kept, ru_removed = strip_missing_geo(ru_domains, categories)
    removed.extend(("dns-domains", e) for e in ru_removed)

    expect_ips = ["geoip:ru"]
    expect_kept, expect_removed = strip_missing_geo(expect_ips, categories)
    removed.extend(("dns-expectIPs", e) for e in expect_removed)

    if domestic and ru_domains_kept:
        server_entry: dict[str, Any] = {
            "address": domestic,
            "domains": sorted(set(ru_domains_kept)),
            "skipFallback": True,
        }
        if expect_kept:
            server_entry["expectIPs"] = expect_kept
        servers.append(server_entry)

    # Удалённый DNS — всё остальное (и блок-домены тоже спрашиваем у него, ничего страшного).
    if remote:
        servers.append(remote)
    else:
        # fallback на публичный резолвер, чтобы конфиг всегда был валиден.
        servers.append("1.1.1.1")

    dns_section = {
        "hosts": cfg.get("DnsHosts") or {},
        "servers": servers,
        "queryStrategy": "UseIP",
    }
    return dns_section, removed


# ---------- fakedns ----------

def _build_fakedns(cfg: dict) -> Optional[list]:
    if not cfg.get("FakeDns"):
        return None
    return [{"ipPool": "198.18.0.0/15", "poolSize": 65535}]
