"""Конвертер conf/routing.json (Hiddify-like) → нативные xray-секции.

Возвращает словарь с ключами:
    routing  — dict, всегда присутствует
    dns      — dict, всегда присутствует (DNS-сплит)
    fakedns  — list | None (если FakeDns=true)
    enable_sniffing — bool (включать sniffing во входящих)
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .logger import get_logger
from .settings import ROUTING_JSON

log = get_logger("xproxy.routing")


def load_routing() -> dict:
    return json.loads(ROUTING_JSON.read_text(encoding="utf-8"))


def build_xray_sections() -> dict:
    cfg = load_routing()
    return {
        "routing": _build_routing(cfg),
        "dns": _build_dns(cfg),
        "fakedns": _build_fakedns(cfg),
        "enable_sniffing": bool(cfg.get("FakeDns")),
    }


# ---------- routing ----------

def _build_routing(cfg: dict) -> dict:
    rules: list[dict] = []

    # Порядок правил из RouteOrder, напр. "block-direct-proxy".
    order_key = str(cfg.get("RouteOrder") or "block-direct-proxy").lower()
    order = order_key.split("-")
    known = {"block", "direct", "proxy"}
    order = [p for p in order if p in known]
    if not order:
        order = ["block", "direct", "proxy"]

    builders = {
        "block": lambda: _group_rules(cfg.get("BlockIp"), cfg.get("BlockSites"), "block"),
        "direct": lambda: _group_rules(cfg.get("DirectIp"), cfg.get("DirectSites"), "direct"),
        "proxy": lambda: _group_rules(cfg.get("ProxyIp"), cfg.get("ProxySites"), "proxy"),
    }
    for group in order:
        rules.extend(builders[group]())

    # Глобальный catchall на прокси, если GlobalProxy.
    if cfg.get("GlobalProxy", True):
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})

    out = {
        "domainStrategy": cfg.get("DomainStrategy") or "IPIfNonMatch",
        "rules": rules,
    }
    log.debug("routing: %d rules", len(rules))
    return out


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


def _build_dns(cfg: dict) -> dict:
    servers: list[Any] = []

    remote = _dns_address(cfg, "Remote")
    domestic = _dns_address(cfg, "Domestic")

    # Локальный (домашний) DNS — только для домашних доменов/geoip:ru.
    ru_domains: list[str] = []
    ru_domains.extend(cfg.get("DirectSites") or [])
    if not any(d.startswith("geosite:") and "ru" in d for d in ru_domains):
        ru_domains.append("geosite:category-ru")
    if domestic:
        servers.append({
            "address": domestic,
            "domains": sorted(set(ru_domains)),
            "expectIPs": ["geoip:ru"],
            "skipFallback": True,
        })

    # Удалённый DNS — всё остальное (и блок-домены тоже спрашиваем у него, ничего страшного).
    if remote:
        servers.append(remote)
    else:
        # fallback на публичный резолвер, чтобы конфиг всегда был валиден.
        servers.append("1.1.1.1")

    return {
        "hosts": cfg.get("DnsHosts") or {},
        "servers": servers,
        "queryStrategy": "UseIP",
    }


# ---------- fakedns ----------

def _build_fakedns(cfg: dict) -> Optional[list]:
    if not cfg.get("FakeDns"):
        return None
    return [{"ipPool": "198.18.0.0/15", "poolSize": 65535}]
