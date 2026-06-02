"""Сборка итогового config.json для xray из базового шаблона + серверa + routing."""
from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from .logger import get_logger
from .routing import build_xray_sections
from .servers import Server
from .settings import CONFIG_TMPL

log = get_logger("xproxy.xray_config")


def load_base_template() -> dict:
    return json.loads(CONFIG_TMPL.read_text(encoding="utf-8"))


def build_xray_config(
    server: Server,
    *,
    categories: dict[str, set[str] | None] | None = None,
) -> dict:
    """Собрать полный xray config.json под выбранный сервер."""
    base = deepcopy(load_base_template())
    sections = build_xray_sections(categories=categories)

    # Sniffing (если есть fakedns — destOverride должен включать 'fakedns').
    sniffing = {
        "enabled": sections["enable_sniffing"] or True,
        "destOverride": ["http", "tls"],
        "metadataOnly": False,
        "routeOnly": False,
    }
    if sections["fakedns"] is not None:
        sniffing["destOverride"] = ["fakedns", "http", "tls"]

    for inbound in base.get("inbounds", []):
        inbound.setdefault("sniffing", sniffing.copy())

    # Outbounds: proxy (выбранный сервер) + direct + block.
    base["outbounds"] = [
        _build_proxy_outbound(server),
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]

    # Routing / DNS / FakeDNS.
    base["routing"] = sections["routing"]
    base["dns"] = sections["dns"]
    if sections["fakedns"] is not None:
        base["fakedns"] = sections["fakedns"]

    return base


def build_xray_config_text(
    server: Server,
    *,
    categories: dict[str, set[str] | None] | None = None,
) -> str:
    return json.dumps(
        build_xray_config(server, categories=categories),
        ensure_ascii=False,
        indent=2,
    )


# ---------- internals ----------

def _effective_server_name(server: Server) -> str:
    """Определить serverName для TLS/Reality.

    Приоритет: явно заданный SNI в параметрах URI → host из URI.
    Если host резолвирован в IP, serverName ОБЯЗАН быть оригинальным
    hostname (т.к. IP-адрес не подходит для SNI/CN).
    Если host и так hostname — используем его напрямую.
    """
    p = server.params
    explicit_sni = p.get("sni") or p.get("host")
    if explicit_sni:
        return explicit_sni
    # Если host был резолвирован, оригинальный hostname — в server.host.
    # Если host не резолвирован, server.host уже hostname.
    return server.host


def _build_proxy_outbound(server: Server) -> dict:
    p = server.params
    network = (p.get("type") or "tcp").lower()
    security = (p.get("security") or "none").lower()

    stream: dict[str, Any] = {
        "network": network,
        "security": security,
    }

    sni = _effective_server_name(server)

    if security == "tls":
        alpn = [a for a in (p.get("alpn") or "").split(",") if a]
        tls: dict[str, Any] = {
            "serverName": sni,
            "allowInsecure": p.get("allowInsecure") in ("1", "true"),
        }
        if alpn:
            tls["alpn"] = alpn
        if p.get("fp"):
            tls["fingerprint"] = p["fp"]
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": p.get("fp", "chrome"),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", ""),
        }

    if network == "ws":
        ws: dict[str, Any] = {"path": p.get("path", "/")}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": p.get("serviceName") or p.get("path", "").lstrip("/")
        }
    elif network == "tcp" and p.get("headerType") == "http":
        host = p.get("host", "")
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [p.get("path", "/")],
                    "headers": {"Host": [h for h in host.split(",") if h]},
                },
            }
        }

    user: dict[str, Any] = {"id": server.uuid, "encryption": "none"}
    flow = p.get("flow")
    if flow:
        user["flow"] = flow

    # address: конкретный IP (если сервер резолвирован) или hostname.
    # serverName в TLS/Reality: всегда оригинальный hostname (для SNI).
    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server.address,
                    "port": server.port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream,
    }
