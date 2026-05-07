"""Build Hiddify/Happ routing import links from routing.json + direct.lst."""
from __future__ import annotations

import base64
import json
from pathlib import Path

from .routing import load_direct_extras, merge_routing_with_direct_extras
from .settings import DIRECT_LIST, ROUTING_JSON

HAPP_ROUTING_ONADD_PREFIX = "happ://routing/onadd/"


def build_routing_onadd_link(
    routing_path: Path = ROUTING_JSON,
    direct_list_path: Path = DIRECT_LIST,
) -> str:
    cfg = json.loads(routing_path.read_text(encoding="utf-8"))
    extras = load_direct_extras(direct_list_path)
    merged = merge_routing_with_direct_extras(cfg, extras)
    payload = json.dumps(
        merged,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.b64encode(payload).decode("ascii")
    return HAPP_ROUTING_ONADD_PREFIX + encoded
