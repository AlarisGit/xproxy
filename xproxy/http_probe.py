"""Isolated HTTP probe. The parent kills/reaps it at the overall deadline.

Run by file path so importing the daemon, its logger and secrets is unnecessary.
Only a bounded result is returned; URLs and response bodies are never logged.
"""
from __future__ import annotations

import ipaddress
import json
import sys

import requests


def probe(spec: dict) -> dict:
    with requests.Session() as session:
        session.trust_env = False
        session.proxies.update(spec.get("proxies") or {})
        session.headers.update({"User-Agent": "xproxy/health", "Accept-Encoding": "identity"})
        with session.get(spec["url"], timeout=spec["timeout"], stream=True,
                         allow_redirects=False) as response:
            kind = spec["kind"]
            if not (200 <= response.status_code < 600):
                return {"ok": False}
            if kind in ("ip", "transfer") and response.status_code != 200:
                return {"ok": False}
            limit = spec.get("bytes", 65536)
            data = bytearray()
            for chunk in response.iter_content(chunk_size=4096):
                data.extend(chunk)
                if len(data) > limit:
                    return {"ok": False}
            if kind == "ip":
                return {"ok": True, "value": str(ipaddress.ip_address(data.decode().strip()))}
            if kind == "transfer":
                return {"ok": len(data) == limit}
            # Headers alone do not prove delivery: consume the complete bounded body.
            return {"ok": True, "value": str(response.status_code)}


if __name__ == "__main__":
    try:
        result = probe(json.load(sys.stdin))
    except Exception:
        result = {"ok": False}
    print(json.dumps(result))
