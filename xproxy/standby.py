"""Preparation and end-to-end validation of a standby xray config."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .healthcheck import proxy_alive, target_alive
from .logger import get_logger
from .platform_utils import PlatformInfo, detect_platform, detect_xray_asset_env
from .servers import Server, tcp_probe
from .settings import (
    BOOT_GRACE,
    CONFIG_TMPL,
    DIRECT_LIST,
    GEO_DIR,
    ROUTING_JSON,
    STANDBY_PRE_STALE_TTL,
    STANDBY_READY_TTL,
    TCP_PROBE_TIMEOUT,
)
from .xray_config import build_xray_config_text
from .xray_control import validate_config_for_service, wait_for_proxy_port

log = get_logger("xproxy.standby")


class StandbyError(RuntimeError):
    """Standby candidate failed preparation or validation."""


@dataclass
class PreparedStandby:
    server: Server
    config_text: str
    fingerprint: str
    created_at: float
    last_ok_at: float
    pre_stale_at: float
    expires_at: float
    status: str = "READY"

    def lifecycle_state(
        self,
        current_fingerprint: str | None = None,
        *,
        now: float | None = None,
    ) -> str:
        if self.status not in ("READY", "PRE_STALE"):
            return self.status
        if current_fingerprint is not None and self.fingerprint != current_fingerprint:
            return "STALE"
        ts = time.time() if now is None else now
        if ts >= self.expires_at:
            return "STALE"
        if ts >= self.pre_stale_at:
            return "PRE_STALE"
        return "READY"

    def is_ready(self, current_fingerprint: str | None = None) -> bool:
        return self.lifecycle_state(current_fingerprint) == "READY"

    def is_usable(self, current_fingerprint: str | None = None) -> bool:
        return self.lifecycle_state(current_fingerprint) in ("READY", "PRE_STALE")

    def needs_refresh(self, current_fingerprint: str | None = None) -> bool:
        return self.lifecycle_state(current_fingerprint) != "READY"

    def slot_key(self) -> tuple[tuple[str, int], str]:
        return self.server.key(), self.fingerprint

    def ttl_detail(self, *, now: float | None = None) -> str:
        ts = time.time() if now is None else now
        state = self.lifecycle_state(now=ts)
        if state == "READY":
            ready_ttl = int(max(0.0, self.pre_stale_at - ts))
            usable_ttl = int(max(0.0, self.expires_at - ts))
            return f"ready_ttl={ready_ttl}s usable_ttl={usable_ttl}s"
        if state == "PRE_STALE":
            usable_ttl = int(max(0.0, self.expires_at - ts))
            return f"usable_ttl={usable_ttl}s"
        return f"state={state}"


def _validate_ttl(name: str, value: float) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def prepare_standby(
    server: Server,
    *,
    info: PlatformInfo | None = None,
    ready_ttl: float = STANDBY_READY_TTL,
    pre_stale_ttl: float = STANDBY_PRE_STALE_TTL,
) -> PreparedStandby:
    """Build and validate a standby production config for `server`."""
    _validate_ttl("ready_ttl", ready_ttl)
    _validate_ttl("pre_stale_ttl", pre_stale_ttl)
    info = info or detect_platform()
    if not tcp_probe(server.address, server.port, timeout=TCP_PROBE_TIMEOUT):
        raise StandbyError(f"tcp probe failed for {_fmt_server(server)}")

    fingerprint_before = standby_fingerprint(server, info=info)
    config_text = build_xray_config_text(server)
    ok, output = validate_config_for_service(config_text, info)
    if not ok:
        last = output.strip().splitlines()[-1] if output.strip() else "unknown error"
        raise StandbyError(f"xray -test failed for {_fmt_server(server)}: {last}")

    validate_standby_end_to_end(config_text)
    fingerprint_after = standby_fingerprint(server, info=info)
    if fingerprint_after != fingerprint_before:
        raise StandbyError(
            f"standby inputs changed during validation for {_fmt_server(server)}"
        )

    now = time.time()
    return PreparedStandby(
        server=server,
        config_text=config_text,
        fingerprint=fingerprint_after,
        created_at=now,
        last_ok_at=now,
        pre_stale_at=now + ready_ttl,
        expires_at=now + ready_ttl + pre_stale_ttl,
    )


def standby_fingerprint(
    server: Server,
    *,
    info: PlatformInfo | None = None,
) -> str:
    """Fingerprint inputs that make a prepared standby reusable."""
    info = info or detect_platform()
    service_asset, source = detect_xray_asset_env(info)
    payload: dict[str, Any] = {
        "server": server.to_dict(),
        "service_asset": service_asset,
        "service_asset_source": source,
        "files": {
            "config_tmpl": _file_fingerprint(CONFIG_TMPL),
            "routing_json": _file_fingerprint(ROUTING_JSON),
            "direct_list": _file_fingerprint(DIRECT_LIST),
            "geosite": _file_fingerprint(GEO_DIR / "geosite.dat"),
            "geoip": _file_fingerprint(GEO_DIR / "geoip.dat"),
        },
    }
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_standby_end_to_end(
    production_config_text: str,
    *,
    boot_timeout: float = BOOT_GRACE,
) -> None:
    """Run a temporary xray instance and check traffic through its SOCKS port."""
    xray_bin = shutil.which("xray")
    if xray_bin is None:
        raise StandbyError("xray binary not found in PATH")

    socks_port, http_port = _pick_two_free_ports()
    test_config_text = build_standby_test_config_text(
        production_config_text,
        socks_port=socks_port,
        http_port=http_port,
    )

    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(GEO_DIR)

    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8",
                                     delete=False) as fh:
        fh.write(test_config_text)
        tmp_path = fh.name

    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        if not wait_for_proxy_port(
            boot_timeout,
            host="127.0.0.1",
            port=socks_port,
        ):
            raise StandbyError(
                "temporary xray listener did not start: "
                f"{_process_output_tail(proc)}"
            )

        if not proxy_alive(socks_host="127.0.0.1", socks_port=socks_port):
            raise StandbyError("standby proxy IP check failed")

        target_ok, target_detail = target_alive(
            socks_host="127.0.0.1",
            socks_port=socks_port,
        )
        if not target_ok:
            raise StandbyError(f"standby target check failed: {target_detail}")
    finally:
        if proc is not None:
            _terminate_process(proc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def build_standby_test_config_text(
    production_config_text: str,
    *,
    socks_port: int,
    http_port: int,
) -> str:
    """Return config text for a temporary xray using local standby ports."""
    cfg = json.loads(production_config_text)
    cfg["inbounds"] = _standby_inbounds(cfg.get("inbounds") or [],
                                        socks_port=socks_port,
                                        http_port=http_port)
    log_section = cfg.get("log")
    if isinstance(log_section, dict):
        log_section["access"] = "none"
        log_section["error"] = "none"
    return json.dumps(cfg, ensure_ascii=False, indent=2)


def _standby_inbounds(
    inbounds: list[dict[str, Any]],
    *,
    socks_port: int,
    http_port: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen_socks = False
    seen_http = False
    for inbound in inbounds:
        item = dict(inbound)
        proto = str(item.get("protocol") or "").lower()
        tag = str(item.get("tag") or "").lower()
        if proto == "socks" or tag == "socks-in":
            item["listen"] = "127.0.0.1"
            item["port"] = socks_port
            out.append(item)
            seen_socks = True
        elif proto == "http" or tag == "http-in":
            item["listen"] = "127.0.0.1"
            item["port"] = http_port
            out.append(item)
            seen_http = True

    if not seen_socks:
        out.append({
            "tag": "standby-socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        })
    if not seen_http:
        out.append({
            "tag": "standby-http-in",
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "settings": {"timeout": 300},
        })
    return out


def _pick_two_free_ports() -> tuple[int, int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(2):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return sockets[0].getsockname()[1], sockets[1].getsockname()[1]
    finally:
        for sock in sockets:
            sock.close()


def _file_fingerprint(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError:
        return {"exists": False}
    return {
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _process_output_tail(proc: subprocess.Popen[bytes]) -> str:
    if proc.poll() is None:
        return "process still running"
    try:
        stdout, stderr = proc.communicate(timeout=0.2)
    except subprocess.TimeoutExpired:
        return "process output unavailable"
    text = (stderr or b"").decode(errors="replace") + \
        (stdout or b"").decode(errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(lines[-5:]) or "no process output"


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _fmt_server(server: Server) -> str:
    if server.resolved_ip and server.resolved_ip != server.host:
        return f"{server.host}:{server.port} ({server.resolved_ip})"
    return f"{server.host}:{server.port}"
