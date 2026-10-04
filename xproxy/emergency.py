"""Warm SSH reserve and asymmetric VLESS failover/recovery policy."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from typing import TYPE_CHECKING

from .healthcheck import internet_alive
from .logger import get_logger
from .notifier import notify
from .settings import (
    HEALTH_INTERVAL,
    VLESS_STABLE_SECONDS, VLESS_STANDBY_FRESH_SECONDS, STREAM_CHECK_INTERVAL,
)
from .tunnels import LocalTunnelError, TunnelConfigFile, TunnelIntent, TunnelManager, TunnelSnapshot
from .xray_config import _build_proxy_outbound, build_ssh_config_text

if TYPE_CHECKING:
    from .daemon import Daemon
    from .servers import Server
    from .standby import PreparedStandby

log = get_logger("xproxy.emergency")


def candidate_key(server: Server) -> str:
    return hashlib.sha256(json.dumps(_build_proxy_outbound(server), sort_keys=True).encode()).hexdigest()


class EmergencyController:
    def __init__(self, daemon: Daemon) -> None:
        self.daemon = daemon
        self.file = TunnelConfigFile()
        self._applied_port: int | None = None
        self._transition_retry_at = 0.0
        self._announced_tunnel: tuple | None = None
        self._config_announced = False
        self._local_failure_until = 0.0
        self._last_recovery_log = 0.0
        self.manager = TunnelManager(self.intent, self.confirm_network, self.tunnel_changed,
                                     preflight=self.preflight)

    def preflight(self) -> None:
        from .xray_control import validate_config_for_service
        try:
            text = build_ssh_config_text(self.file.config.local_port)
            valid, _ = validate_config_for_service(text, self.daemon.platform)
        except Exception as exc:
            raise LocalTunnelError(f"cannot prepare SSH xray config: {type(exc).__name__}") from exc
        if not valid:
            raise LocalTunnelError("SSH xray configuration validation failed; no remote host contacted")

    @property
    def enabled(self) -> bool:
        return self.file.enabled

    def reload(self) -> None:
        if not self.file.reload():
            return
        self.manager.configure(self.file.config, self.enabled)
        if self.file.error:
            self.event("configuration", f"⚠️ SSH configuration rejected: {self.file.error}; "
                       "new SSH connections suspended", urgent=True)
        elif self._config_announced:
            action = "enabled" if self.enabled else "disabled (existing active tunnel drains until VLESS recovery)"
            self.event("configuration", f"ℹ️ SSH emergency configuration {action}; "
                       f"{len(self.file.config.tunnels)} configured hosts")
        self._config_announced = True

    def event(self, topic: str, text: str, *, urgent: bool = False) -> None:
        log.info("%s", text)
        if not self.daemon.dry_run:
            notify(text, urgent=urgent, topic=topic)

    def reconcile(self) -> None:
        """Disk is authoritative on restart. Persisted READY is never trusted."""
        d = self.daemon
        d.state.last_vless = d.state.last_vless or d.state.active
        try:
            cfg = json.loads(d.platform.xray_config.read_text())
            outbound = next(o for o in cfg.get("outbounds", []) if o.get("tag") == "proxy")
        except (OSError, ValueError, StopIteration, TypeError):
            d.state.transport = "unknown"
            d.state.active = None
            return
        if outbound.get("protocol") == "socks":
            servers = outbound.get("settings", {}).get("servers", [])
            if servers and servers[0].get("address") in ("127.0.0.1", "localhost", "::1"):
                d.state.transport = "ssh"
                d.state.active = None
                self._applied_port = int(servers[0]["port"])
                log.info("restored SSH routing from live config; warm tunnel will be checked before use")
            else:
                d.state.transport = "unknown"
                d.state.active = None
            return
        if outbound.get("protocol") != "vless":
            d.state.active = None
            d.state.transport = "unknown"
            return
        d.state.transport = "vless"
        candidates = ([d.state.active] if d.state.active else []) + d.state.ranked_snapshot()
        d.state.active = None
        address = outbound.get("settings", {}).get("vnext", [{}])[0].get("address")
        for candidate in candidates:
            matched = replace(candidate, resolved_ip=address)
            if _build_proxy_outbound(matched) == outbound:
                d.state.active = matched
                d.state.last_vless = matched
                break

    def reset_evidence(self) -> None:
        self._local_failure_until = 0.0

    def local_failure(self) -> None:
        self._local_failure_until = time.monotonic() + 60

    def needed(self) -> bool:
        """Whether traffic needs SSH; independent of maintaining the tunnel."""
        d = self.daemon
        return (not d._stop and d.network.online() and d.state.transport in ("vless", "ssh") and
                time.monotonic() >= self._local_failure_until and
                d._active_channel_ok is False and d._failure_confirmed() and
                not d._standby_ready_for_fast_path())

    def intent(self) -> TunnelIntent:
        d = self.daemon
        network = d.network.snapshot()
        online = network.online and not d._stop
        # An invalid/removed configuration forbids reconnects, while a current
        # traffic-carrying SSH may drain until a verified VLESS is available.
        connect = self.enabled and not d.dry_run and not d._stop
        keep = not d.dry_run and (self.enabled or d.state.transport == "ssh")
        urgent = d._active_channel_ok is False and d._failure_confirmed()
        return TunnelIntent(online, connect and online, keep, urgent, network.generation)

    def confirm_network(self) -> bool:
        if self.daemon._stop or self.daemon.network.suspended():
            return False
        generation = self.daemon.network.snapshot().generation
        online = internet_alive()
        if self.daemon.network.snapshot().generation != generation:
            return False
        return self.daemon._update_network(online, expected_generation=generation)

    def tunnel_changed(self, snapshot: TunnelSnapshot) -> None:
        d = self.daemon
        d._wake_event.set()
        # Connection attempts and one unconfirmed probe failure remain local.
        if snapshot.status in ("CONNECTING", "CHECKING"):
            return
        ident = snapshot.endpoint.id if snapshot.endpoint else "-"
        key = (snapshot.status, ident, snapshot.detail)
        if key == self._announced_tunnel:
            return
        previous = self._announced_tunnel
        self._announced_tunnel = key
        if previous is None and snapshot.status == "IDLE":
            return
        labels = {
            "READY": "🟢 SSH tunnel ready",
            "FAILED": "🔴 SSH tunnel unavailable",
            "LOCAL_ERROR": "🔴 SSH local error; backup hosts not contacted",
            "SUSPENDED": "🟠 SSH paused: waiting for internet",
            "IDLE": "🟢 SSH tunnel stopped",
        }
        self.event("tunnel", f"{labels.get(snapshot.status, snapshot.status)}: {ident}"
                   f"{'; ' + snapshot.detail if snapshot.detail else ''}",
                   urgent=snapshot.status in ("FAILED", "LOCAL_ERROR"))

    def recovery_seconds(self) -> float:
        from .env_config import get
        try:
            seconds = float(get("XPROXY_VLESS_RECOVERY_SECONDS", str(VLESS_STABLE_SECONDS)))
            if 0 < seconds <= 86400:
                return seconds
        except (TypeError, ValueError):
            pass
        return VLESS_STABLE_SECONDS

    def recovery_allowed(self, slot: PreparedStandby) -> bool:
        d = self.daemon
        # Escape a confirmed broken SSH with one good VLESS, including when all
        # SSH hosts are blocked. A single suspect sample does not bypass hold.
        if d._active_channel_ok is False and d._failure_confirmed():
            return True
        if d._active_channel_ok is not True:
            return False
        now = time.monotonic()
        if now - d._health_checked_at > HEALTH_INTERVAL * 3:
            return False
        with d._standby_cond:
            records = [record for record in d._reserves.values()
                       if record.fresh() and record.since is not None and
                       now - record.since >= self.recovery_seconds() and
                       record.transfer_at and now - record.transfer_at <= STREAM_CHECK_INTERVAL * 2]
            primary = next((r for r in records if candidate_key(r.slot.server) == candidate_key(slot.server)
                            and r.slot.fingerprint == slot.fingerprint), None)
            if primary is None:
                return False
            # Check both fingerprints just before changing traffic: routing,
            # geo-assets and credential changes invalidate old evidence too.
            from .standby import standby_fingerprint
            try:
                return any(r.slot.server.key() != primary.slot.server.key() and
                           standby_fingerprint(r.slot.server, info=d.platform) == r.slot.fingerprint and
                           standby_fingerprint(primary.slot.server, info=d.platform) == primary.slot.fingerprint
                           for r in records)
            except Exception:
                return False

    def tick(self) -> None:
        d = self.daemon
        if d.dry_run or not d.network.online():
            return
        now = time.monotonic()
        snapshot = self.manager.snapshot()
        with d._standby_cond:
            slot = d._standby
        if d.state.transport == "ssh":
            if now - self._last_recovery_log >= 60:
                with d._standby_cond:
                    stable = {}
                    for record in d._reserves.values():
                        if record.fresh():
                            age = now - record.since if record.since is not None else 0
                            endpoint = record.slot.server.key()
                            stable[endpoint] = max(stable.get(endpoint, 0), age)
                    ages = sorted(stable.values(), reverse=True)
                log.info("VLESS recovery: fresh_endpoints=%d pair_stable=%.0fs required=%.0fs",
                         len(ages), ages[1] if len(ages) >= 2 else 0, self.recovery_seconds())
                self._last_recovery_log = now
            if now < self._transition_retry_at:
                return
            if (slot is not None and slot.is_usable() and
                    0 <= time.time() - slot.last_ok_at <= VLESS_STANDBY_FRESH_SECONDS and
                    self.recovery_allowed(slot)):
                if d._promote_standby("ssh-recovery"):
                    self._applied_port = None
                    self.event("transport", "🟢 VLESS restored; SSH remains ready as a reserve")
                else:
                    self._transition_retry_at = now + 1
                return
            if snapshot.ready and self._applied_port != snapshot.local_port:
                self._activate(snapshot)
            return
        if self.needed() and snapshot.ready and now >= self._transition_retry_at:
            self._activate(snapshot)

    def _activate(self, snapshot: TunnelSnapshot) -> None:
        d = self.daemon
        with d._apply_lock:
            def current():
                latest = self.manager.snapshot()
                return self.needed() and latest.ready and latest.endpoint == snapshot.endpoint and \
                    latest.local_port == snapshot.local_port and d._active_channel_ok is False
            if not current():
                return
            previous = d.state.active
            previous_transport = d.state.transport
            try:
                text = build_ssh_config_text(snapshot.local_port)
                if not d._apply_verified_config(text, "SSH emergency", guard=current):
                    self._transition_retry_at = time.monotonic() + 60
                    return
            except Exception as exc:
                self.event("transport", f"🔴 Cannot apply SSH emergency config: {type(exc).__name__}; "
                           "see local log", urgent=True)
                log.exception("SSH activation failed")
                self._transition_retry_at = time.monotonic() + 60
                return
            d.state.last_vless = previous or d.state.last_vless
            d.state.active = None
            d.state.transport = "ssh"
            d.state.note_proxy_ok()
            d._record_active_health(True)
            self._applied_port = snapshot.local_port
            d._clear_waiting_for_standby("SSH activated")
            d._invalidate_standby("transport changed to SSH")
            self.reset_evidence()
            d._wake_standby_worker()
            if previous_transport != "ssh":
                self.event("transport", f"🟠 Emergency mode active: traffic through SSH "
                           f"{snapshot.endpoint.id}; VLESS recovery checks continue", urgent=True)
