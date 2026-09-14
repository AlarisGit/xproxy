"""Emergency policy; SSH addresses are touched only by the demand-driven manager."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import replace
from typing import TYPE_CHECKING

from .healthcheck import internet_alive
from .logger import get_logger
from .notifier import notify
from .settings import (
    HEALTH_INTERVAL, STANDBY_FAILURE_TTL,
    VLESS_RECOVERY_INTERVAL, VLESS_RECOVERY_SAMPLES,
    VLESS_STABLE_SECONDS, VLESS_STANDBY_FRESH_SECONDS,
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
        self._lock = threading.RLock()
        self._failures: dict[str, float] = {}
        self._recovery: tuple[str, int, float] | None = None
        self._stable_since: float | None = None
        self._stable_key = None
        self._stable_last = 0.0
        self._release = False
        self._applied_port: int | None = None
        self._transition_retry_at = 0.0
        self._announced_tunnel: tuple | None = None
        self._config_announced = False
        self._local_failure_until = 0.0
        self._completed_pass: tuple[frozenset[str], float] | None = None
        self._episode_confirmed = False
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
                log.info("restored SSH routing from live config; fresh VLESS evidence required before reconnect")
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
        with self._lock:
            self._failures.clear()
            self._recovery = None
            self._stable_since = None
            self._stable_key = None
            self._release = False
            self._local_failure_until = 0.0
            self._completed_pass = None
            self._episode_confirmed = False

    def local_failure(self) -> None:
        with self._lock:
            self._local_failure_until = time.monotonic() + 60

    def complete_pass(self, candidates: list[Server], started: float) -> None:
        with self._lock:
            keys = frozenset(candidate_key(s) for s in candidates)
            if keys and all(self._failures.get(key, -1) >= started for key in keys):
                self._completed_pass = (keys, time.monotonic())

    def failed(self, server: Server) -> None:
        with self._lock:
            self._failures[candidate_key(server)] = time.monotonic()
            self._recovery = None

    def prepared(self, slot: PreparedStandby) -> None:
        key = candidate_key(slot.server) + slot.fingerprint
        now = time.monotonic()
        with self._lock:
            self._local_failure_until = 0.0
            self._completed_pass = None
            self._failures.pop(candidate_key(slot.server), None)
            previous = self._recovery
            if previous is None or previous[0] != key:
                self._recovery = (key, 1, now)
            elif now - previous[2] >= VLESS_RECOVERY_INTERVAL:
                self._recovery = (key, previous[1] + 1, now)
        self.daemon._wake_event.set()

    def _failed_recently(self, server: Server) -> bool:
        with self._lock:
            ts = self._failures.get(candidate_key(server))
        return ts is not None and time.monotonic() - ts <= STANDBY_FAILURE_TTL

    def reserve_lost(self) -> bool:
        d = self.daemon
        active = d.state.active_snapshot()
        candidates = [s for s in d.state.ranked_snapshot() if active is None or s.key() != active.key()]
        # An empty subscription/configuration is not evidence of blocking.
        with self._lock:
            completed = self._completed_pass
        pass_failed = completed is not None and time.monotonic() - completed[1] <= STANDBY_FAILURE_TTL and \
            completed[0] == frozenset(candidate_key(s) for s in candidates)
        return bool(candidates) and (pass_failed or all(self._failed_recently(s) for s in candidates))

    def needed(self) -> bool:
        d = self.daemon
        if d._stop or not self.enabled or time.monotonic() < self._local_failure_until or not d.network.online() or d._standby_ready_for_fast_path():
            return False
        if d.state.transport == "ssh":
            last = d.state.last_vless
            return self._episode_confirmed or (last is not None and self._failed_recently(last)) or self.reserve_lost()
        if d.state.transport != "vless":
            return False
        if time.monotonic() - d._health_checked_at > HEALTH_INTERVAL * 3:
            return False
        if d._active_channel_ok is True:
            return d.state.active is not None and self.reserve_lost()
        return d.state.proxy_failures_snapshot() >= d._fail_threshold_for_current_state()

    def intent(self) -> TunnelIntent:
        d = self.daemon
        needed = self.needed()
        current = self.manager.snapshot()
        existing = current.endpoint is not None and current.status != "IDLE"
        keep = d.state.transport == "ssh" or needed or (existing and self.enabled and not self._release)
        return TunnelIntent(d.network.online() and not d._stop, needed and not d.dry_run, keep)

    def confirm_network(self) -> bool:
        if self.daemon._stop:
            return False
        online = internet_alive()
        self.daemon._update_network(online)
        return online

    def tunnel_changed(self, snapshot: TunnelSnapshot) -> None:
        d = self.daemon
        d._wake_event.set()
        # Connection attempts and one unconfirmed probe failure remain local.
        if snapshot.status in ("CONNECTING", "CHECKING"):
            return
        ident = snapshot.endpoint.id if snapshot.endpoint else "-"
        if snapshot.status == "READY" and d.state.transport == "ssh" and self.needed():
            self._episode_confirmed = True
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

    def needs_fresh_standby(self, slot: PreparedStandby) -> bool:
        if self.daemon.state.transport == "ssh":
            return time.time() - slot.last_ok_at >= VLESS_RECOVERY_INTERVAL
        return self.manager.snapshot().endpoint is not None and \
            time.time() - slot.last_ok_at >= VLESS_STANDBY_FRESH_SECONDS

    def tick(self) -> None:
        d = self.daemon
        if d.dry_run or not d.network.online():
            self._stable_since = None
            return
        now = time.monotonic()
        snapshot = self.manager.snapshot()
        with d._standby_cond:
            slot = d._standby
        if d.state.transport == "ssh":
            self._release = False
            self._stable_since = None
            if now < self._transition_retry_at:
                return
            if slot is not None and slot.is_usable():
                with self._lock:
                    samples = self._recovery[1] if self._recovery and \
                        self._recovery[0] == candidate_key(slot.server) + slot.fingerprint else 0
                if samples >= VLESS_RECOVERY_SAMPLES or d._active_channel_ok is False:
                    if d._promote_standby("ssh-recovery"):
                        self._applied_port = None
                        self.event("transport", "🟠 VLESS restored; SSH retained until active traffic "
                                   "is stable and a fresh VLESS standby is available")
                    else:
                        self._transition_retry_at = now + 60
                    return
            # Same local forward can recover without rewriting/restarting xray.
            if snapshot.ready and self._applied_port != snapshot.local_port:
                self._activate(snapshot)
            return
        healthy = d.state.transport == "vless" and d._active_channel_ok is True and \
            now - d._health_checked_at <= HEALTH_INTERVAL * 3
        if not healthy:
            self._stable_since = None
        else:
            key = candidate_key(d.state.active) if d.state.active else None
            if key != self._stable_key or now - self._stable_last > HEALTH_INTERVAL * 3:
                self._stable_since = now
            self._stable_key, self._stable_last = key, now
            if self._stable_since is None:
                self._stable_since = now
        if self.needed():
            self._release = False
            if snapshot.ready and d._active_channel_ok is False and now >= self._transition_retry_at:
                self._activate(snapshot)
            return
        # Track active stability even while a new standby is still being found.
        # No extra hold is needed once a fresh independent standby arrives.
        if snapshot.endpoint is None or not healthy or slot is None or not slot.is_usable() or \
                (d.state.active is not None and slot.server.key() == d.state.active.key()):
            return
        if self._stable_since is not None and now - self._stable_since >= VLESS_STABLE_SECONDS and \
                time.time() - slot.last_ok_at <= VLESS_STANDBY_FRESH_SECONDS and not self._release:
            self._release = True
            self.event("transport", "🟢 Emergency episode complete: VLESS active and standby "
                       "healthy; SSH checks and connections stopped")

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
            self._episode_confirmed = True
            if previous is not None:
                self.failed(previous)
            d._wake_standby_worker()
            if previous_transport != "ssh":
                self.event("transport", f"🟠 Emergency mode active: traffic through SSH "
                           f"{snapshot.endpoint.id}; VLESS recovery checks continue", urgent=True)
