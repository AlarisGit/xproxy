"""Shared, expiring network evidence. Reading the gate never performs I/O."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .settings import NETWORK_STATUS_TTL


@dataclass(frozen=True)
class NetworkSnapshot:
    online: bool
    generation: int


class Connectivity:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._online = False
        self._checked_at: float | None = None
        self._wall_at: float | None = None
        self._generation = 0
        self._signature: str | None = None

    def update(self, online: bool, signature: str | None = None) -> NetworkSnapshot:
        now, wall = time.monotonic(), time.time()
        with self._lock:
            # Expired evidence must never become current again in the same
            # generation (mach_absolute_time may pause while macOS sleeps).
            gap = self._checked_at is not None and not self._fresh(now, wall)
            changed = signature is not None and self._signature is not None and signature != self._signature
            if online != self._online or gap or changed:
                self._generation += 1
            if signature is not None:
                self._signature = signature
            self._online = online
            self._checked_at, self._wall_at = now, wall
            return NetworkSnapshot(online, self._generation)

    def snapshot(self) -> NetworkSnapshot:
        with self._lock:
            fresh = self._fresh(time.monotonic(), time.time())
            return NetworkSnapshot(self._online and fresh, self._generation)

    def _fresh(self, now: float, wall: float) -> bool:
        return self._checked_at is not None and self._wall_at is not None and \
            0 <= now - self._checked_at <= NETWORK_STATUS_TTL and \
            abs(wall - self._wall_at) <= NETWORK_STATUS_TTL

    def online(self) -> bool:
        return self.snapshot().online
