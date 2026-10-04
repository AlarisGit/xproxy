"""Per-candidate health history. Call under the daemon's standby lock."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from .settings import VLESS_RETRY_SCHEDULE, VLESS_STANDBY_FRESH_SECONDS
from .standby import PreparedStandby


@dataclass
class Reserve:
    slot: PreparedStandby | None = None
    since: float | None = None
    last_ok: float = 0
    wall_ok: float = 0
    retry_at: float = 0
    failures: int = 0
    suspect: bool = False
    transfer_at: float = 0
    samples: deque = field(default_factory=lambda: deque(maxlen=5))

    def fresh(self, ttl: float = VLESS_STANDBY_FRESH_SECONDS) -> bool:
        return (self.slot is not None and not self.suspect and
                0 <= time.monotonic() - self.last_ok <= ttl and
                0 <= time.time() - self.wall_ok <= ttl)

    def success(self, slot: PreparedStandby) -> None:
        now, wall = time.monotonic(), time.time()
        continuous = (self.slot is not None and self.slot.fingerprint == slot.fingerprint and
                      0 <= now - self.last_ok <= VLESS_STANDBY_FRESH_SECONDS and
                      0 <= wall - self.wall_ok <= VLESS_STANDBY_FRESH_SECONDS)
        if not continuous:
            self.since = None
            self.transfer_at = 0
            self.samples.clear()
        self.slot = slot
        self.last_ok, self.wall_ok = now, wall
        self.failures = 0
        self.suspect = False
        self.samples.append(True)
        if self.since is None:
            self.since = now
        if slot.transfer_ok is True:
            self.transfer_at = now
        elif slot.transfer_ok is False:
            # A failed bulk destination cannot by itself prove every route is
            # blocked, but must prevent a voluntary return to VLESS.
            self.transfer_at = 0
            self.since = None

    def failed(self) -> None:
        self.failures += 1
        self.suspect = True
        self.samples.append(False)
        if self.failures >= 2 or self.samples.count(False) >= 3:
            self.failures = max(2, self.failures)
            self.since = None
            self.transfer_at = 0
        self.retry_at = time.monotonic() + VLESS_RETRY_SCHEDULE[
            min(self.failures - 1, len(VLESS_RETRY_SCHEDULE) - 1)]
