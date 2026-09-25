"""Persistent history of observed connectivity and summary delivery state."""
from __future__ import annotations

import html
import os
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .logger import get_logger
from .settings import STATE_DIR

log = get_logger("xproxy.status_journal")


@dataclass(frozen=True)
class Status:
    direct: str
    proxy: str
    vless_primary: str
    vless_secondary: str
    ssh: str

    @property
    def working(self) -> bool:
        return self.direct == "UP" and self.proxy == "UP"


class StatusJournal:
    """One row per changed snapshot; timestamps are Unix seconds with fractions."""

    def __init__(self, path: Path = STATE_DIR / "status.sqlite3") -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("""CREATE TABLE IF NOT EXISTS states (
            ts REAL NOT NULL, direct TEXT NOT NULL, proxy TEXT NOT NULL,
            vless_primary TEXT NOT NULL, vless_secondary TEXT NOT NULL,
            ssh TEXT NOT NULL)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _get(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _set(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.db.commit()

    def latest(self) -> Status | None:
        row = self.db.execute("SELECT direct,proxy,vless_primary,vless_secondary,ssh "
                              "FROM states ORDER BY rowid DESC LIMIT 1").fetchone()
        return Status(*row) if row else None

    def record(self, status: Status, *, ts: float | None = None) -> bool:
        previous = self.latest()
        if previous == status:
            return False
        self.db.execute("INSERT INTO states VALUES(?,?,?,?,?,?)",
                        (time.time() if ts is None else ts, *asdict(status).values()))
        if status.working and (previous is None or not previous.working):
            self.db.execute("INSERT INTO meta(key,value) VALUES('recovery_pending','1') "
                            "ON CONFLICT(key) DO UPDATE SET value='1'")
        self.db.commit()
        log.info("status changed: %s", status)
        return True

    def mark_start(self) -> None:
        # A process restart, including after sleep or power off, starts with
        # unverified connectivity. The first verified UP is a recovery.
        self.record(Status("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"))

    def recovery_pending(self) -> bool:
        return self._get("recovery_pending") == "1"

    def mark_recovery_sent(self) -> None:
        self._set("recovery_pending", "0")

    def daily_sent(self, date: str) -> bool:
        return self._get("daily_sent") == date

    def mark_daily_sent(self, date: str) -> None:
        self._set("daily_sent", date)


def format_summary(status: Status, *, reason: str, ts: float | None = None) -> str:
    stamp = datetime.fromtimestamp(time.time() if ts is None else ts).strftime("%d.%m.%Y %H:%M:%S")
    rows = (
        ("Direct", status.direct), ("Proxy", status.proxy),
        ("VLESS primary", status.vless_primary),
        ("VLESS secondary", status.vless_secondary), ("SSH", status.ssh),
    )
    # Keep the transport labels readable while escaping endpoint names.
    lines = ["Контур           Состояние", "─" * 36]
    lines.extend(f"{name:<16} {value}" for name, value in rows)
    return (f"📊 <b>xproxy · {html.escape(reason)}</b>\n"
            f"<code>{html.escape(stamp)}</code>\n"
            f"<pre>{html.escape(chr(10).join(lines))}</pre>")
