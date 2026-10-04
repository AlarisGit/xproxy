"""Persistent observations, meaningful events and summary delivery state."""
from __future__ import annotations

import html
import os
import sqlite3
import time
from dataclasses import astuple, dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .settings import STATE_DIR


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


@dataclass(frozen=True)
class Event:
    id: int
    ts: float
    kind: str
    detail: str


@dataclass(frozen=True)
class Route:
    channel: str
    server: str
    standby: str = "не готов"
    recovery: tuple[float, float] | None = None
    key: str = ""

    @property
    def label(self) -> str:
        return f"{self.channel} · {self.server}"


def compact(value: str, limit: int = 140) -> str:
    return " ".join(value.split())[:limit]


class StatusJournal:
    """SQLite is owned by the health thread, including lifecycle events.

    Raw snapshots remain available for diagnostics. Events are independently
    deduplicated; old snapshots are not reinterpreted as confirmed outages.
    """

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
        self.db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)""")
        self.db.commit()
        self._network_failures = 0

    def close(self) -> None:
        self.db.close()

    def _get(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _put(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def _event(self, kind: str, detail: str, ts: float) -> None:
        self.db.execute("INSERT INTO events(ts,kind,detail) VALUES(?,?,?)", (ts, kind, compact(detail, 200)))

    def events(self, limit: int = 10) -> list[Event]:
        return [Event(*row) for row in self.db.execute(
            "SELECT id,ts,kind,detail FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def latest(self) -> Status | None:
        row = self.db.execute("SELECT direct,proxy,vless_primary,vless_secondary,ssh "
                              "FROM states ORDER BY rowid DESC LIMIT 1").fetchone()
        return Status(*row) if row else None

    def _snapshot(self, status: Status, ts: float) -> bool:
        if self.latest() == status:
            return False
        self.db.execute("INSERT INTO states VALUES(?,?,?,?,?,?)", (ts, *astuple(status)))
        return True

    def record(self, status: Status, *, ts: float | None = None,
               route: Route | None = None, proxy_confirmed: bool = True,
               allow_failure: bool = True) -> bool:
        ts = time.time() if ts is None else ts
        with self.db:
            changed = self._snapshot(status, ts)
            direct, proxy = self._get("event_direct"), self._get("event_proxy")
            context = self._get("verification_context")
            if status.direct == "DOWN":
                self._network_failures += 1
                if self._network_failures >= 2 and allow_failure and direct != "DOWN":
                    self._event("internet_down", "Интернет недоступен", ts)
                    self._put("event_direct", "DOWN")
                    self._put("event_proxy", "UNKNOWN")
                    self._put("outage_pending", "1")
                return changed
            if status.direct != "UP":
                return changed
            self._network_failures = 0
            if direct != "UP":
                # Normal wake-up does not imply the internet was unavailable.
                if context not in ("wake", "gap") or direct == "DOWN":
                    self._event("internet_up", "Интернет доступен", ts)
                self._put("event_direct", "UP")
            if status.proxy == "DOWN":
                if proxy_confirmed and allow_failure and proxy != "DOWN":
                    self._event("proxy_down", "Прокси недоступен", ts)
                    self._put("event_proxy", "DOWN")
                    self._put("outage_pending", "1")
                return changed
            if status.proxy != "UP":
                return changed
            label = compact(route.label) if route else ""
            route_key = route.key or label if route else ""
            if proxy != "UP":
                ordinary_wake = context == "wake" and self._get("outage_pending") != "1"
                text = "Проверка после сна: прокси доступен" if ordinary_wake else "Прокси доступен"
                self._event("wake_ok" if ordinary_wake else "proxy_up",
                            text + (f" · {label}" if label else ""), ts)
                if context == "startup":
                    self._put("summary_reason", "Запуск xproxy")
                    self._put("recovery_pending", "1")
                elif self._get("outage_pending") == "1" or context is None:
                    self._put("summary_reason", "Прокси восстановлен")
                    self._put("recovery_pending", "1")
            elif label and route_key != self._get("event_route"):
                self._event("route_changed", f"Канал переключён: {label}", ts)
            self._put("event_proxy", "UP")
            self._put("event_route", route_key)
            self._put("verification_context", "")
            self._put("outage_pending", "0")
            return changed

    def lifecycle(self, kind: str, *, ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        labels = {"start": "xproxy запущен", "stop": "xproxy остановлен",
                  "sleep": "Mac перешёл в сон", "wake": "Mac проснулся",
                  "gap": "Перерыв в наблюдении; доступность неизвестна"}
        with self.db:
            if kind == "start":
                if self._get("session_open") == "1":
                    self._event("gap", labels["gap"], ts)
                self._put("session_open", "1")
                self._put("recovery_pending", "0")
                self._put("outage_pending", "0")
            elif kind == "stop":
                self._put("session_open", "0")
            self._event(kind, labels[kind], ts)
            self._put("event_direct", "UNKNOWN")
            self._put("event_proxy", "UNKNOWN")
            self._put("event_route", "")
            self._put("verification_context", "startup" if kind == "start" else
                      "wake" if kind in ("sleep", "wake") else "gap")
            self._snapshot(Status("UNKNOWN", "UNKNOWN", "N/A", "N/A", "N/A"), ts)
        self._network_failures = 0

    def mark_start(self) -> None:
        self.lifecycle("start")

    def recovery_pending(self) -> bool:
        return self._get("recovery_pending") == "1"

    def summary_reason(self) -> str:
        return self._get("summary_reason") or "Прокси восстановлен"

    def mark_recovery_sent(self) -> None:
        with self.db:
            self._put("recovery_pending", "0")

    def daily_sent(self, date: str) -> bool:
        return self._get("daily_sent") == date

    def mark_daily_sent(self, date: str) -> None:
        with self.db:
            self._put("daily_sent", date)


def format_summary(status: Status, *, reason: str, route: Route | None = None,
                   events: Sequence[Event] = (), ts: float | None = None) -> str:
    stamp = datetime.fromtimestamp(time.time() if ts is None else ts).strftime("%d.%m.%Y %H:%M:%S")
    if route is None:
        # Compatibility for callers without a loaded runtime route.
        route = Route("VLESS", status.vless_primary.removeprefix("UP "),
                      status.vless_secondary.removeprefix("READY "))
    lines = [f"Канал: {compact(route.label)}", f"Standby VLESS: {compact(route.standby)}"]
    if route.channel == "SSH" and route.recovery is not None:
        elapsed, required = route.recovery
        def duration(seconds):
            minutes, seconds = divmod(max(0, int(seconds)), 60)
            return f"{minutes}:{seconds:02d}"
        lines.append(f"Устойчивость пары VLESS: {duration(elapsed)} из {duration(required)}")
    lines.extend(("", "Последние 10 событий:"))
    for event in events[:10]:
        when = datetime.fromtimestamp(event.ts).strftime("%d.%m %H:%M:%S")
        lines.append(f"{when}  {compact(event.detail, 200)}")
    if not events:
        lines.append("Пока нет событий")
    return (f"📊 <b>xproxy · {html.escape(reason)}</b>\n"
            f"<code>{stamp}</code>\n<pre>{html.escape(chr(10).join(lines))}</pre>")
