"""In-memory состояние демона + персист активного сервера в state/active.json."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .logger import get_logger
from .servers import Server
from .settings import ACTIVE_STATE, SERVER_PENALTY_DURATION, STATE_DIR

log = get_logger("xproxy.state")


ServerKey = Tuple[str, int]


def _key(server: Server) -> ServerKey:
    return (server.host, server.port)


@dataclass
class DaemonState:
    ranked: List[Server] = field(default_factory=list)
    active: Optional[Server] = None
    last_subscription_refresh: float = 0.0
    last_rotation: float = 0.0
    last_git_pull: float = 0.0
    consecutive_proxy_failures: int = 0

    # (host, port) → unix_ts до которого сервер считается "в штрафной".
    # Истёкшие записи фильтруются лениво в next_candidates/penalized_keys.
    server_penalty: Dict[ServerKey, float] = field(default_factory=dict)

    # Статистика и heartbeat.
    start_time: float = field(default_factory=time.time)
    last_heartbeat_date: str = ""          # 'YYYY-MM-DD' последнего heartbeat
    rotations_today: int = 0
    rotations_today_date: str = ""         # счётчик сбрасывается при смене даты

    # Stale subscription tracking.
    last_live_fetch: float = 0.0           # unix_ts последнего успешного live-фетча
    _stale_notified: bool = False           # уведомление об устаревшей подписке уже отправлено

    # ---------- активный сервер ----------
    def set_active(self, server: Server) -> None:
        prev = self.active
        self.active = server
        self.consecutive_proxy_failures = 0
        self.last_rotation = time.time()
        # Активный сервер получил шанс работать — снимаем с него штраф, если был.
        self.server_penalty.pop(_key(server), None)
        if prev is not None and _key(prev) != _key(server):
            self._bump_rotation_counter()
        _save_active(server)

    def note_proxy_fail(self) -> int:
        self.consecutive_proxy_failures += 1
        return self.consecutive_proxy_failures

    def note_proxy_ok(self) -> None:
        self.consecutive_proxy_failures = 0

    # ---------- penalty box ----------
    def penalize(self, server: Server, duration: float = SERVER_PENALTY_DURATION) -> None:
        """Отправить сервер в конец списка на `duration` секунд."""
        self.server_penalty[_key(server)] = time.time() + duration

    def penalized_keys(self) -> Dict[ServerKey, float]:
        """Активные (ещё не истёкшие) штрафы. Попутно чистит просроченные."""
        now = time.time()
        expired = [k for k, t in self.server_penalty.items() if t <= now]
        for k in expired:
            self.server_penalty.pop(k, None)
        return dict(self.server_penalty)

    # ---------- выбор следующего сервера ----------
    def next_candidates(self) -> List[Server]:
        """Порядок: сначала "чистые", потом "в штрафе" (с раньше истекающим штрафом —
        раньше); активный каждый раз отправляется в конец своей группы.
        Никто не исключается: если все в штрафе, мы всё равно пройдём по всем.
        """
        if not self.ranked:
            return []
        penalties = self.penalized_keys()
        active_key = _key(self.active) if self.active else None

        clean: List[Server] = []
        penalized: List[Tuple[float, int, Server]] = []
        for i, s in enumerate(self.ranked):
            k = _key(s)
            if k in penalties:
                penalized.append((penalties[k], i, s))
            else:
                clean.append(s)
        # Штрафники: раньше истечёт → раньше пробуем.
        penalized.sort(key=lambda t: (t[0], t[1]))
        ordered = clean + [s for _, _, s in penalized]

        # Активный — в конец своей группы, чтобы сначала пробовать альтернативы.
        if active_key is not None:
            rest = [s for s in ordered if _key(s) != active_key]
            tail = [s for s in ordered if _key(s) == active_key]
            return rest + tail
        return ordered

    # ---------- внутренние ----------
    def _bump_rotation_counter(self) -> None:
        today = time.strftime("%Y-%m-%d", time.localtime())
        if self.rotations_today_date != today:
            self.rotations_today = 0
            self.rotations_today_date = today
        self.rotations_today += 1


def load_active() -> Optional[Server]:
    if not ACTIVE_STATE.exists():
        return None
    try:
        data = json.loads(ACTIVE_STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("cannot read %s: %s", ACTIVE_STATE, exc)
        return None
    try:
        return Server(**data)
    except TypeError as exc:
        log.warning("stale active state schema: %s", exc)
        return None


def _save_active(server: Server) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ACTIVE_STATE.write_text(
        json.dumps(server.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
