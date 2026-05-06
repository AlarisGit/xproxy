"""Автоматическое обновление из git и безопасный рестарт процесса.

Ключевые принципы:
- `git pull --ff-only` — никаких мёрджей и rewrite истории;
- работаем только с чистым working tree и существующим upstream;
- после pull импортируем новый код в subprocess — если падает, НЕ рестартимся;
- рестарт через os.execv сохраняет PID, systemd/launchd этого не замечает;
- rate-limit: если за AUTOUPDATE_RESTARTS_WINDOW случилось >= _LIMIT
  перезапусков — автоапдейт приостанавливается до следующего «окна».
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .fs_utils import secure_write
from .logger import get_logger
from .settings import (
    AUTOUPDATE_RESTARTS_LIMIT,
    AUTOUPDATE_RESTARTS_WINDOW,
    PROJECT_ROOT,
    STATE_DIR,
)

log = get_logger("xproxy.autoupdate")

_RESTART_HISTORY: Path = STATE_DIR / "restart_history.json"
_REQUIREMENTS: Path = PROJECT_ROOT / "requirements.txt"
_MANUAL_DEPLOY_FILES: tuple[Path, ...] = (
    PROJECT_ROOT / "deploy" / "sudoers.xproxy",
    PROJECT_ROOT / "deploy" / "xproxy.service",
    PROJECT_ROOT / "deploy" / "com.xproxy.daemon.plist",
)
_ENV_MARKER = "XPROXY_UPDATED_AT"   # ставится перед exec, видим в новом процессе
_VALIDATE_TIMEOUT = 25
_PIP_TIMEOUT = 300


# ---------- git helpers ----------

class GitError(RuntimeError):
    pass


def _git(*args: str, timeout: int = 30) -> str:
    """Выполнить git <args> в корне проекта, вернуть stdout. Кидает GitError."""
    git_bin = shutil.which("git")
    if git_bin is None:
        raise GitError("git not found in PATH")
    proc = subprocess.run(
        [git_bin, "-C", str(PROJECT_ROOT), *args],
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise GitError(
            f"git {' '.join(args)} exited {proc.returncode}: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout.decode(errors="replace").strip()


def _is_git_repo() -> bool:
    try:
        _git("rev-parse", "--git-dir")
        return True
    except GitError:
        return False


def _tree_clean() -> bool:
    out = _git("status", "--porcelain")
    return out == ""


def _current_branch() -> Optional[str]:
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    if branch == "HEAD":   # detached
        return None
    return branch


def _upstream_for(branch: str) -> Optional[str]:
    try:
        return _git("rev-parse", "--abbrev-ref", f"{branch}@{{upstream}}")
    except GitError:
        return None


def _head() -> str:
    return _git("rev-parse", "HEAD")


def rollback_to(old_head: str) -> bool:
    """Откатить working tree на old_head после неудачного pull.

    Безопасно, т.к. перед pull мы проверили _tree_clean() — локальных
    изменений нет, reset не затирает пользовательские данные.

    Возвращает True при успехе, False при неудаче (working tree
    остаётся на плохом коммите).
    """
    log.warning("rolling back working tree to %s", old_head[:7])
    try:
        _git("reset", "--hard", old_head)
    except GitError as exc:
        log.error("rollback to %s FAILED: %s — working tree stuck on bad commit!",
                  old_head[:7], exc)
        return False
    log.info("working tree rolled back to %s", old_head[:7])
    return True


def _commits_behind(branch: str, upstream: str) -> int:
    # число коммитов в upstream, которых нет локально
    out = _git("rev-list", "--count", f"{branch}..{upstream}")
    try:
        return int(out)
    except ValueError:
        return 0


# ---------- public API ----------

@dataclass
class UpdateResult:
    updated: bool
    old_head: str = ""
    new_head: str = ""
    requirements_changed: bool = False
    manual_deploy_changed: bool = False
    reason: str = ""
    error: str = ""   # детали ошибки git (если reason in FAILURE_REASONS)


# Reasons, при которых обновление не прошло по реальной ошибке и пользователь
# должен узнать об этом. Остальные "не-обновления" — стабильные состояния
# (tree not clean, no upstream, up to date и т.п.), о них не спамим.
FAILURE_REASONS = frozenset({"fetch failed", "pull failed"})


def check_and_pull() -> UpdateResult:
    """Попытаться обновиться. Возвращает UpdateResult с деталями."""
    if not _is_git_repo():
        return UpdateResult(False, reason="not a git repo")
    if not _tree_clean():
        return UpdateResult(False, reason="working tree not clean")
    branch = _current_branch()
    if branch is None:
        return UpdateResult(False, reason="detached HEAD")
    upstream = _upstream_for(branch)
    if upstream is None:
        return UpdateResult(False, reason=f"no upstream for {branch}")

    try:
        _git("fetch", "--quiet", timeout=60)
    except GitError as exc:
        log.warning("git fetch failed: %s", exc)
        return UpdateResult(False, reason="fetch failed", error=str(exc))

    behind = _commits_behind(branch, upstream)
    if behind == 0:
        return UpdateResult(False, reason="up to date")

    old_head = _head()
    old_req_hash = _file_hash(_REQUIREMENTS)
    old_deploy_hashes = _file_hashes(_MANUAL_DEPLOY_FILES)

    try:
        _git("pull", "--ff-only", "--quiet", timeout=60)
    except GitError as exc:
        log.warning("git pull --ff-only failed: %s", exc)
        return UpdateResult(False, reason="pull failed", error=str(exc))

    new_head = _head()
    if new_head == old_head:
        return UpdateResult(False, reason="head unchanged")

    new_req_hash = _file_hash(_REQUIREMENTS)
    req_changed = (old_req_hash != new_req_hash)
    new_deploy_hashes = _file_hashes(_MANUAL_DEPLOY_FILES)
    deploy_changed = (old_deploy_hashes != new_deploy_hashes)

    log.info(
        "git pull: %s → %s (%d commits, requirements_changed=%s, "
        "manual_deploy_changed=%s)",
        old_head[:7], new_head[:7], behind, req_changed, deploy_changed,
    )
    return UpdateResult(
        updated=True,
        old_head=old_head,
        new_head=new_head,
        requirements_changed=req_changed,
        manual_deploy_changed=deploy_changed,
        reason="ok",
    )


def validate_new_code() -> tuple[bool, str]:
    """Запустить чистый python-подпроцесс и убедиться, что импорт не падает."""
    code = (
        "import importlib; "
        "importlib.import_module('xproxy.daemon'); "
        "importlib.import_module('xproxy.xray_control'); "
        "print('ok')"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)  # избегаем случайного подмешивания
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            cwd=str(PROJECT_ROOT),
            timeout=_VALIDATE_TIMEOUT,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, "validate subprocess timed out"
    if proc.returncode == 0:
        return True, ""
    err = (proc.stderr or proc.stdout or b"").decode(errors="replace").strip()
    return False, err


def install_requirements() -> tuple[bool, str]:
    """Install requirements with the same Python executable that runs xproxy."""
    if not _REQUIREMENTS.exists():
        return True, ""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(_REQUIREMENTS)],
            capture_output=True,
            cwd=str(PROJECT_ROOT),
            timeout=_PIP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, "pip install timed out"
    output = (proc.stderr or b"").decode(errors="replace") + \
             (proc.stdout or b"").decode(errors="replace")
    return proc.returncode == 0, output.strip()


def restart_self() -> None:
    """Заменить текущий процесс новой копией (PID сохраняется)."""
    # Отметим рестарт в истории.
    _record_restart(time.time())
    # Маркер для нового процесса — видно в env, можно залогировать.
    os.environ[_ENV_MARKER] = f"{time.time():.0f}"

    log.info("restarting self via execv: %s %s", sys.executable, sys.argv)
    # Сбросить логгеры, чтобы записать все буфера на диск.
    logging.shutdown()

    argv: List[str] = [sys.executable] + sys.argv
    os.execv(sys.executable, argv)  # no return on success


def post_restart_banner() -> None:
    """Если процесс стартовал после автоапдейта — залогируем."""
    ts = os.environ.get(_ENV_MARKER)
    if ts:
        log.info("process started after autoupdate restart (triggered at %s)", ts)


# ---------- rate-limit ----------

def too_many_restarts() -> bool:
    """True, если за AUTOUPDATE_RESTARTS_WINDOW уже было >= _LIMIT рестартов."""
    now = time.time()
    history = _load_history()
    recent = [t for t in history if now - t <= AUTOUPDATE_RESTARTS_WINDOW]
    return len(recent) >= AUTOUPDATE_RESTARTS_LIMIT


def _record_restart(ts: float) -> None:
    history = _load_history()
    history.append(ts)
    # отсекаем старое, чтобы файл не рос
    cutoff = ts - AUTOUPDATE_RESTARTS_WINDOW * 4
    history = [t for t in history if t >= cutoff]
    secure_write(_RESTART_HISTORY, json.dumps(history))


def _load_history() -> list[float]:
    if not _RESTART_HISTORY.exists():
        return []
    try:
        data = json.loads(_RESTART_HISTORY.read_text(encoding="utf-8"))
        return [float(x) for x in data if isinstance(x, (int, float))]
    except (OSError, json.JSONDecodeError, ValueError):
        return []


# ---------- misc ----------

def _file_hash(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_hashes(paths: tuple[Path, ...]) -> dict[str, str]:
    return {str(path.relative_to(PROJECT_ROOT)): _file_hash(path) for path in paths}
