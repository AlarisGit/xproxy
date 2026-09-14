"""Optional SCP publication of a verified config after a VLESS upstream change."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .logger import get_logger
from .platform_utils import PlatformInfo, detect_platform
from .settings import (
    CONFIG_SYNC_CONNECT_TIMEOUT,
    CONFIG_SYNC_TIMEOUT,
    SYNC_CONFIG,
)

log = get_logger("xproxy.config_sync")


@dataclass(frozen=True)
class ConfigSyncTarget:
    host: str
    port: int
    user: str
    path: str

    @property
    def remote(self) -> str:
        return f"{self.user}@{self.host}:{self.path}"

    def safe_label(self) -> str:
        return f"{self.user}@{self.host}:{self.path}"


class ConfigSyncError(RuntimeError):
    """sync.json exists but config publication failed or is invalid."""


def load_config_sync(path: Path = SYNC_CONFIG) -> Optional[ConfigSyncTarget]:
    """Load optional conf/sync.json.

    Missing file means the host does not publish xray config changes. Existing
    but malformed file is treated as an operator error and reported to logs.
    """
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigSyncError(f"cannot read {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigSyncError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigSyncError(f"{path} must contain a JSON object")

    missing = [
        key for key in ("host", "port", "user", "path")
        if key not in data or data[key] in (None, "")
    ]
    if missing:
        raise ConfigSyncError(
            f"{path} missing required keys: {', '.join(missing)}"
        )

    host = _as_nonempty_str(data["host"], "host", path)
    user = _as_nonempty_str(data["user"], "user", path)
    remote_path = _as_nonempty_str(data["path"], "path", path)
    try:
        port = int(data["port"])
    except (TypeError, ValueError) as exc:
        raise ConfigSyncError(f"{path} key port must be an integer") from exc
    if port < 1 or port > 65535:
        raise ConfigSyncError(f"{path} key port must be in 1..65535")

    return ConfigSyncTarget(
        host=host,
        port=port,
        user=user,
        path=remote_path,
    )


def sync_current_config(
    *,
    info: PlatformInfo | None = None,
    sync_path: Path = SYNC_CONFIG,
    config_text: str | None = None,
) -> Optional[ConfigSyncTarget]:
    """Copy the current xray config to the optional sync target via SCP.

    Returns the target when a copy was attempted and completed, or None when
    sync is disabled because sync.json is absent.
    """
    target = load_config_sync(sync_path)
    if target is None:
        log.debug("config sync disabled: %s not found", sync_path)
        return None

    info = info or detect_platform()
    source = info.xray_config
    if config_text is None and not source.exists():
        raise ConfigSyncError(f"xray config does not exist: {source}")
    text = config_text if config_text is not None else source.read_text(encoding="utf-8")
    try:
        cfg = json.loads(text)
    except ValueError as exc:
        raise ConfigSyncError("cannot publish invalid xray JSON") from exc
    if not isinstance(cfg, dict) or not isinstance(cfg.get("outbounds"), list) or \
            not all(isinstance(o, dict) for o in cfg["outbounds"]):
        raise ConfigSyncError("cannot publish malformed xray outbounds")
    upstreams = [o for o in cfg["outbounds"] if o.get("tag") == "proxy"]
    if len(upstreams) != 1 or upstreams[0].get("protocol") != "vless":
        log.info("config sync skipped: only VLESS configurations can be published")
        return None
    if shutil.which("scp") is None:
        raise ConfigSyncError("scp binary not found in PATH")

    # A private directory protects the local snapshot, while 0644 preserves the
    # permissions expected by the existing remote publication setup.
    with tempfile.TemporaryDirectory(prefix="xproxy-sync-") as tmp:
        snapshot = Path(tmp) / "config.json"
        snapshot.write_text(text, encoding="utf-8")
        os.chmod(snapshot, 0o644)
        detail = _run_scp(snapshot, target, ignore_ssh_config=False)
        if detail and _ssh_config_permissions_error(detail):
            log.warning("scp SSH config permissions error; retrying with -F none")
            detail = _run_scp(snapshot, target, ignore_ssh_config=True)
    if detail:
        raise ConfigSyncError(
            f"scp to {target.safe_label()} failed: {detail}"
        )

    log.info("synced xray config %s → %s", source, target.safe_label())
    return target


def _run_scp(
    source: Path,
    target: ConfigSyncTarget,
    *,
    ignore_ssh_config: bool,
) -> str:
    cmd = ["scp"]
    if ignore_ssh_config:
        cmd.extend(["-F", "none"])
    cmd.extend([
        "-P",
        str(target.port),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={CONFIG_SYNC_CONNECT_TIMEOUT}",
        str(source),
        target.remote,
    ])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=CONFIG_SYNC_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConfigSyncError(f"scp timed out after {CONFIG_SYNC_TIMEOUT}s") from exc

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace").strip()
        stdout = proc.stdout.decode(errors="replace").strip()
        return stderr or stdout or f"exit code {proc.returncode}"
    return ""


def _ssh_config_permissions_error(detail: str) -> bool:
    lowered = detail.lower()
    return "bad owner or permissions" in lowered and "ssh_config" in lowered


def _as_nonempty_str(value: Any, key: str, path: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigSyncError(f"{path} key {key} must be a non-empty string")
    return value.strip()
