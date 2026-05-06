"""Кросс-платформенные детали: пути xray, команды рестарта, запись конфига."""
from __future__ import annotations

import os
import platform
import plistlib
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class PlatformInfo:
    name: str                     # "macos" | "linux"
    xray_config: Path             # путь к xray config.json (пишем через sudo при необходимости)
    restart_cmd: List[str]        # команда рестарта xray
    needs_sudo_write: bool        # писать config.json через sudo?


def detect_platform() -> PlatformInfo:
    system = platform.system().lower()
    if system == "darwin":
        # Apple Silicon: /opt/homebrew, Intel: /usr/local.
        prefix = Path("/opt/homebrew") if Path("/opt/homebrew/bin/xray").exists() \
            else Path("/usr/local")
        return PlatformInfo(
            name="macos",
            xray_config=prefix / "etc/xray/config.json",
            restart_cmd=["brew", "services", "restart", "xray"],
            needs_sudo_write=False,
        )
    if system == "linux":
        return PlatformInfo(
            name="linux",
            xray_config=Path("/usr/local/etc/xray/config.json"),
            restart_cmd=["sudo", "-n", "systemctl", "restart", "xray"],
            needs_sudo_write=True,
        )
    raise RuntimeError(f"Unsupported platform: {system}")


def write_xray_config(content: str, info: PlatformInfo | None = None) -> None:
    """Записать config.json xray-а с учётом платформы и прав доступа."""
    info = info or detect_platform()
    target = info.xray_config
    target.parent.mkdir(parents=True, exist_ok=True) if _can_mkdir(target.parent) else None

    # Пробуем прямую запись. Ловим широко OSError (а не только PermissionError),
    # потому что отказы записи прилетают под разными errno:
    #   - EACCES/EPERM — файл принадлежит root (PermissionError);
    #   - EROFS       — /usr/local/etc смонтирован read-only (OSError);
    #   - ENOENT      — asset-структура другая, директория отсутствует.
    # В любом из этих случаев на Linux имеет смысл попробовать sudo tee.
    try:
        _atomic_write_direct(target, content)
        return
    except OSError:
        if not info.needs_sudo_write:
            raise

    # Fallback: sudo tee into a sibling tmp file, then sudo mv -f over target.
    # `tee target` is not safe enough here: a crash can leave config.json
    # truncated after xproxy already validated a different byte sequence.
    if shutil.which("sudo") is None:
        raise RuntimeError("sudo недоступен, а прямая запись конфига запрещена")
    tmp = target.parent / f".{target.name}.xproxy.{os.getpid()}.tmp"
    proc = subprocess.run(
        ["sudo", "-n", "tee", str(tmp)],
        input=content.encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        _sudo_write_legacy(target, content, tmp, proc.stderr)
        return
    proc = subprocess.run(
        ["sudo", "-n", "chmod", "0644", str(tmp)],
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"sudo chmod {tmp} failed: {proc.stderr.decode(errors='replace').strip()}"
        )
    proc = subprocess.run(
        ["sudo", "-n", "mv", "-f", str(tmp), str(target)],
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"sudo mv {tmp} {target} failed: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )


def restart_xray(info: PlatformInfo | None = None) -> None:
    info = info or detect_platform()
    # На Linux/systemd сбрасываем накопленный start-limit state перед рестартом.
    # Во время агрессивных ротаций (xproxy быстро пробует несколько серверов подряд)
    # systemd может пометить unit как "start-request-repeated-too-quickly" и
    # отказывать в запуске до ручного reset-failed. Делаем это идемпотентно:
    # если предыдущих отказов не было, команда просто ничего не изменит.
    if info.name == "linux":
        subprocess.run(
            ["sudo", "-n", "systemctl", "reset-failed", "xray"],
            capture_output=True,
        )
    proc = subprocess.run(info.restart_cmd, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"restart xray failed ({' '.join(info.restart_cmd)}): "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )


def xray_is_running() -> bool:
    """Проверка, запущен ли процесс xray, без platform-specific зависимостей."""
    if shutil.which("pgrep"):
        return subprocess.run(["pgrep", "-x", "xray"], capture_output=True).returncode == 0
    # Fallback: /proc на Linux.
    proc_root = Path("/proc")
    if proc_root.is_dir():
        for pid_dir in proc_root.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                comm = (pid_dir / "comm").read_text().strip()
            except OSError:
                continue
            if comm == "xray":
                return True
    return False


def detect_xray_asset_env(info: PlatformInfo | None = None) -> tuple[str | None, str]:
    """Return XRAY_LOCATION_ASSET used by the production xray service, if visible.

    The value is used only for pre-write validation.  If xproxy validates with
    its own asset directory while the actual xray service starts without the
    same environment, xray may fail after we have already published config.json.
    """
    info = info or detect_platform()
    if info.name == "linux" and shutil.which("systemctl"):
        return _detect_systemd_xray_asset_env()

    if info.name == "macos" and shutil.which("launchctl"):
        plist_value, plist_source = _detect_launchd_plist_asset_env()
        if plist_value:
            return plist_value, plist_source
        # NOTE: launchctl getenv reads the global launchd domain. If
        # XRAY_LOCATION_ASSET is set only in a plist's EnvironmentVariables
        # and that plist is not listed in _detect_launchd_plist_asset_env(),
        # this returns None. Add that plist path to candidates if diagnostics
        # show prod validation using the wrong asset directory.
        try:
            proc = subprocess.run(
                ["launchctl", "getenv", "XRAY_LOCATION_ASSET"],
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            return None, "launchctl getenv XRAY_LOCATION_ASSET timed out"
        if proc.returncode == 0:
            value = proc.stdout.decode(errors="replace").strip() or None
            return value, "launchctl getenv XRAY_LOCATION_ASSET"
        return None, (
            "launchctl getenv XRAY_LOCATION_ASSET unavailable: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )

    return os.environ.get("XRAY_LOCATION_ASSET"), "current process environment fallback"


def _detect_systemd_xray_asset_env() -> tuple[str | None, str]:
    commands = [
        ["systemctl", "show", "xray", "--property=Environment", "--value"],
        ["systemctl", "show", "xray", "--property=Environment"],
    ]
    last_err = ""
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            last_err = "timed out"
            continue
        if proc.returncode != 0:
            last_err = proc.stderr.decode(errors="replace").strip()
            continue
        env_line = proc.stdout.decode(errors="replace").strip()
        value = _parse_env_assignment(env_line, "XRAY_LOCATION_ASSET")
        return value, "systemd xray.service Environment"
    return None, f"systemd xray.service Environment unavailable: {last_err}"


def _detect_launchd_plist_asset_env() -> tuple[str | None, str]:
    candidates = [
        Path.home() / "Library/LaunchAgents/homebrew.mxcl.xray.plist",
        Path("/Library/LaunchDaemons/homebrew.mxcl.xray.plist"),
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            with path.open("rb") as fh:
                data = plistlib.load(fh)
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
        env = data.get("EnvironmentVariables")
        if not isinstance(env, dict):
            continue
        value = env.get("XRAY_LOCATION_ASSET")
        if isinstance(value, str) and value:
            return value, f"launchd plist {path}"
    return None, ""


def _parse_env_assignment(env_line: str, name: str) -> str | None:
    """Parse systemd Environment= output and return one variable value."""
    if not env_line:
        return None
    if env_line.startswith("Environment="):
        env_line = env_line[len("Environment="):]
    try:
        parts = shlex.split(env_line)
    except ValueError:
        parts = env_line.split()
    prefix = f"{name}="
    for part in parts:
        if part.startswith(prefix):
            return part[len(prefix):] or None
    return None


def _sudo_write_legacy(
    target: Path,
    content: str,
    attempted_tmp: Path,
    first_stderr: bytes,
) -> None:
    """Fallback for hosts that have not yet installed the new sudoers file.

    This keeps the first autoupdate rollout compatible with old installs where
    only `sudo tee config.json` is whitelisted. New installs use the atomic
    tmp+chmod+mv path above; the legacy path should disappear after sudoers is
    updated via deploy/install.sh.
    """
    log_msg = first_stderr.decode(errors="replace").strip()
    proc = subprocess.run(
        ["sudo", "-n", "tee", str(target)],
        input=content.encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"sudo tee {attempted_tmp} failed: {log_msg}; legacy sudo tee "
            f"{target} failed: {proc.stderr.decode(errors='replace').strip()}"
        )


def _can_mkdir(path: Path) -> bool:
    try:
        return os.access(path.parent, os.W_OK) or path.exists()
    except OSError:
        return False


def _atomic_write_direct(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = 0o644
    try:
        mode = target.stat().st_mode & 0o777
    except OSError:
        pass
    fd, tmp_s = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    tmp = Path(tmp_s)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
        _fsync_dir(target.parent)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
