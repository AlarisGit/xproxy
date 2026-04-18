"""Кросс-платформенные детали: пути xray, команды рестарта, запись конфига."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
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
        target.write_text(content, encoding="utf-8")
        return
    except OSError:
        if not info.needs_sudo_write:
            raise

    # Fallback: sudo -n tee.
    if shutil.which("sudo") is None:
        raise RuntimeError("sudo недоступен, а прямая запись конфига запрещена")
    proc = subprocess.run(
        ["sudo", "-n", "tee", str(target)],
        input=content.encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"sudo tee {target} failed: {proc.stderr.decode(errors='replace').strip()}"
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


def _can_mkdir(path: Path) -> bool:
    try:
        return os.access(path.parent, os.W_OK) or path.exists()
    except OSError:
        return False
