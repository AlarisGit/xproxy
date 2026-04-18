"""Скачивание geosite.dat и geoip.dat с учётом TTL.

Файлы кладутся в ~/.config/xproxy/geo/. Для использования xray-ом путь
надо прокинуть через переменную XRAY_LOCATION_ASSET (см. deploy/).
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests

from .logger import get_logger
from .platform_utils import PlatformInfo, detect_platform
from .routing import load_routing
from .settings import GEO_DIR, GEO_REFRESH, USER_AGENT

log = get_logger("xproxy.geo")

_FILES = {
    "geosite.dat": "GeositeUrl",
    "geoip.dat": "GeoipUrl",
}
_DOWNLOAD_TIMEOUT = 60


def ensure_geo_assets(force: bool = False) -> dict[str, Path]:
    """Скачивает geosite.dat/geoip.dat при необходимости. Возвращает пути."""
    cfg = load_routing()
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    result: dict[str, Path] = {}

    for name, url_key in _FILES.items():
        url = cfg.get(url_key)
        target = GEO_DIR / name
        if not url:
            log.warning("no %s in routing.json — skip", url_key)
            if target.exists():
                result[name] = target
            continue

        if not force and _is_fresh(target):
            log.debug("%s is fresh, skip download", name)
            result[name] = target
            continue

        try:
            _download(url, target)
            log.info("downloaded %s → %s (%d bytes)", name, target, target.stat().st_size)
            result[name] = target
        except Exception as exc:  # noqa: BLE001
            log.warning("download %s failed: %s", name, exc)
            if target.exists():
                result[name] = target  # используем старую версию

    return result


def _is_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < GEO_REFRESH


def _download(url: str, target: Path) -> None:
    tmp = target.with_suffix(target.suffix + ".part")
    # trust_env=False: не давать HTTP_PROXY из шелла завести нас через xray.
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    with session.get(
        url,
        timeout=_DOWNLOAD_TIMEOUT,
        stream=True,
        allow_redirects=True,
    ) as resp:
        resp.raise_for_status()
        with tmp.open("wb") as fh:
            shutil.copyfileobj(resp.raw, fh)
    tmp.replace(target)


# ---------- Деплой в asset-dir xray ----------

def deploy_to_xray_assets(info: Optional[PlatformInfo] = None,
                          force: bool = False) -> None:
    """Скопировать скачанные geo-файлы в xray asset directory.

    macOS: прямой copy (директория обычно принадлежит пользователю brew).
    Linux: через `sudo -n install` (нужны права в sudoers, см. deploy/).
    """
    info = info or detect_platform()
    dst_dir = info.xray_asset_dir
    if not dst_dir.exists():
        log.warning("xray asset dir %s does not exist — skip deploy", dst_dir)
        return

    for name in _FILES:
        src = GEO_DIR / name
        dst = dst_dir / name
        if not src.exists():
            continue
        if not force and _same_file(src, dst):
            log.debug("%s already deployed to %s", name, dst)
            continue
        try:
            _install_file(src, dst, info)
            log.info("deployed %s → %s", name, dst)
        except Exception as exc:  # noqa: BLE001
            log.warning("deploy %s → %s failed: %s", name, dst, exc)


def _same_file(a: Path, b: Path) -> bool:
    if not b.exists():
        return False
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        return _sha256(a) == _sha256(b)
    except OSError:
        return False


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _install_file(src: Path, dst: Path, info: PlatformInfo) -> None:
    """Копия с сохранением прав; fallback на sudo для Linux."""
    try:
        shutil.copy2(src, dst)
        return
    except PermissionError:
        if not info.needs_sudo_write:
            raise
    # Fallback: sudo -n install (атомарнее, чем cp).
    install_bin = shutil.which("install") or "/usr/bin/install"
    proc = subprocess.run(
        ["sudo", "-n", install_bin, "-m", "0644", str(src), str(dst)],
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"sudo install failed: {proc.stderr.decode(errors='replace').strip()}"
        )
