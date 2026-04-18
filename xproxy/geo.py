"""Скачивание geosite.dat и geoip.dat с учётом TTL.

Файлы кладутся в ~/.config/xproxy/geo/. xray видит их через переменную
XRAY_LOCATION_ASSET, которая прописывается один раз при установке:

  - macOS (brew services):  launchctl setenv XRAY_LOCATION_ASSET ~/.config/xproxy/geo
  - Linux  (systemd):       Environment=XRAY_LOCATION_ASSET=/home/<user>/.config/xproxy/geo
                            в override'е юнита xray.service

Мы НЕ пишем ничего в системные директории xray (/usr/local/share/xray и т.п.) —
это упрощает конфигурацию (без sudo) и убирает класс ошибок FS (EROFS/EACCES).
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

import requests

from .logger import get_logger
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
