"""Управление процессом xray: запись конфига, рестарт, ожидание поднятия порта.

Ключевая страховка: перед записью боевого config.json мы ВСЕГДА прогоняем
`xray -test` на временном файле. Если тест не прошёл — боевой конфиг не
трогаем, xray остаётся с предыдущим рабочим состоянием.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .logger import get_logger
from .platform_utils import (
    PlatformInfo,
    detect_platform,
    restart_xray as _platform_restart,
    write_xray_config,
    xray_is_running,
)
from .servers import Server
from .settings import BOOT_GRACE, GEO_DIR, SOCKS_HOST, SOCKS_PORT, STATE_DIR
from .xray_config import build_xray_config_text

log = get_logger("xproxy.xray_control")

BACKUP_PATH: Path = STATE_DIR / "xray_config.backup.json"
_TEST_TIMEOUT = 20


class XrayConfigError(RuntimeError):
    """Сгенерированный конфиг не прошёл xray -test."""


def apply_server(server: Server, *, dry_run: bool = False,
                 info: PlatformInfo | None = None) -> None:
    """Сгенерировать конфиг, провалидировать, забэкапить, записать и рестартовать."""
    info = info or detect_platform()
    cfg_text = build_xray_config_text(server)

    # 1. Валидация: xray -test на временном файле.
    ok, err = validate_config_text(cfg_text, info)
    if not ok:
        short = err.strip().splitlines()[-1] if err.strip() else "unknown error"
        raise XrayConfigError(
            f"xray -test failed for {server.host}:{server.port}: {short}"
        )

    if dry_run:
        log.info("[dry-run] config valid; would write %d bytes to %s and restart xray",
                 len(cfg_text), info.xray_config)
        return

    # 2. Бэкап текущего конфига (best-effort).
    try:
        _backup_current_config(info)
    except Exception as exc:  # noqa: BLE001
        log.warning("config backup skipped: %s", exc)

    log.info("write xray config → %s (%s:%d, %s)",
             info.xray_config, server.host, server.port, server.country)
    write_xray_config(cfg_text, info)

    log.info("restart xray: %s", " ".join(info.restart_cmd))
    _platform_restart(info)

    if wait_for_proxy_port():
        log.info("xray listener ready on %s:%d", SOCKS_HOST, SOCKS_PORT)
    else:
        log.warning("xray listener on %s:%d did not come up in %ds",
                    SOCKS_HOST, SOCKS_PORT, BOOT_GRACE)


def validate_config_text(cfg_text: str,
                         info: PlatformInfo | None = None) -> tuple[bool, str]:
    """Прогнать `xray -test` на произвольной JSON-строке. Возвращает (ok, stderr+stdout)."""
    info = info or detect_platform()
    xray_bin = shutil.which("xray")
    if xray_bin is None:
        return False, "xray binary not found in PATH"

    # В конфиге log.access/log.error обычно указывают на /var/log/xray/*.log,
    # куда может писать только боевой процесс xray (запущен от root). При
    # `xray -test` из-под нашего пользователя открытие этих файлов на запись
    # падает с permission denied, хотя сам конфиг валиден. Подменяем пути на
    # "none" (штатное значение xray = отключить файл-лог) — тест становится
    # чистой проверкой синтаксиса и разрешения geo-правил.
    test_text = _neutralize_log_paths(cfg_text)

    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8",
                                     delete=False) as fh:
        fh.write(test_text)
        tmp_path = fh.name
    try:
        env = os.environ.copy()
        # Тест читает те же geo-файлы, что будет использовать боевой процесс
        # (скачанные нами в GEO_DIR; xray в системе тоже смотрит туда через env).
        env["XRAY_LOCATION_ASSET"] = str(GEO_DIR)
        proc = subprocess.run(
            [xray_bin, "-test", "-c", tmp_path],
            capture_output=True,
            env=env,
            timeout=_TEST_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, "xray -test timed out"
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    output = (proc.stderr or b"").decode(errors="replace") + \
             (proc.stdout or b"").decode(errors="replace")
    return proc.returncode == 0, output


def _neutralize_log_paths(cfg_text: str) -> str:
    """Вернуть копию конфига, где log.access/log.error заменены на "none".

    "none" — штатное значение xray, которое означает «не писать файл-лог»
    (см. https://xtls.github.io/config/log.html). Это нужно только для
    `xray -test`, чтобы валидация не требовала прав на запись в /var/log/xray.
    Боевой config.json на диске остаётся с оригинальными путями.
    Если JSON невалиден — возвращаем исходный текст, пусть xray сам
    диагностирует проблему через свой парсер.
    """
    try:
        cfg = json.loads(cfg_text)
    except (ValueError, TypeError):
        return cfg_text
    log_section = cfg.get("log")
    if isinstance(log_section, dict):
        changed = False
        for key in ("access", "error"):
            if isinstance(log_section.get(key), str) and log_section[key] != "none":
                log_section[key] = "none"
                changed = True
        if changed:
            return json.dumps(cfg, ensure_ascii=False, indent=2)
    return cfg_text


def restore_backup(info: PlatformInfo | None = None) -> bool:
    """Восстановить бэкап config.json, если он есть. Возвращает True при успехе."""
    info = info or detect_platform()
    if not BACKUP_PATH.exists():
        log.warning("no backup at %s", BACKUP_PATH)
        return False
    text = BACKUP_PATH.read_text(encoding="utf-8")
    ok, err = validate_config_text(text, info)
    if not ok:
        log.error("backup at %s is not valid (%s) — refusing to restore",
                  BACKUP_PATH, err.strip().splitlines()[-1:])
        return False
    write_xray_config(text, info)
    _platform_restart(info)
    return wait_for_proxy_port()


def wait_for_proxy_port(timeout: float = BOOT_GRACE) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_open(SOCKS_HOST, SOCKS_PORT):
            return True
        time.sleep(0.25)
    return False


def is_running() -> bool:
    return xray_is_running()


# ---------- internals ----------

def _backup_current_config(info: PlatformInfo) -> None:
    src = info.xray_config
    if not src.exists():
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, BACKUP_PATH)
    log.debug("backed up %s → %s", src, BACKUP_PATH)


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
