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

from .fs_utils import secure_write
from .logger import get_logger
from .platform_utils import (
    PlatformInfo,
    detect_platform,
    detect_xray_asset_env,
    restart_xray as _platform_restart,
    write_xray_config,
    xray_is_running,
)
from .servers import Server
from .settings import BOOT_GRACE, GEO_DIR, SOCKS_HOST, SOCKS_PORT, STATE_DIR
from .xray_config import build_xray_config_text

log = get_logger("xproxy.xray_control")


def _fmt_server(server: Server) -> str:
    """Короткое имя сервера для логов xray_control: 'host:port (ip)' или 'host:port'."""
    if server.resolved_ip and server.resolved_ip != server.host:
        return f"{server.host}:{server.port} ({server.resolved_ip})"
    return f"{server.host}:{server.port}"

BACKUP_PATH: Path = STATE_DIR / "xray_config.backup.json"
_TEST_TIMEOUT = 20


class XrayConfigError(RuntimeError):
    """Сгенерированный конфиг не прошёл xray -test."""


class XrayStartError(RuntimeError):
    """xray не поднял локальный listener после записи и рестарта."""


class ConfigUnchanged(RuntimeError):
    """Сгенерированный конфиг идентичен текущему — запись и рестарт не нужны."""


def apply_server(server: Server, *, dry_run: bool = False,
                 info: PlatformInfo | None = None) -> None:
    """Сгенерировать конфиг, провалидировать, забэкапить, записать и рестартовать.

    Если сгенерированный конфиг совпадает с текущим на диске — поднимает
    ConfigUnchanged (xray не перезагружается, соединения не рвутся).
    """
    cfg_text = build_xray_config_text(server)
    apply_config_text(
        cfg_text,
        label=f"{_fmt_server(server)}, {server.country}",
        dry_run=dry_run,
        info=info,
    )


def apply_config_text(
    cfg_text: str,
    *,
    label: str = "prepared config",
    dry_run: bool = False,
    info: PlatformInfo | None = None,
) -> None:
    """Провалидировать, записать готовый config.json и перезапустить xray.

    Используется для standby promotion: конфиг уже был собран и проверен
    заранее, но перед публикацией всё равно прогоняем production validation,
    чтобы не применить устаревший или несовместимый snapshot.
    """
    info = info or detect_platform()

    # 1. Валидация: xray -test на временном файле. Сначала проверяем конфиг
    # на asset-каталоге xproxy, затем повторяем тест в окружении продового
    # xray-сервиса. Это ловит главный опасный класс ошибок: xproxy видит
    # свежий geosite.dat, а xray.service стартует без XRAY_LOCATION_ASSET и
    # падает на отсутствующей geosite:/geoip: категории.
    ok, err = validate_config_for_service(cfg_text, info)
    if not ok:
        short = err.strip().splitlines()[-1] if err.strip() else "unknown error"
        raise XrayConfigError(
            f"xray -test failed for {label}: {short}"
        )

    # 2. Diff: если конфиг не изменился — не трогаем xray.
    # Diff намеренно после xray -test: уже опубликованный конфиг мог стать
    # невалидным для текущего service-env, и ConfigUnchanged не должен это
    # маскировать.
    if not dry_run and _config_matches_current(cfg_text, info):
        log.info("config unchanged, skip write+restart (%s)",
                 label)
        raise ConfigUnchanged(
            f"config for {label} is identical to current"
        )

    if dry_run:
        log.info("[dry-run] config valid; would write %d bytes to %s and restart xray",
                 len(cfg_text), info.xray_config)
        return

    # 3. Бэкап текущего конфига (best-effort).
    try:
        _backup_current_config(info)
    except Exception as exc:  # noqa: BLE001
        log.warning("config backup skipped: %s", exc)

    log.info("write xray config → %s (%s)", info.xray_config, label)
    write_xray_config(cfg_text, info)

    log.info("restart xray: %s", " ".join(info.restart_cmd))
    try:
        _platform_restart(info)
    except Exception as exc:  # noqa: BLE001
        msg = f"xray restart failed after writing config for {label}: {exc}"
        log.error(msg)
        raise XrayStartError(msg) from exc

    if wait_for_proxy_port():
        log.info("xray listener ready on %s:%d", SOCKS_HOST, SOCKS_PORT)
    else:
        diag = _diagnose_start_failure(cfg_text, info)
        msg = (
            f"xray listener on {SOCKS_HOST}:{SOCKS_PORT} did not come up "
            f"in {BOOT_GRACE}s; {diag}"
        )
        log.error(msg)
        raise XrayStartError(msg)


def validate_config_text(
    cfg_text: str,
    info: PlatformInfo | None = None,
    *,
    asset_dir: Path | None = None,
) -> tuple[bool, str]:
    """Прогнать `xray -test` на произвольной JSON-строке. Возвращает (ok, stderr+stdout)."""
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(asset_dir or GEO_DIR)
    return _run_xray_test(cfg_text, env=env)


def validate_config_for_service(
    cfg_text: str,
    info: PlatformInfo | None = None,
    *,
    asset_dir: Path | None = None,
) -> tuple[bool, str]:
    """Validate config with xproxy assets and with the production xray env."""
    info = info or detect_platform()
    managed_asset_dir = asset_dir or GEO_DIR

    managed_env = os.environ.copy()
    managed_env["XRAY_LOCATION_ASSET"] = str(managed_asset_dir)
    ok, output = _run_xray_test(cfg_text, env=managed_env)
    if not ok:
        return False, _with_context("xproxy asset validation failed", output)

    service_asset, source = detect_xray_asset_env(info)
    if _same_asset_path(service_asset, managed_asset_dir):
        return True, output

    service_env = os.environ.copy()
    if service_asset:
        service_env["XRAY_LOCATION_ASSET"] = service_asset
        asset_label = service_asset
    else:
        # Не можем определить XRAY_LOCATION_ASSET xray-сервиса. Тест без
        # переменной бессмысленнен: xray подхватит встроенный geosite.dat
        # (обычно из homebrew), где нет кастомных категорий, и тест упадёт
        # даже при валидном конфиге. Вместо этого верим managed-тесту и
        # предупреждаем: конфиг валиден с managed-ассетами, но xray-сервис
        # может не увидеть их, если env не настроен.
        log.warning(
            "cannot detect xray service XRAY_LOCATION_ASSET (%s) — "
            "skipping service env test; config validated with xproxy "
            "assets only; run `launchctl setenv XRAY_LOCATION_ASSET %s` "
            "on macOS or set xray.service override on Linux",
            source, managed_asset_dir,
        )
        return True, output

    ok, service_output = _run_xray_test(cfg_text, env=service_env)
    if ok:
        if service_asset != str(managed_asset_dir):
            log.warning(
                "xray service XRAY_LOCATION_ASSET differs from xproxy GEO_DIR "
                "(service=%s via %s, xproxy=%s); config still passed service test",
                asset_label, source, managed_asset_dir,
            )
        return True, service_output

    return False, _with_context(
        "production xray validation failed "
        f"(XRAY_LOCATION_ASSET={asset_label}, source={source})",
        service_output,
    )


def _run_xray_test(cfg_text: str, *, env: dict[str, str]) -> tuple[bool, str]:
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


def _with_context(prefix: str, output: str) -> str:
    text = output.strip()
    if not text:
        return prefix
    return f"{prefix}: {text}"


def _same_asset_path(service_asset: str | None, managed_asset_dir: Path) -> bool:
    """True if service and managed asset dirs refer to the same filesystem path."""
    if not service_asset:
        return False
    try:
        service_path = Path(service_asset).expanduser().resolve(strict=False)
        managed_path = Path(managed_asset_dir).expanduser().resolve(strict=False)
    except OSError:
        return service_asset.rstrip("/") == str(managed_asset_dir).rstrip("/")
    return service_path == managed_path


def _diagnose_start_failure(cfg_text: str, info: PlatformInfo) -> str:
    """Collect concise diagnostics after xray restart left the listener down."""
    parts: list[str] = []
    parts.append(f"xray_running={xray_is_running()}")

    service_asset, source = detect_xray_asset_env(info)
    parts.append(f"service_XRAY_LOCATION_ASSET={service_asset or '<unset>'} ({source})")

    ok, output = validate_config_for_service(cfg_text, info)
    if ok:
        parts.append("prod xray -test still passes")
    else:
        last = output.strip().splitlines()[-1] if output.strip() else "unknown error"
        parts.append(f"prod xray -test now fails: {last}")

    log_tail = _tail_configured_error_log(cfg_text)
    if log_tail:
        parts.append(f"recent xray error log: {log_tail}")
    return "; ".join(parts)


def _tail_configured_error_log(cfg_text: str, max_bytes: int = 8192) -> str:
    try:
        cfg = json.loads(cfg_text)
    except (ValueError, TypeError):
        return ""
    log_section = cfg.get("log")
    if not isinstance(log_section, dict):
        return ""
    path_s = log_section.get("error")
    if not isinstance(path_s, str) or not path_s or path_s == "none":
        return ""
    path = Path(path_s)
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
            data = fh.read()
    except OSError:
        return ""
    lines = [line.strip() for line in data.decode(errors="replace").splitlines()
             if line.strip()]
    relevant = [
        line for line in lines
        if any(kw in line.lower() for kw in ("error", "failed", "warning"))
    ]
    chosen = relevant[-3:] if relevant else lines[-3:]
    return " | ".join(chosen)


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
    ok, err = validate_config_for_service(text, info)
    if not ok:
        log.error("backup at %s is not valid (%s) — refusing to restore",
                  BACKUP_PATH, err.strip().splitlines()[-1:])
        return False
    write_xray_config(text, info)
    _platform_restart(info)
    return wait_for_proxy_port()


def wait_for_proxy_port(
    timeout: float = BOOT_GRACE,
    *,
    host: str = SOCKS_HOST,
    port: int = SOCKS_PORT,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.25)
    return False


def is_running() -> bool:
    return xray_is_running()


# ---------- internals ----------

def _config_matches_current(new_text: str, info: PlatformInfo) -> bool:
    """True, если new_text совпадает с текущим config.json на диске."""
    target = info.xray_config
    if not target.exists():
        return False
    try:
        current = target.read_text(encoding="utf-8")
    except OSError:
        return False
    return current == new_text


def _backup_current_config(info: PlatformInfo) -> None:
    src = info.xray_config
    if not src.exists():
        return
    content = src.read_text(encoding="utf-8")
    secure_write(BACKUP_PATH, content)
    log.debug("backed up %s → %s", src, BACKUP_PATH)


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
