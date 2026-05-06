"""Скачивание geosite.dat / geoip.dat с защитой от частичных скачиваний
и экспоненциальным бэкоффом при ошибках.

Ключевые инварианты:

1. Файл заменяется на новую версию ТОЛЬКО после полного и успешного
   скачивания (проверяется Content-Length, если сервер его прислал).
   При обрыве соединения сохраняется работающая старая копия — xray
   не упадёт из-за битого файла.
2. При отсутствии файла — инициируем скачивание.
3. Максимальный интервал между успешными скачиваниями — GEO_REFRESH
   (по умолчанию 6 часов). Интервалы между неудачными попытками
   увеличиваются по GEO_RETRY_SCHEDULE (10с → 1м → 5м → ...).
4. Состояние (last_success, last_attempt, consecutive_failures) живёт
   в state/geo_state.json — переживает рестарты.

Файлы лежат в GEO_DIR (см. settings.py). xray видит их через переменную
XRAY_LOCATION_ASSET, прописанную в юните при установке.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import requests

from .fs_utils import secure_write
from .logger import get_logger
from .routing import load_routing
from .settings import (
    GEO_DIR,
    GEO_REFRESH,
    GEO_RETRY_SCHEDULE,
    HTTP_HOST,
    HTTP_PORT,
    STATE_DIR,
    USER_AGENT,
)

log = get_logger("xproxy.geo")

# Имя файла → ключ URL в routing.json → «категория» (geosite / geoip).
# Категория используется как namespace для load_geo_categories().
_FILES: tuple[tuple[str, str, str], ...] = (
    ("geosite.dat", "GeositeUrl", "geosite"),
    ("geoip.dat", "GeoipUrl", "geoip"),
)
_DOWNLOAD_TIMEOUT = 60
_GEO_STATE_FILE: Path = STATE_DIR / "geo_state.json"


@dataclass(frozen=True)
class _DownloadRoute:
    name: str
    proxies: dict[str, str] | None = None


# ---------- public types ----------

@dataclass
class GeoResult:
    """Результат одной итерации ensure_geo_assets()."""
    paths: dict[str, Path] = field(default_factory=dict)
    # Файлы, скачанные в этом вызове (имена без пути).
    freshly_downloaded: set[str] = field(default_factory=set)
    # Через сколько секунд стоит повторить попытку (для планировщика в daemon).
    next_attempt_in: float = GEO_REFRESH
    # Человекочитаемые ошибки (имя → причина), если что-то не удалось скачать.
    errors: dict[str, str] = field(default_factory=dict)


# ---------- public API ----------

def ensure_geo_assets(
    force: bool = False,
    *,
    validation_server=None,
    platform_info=None,
) -> GeoResult:
    """Убедиться, что geosite.dat / geoip.dat доступны и свежие.

    - Если файла нет — скачиваем безусловно (приоритет).
    - Если файл старше GEO_REFRESH или force=True — пытаемся обновить.
    - На ошибке сохраняем рабочую копию, увеличиваем счётчик и
      планируем следующую попытку по бэкоффу.
    """
    cfg = load_routing()
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    state = _load_state()
    state_before = json.dumps(state, sort_keys=True)
    result = GeoResult()
    now = time.time()

    # Минимальный бэкофф среди файлов, которые сейчас не нужно трогать
    # или которые только что успешно обновились. Дефолт — GEO_REFRESH.
    next_delays: list[float] = []

    download_plan: list[tuple[str, str, Path, dict]] = []

    for name, url_key, _category in _FILES:
        target = GEO_DIR / name
        url = cfg.get(url_key)
        file_state = state.setdefault(name, _default_file_state())

        if not url:
            log.warning("no %s in routing.json — skip", url_key)
            if target.exists():
                result.paths[name] = target
            next_delays.append(GEO_REFRESH)
            continue

        exists = target.exists()
        # Опортунистически чиним права на старых файлах, записанных до
        # того, как мы начали выставлять 0644 в _download(). Без этого
        # xray-сервис под другим пользователем не сможет их прочитать
        # до следующей ПОЛНОЙ перезакачки (через GEO_REFRESH часов).
        if exists:
            try:
                mode = target.stat().st_mode & 0o777
                if mode != 0o644:
                    os.chmod(target, 0o644)
                    log.info("fixed perms on %s: 0o%o → 0o644", target, mode)
            except OSError as exc:
                log.debug("could not chmod %s: %s", target, exc)
        age = (now - target.stat().st_mtime) if exists else float("inf")
        # Валидность текущего файла проверяем ПАРСЕРОМ, а не только
        # по mtime: старая версия кода могла опубликовать битый .dat (до
        # введения валидации перед replace). Такой файл нельзя считать
        # «годным» только потому, что он свежий — иначе восстановление
        # откладывается до GEO_REFRESH.
        is_valid = exists and _file_parses(target)
        if exists and not is_valid:
            log.warning("%s exists but fails validation — forcing re-download",
                        target)
        needs_download = force or not is_valid or age >= GEO_REFRESH

        # Если файл есть, валиден и свежий — просто используем его.
        if not needs_download:
            result.paths[name] = target
            # До следующей плановой проверки осталось GEO_REFRESH - age.
            next_delays.append(max(60.0, GEO_REFRESH - age))
            continue

        # Перед попыткой проверим, не в середине ли мы бэкоффа после
        # недавней неудачи (force обходит это).
        if not force and file_state["failures"] > 0:
            wait = _backoff_seconds(file_state["failures"])
            since_attempt = now - float(file_state["last_attempt"] or 0)
            if since_attempt < wait:
                remaining = wait - since_attempt
                if exists:
                    result.paths[name] = target  # работаем со старой копией
                next_delays.append(remaining)
                log.debug("%s: in backoff, next retry in %.0fs (failures=%d)",
                          name, remaining, file_state["failures"])
                continue

        download_plan.append((name, url, target, file_state))

    if download_plan:
        downloaded = _stage_and_validate_geo(
            download_plan,
            validation_server=validation_server,
            platform_info=platform_info,
            errors=result.errors,
        )
        if downloaded:
            for name, _url, target, file_state in download_plan:
                file_state["last_attempt"] = now
                if name not in downloaded:
                    file_state["failures"] = int(file_state["failures"]) + 1
                    if target.exists():
                        result.paths[name] = target
                    next_delays.append(_backoff_seconds(file_state["failures"]))
                    continue
                size = target.stat().st_size
                log.info("downloaded %s → %s (%d bytes)", name, target, size)
                file_state["last_success"] = now
                file_state["failures"] = 0
                result.paths[name] = target
                result.freshly_downloaded.add(name)
                next_delays.append(GEO_REFRESH)
        else:
            for name, _url, target, file_state in download_plan:
                file_state["last_attempt"] = now
                file_state["failures"] = int(file_state["failures"]) + 1
                if target.exists():
                    result.paths[name] = target
                next_delays.append(_backoff_seconds(file_state["failures"]))

    # Пишем state только если он реально изменился — это типичный случай,
    # когда все файлы свежие/в бэкоффе и в тике ничего не менялось.
    if json.dumps(state, sort_keys=True) != state_before:
        _save_state(state)

    # Следующая проверка — когда истечёт самый короткий из интервалов
    # (чтобы не пропустить retry упавшего файла).
    if next_delays:
        result.next_attempt_in = max(10.0, min(next_delays))
    return result


def load_geo_categories(asset_dir: Path | None = None) -> dict[str, set[str] | None]:
    """Вернуть `{"geosite": {...} | None, "geoip": {...} | None}`.

    - `set[str]` — файл существует и успешно разобран (может быть пустым
      set'ом, если в валидном .dat действительно нет категорий; трактуем
      как «категорий нет»).
    - `None` — файла нет, либо он не читается, либо не парсится. Важно
      отличать этот случай: если вернуть `set()`, вышестоящий код решит,
      что все `geosite:*`/`geoip:*` ссылки невалидны, и вырежет их из
      routing/DNS, сделав живую деградацию конфига из-за битого ассета.
      `None` означает «не знаем» — правила не трогаем.
    """
    out: dict[str, set[str] | None] = {}
    root = asset_dir or GEO_DIR
    for name, _url_key, category in _FILES:
        path = root / name
        if not path.exists():
            out[category] = None
            continue
        try:
            out[category] = _parse_geo_entries(path)
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to parse %s: %s", path, exc)
            out[category] = None
    return out


def geo_categories_all_readable(categories: dict[str, set[str] | None]) -> bool:
    """True, если ВСЕ известные файлы успешно распарсились.

    DEPRECATED для guard-логики: используйте `required_geo_kinds_readable()`
    (учитывает, что часть ассетов может быть не нужна текущему routing.json).
    Оставлено на случай, если где-то потребуется самая строгая проверка.
    """
    return all(v is not None for v in categories.values())


def required_geo_kinds(cfg: dict) -> set[str]:
    """Собрать множество kind'ов (`geosite` / `geoip`), на которые реально
    ссылается текущий routing.json.

    Рекурсивно обходит значения словаря, чтобы покрыть и `DirectIp`,
    `ProxySites`, `BlockIp`, DNS-домены, expectIPs и т.д. без явного
    перечисления полей (иначе при появлении новой секции в Hiddify-конфиге
    мы бы молча её пропустили).
    """
    needed: set[str] = set()

    def scan(v: object) -> None:
        if isinstance(v, str):
            kind, _ = parse_geo_ref(v)
            if kind is not None:
                needed.add(kind)
        elif isinstance(v, list):
            for item in v:
                scan(item)
        elif isinstance(v, dict):
            for item in v.values():
                scan(item)
    scan(cfg)
    return needed


def required_geo_kinds_readable(
    categories: dict[str, set[str] | None],
    cfg: dict,
) -> tuple[bool, list[str]]:
    """True, если каждый kind, на который ссылается routing.json,
    распарсился. Возвращает также список нечитаемых *нужных* kind'ов —
    удобно логировать именно это, а не весь набор.

    Частный случай: routing.json без geo-ссылок → ok=True, даже если обе
    `.dat` отсутствуют (это валидная конфигурация, xray без geo-правил
    отработает). Зеркально — при наличии geosite:* и отсутствии geoip:*
    достаточно валидного geosite.dat.
    """
    required = required_geo_kinds(cfg)
    missing = [k for k in required if categories.get(k) is None]
    return (not missing), missing


def _file_parses(path: Path) -> bool:
    """Быстрая проверка: файл на диске — валидный v2ray-geodata с ≥1 записью.

    Используется для обнаружения уже опубликованного битого .dat (напр.
    файл мог попасть на диск ещё до введения валидации перед replace).
    """
    try:
        entries = _parse_geo_entries(path)
    except Exception:  # noqa: BLE001
        return False
    return bool(entries)


def _stage_and_validate_geo(
    download_plan: list[tuple[str, str, Path, dict]],
    *,
    validation_server,
    platform_info,
    errors: dict[str, str],
) -> set[str]:
    """Download planned geo files into staging and publish only after checks."""
    planned_names = {name for name, _url, _target, _state in download_plan}
    staging_path = Path(tempfile.mkdtemp(dir=str(GEO_DIR), prefix=".geo-staging."))
    try:
        # Stage current live files for the kinds that are not being refreshed.
        # The staged directory must be a complete XRAY_LOCATION_ASSET candidate,
        # otherwise xray -test would validate a state that can never become live.
        for name, _url_key, _category in _FILES:
            if name in planned_names:
                continue
            live = GEO_DIR / name
            if live.exists():
                shutil.copy2(live, staging_path / name)
                os.chmod(staging_path / name, 0o644)

        downloaded: set[str] = set()
        for name, url, _target, _state in download_plan:
            try:
                _download(url, staging_path / name)
            except Exception as exc:  # noqa: BLE001
                errors[name] = str(exc)
                log.warning("download %s into staging failed: %s", name, exc)
                return set()
            downloaded.add(name)

        categories = load_geo_categories(staging_path)
        from .routing import validate_geo_categories_for_routing
        missing = validate_geo_categories_for_routing(categories)
        if missing:
            summary = ", ".join(f"{group}:{entry}" for group, entry in missing[:10])
            tail = f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""
            errors["geo-set"] = (
                "staged geo assets do not cover routing references: "
                f"{summary}{tail}"
            )
            log.warning("%s", errors["geo-set"])
            return set()

        if validation_server is not None:
            from .xray_config import build_xray_config_text
            from .xray_control import validate_config_text

            cfg_text = build_xray_config_text(
                validation_server,
                categories=categories,
            )
            ok, output = validate_config_text(
                cfg_text,
                platform_info,
                asset_dir=staging_path,
            )
            if not ok:
                last = output.strip().splitlines()[-1] if output.strip() else "unknown error"
                errors["geo-set"] = f"xray -test failed with staged geo assets: {last}"
                log.warning("%s", errors["geo-set"])
                return set()
        else:
            errors["geo-set"] = (
                "staged geo assets passed category validation, but no server "
                "is available for xray -test"
            )
            log.warning("%s", errors["geo-set"])
            return set()

        backups: dict[Path, Path | None] = {}
        for name, _url, target, _state in download_plan:
            if target.exists():
                backup = staging_path / f"{name}.live-backup"
                shutil.copy2(target, backup)
                backups[target] = backup
            else:
                backups[target] = None

        replaced: list[Path] = []
        try:
            for name, _url, target, _state in download_plan:
                staged = staging_path / name
                os.chmod(staged, 0o644)
                os.replace(staged, target)
                replaced.append(target)
        except OSError as exc:
            log.error("geo publish failed after staging validation: %s", exc)
            for target in reversed(replaced):
                backup = backups.get(target)
                try:
                    if backup is not None and backup.exists():
                        os.replace(backup, target)
                    else:
                        target.unlink(missing_ok=True)
                except OSError as rollback_exc:
                    # A partial rollback is possible only after an FS/I/O
                    # failure. Later live-config writes are still gated by
                    # geo category validation and xray -test, so mixed live
                    # geo files must not be blindly published into config.
                    log.error("geo rollback failed for %s: %s", target, rollback_exc)
            errors["geo-set"] = f"failed to publish staged geo assets: {exc}"
            return set()
        return downloaded
    finally:
        shutil.rmtree(staging_path, ignore_errors=True)


# ---------- download ----------

def _download(url: str, target: Path) -> None:
    """Скачать url, проверить полноту и сделать atomic rename.

    Сначала пробуем прямой доступ. Если CDN GitHub/release-assets недоступен
    напрямую, повторяем через локальный HTTP inbound xray. Env-proxy всё равно
    игнорируются: маршрут должен быть явным и предсказуемым.
    """
    failures: list[str] = []
    for route in _download_routes():
        try:
            _download_via_route(url, target, route)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{route.name}: {exc}")
            log.warning("download via %s failed: %s", route.name, exc)
            continue
        if failures:
            log.info("downloaded %s via %s after fallback (%s)",
                     target.name, route.name, "; ".join(failures))
        return
    raise IOError("; ".join(failures) or "all download routes failed")


def _download_routes() -> tuple[_DownloadRoute, ...]:
    proxy_url = f"http://{HTTP_HOST}:{HTTP_PORT}"
    return (
        _DownloadRoute("direct"),
        _DownloadRoute("xray-http", {"http": proxy_url, "https": proxy_url}),
    )


def _download_via_route(url: str, target: Path, route: _DownloadRoute) -> None:
    """Скачать url через конкретный маршрут в target.part и опубликовать."""
    # Отдельный tmp-файл в той же директории — критично для os.replace()
    # (atomic rename работает только в рамках одной FS).
    fd, tmp_path = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=target.name + ".",
        suffix=".part",
    )
    tmp = Path(tmp_path)
    # Закроем fd сразу — будем работать через Path.open(), чтобы использовать
    # стандартный буферизованный writer.
    os.close(fd)

    downloaded = 0
    expected: int | None = None
    try:
        # trust_env=False: не давать HTTP_PROXY из шелла менять маршрут.
        # Context manager закрывает connection pool по выходу.
        with requests.Session() as session:
            session.trust_env = False
            session.headers.update({"User-Agent": USER_AGENT})
            with session.get(
                url,
                timeout=_DOWNLOAD_TIMEOUT,
                stream=True,
                allow_redirects=True,
                proxies=route.proxies,
            ) as resp:
                resp.raise_for_status()
                cl = resp.headers.get("Content-Length")
                if cl and cl.isdigit():
                    expected = int(cl)
                # Пишем большими чанками, считаем байты вручную — так мы
                # обнаружим обрыв соединения по несовпадению с Content-Length.
                with tmp.open("wb") as fh:
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        downloaded += len(chunk)

        if downloaded == 0:
            raise IOError("downloaded 0 bytes")
        if expected is not None and downloaded != expected:
            raise IOError(
                f"incomplete download: got {downloaded} of {expected} bytes"
            )

        # Санити по размеру — ловит HTML-страницу ошибки от CDN, которую
        # отдают с HTTP 200 вместо .dat (типичный случай для зеркал).
        if downloaded < 1024:
            raise IOError(f"suspiciously small download ({downloaded} bytes)")

        # ВАЛИДАЦИЯ ФОРМАТА до публикации. Даже если Content-Length совпал,
        # тело может быть битым/HTML — тогда protobuf-парсер либо упадёт,
        # либо не найдёт ни одной записи верхнего уровня. Оба случая
        # означают: НЕ заменять рабочий файл.
        try:
            entries = _parse_geo_entries(tmp)
        except Exception as exc:  # noqa: BLE001
            raise IOError(f"downloaded file is not a valid v2ray geodata: {exc}") from exc
        if not entries:
            raise IOError("downloaded file contains no geodata entries "
                          "(likely HTML error page or truncated)")

        # Выставляем 0644 ДО replace: tempfile.mkstemp() создаёт .part с
        # безопасными правами 0600 (владелец), а `os.replace` сохраняет
        # их при переименовании. В итоге xray-сервис под отдельным
        # пользователем (на Linux обычно `nobody`/`xray`) не может
        # прочитать файл — xray молча стартует со встроенными geo-данными
        # либо падает. Содержимое geosite.dat/geoip.dat не секретно,
        # стандартный набор 0644 корректен для shared-ассета.
        os.chmod(tmp, 0o644)
        # Успех — атомарно заменяем боевой файл.
        os.replace(tmp, target)
    except BaseException:
        # Никогда не оставляем недокачанный .part на диске.
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


# ---------- state ----------

def _default_file_state() -> dict:
    return {"last_success": 0.0, "last_attempt": 0.0, "failures": 0}


def _load_state() -> dict:
    if not _GEO_STATE_FILE.exists():
        return {}
    try:
        data = json.loads(_GEO_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        log.warning("geo state file corrupt, resetting")
    return {}


def _save_state(state: dict) -> None:
    try:
        secure_write(_GEO_STATE_FILE, json.dumps(state, indent=2))
    except OSError as exc:
        log.warning("failed to persist geo state: %s", exc)


def _backoff_seconds(failures: int) -> float:
    """Вернуть задержку перед следующей попыткой после `failures` неудач.

    failures=1 → первый элемент; failures >= len(schedule) → последний.
    """
    if failures <= 0:
        return 0.0
    idx = min(failures - 1, len(GEO_RETRY_SCHEDULE) - 1)
    return float(GEO_RETRY_SCHEDULE[idx])


# ---------- .dat parser ----------

def _parse_geo_entries(path: Path) -> set[str]:
    """Извлечь country_code каждой записи верхнего уровня из v2ray-geodata.

    Формат (protobuf):
        GeoSiteList { repeated GeoSite entry = 1; }
        GeoSite     { string country_code = 1; repeated Domain domain = 2; }
        (то же самое с заменой Site↔IP для geoip.dat)

    Нам нужен только список country_code, чтобы проверить наличие
    конкретной категории (напр. "category-ru"). Полноценный protobuf
    не нужен — обходим на голых varint'ах.
    """
    data = path.read_bytes()
    codes: set[str] = set()
    i = 0
    n = len(data)
    while i < n:
        tag, i = _read_varint(data, i)
        field_num = tag >> 3
        wire = tag & 0x7
        # Верхний уровень v2ray-geodata — ровно repeated message field=1.
        # Любое отклонение трактуем как «файл битый/не тот формат», чтобы
        # не опубликовать мусор как валидный asset.
        if field_num != 1 or wire != 2:
            raise ValueError(
                f"unexpected top-level tag field={field_num} wire={wire}"
            )
        length, i = _read_varint(data, i)
        entry_end = i + length
        if entry_end > n:
            raise ValueError("truncated entry (length exceeds file)")
        code = _extract_country_code(data, i, entry_end)
        if code:
            codes.add(code.lower())
        i = entry_end
    return codes


def _extract_country_code(data: bytes, start: int, end: int) -> str:
    """Внутри одной записи GeoSite/GeoIP найти field 1 (country_code)."""
    i = start
    while i < end:
        tag, i = _read_varint(data, i)
        field_num = tag >> 3
        wire = tag & 0x7
        if wire == 2:
            length, i = _read_varint(data, i)
            if field_num == 1:
                return data[i:i + length].decode("utf-8", errors="replace")
            i += length
        elif wire == 0:
            _, i = _read_varint(data, i)
        elif wire == 1:
            i += 8
        elif wire == 5:
            i += 4
        else:
            break
    return ""


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


# Утилита для чтения извне: приводит "geosite:ru" / "geoip:category-ru" к
# (kind, code). Для не-гео записей возвращает (None, None).
def parse_geo_ref(value: str) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, None
    for kind in ("geosite", "geoip"):
        prefix = f"{kind}:"
        if value.lower().startswith(prefix):
            # Категория может содержать "@tag" (xray). Для проверки
            # наличия в .dat значим только левый кусок до '@'.
            code = value[len(prefix):].split("@", 1)[0]
            return kind, code.lower()
    return None, None


def strip_missing_geo(
    items: Iterable[str] | None,
    categories: dict[str, set[str] | None],
) -> tuple[list[str], list[str]]:
    """Из списка удалить geosite:/geoip:-ссылки на отсутствующие категории.

    Возвращает (kept, removed). Не-гео значения (CIDR, домены) всегда
    остаются в kept. Если соответствующий .dat не удалось прочитать
    (categories[kind] is None) — сохраняем ссылку как есть: мы не знаем,
    валидна она или нет, и лучше отдать xray старые правила, чем выкинуть
    их из-за временной проблемы с ассетом.
    """
    if not items:
        return [], []
    kept: list[str] = []
    removed: list[str] = []
    for item in items:
        kind, code = parse_geo_ref(item)
        if kind is None:
            kept.append(item)
            continue
        available = categories.get(kind)
        if available is None:
            # Ассет не прочитан — не можем судить; оставляем как есть.
            kept.append(item)
            continue
        if code and code in available:
            kept.append(item)
        else:
            removed.append(item)
    return kept, removed
