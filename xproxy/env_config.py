"""Парсер локального конфиг-файла .env (формат key=value).

Правила формата:
- Одна строка — один параметр `KEY=VALUE`.
- Текст от `#` до конца строки — комментарий.
- Пустые строки игнорируются.
- Ведущие/хвостовые пробелы у ключа и значения обрезаются.
- Значение может быть обёрнуто в одинарные или двойные кавычки (они снимаются).

Значения НИКОГДА не логируются — это секреты.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from .logger import get_logger

log = get_logger("xproxy.env_config")


class EnvConfigError(RuntimeError):
    pass


_CACHE: dict[Path, Dict[str, str]] = {}


def load_env(path: Path) -> Dict[str, str]:
    """Считать .env. Результат кэшируется по пути. Секреты в лог не попадают."""
    if path in _CACHE:
        return _CACHE[path]
    if not path.exists():
        raise EnvConfigError(f"env file not found: {path}")

    result: Dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        hash_idx = raw.find("#")
        line = raw if hash_idx < 0 else raw[:hash_idx]
        line = line.strip()
        if not line:
            continue
        if "=" not in line:
            log.warning("%s:%d: skipping malformed line (no '=')", path, lineno)
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if not key:
            log.warning("%s:%d: empty key", path, lineno)
            continue
        result[key] = value

    _CACHE[path] = result
    log.debug("loaded %d keys from %s", len(result), path)
    return result


def get(key: str, default: Optional[str] = None) -> Optional[str]:
    """Достать значение по ключу. Возвращает default, если нет файла или ключа."""
    from .settings import ENV_FILE  # lazy чтобы избежать циклов
    try:
        return load_env(ENV_FILE).get(key, default)
    except EnvConfigError:
        return default


def require(key: str) -> str:
    """Достать значение; бросает EnvConfigError, если нет или пусто."""
    value = get(key)
    if not value:
        raise EnvConfigError(f"required env key missing or empty: {key}")
    return value


def reset_cache() -> None:
    """Для тестов: сбросить кэш."""
    _CACHE.clear()
