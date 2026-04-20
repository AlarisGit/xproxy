"""Утилиты для безопасной работы с файловой системой.

state/ содержит чувствительные данные (UUID подписки, параметры серверов),
поэтому директория и файлы должны быть доступны только владельцу.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def secure_mkdir(path: Path) -> None:
    """Создать директорию с режимом 0700 (только владелец)."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def secure_write(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Записать файл с режимом 0600 (только владелец).

    Атомарная запись через tempfile + rename: при крахе процесса
    не останется наполовину записанного файла. Временный файл создаётся
    с уникальным именем (tempfile), чтобы параллельные записи в один
    target не конфликтовали за один и тот же *.tmp.
    """
    secure_mkdir(path.parent)
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=path.name + ".",
        suffix=".tmp",
    )
    try:
        os.write(fd, content.encode(encoding))
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, str(path))