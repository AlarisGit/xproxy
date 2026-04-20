"""Утилиты для безопасной работы с файловой системой.

state/ содержит чувствительные данные (UUID подписки, параметры серверов),
поэтому директория и файлы должны быть доступны только владельцу.
"""
from __future__ import annotations

import os
from pathlib import Path


def secure_mkdir(path: Path) -> None:
    """Создать директорию с режимом 0700 (только владелец)."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def secure_write(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Записать файл с режимом 0600 (только владелец).

    Атомарная запись через временный файл + rename: при крахе процесса
    не останется наполовину записанного файла. Переименование на той же
    ФС атомарно в POSIX.
    """
    secure_mkdir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode(encoding))
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))