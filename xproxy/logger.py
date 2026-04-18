"""Логирование: stderr + (опционально) ротируемый /var/log/xproxy/xproxy.log.

ВАЖНО про файловый лог:
  - Файловый хендлер активируется ТОЛЬКО когда явно вызван
    `setup_logging(with_file=True)`. Делает это только `main.py`.
  - `get_logger()` без явной настройки цепляет лишь stderr-хендлер (lazy).
    Это защищает production-лог от случайных записей из одноразовых
    debug/test скриптов, которые просто импортируют модули xproxy.

Если директория /var/log/xproxy/ не существует или недоступна на запись —
файловый хендлер тихо пропускается, и мы остаёмся с stderr-логом.
Создать директорию и выдать права нужно один раз при установке (см. deploy/install.sh).
"""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from .settings import LOG_BACKUP_COUNT, LOG_DIR, LOG_FILE, LOG_MAX_BYTES

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False
_file_handler_attached = False


def setup_logging(level: int = logging.INFO, *, with_file: bool = False) -> None:
    """Настроить root logger.

    - `with_file=False` (по умолчанию) — только stderr. Безопасно для
      импорта из скриптов/тестов: production-лог не загрязняется.
    - `with_file=True` — дополнительно цепляет RotatingFileHandler.
      Должен вызываться только из main.py (реальный запуск демона).
    """
    global _configured, _file_handler_attached

    root = logging.getLogger()

    if not _configured:
        root.setLevel(level)
        for h in list(root.handlers):
            root.removeHandler(h)
        fmt = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
        stream = logging.StreamHandler(stream=sys.stderr)
        stream.setFormatter(fmt)
        root.addHandler(stream)
        _configured = True
    else:
        # Уровень может быть уточнён повторным вызовом (main.py с -v).
        root.setLevel(level)

    if with_file and not _file_handler_attached:
        fmt = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
        file_handler = _make_file_handler(fmt)
        if file_handler is not None:
            root.addHandler(file_handler)
            _file_handler_attached = True
        else:
            logging.getLogger("xproxy.logger").warning(
                "file logging disabled: %s is not writable "
                "(run deploy/install.sh to create it)", LOG_DIR,
            )


def _make_file_handler(fmt: logging.Formatter) -> RotatingFileHandler | None:
    try:
        if not LOG_DIR.exists():
            # Пытаемся создать без sudo — сработает, только если /var/log/xproxy
            # уже принадлежит текущему пользователю (или выставлены нужные права).
            LOG_DIR.mkdir(parents=True, exist_ok=True)
        if not os.access(LOG_DIR, os.W_OK):
            return None
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(fmt)
        return handler
    except OSError:
        return None


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)
