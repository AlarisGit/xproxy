"""A process-wide writer lease, supported by both macOS and Linux."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path

from .fs_utils import secure_mkdir
from .settings import STATE_DIR


class InstanceLock:
    def __init__(self, path: Path = STATE_DIR / "daemon.lock") -> None:
        self.path = path
        self.fd: int | None = None

    def __enter__(self):
        secure_mkdir(self.path.parent)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError("another xproxy instance owns this installation") from None
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
