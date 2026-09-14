"""Run the suite in an isolated installation, without services or network I/O.

Usage: .venv/bin/python -B tests/run.py
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RUNNER = """
import logging
import sys
import unittest

logging.disable(logging.CRITICAL)
def guard(event, args):
    if event in ('socket.connect', 'socket.getaddrinfo', 'subprocess.Popen'):
        raise RuntimeError('Unmocked external action: ' + event)
sys.addaudithook(guard)
result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover('tests'))
sys.exit(not result.wasSuccessful())
"""


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xproxy-tests-") as tmp:
        for name in ("xproxy", "tests", "conf"):
            shutil.copytree(ROOT / name, Path(tmp) / name,
                            ignore=shutil.ignore_patterns("__pycache__", "tunnels.json", "sync.json"))
        shutil.copy2(ROOT / "main.py", Path(tmp) / "main.py")
        result = subprocess.run([sys.executable, "-B", "-c", RUNNER], cwd=tmp,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, timeout=120)
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
