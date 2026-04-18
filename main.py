"""xproxy — watchdog/updater поверх xray.

Режимы запуска:
    python main.py --daemon     # долгоживущий цикл (основной режим)
    python main.py --once       # одна итерация обновления + проверки
    python main.py --dry-run    # ничего не пишет/не рестартит, только диагностика
"""
from __future__ import annotations

import argparse
import logging
import sys

from xproxy.daemon import Daemon
from xproxy.logger import get_logger, setup_logging
from xproxy.platform_utils import detect_platform


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="xproxy", description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--daemon", action="store_true", help="запустить основной цикл")
    mode.add_argument("--once", action="store_true", help="одна итерация и выход")
    p.add_argument("--dry-run", action="store_true",
                   help="не писать xray-конфиг и не рестартить сервис")
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG-логирование")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(
        level=logging.DEBUG if args.verbose else logging.INFO,
        with_file=True,
    )
    log = get_logger("xproxy.main")

    info = detect_platform()
    log.info("platform=%s xray_config=%s restart_cmd=%s",
             info.name, info.xray_config, " ".join(info.restart_cmd))

    daemon = Daemon(dry_run=args.dry_run, platform=info)

    if args.daemon:
        daemon.run_forever()
    elif args.once:
        daemon.run_once()
    else:
        log.info("no mode selected; run with --daemon or --once (see --help)")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())