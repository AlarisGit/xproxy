"""Telegram delivery of verified status summaries only."""
from __future__ import annotations

import socket
from html import escape

import requests

from .env_config import get as env_get
from .logger import get_logger
from .settings import SOCKS_HOST, SOCKS_PORT, USER_AGENT

log = get_logger("xproxy.notifier")
_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def is_configured() -> bool:
    return bool(env_get("TELEGRAM_BOT_TOKEN")) and bool(env_get("TELEGRAM_ALERTS_USER_ID"))


def notify(text: str, *, urgent: bool = False, blocking: bool = False,
           topic: str | None = None) -> None:
    """Retain event call sites as local logs; events are never sent to Telegram."""
    (log.warning if urgent else log.info)("event%s: %s", f" [{topic}]" if topic else "", text)


def send_summary(text: str) -> bool:
    """Send once through the verified local proxy; no queue or direct fallback."""
    token = env_get("TELEGRAM_BOT_TOKEN") or ""
    chat_id = env_get("TELEGRAM_ALERTS_USER_ID") or ""
    if not token or not chat_id:
        log.debug("Telegram summary skipped: credentials absent")
        return False
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    socks = f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
    session.proxies.update({"http": socks, "https": socks})
    try:
        hostname = socket.gethostname().split(".", 1)[0]
        response = session.post(
            _TELEGRAM_API.format(token=token),
            data={"chat_id": chat_id, "text": f"<b>{escape(hostname)}</b>\n{text}",
                  "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=6,
        )
        if response.status_code == 200:
            log.info("Telegram summary sent")
            return True
        log.warning("Telegram summary failed: HTTP %d", response.status_code)
    except requests.RequestException as exc:
        # Never include the request URL: it contains the bot token.
        log.warning("Telegram summary failed: %s", type(exc).__name__)
    finally:
        session.close()
    return False
