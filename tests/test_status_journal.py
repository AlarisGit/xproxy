from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from xproxy import daemon, notifier
from xproxy.status_journal import Status, StatusJournal, format_summary


class StatusJournalTests(unittest.TestCase):
    def test_exact_timestamps_and_restart_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "states.sqlite3"
            journal = StatusJournal(path)
            journal.mark_start()
            online = Status("UP", "UP", "UP primary", "READY secondary", "IDLE -")
            self.assertTrue(journal.record(online, ts=1234.125))
            self.assertFalse(journal.record(online, ts=1235.5))
            self.assertTrue(journal.recovery_pending())
            journal.mark_recovery_sent()
            journal.mark_daily_sent("2026-09-24")
            journal.close()
            journal = StatusJournal(path)
            self.assertTrue(journal.daily_sent("2026-09-24"))
            self.assertFalse(journal.recovery_pending())
            journal.mark_start()
            journal.record(online, ts=1236.25)
            self.assertTrue(journal.recovery_pending())
            journal.close()
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT ts FROM states WHERE ts=1234.125").fetchone()[0], 1234.125)
                self.assertEqual(db.execute("SELECT count(*) FROM states").fetchone()[0], 4)

    def test_summary_escapes_server_names(self):
        text = format_summary(Status("UP", "UP", "UP <primary>", "READY secondary", "IDLE"),
                              reason="Proxy восстановлен", ts=100)
        self.assertIn("<pre>", text)
        self.assertIn("&lt;primary&gt;", text)

    def test_daily_summary_waits_until_offset_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = StatusJournal(Path(tmp) / "states.sqlite3")
            journal.record(Status("UP", "UP", "UP primary", "READY secondary", "IDLE"))
            d = daemon.Daemon()
            d._journal = journal
            d._heartbeat_minute_offset = 30
            at_1229 = time.struct_time((2026, 9, 24, 12, 29, 0, 3, 267, -1))
            at_1230 = time.struct_time((2026, 9, 24, 12, 30, 0, 3, 267, -1))
            with mock.patch.object(daemon, "tg_configured", return_value=True), \
                    mock.patch.object(daemon, "send_summary", return_value=True) as send:
                with mock.patch.object(daemon.time, "localtime", return_value=at_1229):
                    d.tick_heartbeat()
                send.assert_not_called()
                with mock.patch.object(daemon.time, "localtime", return_value=at_1230):
                    d.tick_heartbeat()
                    d.tick_heartbeat()
                send.assert_called_once()
            journal.close()
            reopened = StatusJournal(Path(tmp) / "states.sqlite3")
            self.assertTrue(reopened.daily_sent("2026-09-24"))
            reopened.close()
            d.emergency.manager._pool.shutdown(wait=False)

    def test_summary_uses_only_socks(self):
        response = mock.Mock(status_code=200)
        session = mock.Mock()
        session.post.return_value = response
        with mock.patch.object(notifier, "env_get", side_effect=lambda key: "token" if key == "TELEGRAM_BOT_TOKEN" else "42"), \
                mock.patch.object(notifier.requests, "Session", return_value=session):
            self.assertTrue(notifier.send_summary("<pre>status</pre>"))
        self.assertFalse(session.trust_env)
        self.assertIn("socks5h://", session.proxies.update.call_args.args[0]["https"])
        self.assertEqual(session.post.call_count, 1)


if __name__ == "__main__":
    unittest.main()
