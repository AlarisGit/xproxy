from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import Future
from pathlib import Path
from unittest import mock

from xproxy import daemon, power
from xproxy.connectivity import Connectivity
from xproxy.platform_utils import PlatformInfo
from xproxy.servers import Server
from xproxy.status_journal import Event, Route, Status, StatusJournal, format_summary
from xproxy.tunnels import parse_tunnels, TunnelConfigError, TunnelIntent, TunnelManager

UP = Status('UP', 'UP', 'UP Germany', 'READY Finland', 'READY fr')
PROXY_DOWN = Status('UP', 'DOWN', 'DOWN Germany', 'READY Finland', 'READY fr')
OFFLINE = Status('DOWN', 'N/A', 'N/A', 'N/A', 'N/A')
VLESS = Route('VLESS', 'Germany', 'Finland')
SSH = Route('SSH', 'France · fr', 'Finland', (260, 600))


class EventJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'status.sqlite3'
        self.j = StatusJournal(self.path)
        self.addCleanup(self.j.close)
        self.j.mark_start()
        self.j.record(UP, route=VLESS)
        self.j.mark_recovery_sent()

    def kinds(self):
        return [e.kind for e in reversed(self.j.events(100))]

    def test_unconfirmed_proxy_failure_does_not_create_recovery(self):
        self.j.record(PROXY_DOWN, route=VLESS, proxy_confirmed=False)
        self.j.record(UP, route=VLESS)
        self.assertEqual(self.kinds(), ['start', 'internet_up', 'proxy_up'])
        self.assertFalse(self.j.recovery_pending())

    def test_confirmed_failure_and_recovery_have_observation_timestamps(self):
        self.j.record(PROXY_DOWN, route=VLESS, ts=100)
        self.j.record(PROXY_DOWN, route=VLESS, ts=101)
        self.j.record(UP, route=SSH, ts=110)
        events = self.j.events()
        self.assertEqual([(e.kind, e.ts) for e in events[:2]], [('proxy_up', 110), ('proxy_down', 100)])
        self.assertTrue(self.j.recovery_pending())
        self.assertEqual(self.j.summary_reason(), 'Прокси восстановлен')

    def test_offline_suppresses_proxy_outage_and_confirms_twice(self):
        self.j.record(OFFLINE, ts=100)
        self.assertNotIn('internet_down', self.kinds())
        self.j.record(OFFLINE, ts=105)
        self.j.record(OFFLINE, ts=110)
        self.assertEqual(self.kinds().count('internet_down'), 1)
        self.assertNotIn('proxy_down', self.kinds())
        self.j.record(UP, route=VLESS, ts=115)
        self.assertEqual(self.kinds()[-2:], ['internet_up', 'proxy_up'])
        self.assertTrue(self.j.recovery_pending())

    def test_single_network_failure_is_silent(self):
        self.j.record(OFFLINE)
        self.j.record(UP, route=VLESS)
        self.assertEqual(self.kinds(), ['start', 'internet_up', 'proxy_up'])
        self.assertFalse(self.j.recovery_pending())

    def test_standby_changes_are_not_events_and_channel_changes_are(self):
        stamp = self.j.events()[0].ts
        self.j.record(Status('UP', 'UP', 'UP Germany', 'UNAVAILABLE -', 'READY fr'),
                      route=Route('VLESS', 'Germany'))
        self.assertEqual(self.j.events()[0].ts, stamp)
        self.j.record(UP, route=SSH)
        self.assertEqual(self.j.events()[0].kind, 'route_changed')
        self.assertFalse(self.j.recovery_pending())

    def test_country_edit_is_not_a_route_change(self):
        self.j.record(UP, route=Route('SSH', 'fr', key='ssh:host:22'))
        before = self.j.events()
        self.j.record(UP, route=Route('SSH', 'France · fr', key='ssh:host:22'))
        self.assertEqual(self.j.events(), before)

    def test_normal_sleep_is_not_outage_or_notification(self):
        self.j.lifecycle('sleep', ts=100)
        self.j.lifecycle('wake', ts=500)
        self.j.record(OFFLINE, ts=501, allow_failure=False)
        self.j.record(OFFLINE, ts=503, allow_failure=False)
        self.j.record(UP, route=VLESS, ts=505)
        self.assertEqual(self.kinds()[-3:], ['sleep', 'wake', 'wake_ok'])
        self.assertFalse(self.j.recovery_pending())

    def test_failure_after_wake_grace_is_real(self):
        self.j.lifecycle('sleep')
        self.j.lifecycle('wake')
        self.j.record(OFFLINE, allow_failure=False)
        self.j.record(OFFLINE, allow_failure=False)
        self.j.record(OFFLINE, allow_failure=True)
        self.j.record(UP, route=SSH)
        self.assertEqual(self.kinds()[-3:], ['internet_down', 'internet_up', 'proxy_up'])
        self.assertTrue(self.j.recovery_pending())

    def test_sleep_does_not_erase_preexisting_outage(self):
        self.j.record(PROXY_DOWN)
        self.j.lifecycle('sleep')
        self.j.lifecycle('wake')
        self.j.record(UP, route=SSH)
        self.assertEqual(self.j.events()[0].kind, 'proxy_up')
        self.assertTrue(self.j.recovery_pending())

    def test_clean_restart_and_crash_never_invent_failure(self):
        self.j.lifecycle('stop')
        self.j.mark_start()
        self.assertNotIn('gap', self.kinds())
        self.j.record(UP)
        self.assertEqual(self.j.summary_reason(), 'Запуск xproxy')
        self.j.mark_start()  # no clean stop: observations were interrupted
        self.assertEqual(self.kinds()[-2:], ['gap', 'start'])
        self.assertNotIn('proxy_down', self.kinds())
        self.assertNotIn('internet_down', self.kinds())

    def test_latest_ten_survive_reopen_and_use_sequence_order(self):
        for index in range(8):
            self.j.record(PROXY_DOWN, ts=100-index)
            self.j.record(UP, route=VLESS, ts=200-index)
        expected = self.j.events()
        self.assertEqual(len(expected), 10)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('select count(*) from events').fetchone()[0], 19)
        reopened = StatusJournal(self.path)
        try:
            self.assertEqual(reopened.events(), expected)
        finally:
            reopened.close()

    def test_existing_database_is_migrated_without_reinterpreting_old_rows(self):
        path = Path(self.tmp.name) / 'old.sqlite3'
        with sqlite3.connect(path) as db:
            db.execute('create table states (ts real, direct text, proxy text, vless_primary text, vless_secondary text, ssh text)')
            db.execute("insert into states values (100,'DOWN','DOWN','N/A','N/A','N/A')")
            db.execute('create table meta (key text primary key,value text)')
            db.execute("insert into meta values ('daily_sent','2026-10-04')")
        j = StatusJournal(path)
        try:
            self.assertEqual(j.events(), [])
            self.assertTrue(j.daily_sent('2026-10-04'))
            j.mark_start()
            j.record(UP)
            self.assertNotIn('proxy_down', [e.kind for e in j.events()])
        finally:
            j.close()

    def test_summary_route_history_html_and_limit(self):
        events = [Event(i, i, 'proxy_up', f'event {i} <server>') for i in range(20, 0, -1)]
        text = format_summary(UP, reason='Сводка', route=SSH, events=events, ts=1)
        self.assertIn('Канал: SSH · France · fr', text)
        self.assertIn('Standby VLESS: Finland', text)
        self.assertIn('4:20 из 10:00', text)
        self.assertIn('&lt;server&gt;', text)
        self.assertEqual(text.count('&lt;server&gt;'), 10)
        self.assertNotIn('Интернет доступен', text)
        self.assertNotIn('VLESS primary', text)
        self.assertNotIn('Устойчивость', format_summary(UP, reason='Сводка', route=VLESS))


class PowerTests(unittest.TestCase):
    def make_daemon(self, platform_name='macos'):
        d = daemon.Daemon(platform=PlatformInfo(platform_name, Path('/unused/xray.json'), [], False))
        self.addCleanup(lambda: d.emergency.manager._pool.shutdown(wait=False))
        return d

    def test_linux_does_not_load_apple_frameworks(self):
        monitor = power.PowerMonitor('linux', mock.Mock())
        with mock.patch.object(power.C, 'CDLL') as load:
            monitor.start()
            monitor.close()
        load.assert_not_called()
        self.assertIsNone(monitor._thread)

    def test_native_notifications_acknowledge_and_do_not_treat_query_as_sleep(self):
        callback, ack = mock.Mock(), mock.Mock()
        monitor = power.PowerMonitor('macos', callback)
        monitor._handle(power.CAN_SLEEP, 1, ack)
        callback.assert_not_called()
        monitor._handle(power.WILL_SLEEP, 2, ack)
        monitor._handle(power.HAS_POWERED_ON, 3, ack)
        self.assertEqual(callback.call_args_list, [mock.call('sleep'), mock.call('wake')])
        self.assertEqual(ack.call_args_list, [mock.call(1), mock.call(2)])
        callback.side_effect = RuntimeError('test')
        monitor._handle(power.WILL_SLEEP, 4, ack)
        ack.assert_called_with(4)

    def test_sleep_invalidates_and_prevents_late_probe_publication(self):
        network = Connectivity()
        old = network.update(True).generation
        network.suspend()
        self.assertFalse(network.update(True).online)
        network.resume()
        self.assertFalse(network.update(True, expected_generation=old).online)
        self.assertTrue(network.update(True).online)

    def test_sleep_stops_checks_and_wake_discards_recovery_evidence(self):
        d = self.make_daemon()
        d.network.update(True)
        d._reserves['old'] = object()
        d._health_samples.append(False)
        d._on_power_event('sleep')
        self.assertFalse(d.network.online())
        self.assertFalse(d.emergency.intent().online)
        with mock.patch.object(daemon, 'internet_alive') as internet:
            d.tick()
        internet.assert_not_called()
        self.assertFalse(d._reserves)
        self.assertFalse(d._health_samples)
        d._on_power_event('wake')
        d._drain_power_events()
        self.assertFalse(d.network.suspended())
        self.assertFalse(d.network.online())
        self.assertGreater(d._resume_grace_until, time.monotonic())

    def test_new_sleep_is_not_overridden_by_queued_wake(self):
        d = self.make_daemon()
        for event in ('sleep', 'wake', 'sleep'):
            d._on_power_event(event)
        d._drain_power_events()
        self.assertTrue(d.network.suspended())

    def test_sleep_during_network_probe_discards_result(self):
        d = self.make_daemon()
        def probe():
            d._on_power_event('sleep')
            return True
        with mock.patch.object(daemon, 'internet_alive', side_effect=probe), \
             mock.patch.object(d, 'tick_health') as health:
            d.tick()
        health.assert_not_called()
        self.assertFalse(d.network.online())

    def test_summary_is_suppressed_while_sleeping(self):
        d = self.make_daemon()
        d._on_power_event('sleep')
        with mock.patch.object(daemon, 'send_summary') as send:
            self.assertFalse(d._send_status_summary(UP, 'test'))
        send.assert_not_called()

    def test_old_ssh_readiness_cannot_survive_network_generation(self):
        request = [TunnelIntent(True, True, True, generation=1)]
        manager = TunnelManager(lambda: request[0], lambda: True, mock.Mock())
        self.addCleanup(lambda: manager._pool.shutdown(wait=False))
        manager._publish('READY', ok=True, generation=1)
        self.assertTrue(manager.snapshot().ready)
        request[0] = TunnelIntent(True, True, True, generation=2)
        self.assertFalse(manager.snapshot().ready)

    def test_ssh_probe_result_after_sleep_and_wake_is_rejected(self):
        request = [TunnelIntent(True, True, True, generation=1)]
        manager = TunnelManager(lambda: request[0], lambda: True, mock.Mock())
        self.addCleanup(lambda: manager._pool.shutdown(wait=False))
        def finish_after_wake(*_args):
            request[0] = TunnelIntent(True, True, True, generation=3)
            future = Future()
            future.set_result(True)
            return future
        with mock.patch.object(manager._pool, 'submit', side_effect=finish_after_wake), \
             mock.patch.object(manager, '_alive', return_value=True):
            self.assertFalse(manager._check(time.monotonic() + 10))

    def test_long_gap_does_not_invent_sleep_on_linux(self):
        d = self.make_daemon('linux')
        with tempfile.TemporaryDirectory() as tmp:
            d._journal = StatusJournal(Path(tmp) / 'status.sqlite3')
            try:
                d._journal.mark_start()
                d._last_tick_wall = time.time() - 120
                with mock.patch.object(daemon, 'internet_alive', return_value=False), \
                     mock.patch.object(d, 'tick_heartbeat'):
                    d.tick()
                kinds = [event.kind for event in d._journal.events()]
                self.assertIn('gap', kinds)
                self.assertNotIn('sleep', kinds)
                self.assertNotIn('internet_down', kinds)
            finally:
                d._journal.close()

    def test_confirmed_outage_is_recorded_before_same_tick_failover(self):
        d = self.make_daemon('linux')
        d.state.active = Server(uri='test', protocol='vless', uuid='test',
                                host='example.org', port=443, country='Germany')
        d.network.update(True)
        d._record_active_health(True)
        with tempfile.TemporaryDirectory() as tmp:
            d._journal = StatusJournal(Path(tmp) / 'status.sqlite3')
            try:
                d._journal.mark_start()
                def activate(_reason=None, **_kwargs):
                    d.state.transport = 'ssh'
                    d.state.active = None
                    d.state.note_proxy_ok()
                    d._record_active_health(True)
                with mock.patch.object(daemon, 'tg_configured', return_value=False), \
                     mock.patch.object(daemon, 'is_running', return_value=True), \
                     mock.patch.object(daemon, 'proxy_alive', return_value=False), \
                     mock.patch.object(d, '_handle_rotation_needed', side_effect=activate):
                    d._record_status(True)
                    d.tick_health(has_internet=True)
                    d.tick_health(has_internet=True)
                    d._record_status(True)
                self.assertEqual([e.kind for e in d._journal.events()[:2]], ['proxy_up', 'proxy_down'])
                self.assertIn('SSH', d._journal.events()[0].detail)
            finally:
                d._journal.close()

    def test_country_is_optional_and_validated(self):
        base = '{"tunnels":[{"id":"fr","host":"vpn.example","user":"test"%s}]}'
        self.assertIsNone(parse_tunnels(base % '').tunnels[0].country)
        self.assertEqual(parse_tunnels(base % ',"country":"Франция"').tunnels[0].country, 'Франция')
        self.assertEqual(parse_tunnels(base % '').tunnels[0],
                         parse_tunnels(base % ',"country":"Франция"').tunnels[0])
        with self.assertRaises(TunnelConfigError):
            parse_tunnels(base % ',"country":42')
