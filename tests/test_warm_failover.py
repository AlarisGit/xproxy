"""Fast recovery, bounded probes and the two-route VLESS stability window."""
from __future__ import annotations

import json
import subprocess
import threading
import time
import unittest
from dataclasses import replace
from unittest import mock

from xproxy import daemon, emergency, healthcheck, http_probe, standby
from xproxy.reserves import Reserve
from xproxy.tunnels import TunnelConfig, TunnelSnapshot, TunnelIntent
from test_emergency import A, server, slot


class RecoveryWindowTests(unittest.TestCase):
    def setUp(self):
        self.clock = 1000.0
        for name in ("time", "monotonic"):
            patcher = mock.patch.object(time, name, side_effect=lambda: self.clock)
            patcher.start()
            self.addCleanup(patcher.stop)
        with mock.patch.object(daemon, "load_active", return_value=None):
            self.d = daemon.Daemon()
        self.addCleanup(self.d.emergency.manager._pool.shutdown, wait=False)
        self.d.state.transport = "ssh"
        self.d.state.ranked = [server(1), server(2), server(3)]
        self.d.emergency.file.config = TunnelConfig((A,))
        self.fp = mock.patch.object(standby, "standby_fingerprint", return_value="fp")
        self.fp.start()
        self.addCleanup(self.fp.stop)

    def observe(self, *servers):
        self.d.network.update(True)
        self.d._record_active_health(True)
        for s in servers:
            prepared = slot(s)
            prepared.transfer_ok = True
            record = self.d._reserves.setdefault(emergency.candidate_key(s), Reserve())
            record.success(prepared)
        self.d._standby = self.d._reserves[emergency.candidate_key(servers[0])].slot

    def stable(self, *servers):
        for ts in range(1000, 1601, 15):
            self.clock = ts
            self.observe(*servers)

    def allowed(self):
        return self.d.emergency.recovery_allowed(self.d._standby)

    def test_one_good_vless_never_leaves_healthy_ssh(self):
        self.stable(server(1))
        self.assertFalse(self.allowed())

    def test_two_aliases_of_one_endpoint_do_not_count_as_a_pair(self):
        alias = replace(server(1), uuid=server(2).uuid, country="another country")
        self.stable(server(1), alias)
        self.assertFalse(self.allowed())

    def test_broken_ssh_escapes_to_one_vless_without_hold_or_ssh_config(self):
        self.observe(server(1))
        self.d.emergency.file.config = TunnelConfig(())
        self.d._record_active_health(False)
        self.d.state.consecutive_proxy_failures = 1
        self.assertFalse(self.allowed())
        self.d.state.consecutive_proxy_failures = 2
        self.assertTrue(self.allowed())
        with mock.patch.object(self.d, "_promote_standby", return_value=True) as promote, \
                mock.patch.object(self.d.emergency, "event"):
            self.d.emergency.tick()
            promote.assert_called_once_with("ssh-recovery")

    def test_suspect_blocks_return_but_successful_confirmation_preserves_window(self):
        self.stable(server(1), server(2))
        self.assertTrue(self.allowed())
        record = self.d._reserves[emergency.candidate_key(server(2))]
        start = record.since
        record.failed()
        self.assertFalse(self.allowed())
        self.clock += 1
        self.observe(server(1), server(2))
        self.assertEqual(record.since, start)
        self.assertTrue(self.allowed())

    def test_confirmed_failure_restarts_ten_minute_window(self):
        self.stable(server(1), server(2))
        record = self.d._reserves[emergency.candidate_key(server(2))]
        record.failed()
        record.failed()
        self.clock += 2
        self.observe(server(1), server(2))
        self.assertEqual(record.since, self.clock)
        self.assertFalse(self.allowed())

    def test_replaced_credentials_and_configuration_require_new_history(self):
        self.stable(server(1), server(2))
        changed = replace(server(2), uuid=server(3).uuid)
        self.d._reserves.pop(emergency.candidate_key(server(2)))
        self.observe(server(1), changed)
        self.assertFalse(self.allowed())
        with mock.patch.object(standby, "standby_fingerprint", return_value="changed"):
            self.assertFalse(self.allowed())

    def test_pair_must_be_fresh_and_sleep_cannot_complete_hold(self):
        self.stable(server(1), server(2))
        self.clock += 31
        self.d._record_active_health(True)
        self.assertFalse(self.allowed())
        self.observe(server(1), server(2))
        self.assertFalse(self.allowed())
        self.d._invalidate_standby("network changed or resumed")
        self.assertFalse(self.d._reserves)

    def test_transfer_failure_only_blocks_voluntary_return(self):
        self.stable(server(1), server(2))
        prepared = slot(server(2))
        prepared.transfer_ok = False
        record = self.d._reserves[emergency.candidate_key(server(2))]
        record.success(prepared)
        self.assertTrue(record.fresh())
        self.assertFalse(self.allowed())

    def test_configurable_hold_and_invalid_value_fallback(self):
        with mock.patch("xproxy.env_config.get", return_value="120"):
            self.assertEqual(self.d.emergency.recovery_seconds(), 120)
        for value in ("nan", "inf", "-1", "0", "bad"):
            with self.subTest(value=value), mock.patch("xproxy.env_config.get", return_value=value):
                self.assertEqual(self.d.emergency.recovery_seconds(), 600)


class FastFailoverTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(daemon, "load_active", return_value=None):
            self.d = daemon.Daemon()
        self.addCleanup(self.d.emergency.manager._pool.shutdown, wait=False)
        self.d.network.update(True)
        self.d.state.active = server(1)
        self.d.state.ranked = [server(1), server(2), server(3)]
        self.d._runtime_started = True

    def test_absent_ssh_does_not_raise_failure_threshold(self):
        with mock.patch.object(daemon, "is_running", return_value=True), \
                mock.patch.object(daemon, "proxy_alive", return_value=False), \
                mock.patch.object(self.d, "_handle_rotation_needed") as rotate:
            self.d.tick_health(has_internet=True)
            rotate.assert_not_called()
            self.d.tick_health(has_internet=True)
            rotate.assert_called_once_with(reason="proxy-failing")

    def test_three_failures_in_five_samples_detect_intermittent_failure(self):
        with mock.patch.object(daemon, "is_running", return_value=True), \
                mock.patch.object(daemon, "proxy_alive", side_effect=[False, True, False, True, False]), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(self.d, "_handle_rotation_needed") as rotate:
            for _ in range(4):
                self.d.tick_health(has_internet=True)
            rotate.assert_not_called()
            self.d.tick_health(has_internet=True)
            rotate.assert_called_once()

    def test_previous_route_failures_do_not_follow_new_active(self):
        self.d._record_active_health(False)
        self.d._health_samples.extend([False, False, False])
        self.d.state.active = server(2)
        self.d.state.note_proxy_ok()
        self.d._record_active_health(True)
        self.assertFalse(self.d._failure_confirmed())

    def test_no_reserve_does_not_repeat_slow_active_check(self):
        self.d._record_active_health(False)
        with mock.patch.object(self.d, "_active_still_needs_standby") as check:
            self.assertFalse(self.d._promote_standby("proxy-failing", require_active_failure=True))
            check.assert_not_called()

    def test_ready_ssh_activates_without_waiting_for_scan(self):
        self.d._record_active_health(False)
        self.d.state.consecutive_proxy_failures = 2
        snapshot = TunnelSnapshot("READY", A, 20808, time.monotonic())
        with mock.patch.object(self.d.emergency.manager, "snapshot", return_value=snapshot), \
                mock.patch.object(self.d.emergency, "_activate") as activate:
            self.d.emergency.tick()
            activate.assert_called_once_with(snapshot)

    def test_second_parallel_candidate_is_published_while_first_is_blocked(self):
        first_started = threading.Event()
        release = threading.Event()
        published = []
        def prepare(candidate, **kwargs):
            if candidate.key() == server(2).key():
                first_started.set()
                if not release.wait(2):
                    raise AssertionError("other candidate did not publish")
                raise standby.StandbyError("blocked")
            self.assertTrue(first_started.wait(1))
            return slot(candidate)
        def wake():
            if self.d._standby is not None:
                published.append(self.d._standby.server.key())
                self.d._standby_stop = True
                release.set()
        with mock.patch.object(daemon, "prepare_standby", side_effect=prepare), \
                mock.patch.object(self.d._wake_event, "set", side_effect=wake):
            self.d._standby_worker_loop()
        self.assertEqual(published, [server(3).key()])
        self.assertFalse(self.d._inflight)

    def test_one_endpoint_cannot_occupy_both_parallel_workers(self):
        first = self.d._select_standby_candidate_locked()
        self.d._inflight[emergency.candidate_key(first)] = first
        alias = replace(first, uuid=server(3).uuid)
        self.d.state.ranked = [server(1), first, alias, server(3)]
        self.assertEqual(self.d._select_standby_candidate_locked().key(), server(3).key())

    def test_ssh_failure_accelerates_existing_vless_backoff(self):
        record = Reserve(retry_at=time.monotonic() + 60)
        self.d._reserves[emergency.candidate_key(server(2))] = record
        self.d.state.transport = "ssh"
        self.d._handle_rotation_needed("proxy-failing")
        self.assertLessEqual(record.retry_at, time.monotonic() + 1)

    def test_urgent_ssh_retries_do_not_inherit_warm_backoff(self):
        manager = self.d.emergency.manager
        request = TunnelIntent(True, True, True, True)
        manager._retry_at = time.monotonic() + 60
        with mock.patch.object(manager, "intent", return_value=request), \
                mock.patch.object(manager, "_allowed", return_value=False):
            manager.step()
            self.assertLessEqual(manager._retry_at, time.monotonic() + 1)
            manager._retry_round = 20
            manager._backoff()
            self.assertLessEqual(manager._retry_at, time.monotonic() + 15)


class BoundedProbeTests(unittest.TestCase):
    def test_overall_timeout_covers_child_including_dns_and_body(self):
        with mock.patch.object(healthcheck.subprocess, "run", side_effect=subprocess.TimeoutExpired("probe", 3)) as run:
            self.assertIsNone(healthcheck._bounded_http("https://example.test", {}, "target", 3))
            self.assertEqual(run.call_args.kwargs["timeout"], 3)
            self.assertIn("http_probe.py", run.call_args.args[0][-1])

    def test_target_consumes_body_and_rejects_oversized_response(self):
        response = mock.MagicMock(status_code=401)
        response.__enter__.return_value = response
        response.iter_content.return_value = iter([b"body"])
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = response
        with mock.patch.object(http_probe.requests, "Session", return_value=session):
            spec = dict(url="https://example.test", timeout=3, kind="target", bytes=8)
            self.assertTrue(http_probe.probe(spec)["ok"])
            response.iter_content.return_value = iter([b"0123456789"])
            self.assertFalse(http_probe.probe(spec)["ok"])
        self.assertFalse(session.trust_env)

    def test_truncated_transfer_is_not_a_success(self):
        response = mock.MagicMock(status_code=200)
        response.__enter__.return_value = response
        response.iter_content.return_value = iter([b"abc"])
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = response
        with mock.patch.object(http_probe.requests, "Session", return_value=session):
            self.assertFalse(http_probe.probe(dict(url="https://example.test", timeout=3,
                                                  kind="transfer", bytes=16))["ok"])

    def test_temporary_probe_does_not_bind_production_health_port(self):
        config = json.dumps({"inbounds": [
            {"tag": "socks-in", "protocol": "socks", "port": 10808},
            {"tag": "xproxy-upstream-probe", "protocol": "socks", "port": 10810},
        ]})
        result = json.loads(standby.build_standby_test_config_text(config, socks_port=11808, http_port=11809))
        self.assertEqual([i["port"] for i in result["inbounds"]], [11808, 11809])
