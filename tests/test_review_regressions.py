"""Interaction regressions from the independent emergency-mode review."""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, nullcontext
from dataclasses import replace
from pathlib import Path
from unittest import mock

from xproxy import daemon, healthcheck, notifier, tunnels, xray_config, xray_control
from xproxy.emergency import candidate_key
from xproxy.platform_utils import PlatformInfo
from xproxy.tunnels import AttemptResult, TunnelConfig, TunnelConfigFile, TunnelIntent, TunnelManager
from test_emergency import A, B, server, slot


def vless_config(s):
    return json.dumps({"outbounds": [xray_config._build_proxy_outbound(s)]})


SSH_CONFIG = json.dumps({"outbounds": [{"tag": "proxy", "protocol": "socks",
    "settings": {"servers": [{"address": "127.0.0.1", "port": 20808}]}}]})


class ReviewFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "config.json"
        self.config.write_text(vless_config(server(1)))
        self.info = PlatformInfo("macos", self.config, [], False)
        with mock.patch.object(daemon, "load_active", return_value=server(1)):
            self.d = daemon.Daemon(platform=self.info)
        self.addCleanup(self.d.emergency.manager._pool.shutdown, wait=False)
        self.d.state.ranked = [server(1), server(2), server(3)]
        self.d._update_network(True, "route")
        self.d._record_active_health(True)
        self.d.emergency.file.config = TunnelConfig((A, B))
        self.d.emergency.manager.configure(TunnelConfig((A, B)), True)
        self.mocks = ExitStack()
        self.addCleanup(self.mocks.close)
        self.mocks.enter_context(mock.patch.object(notifier, "is_configured", return_value=False))

    def patch(self, obj, name, **kwargs):
        return self.mocks.enter_context(mock.patch.object(obj, name, **kwargs))


class SshPriorityRegressions(ReviewFixture):
    def manager(self):
        self.request = TunnelIntent(True, True, True)
        m = TunnelManager(lambda: self.request, mock.Mock(return_value=True), mock.Mock(),
                          state_dir=self.root)
        m.configure(TunnelConfig((A, B)), True)
        self.addCleanup(m.close)
        return m

    def test_cancel_before_popen_then_resume_retries_the_same_host(self):
        m = self.manager()
        def confirm():
            self.request = TunnelIntent(False, False, True)
            return False
        m.confirm_network.side_effect = confirm
        self.patch(tunnels.shutil, "which", return_value="/usr/bin/ssh")
        self.patch(tunnels.os, "access", return_value=True)
        self.patch(tunnels.subprocess, "run", return_value=mock.Mock(returncode=0))
        listener = self.patch(tunnels, "_listener", return_value=False)
        spawn = self.patch(tunnels.subprocess, "Popen")
        self.patch(tunnels, "_process_identity", return_value="owned process")
        self.patch(m, "_check", return_value=True)
        m.step()
        m.step()  # repeated offline tick must not consume the primary
        spawn.assert_not_called()
        self.request = TunnelIntent(True, True, True)
        m.confirm_network.side_effect = None
        m.confirm_network.return_value = True
        spawn.return_value.pid = 123
        spawn.return_value.poll.return_value = None
        listener.side_effect = [False, True]
        m.step()
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(spawn.call_args.args[0][-1], f"{A.user}@{A.host}")
        self.assertTrue(m.snapshot().ready)
        m._pid = m._proc = None  # fake process is not a real signal target

    def test_network_loss_after_failed_attempt_does_not_consume_priority(self):
        m = self.manager()
        def offline():
            self.request = TunnelIntent(False, False, True)
            return False
        m.confirm_network.side_effect = offline
        attempt = self.patch(m, "_attempt", return_value=AttemptResult.FAILED)
        m.step()
        self.request = TunnelIntent(True, True, True)
        m.confirm_network.side_effect = None
        m.step()
        self.assertEqual([c.args[0] for c in attempt.call_args_list], [A, A])

    def test_key_reload_on_working_backup_retries_updated_backup_first(self):
        m = self.manager()
        m._endpoint, m._pid = B, 123
        updated = replace(B, identity_file="/new/key", known_hosts_file="/new/known_hosts")
        m.configure(TunnelConfig((A, updated)), True)
        alive = self.patch(m, "_alive", return_value=True)
        self.patch(m, "_check", return_value=True)
        attempt = self.patch(m, "_attempt", return_value=AttemptResult.FAILED)
        m.step()
        attempt.assert_not_called()
        alive.return_value = False
        m.step()
        self.assertEqual(attempt.call_args.args[0], updated)
        m.step()
        self.assertEqual([c.args[0] for c in attempt.call_args_list], [updated, A])

    def test_sleeping_generated_loop_is_retired_without_connecting(self):
        m = self.manager()
        path = self.root / ".fr-tunnel" / "ssh-tunnel-fr.sh"
        path.parent.mkdir()
        path.write_text("#!/bin/bash\n"
            "# авто-генерация start-fr-tunnel.sh — не редактировать\n"
            "while true; do\n"
            f"    ssh -p {A.port} -o BatchMode=yes -o ServerAliveInterval=30 "
            "-o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes "
            f"-L 20808:127.0.0.1:10808 -L 20809:127.0.0.1:10809 -N {A.user}@{A.host} "
            f"2>{path.parent}/tunnel.log\n    sleep 30\ndone\n")
        uid = tunnels.os.getuid()
        self.patch(tunnels.Path, "home", return_value=self.root)
        self.patch(tunnels.subprocess, "run", return_value=mock.Mock(stdout=
            f"{uid} 122 1 /bin/bash {path}\n{uid} 123 122 sleep 30\n"))
        self.patch(tunnels, "_process_identity", return_value="same creation identity")
        kill = self.patch(tunnels.os, "kill")
        spawn = self.patch(tunnels.subprocess, "Popen")
        self.assertFalse(m._adopt_legacy())  # retired loop, no child to adopt
        kill.assert_called_once_with(122, tunnels.signal.SIGTERM)
        spawn.assert_not_called()
        # A replaced script at the same pathname is not ours to signal.
        kill.reset_mock()
        path.write_text("#!/bin/bash\nwhile true; do sleep 30; done\n")
        self.assertFalse(m._adopt_legacy())
        kill.assert_not_called()

    def test_local_error_on_current_backup_keeps_its_priority_after_backoff(self):
        m = self.manager()
        m._endpoint, m._pid = B, 123
        self.patch(m, "_alive", return_value=False)
        attempt = self.patch(m, "_attempt", side_effect=tunnels.LocalTunnelError("missing key"))
        m.step()
        m._retry_at = 0  # advance beyond the retry delay
        m.step()
        self.assertEqual([c.args[0] for c in attempt.call_args_list], [B, B])


class EvidenceRegressions(ReviewFixture):
    def test_successful_reserve_closes_the_failed_scan_episode(self):
        d = self.d
        clock = [1000.0]
        self.patch(time, "monotonic", side_effect=lambda: clock[0])
        self.patch(time, "time", side_effect=lambda: clock[0])
        d._update_network(True, "route")
        d._record_active_health(True)
        with d._standby_cond:
            first = d._select_standby_candidate_locked()
            d.emergency.failed(first)
            second = d._select_standby_candidate_locked()
            prepared = slot(second)
            d._publish_standby_locked(prepared)
            d.emergency.prepared(prepared)
        for now in range(1015, 1601, 15):
            clock[0] = now
            d._update_network(True, "route")
            d._record_active_health(True)
        with d._standby_cond:
            d._handle_prepare_failure_locked(second, "remote failed", False)
            d.emergency.failed(second)
            retry = d._select_standby_candidate_locked()
        self.assertEqual(retry, first)
        self.assertFalse(d.emergency._failed_recently(first))
        self.assertFalse(d.emergency.reserve_lost())
        self.assertFalse(d.emergency.needed())

    def test_uninterrupted_long_failed_pass_still_confirms_lost_reserves(self):
        d = self.d
        clock = [1000.0]
        self.patch(time, "monotonic", side_effect=lambda: clock[0])
        self.patch(time, "time", side_effect=lambda: clock[0])
        d._update_network(True, "route")
        with d._standby_cond:
            first = d._select_standby_candidate_locked()
            d.emergency.failed(first)
            second = d._select_standby_candidate_locked()
        for now in range(1015, 1601, 15):
            clock[0] = now
            d._update_network(True, "route")
            d._record_active_health(True)
        with d._standby_cond:
            d.emergency.failed(second)
            self.assertIsNone(d._select_standby_candidate_locked())
        self.assertTrue(d.emergency.reserve_lost())

    def test_expired_wall_clock_evidence_invalidates_slots_when_network_resumes(self):
        d = self.d
        clocks = [1000.0, 1000.0]
        self.patch(time, "monotonic", side_effect=lambda: clocks[0])
        self.patch(time, "time", side_effect=lambda: clocks[1])
        d._update_network(True, "route")
        d._standby = slot(server(2))
        d.emergency.failed(server(3))
        before = d.network.snapshot().generation
        clocks[:] = [1001.0, 1101.0]  # macOS sleep: monotonic barely advanced
        self.assertFalse(d.network.online())
        d._update_network(True, "route")
        self.assertGreater(d.network.snapshot().generation, before)
        self.assertIsNone(d._standby)
        self.assertFalse(d.emergency._failed_recently(server(3)))
        self.assertIsNone(d._active_channel_ok)

    def test_changed_active_credentials_are_prepared_and_promoted_after_failure(self):
        d = self.d
        old = server(1)
        updated = replace(old, uuid=server(2).uuid, params={"security": "reality", "pbk": "new-key"})
        d.state.ranked = [updated]
        with d._standby_cond:
            self.assertIsNone(d._select_standby_candidate_locked())
        self.assertFalse(d.emergency.reserve_lost())
        d._runtime_started = True
        d._record_active_health(False)
        d.state.consecutive_proxy_failures = 5
        prepared = slot(updated)
        prepared.config_text = vless_config(updated)
        prepare = self.patch(daemon, "prepare_standby", return_value=prepared)
        self.patch(d._wake_event, "set", side_effect=lambda: setattr(d, "_standby_stop", True))
        d._standby_worker_loop()
        self.assertEqual(prepare.call_args.args[0], updated)
        self.assertIs(d._standby, prepared)
        d._standby_stop = False
        self.patch(daemon, "internet_alive", return_value=True)
        self.patch(daemon, "is_running", return_value=True)
        self.patch(daemon, "proxy_alive", side_effect=[False, False, True])
        self.patch(daemon, "target_alive", return_value=(True, ""))
        self.patch(daemon, "standby_fingerprint", return_value="fp")
        apply = self.patch(daemon, "apply_config_text")
        self.patch(daemon, "commit_config")
        self.patch(d, "_schedule_config_sync_after_vless_change")
        d.tick_health(has_internet=True)
        self.assertEqual(candidate_key(d.state.active), candidate_key(updated))
        self.assertEqual(apply.call_args.args[0], prepared.config_text)
        self.assertTrue(d._active_channel_ok)
        self.assertIsNone(d._standby)

    def test_active_recovery_discards_same_endpoint_variant_without_redundancy(self):
        d = self.d
        d._record_active_health(False)
        d._standby = slot(replace(server(1), uuid=server(2).uuid))
        d._record_active_health(True)
        self.assertIsNone(d._standby)
        self.assertFalse(d._standby_ready_for_fast_path())


class RecoveryRegressions(ReviewFixture):
    def transaction(self, previous, desired, current=None):
        self.config.write_text(desired if current is None else current)
        journal = self.root / "transition.json"
        journal.write_text(json.dumps({"version": 1, "previous": previous,
            "desired_hash": hashlib.sha256(desired.encode()).hexdigest()}))
        self.patch(xray_control, "TRANSACTION_PATH", new=journal)
        self.patch(xray_control, "VLESS_BACKUP_PATH", new=self.root / "vless.json")
        self.patch(xray_control, "validate_config_for_service", return_value=(True, ""))
        self.patch(xray_control, "wait_for_proxy_port", return_value=True)
        return journal

    def test_healthy_old_process_cannot_commit_unloaded_disk_config(self):
        previous, desired = vless_config(server(1)), SSH_CONFIG
        journal = self.transaction(previous, desired)
        running = [previous]
        restart = self.patch(xray_control, "_platform_restart",
            side_effect=lambda info: running.__setitem__(0, info.xray_config.read_text()))
        self.patch(xray_control, "is_running", return_value=True)
        def probe():
            self.assertEqual(running[0], desired)
            return True
        self.patch(healthcheck, "proxy_alive", side_effect=probe)
        self.patch(healthcheck, "target_alive", return_value=(True, ""))
        self.assertTrue(xray_control.recover_interrupted_config(self.info, online=True))
        restart.assert_called_once()
        self.assertFalse(journal.exists())

    def test_crash_before_first_write_does_not_leave_unresolvable_journal(self):
        journal = self.transaction(None, vless_config(server(1)))
        self.config.unlink()
        restart = self.patch(xray_control, "_platform_restart")
        self.assertTrue(xray_control.recover_interrupted_config(self.info, online=True))
        self.assertFalse(journal.exists())
        restart.assert_not_called()

    def test_rollback_written_before_crash_requires_restart_even_when_file_is_previous(self):
        previous, desired = SSH_CONFIG, vless_config(server(1))
        journal = self.transaction(previous, desired, current=previous)
        running = [desired]
        restart = self.patch(xray_control, "_platform_restart",
            side_effect=lambda info: running.__setitem__(0, info.xray_config.read_text()))
        self.assertFalse(xray_control.recover_interrupted_config(self.info, online=False))
        restart.assert_not_called()
        self.assertTrue(journal.exists())
        self.assertTrue(xray_control.recover_interrupted_config(self.info, online=True))
        self.assertEqual(running[0], previous)
        self.assertFalse(journal.exists())

    def test_tick_reconciles_transport_after_recovery_rollback_in_both_directions(self):
        for previous, desired, transport in ((SSH_CONFIG, vless_config(server(1)), "ssh"),
                                             (vless_config(server(1)), SSH_CONFIG, "vless")):
            with self.subTest(transport=transport), ExitStack() as patches:
                journal = self.transaction(previous, desired)
                d = self.d
                d._next_health_at = 0
                d.emergency.reconcile()  # the real startup ordering
                self.assertNotEqual(d.state.transport, transport)
                patches.enter_context(mock.patch.object(xray_control, "_platform_restart"))
                patches.enter_context(mock.patch.object(healthcheck, "proxy_alive", side_effect=[False, True]))
                patches.enter_context(mock.patch.object(healthcheck, "target_alive", return_value=(True, "")))
                patches.enter_context(mock.patch.object(daemon, "internet_alive", return_value=True))
                patches.enter_context(mock.patch.object(daemon, "is_running", return_value=True))
                patches.enter_context(mock.patch.object(daemon, "proxy_alive", return_value=True))
                patches.enter_context(mock.patch.object(daemon, "target_alive", return_value=(True, "")))
                patches.enter_context(mock.patch.object(d.emergency, "reload"))
                patches.enter_context(mock.patch.object(d, "tick_heartbeat"))
                patches.enter_context(mock.patch.object(d, "_sample_global_status"))
                d.tick()
                self.assertEqual(d.state.transport, transport)
                self.assertEqual(self.config.read_text(), previous)
                self.assertFalse(journal.exists())
                self.assertTrue(d._active_channel_ok)
                self.assertEqual(d.state.active is None, transport == "ssh")


class MaintenanceAndQueueRegressions(ReviewFixture):
    def test_health_waits_for_maintenance_restart_without_switch_or_penalty(self):
        for fault in ("listener", "probe"):
            with self.subTest(fault=fault), ExitStack() as patches:
                d = self.d
                d._runtime_started = True
                d._standby = slot(server(2))
                d._rebuild_pending = True
                d._record_active_health(True)
                restarting, release, health_started, health_done = (threading.Event() for _ in range(4))
                healthy = [True]
                errors = []
                def apply(*args, **kwargs):
                    healthy[0] = False
                    restarting.set()
                    if not release.wait(2):
                        raise AssertionError("test did not release maintenance restart")
                    healthy[0] = True
                    return True
                def health():
                    health_started.set()
                    try:
                        d.tick_health(has_internet=True)
                    except BaseException as exc:
                        errors.append(exc)
                    finally:
                        health_done.set()
                patches.enter_context(mock.patch.object(d, "_apply_verified_config", side_effect=apply))
                patches.enter_context(mock.patch.object(d, "_geo_ready_for_rebuild", return_value=True))
                patches.enter_context(mock.patch.object(daemon, "build_xray_config_text", return_value="rebuilt A"))
                patches.enter_context(mock.patch.object(daemon, "is_running", side_effect=lambda: healthy[0] if fault == "listener" else True))
                patches.enter_context(mock.patch.object(daemon, "proxy_alive", side_effect=lambda: healthy[0]))
                patches.enter_context(mock.patch.object(daemon, "target_alive", return_value=(True, "")))
                promote = patches.enter_context(mock.patch.object(d, "_promote_standby"))
                repair = patches.enter_context(mock.patch.object(d, "_repair_xray_listener"))
                maintenance = threading.Thread(target=d._rebuild_config_if_active)
                sample = threading.Thread(target=health)
                maintenance.start()
                try:
                    self.assertTrue(restarting.wait(2))
                    sample.start()
                    self.assertTrue(health_started.wait(2))
                    self.assertFalse(health_done.wait(0.05))
                finally:
                    release.set()
                    maintenance.join(2)
                    if sample.ident is not None:
                        sample.join(2)
                self.assertFalse(maintenance.is_alive() or sample.is_alive())
                self.assertEqual(errors, [])
                promote.assert_not_called()
                repair.assert_not_called()
                self.assertEqual(d.state.active.key(), server(1).key())
                self.assertEqual(d.state.penalized_keys(), {})
                self.assertEqual(d.state.proxy_failures_snapshot(), 0)

    def test_queued_listener_repair_rechecks_after_acquiring_apply_lock(self):
        d = self.d
        d._runtime_started = True
        ready, done = threading.Event(), threading.Event()
        running = [False]
        self.patch(daemon, "is_running", side_effect=lambda: running[0])
        repair = self.patch(d, "_repair_xray_listener_with_apply_lock")
        def worker():
            ready.set()
            try:
                d._repair_xray_listener()
            finally:
                done.set()
        with d._apply_lock:
            t = threading.Thread(target=worker)
            t.start()
            self.assertTrue(ready.wait(2))
            self.assertFalse(done.wait(0.05))
            running[0] = True
        t.join(2)
        self.assertFalse(t.is_alive())
        repair.assert_not_called()

    def test_startup_config_alert_preserves_persisted_topics_before_sender_start(self):
        d = self.d
        path = self.root / "queue.json"
        path.write_text(json.dumps([
            notifier._PendingNotify("pending update", time.time(), topic="update").to_dict(),
            notifier._PendingNotify("old config event", time.time(), topic="configuration").to_dict(),
        ]))
        tunnels_path = self.root / "tunnels.json"
        tunnels_path.write_text('{"tunnels":')
        d.emergency.file = TunnelConfigFile(tunnels_path)
        queue = notifier._NotificationQueue()
        self.patch(notifier, "_QUEUE_FILE", new=path)
        self.patch(notifier, "_queue", new=queue)
        self.patch(notifier, "is_configured", return_value=True)
        self.patch(daemon, "InstanceLock", return_value=nullcontext())
        self.patch(d, "_load_cached_servers")
        self.patch(daemon, "internet_alive", return_value=False)
        self.patch(daemon, "start_queue", side_effect=queue._load_from_disk)
        self.patch(daemon, "drain_queue")
        self.patch(daemon, "set_network_provider")
        self.patch(daemon, "set_status_provider")
        d.run_once()
        events = {item["topic"]: item["text"] for item in json.loads(path.read_text())}
        self.assertEqual(events["update"], "pending update")
        self.assertIn("configuration rejected", events["configuration"])
        self.assertEqual(set(events), {"update", "configuration", "network"})
