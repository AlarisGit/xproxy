from __future__ import annotations

import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from xproxy import daemon, notifier, tunnels, xray_control, emergency, routing, xray_config
from xproxy.connectivity import Connectivity
from xproxy.platform_utils import PlatformInfo
from xproxy.servers import Server
from xproxy.standby import PreparedStandby
from xproxy.tunnels import (
    AttemptResult, LocalTunnelError, TunnelConfig, TunnelConfigError, TunnelConfigFile,
    TunnelEndpoint, TunnelIntent, TunnelManager, TunnelSnapshot, parse_tunnels,
)


def server(n: int) -> Server:
    return Server(uri=f"vless-{n}", protocol="vless",
                  uuid=f"00000000-0000-0000-0000-{n:012d}", host=f"192.0.2.{n}",
                  port=443, country=f"country-{n}")


def slot(s: Server) -> PreparedStandby:
    now = time.time()
    return PreparedStandby(s, '{"outbounds":[]}', "fp", now, now, now + 300, now + 900)


A = TunnelEndpoint("primary", "192.0.2.101", 22, "test")
B = TunnelEndpoint("backup", "192.0.2.102", 22, "test")


class TunnelConfigurationTests(unittest.TestCase):
    def test_missing_empty_and_invalid_updates_do_not_enable_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tunnels.json"
            config = TunnelConfigFile(path)
            config.reload()
            self.assertFalse(config.enabled)
            path.write_text('{"tunnels":[]}')
            config.reload()
            self.assertFalse(config.enabled)
            path.write_text(json.dumps({"tunnels": [dict(id="fr", host="192.0.2.1", user="u")]}))
            config.reload()
            self.assertTrue(config.enabled)
            previous = config.config
            path.write_text('{"tunnels":')
            config.reload()
            self.assertFalse(config.enabled)
            self.assertEqual(config.config, previous)
            path.unlink()
            config.reload()
            self.assertFalse(config.enabled)

    def test_priority_and_host_sets_are_local_to_each_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = [TunnelConfigFile(Path(tmp) / name) for name in ("one.json", "two.json")]
            for config, ids in zip(files, (("fr", "de"), ("us",))):
                config.path.write_text(json.dumps({"tunnels": [
                    dict(id=i, host=i + ".example", user="u") for i in ids]}))
                config.reload()
            self.assertEqual([e.id for e in files[0].config.tunnels], ["fr", "de"])
            self.assertEqual([e.id for e in files[1].config.tunnels], ["us"])

    def test_bad_addresses_ports_and_duplicate_ids_are_rejected(self):
        for update in ({"host": "-oProxyCommand=bad"}, {"port": True}, {"port": 0},
                       {"identity_file": "relative-key"}, {"host": "x;touch /tmp/bad"}):
            with self.subTest(update=update), self.assertRaises(TunnelConfigError):
                parse_tunnels(json.dumps({"tunnels": [{"id": "one", "host": "example.com", "user": "u", **update}]}))

    def test_ssh_has_no_hidden_proxy_or_extra_forwards_on_either_platform(self):
        for platform_name in ("Darwin", "Linux"):
            with self.subTest(platform=platform_name):
                cmd = tunnels.ssh_command(A, 20808, "owned-token")
                self.assertEqual(cmd[:3], ["ssh", "-F", "/dev/null"])
                self.assertIn("BatchMode=yes", cmd)
                self.assertIn("StrictHostKeyChecking=yes", cmd)
                self.assertIn("ProxyCommand=none", cmd)
                self.assertIn("127.0.0.1:20808:127.0.0.1:10808", cmd)
                self.assertEqual(cmd.count("-L"), 1)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.request = TunnelIntent(True, True, True)
        self.manager = TunnelManager(lambda: self.request, mock.Mock(return_value=True),
                                     mock.Mock(), state_dir=Path(self.tmp.name))
        self.manager.configure(TunnelConfig((A, B)), True)
        self.addCleanup(self.manager.close)

    def test_normal_and_offline_modes_never_contact_ssh_hosts(self):
        with mock.patch.object(self.manager, "_attempt") as attempt, \
                mock.patch.object(self.manager, "_check") as check:
            for request in (TunnelIntent(True, False, False), TunnelIntent(False, True, True)):
                self.request = request
                self.manager.step()
            attempt.assert_not_called()
            check.assert_not_called()
            self.manager.confirm_network.assert_not_called()

    def test_only_failed_primary_allows_next_host(self):
        with mock.patch.object(self.manager, "_attempt", side_effect=[AttemptResult.FAILED, AttemptResult.READY]) as attempt:
            self.manager.step()
            self.assertEqual([c.args[0].id for c in attempt.call_args_list], ["primary"])
            self.manager.step()
            self.assertEqual([c.args[0].id for c in attempt.call_args_list], ["primary", "backup"])

    def test_vless_recovery_between_attempts_keeps_backup_address_unused(self):
        with mock.patch.object(self.manager, "_attempt", return_value=AttemptResult.FAILED) as attempt:
            self.manager.step()
            self.request = TunnelIntent(True, False, False)
            self.manager.step()
            self.assertEqual(attempt.call_count, 1)

    def test_network_loss_after_failure_keeps_backup_address_unused(self):
        def lost():
            self.request = TunnelIntent(False, False, True)
            return False
        self.manager.confirm_network.side_effect = lost
        with mock.patch.object(self.manager, "_attempt", return_value=AttemptResult.FAILED) as attempt:
            self.manager.step()
            self.manager.step()
            self.assertEqual(attempt.call_count, 1)

    def test_local_port_or_key_errors_do_not_try_other_hosts(self):
        with mock.patch.object(self.manager, "_attempt", side_effect=LocalTunnelError("occupied")) as attempt:
            self.manager.step()
            self.manager.step()
            self.assertEqual(attempt.call_count, 1)
            self.assertEqual(self.manager.snapshot().status, "LOCAL_ERROR")
            self.manager.confirm_network.assert_not_called()

    def test_existing_tunnel_is_retried_before_other_hosts(self):
        self.manager._endpoint = B
        self.manager._pid = 123
        with mock.patch.object(self.manager, "_alive", return_value=False), \
                mock.patch.object(self.manager, "_attempt", side_effect=[AttemptResult.FAILED, AttemptResult.READY]) as attempt:
            self.manager.step()
            self.manager.step()
            self.assertEqual([c.args[0].id for c in attempt.call_args_list], ["backup", "primary"])

    def test_healthy_secondary_does_not_probe_primary(self):
        self.manager._endpoint = B
        self.manager._pid = 123
        with mock.patch.object(self.manager, "_alive", return_value=True), \
                mock.patch.object(self.manager, "_check", return_value=True), \
                mock.patch.object(self.manager, "_attempt") as attempt:
            self.manager.step()
            self.manager.step()
            attempt.assert_not_called()
        self.manager._pid = None

    def test_removed_current_endpoint_can_drain_but_cannot_reconnect(self):
        self.manager._endpoint = A
        self.manager._pid = 123
        self.manager.configure(TunnelConfig(()), False)
        self.request = TunnelIntent(True, False, True)
        with mock.patch.object(self.manager, "_alive", return_value=True), \
                mock.patch.object(self.manager, "_check", return_value=True), \
                mock.patch.object(self.manager, "_attempt") as attempt:
            self.manager.step()
            self.assertTrue(self.manager.snapshot().ready)
            attempt.assert_not_called()
        self.manager._pid = None

    def test_reused_pid_is_not_adopted_or_signalled(self):
        path = Path(self.tmp.name) / "ssh-process.json"
        path.write_text(json.dumps(dict(pid=123, identity="old process", token="unique")))
        with mock.patch.object(tunnels, "_process_identity", return_value="other process"), \
                mock.patch.object(tunnels.os, "kill") as kill:
            self.assertFalse(self.manager.adopt())
            self.manager.close()
            kill.assert_not_called()

    def test_hot_reload_does_not_replace_a_healthy_current_connection(self):
        self.manager._endpoint, self.manager._pid = B, 123
        self.manager.configure(TunnelConfig((A, B), 20818), True)
        with mock.patch.object(self.manager, "_alive", return_value=True), \
                mock.patch.object(self.manager, "_check", return_value=True), \
                mock.patch.object(self.manager, "_attempt") as attempt:
            self.manager.step()
            self.assertEqual(self.manager.snapshot().endpoint, B)
            self.assertEqual(self.manager.snapshot().local_port, 20808)
            attempt.assert_not_called()
        self.manager._pid = None

    def test_demand_withdrawn_during_local_preflight_prevents_ssh_spawn(self):
        def known(*args, **kwargs):
            self.request = TunnelIntent(True, False, False)
            return mock.Mock(returncode=0)
        with mock.patch.object(tunnels.shutil, "which", return_value="/usr/bin/ssh"), \
                mock.patch.object(tunnels.os, "access", return_value=True), \
                mock.patch.object(tunnels.subprocess, "run", side_effect=known), \
                mock.patch.object(tunnels, "_listener", return_value=False), \
                mock.patch.object(tunnels.subprocess, "Popen") as spawn:
            self.manager._spawn(A, 20808)
            spawn.assert_not_called()

    def test_legacy_match_requires_the_configured_destination_and_ports(self):
        command = "ssh -N -p 22 -L 20808:127.0.0.1:10808 -L 20809:127.0.0.1:10809 test@192.0.2.101"
        self.assertTrue(tunnels._legacy_matches(command, A, 20808))
        self.assertFalse(tunnels._legacy_matches(command, B, 20808))
        self.assertFalse(tunnels._legacy_matches(command, A, 20818))

    def test_restart_finishes_interrupted_legacy_loop_handoff(self):
        command = "ssh -N -p 22 -L 20808:127.0.0.1:10808 test@192.0.2.101"
        identity = "Mon Sep 14 12:00:00 2026 " + command
        path = Path(self.tmp.name) / "ssh-process.json"
        from dataclasses import asdict
        path.write_text(json.dumps(dict(pid=123, identity=identity, endpoint=asdict(A),
            local_port=20808, legacy_command=command, legacy_parent=122,
            legacy_parent_identity="parent identity")))
        with mock.patch.object(tunnels, "_process_identity", side_effect=lambda p: identity if p == 123 else "parent identity"), \
                mock.patch.object(tunnels.os, "kill") as kill:
            self.assertTrue(self.manager.adopt())
            kill.assert_called_once_with(122, tunnels.signal.SIGTERM)
        self.manager._pid = None

    def test_shutdown_before_adoption_does_not_erase_existing_ownership(self):
        path = Path(self.tmp.name) / "ssh-process.json"
        path.write_text('{"existing":true}')
        self.manager.close()
        self.assertTrue(path.exists())


class EmergencyPolicyTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(daemon, "load_active", return_value=None):
            self.d = daemon.Daemon()
        self.d.network.update(True)
        self.d.state.active = server(1)
        self.d.state.last_vless = server(1)
        self.d.state.ranked = [server(1), server(2), server(3)]
        self.d.emergency.file.config = TunnelConfig((A, B))
        self.d.emergency.manager.configure(TunnelConfig((A, B)), True)
        self.d._record_active_health(True)
        self.addCleanup(self.d.emergency.manager._pool.shutdown, wait=False)

    def test_empty_slot_is_not_evidence_until_all_alternatives_fail(self):
        self.assertFalse(self.d.emergency.needed())
        self.d.emergency.failed(server(2))
        self.assertFalse(self.d.emergency.needed())
        self.d.emergency.failed(server(3))
        self.assertTrue(self.d.emergency.needed())
        self.d._standby = slot(server(2))
        self.assertFalse(self.d.emergency.needed())

    def test_missing_alternatives_or_local_failure_does_not_expose_hosts(self):
        self.d.state.ranked = [server(1)]
        self.assertFalse(self.d.emergency.needed())
        self.d._record_active_health(False)
        self.d.state.consecutive_proxy_failures = 5
        self.d.emergency.local_failure()
        self.assertFalse(self.d.emergency.needed())

    def test_confirmed_active_failure_can_start_emergency_without_waiting_for_full_scan(self):
        self.d._record_active_health(False)
        self.d.state.consecutive_proxy_failures = 4
        self.assertFalse(self.d.emergency.needed())
        self.d.state.consecutive_proxy_failures = 5
        self.assertTrue(self.d.emergency.needed())

    def test_saved_ssh_mode_does_not_authorize_reconnection_without_fresh_vless_failure(self):
        self.d.state.transport = "ssh"
        self.d.state.active = None
        self.assertFalse(self.d.emergency.needed())
        self.d.emergency.failed(server(1))
        self.assertTrue(self.d.emergency.needed())

    def test_previous_active_is_included_in_ssh_recovery_scan(self):
        self.d.state.transport = "ssh"
        self.d.state.active = None
        self.d.state.ranked = [server(1)]
        with self.d._standby_cond:
            self.assertEqual(self.d._select_standby_candidate_locked().key(), server(1).key())

    def test_failed_pass_restarts_after_backoff(self):
        self.d.state.ranked = [server(1), server(2)]
        with self.d._standby_cond, mock.patch.object(daemon.time, "monotonic", return_value=100):
            self.assertIsNotNone(self.d._select_standby_candidate_locked())
            self.assertIsNone(self.d._select_standby_candidate_locked())
        with self.d._standby_cond, mock.patch.object(daemon.time, "monotonic", return_value=161):
            self.assertIsNotNone(self.d._select_standby_candidate_locked())

    def test_offline_does_not_repair_xray_or_increment_failures(self):
        with mock.patch.object(daemon, "is_running") as running, \
                mock.patch.object(self.d, "_handle_rotation_needed") as rotate:
            self.d.tick_health(has_internet=False)
            running.assert_not_called()
            rotate.assert_not_called()
            self.assertEqual(self.d.state.consecutive_proxy_failures, 0)

    def test_shutdown_requires_stable_vless_and_fresh_standby(self):
        clock = [1000.0]
        with mock.patch("time.time", side_effect=lambda: clock[0]), \
                mock.patch("time.monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.d.emergency, "event"):
            self.d._standby = slot(server(2))
            snapshot = TunnelSnapshot("READY", A, 20808, 1000)
            with mock.patch.object(self.d.emergency.manager, "snapshot", return_value=snapshot):
                for ts in range(1000, 1121, 15):
                    clock[0] = ts
                    self.d.network.update(True)
                    self.d._record_active_health(True)
                    self.d.emergency.tick()
                self.assertFalse(self.d.emergency._release)  # standby is stale for teardown
                self.d._standby.last_ok_at = clock[0]
                self.d.emergency.tick()
                self.assertTrue(self.d.emergency._release)
                self.assertFalse(self.d.emergency.intent().keep)

    def test_new_standby_releases_ssh_without_repeating_active_stabilization(self):
        clock = [1000.0]
        with mock.patch("time.time", side_effect=lambda: clock[0]), \
                mock.patch("time.monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.d.emergency, "event"), \
                mock.patch.object(self.d.emergency.manager, "snapshot", return_value=TunnelSnapshot("READY", A, 20808, 1000)):
            for ts in range(1000, 1121, 15):
                clock[0] = ts
                self.d.network.update(True)
                self.d._record_active_health(True)
                self.d.emergency.tick()
            self.assertFalse(self.d.emergency._release)
            self.d._standby = slot(server(2))
            self.d.emergency.tick()
            self.assertTrue(self.d.emergency._release)

    def test_live_ssh_config_is_preserved_on_startup_even_with_saved_vless(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps({"outbounds": [{"tag": "proxy", "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.1", "port": 20808}]}}]}))
            self.d.platform = PlatformInfo("macos", config, [], False)
            self.d.emergency.reconcile()
            self.assertEqual(self.d.state.transport, "ssh")
            self.assertIsNone(self.d.state.active)
            self.assertEqual(self.d.state.last_vless.key(), server(1).key())
            self.assertFalse(self.d.emergency.needed())

    def test_missing_live_outbound_does_not_trust_saved_active_as_vless_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text('{}')
            self.d.platform = PlatformInfo("linux", config, [], False)
            self.d.emergency.reconcile()
            self.d._record_active_health(False)
            self.d.state.consecutive_proxy_failures = 5
            self.assertEqual(self.d.state.transport, "unknown")
            self.assertFalse(self.d.emergency.needed())

    def test_offline_keeps_prepared_process_without_probes_on_repeated_steps(self):
        manager = self.d.emergency.manager
        manager._endpoint, manager._pid = A, 123
        manager._publish("READY", ok=True)
        self.d.network.update(False)
        with mock.patch.object(manager, "_terminate") as terminate, \
                mock.patch.object(manager, "_check") as check, \
                mock.patch.object(manager, "_attempt") as attempt:
            for _ in range(3):
                manager.step()
            terminate.assert_not_called()
            check.assert_not_called()
            attempt.assert_not_called()
        manager._pid = None

    def test_route_change_and_wakeup_discard_old_failure_evidence(self):
        self.d._update_network(True, "wifi-a")
        self.d._record_active_health(True)
        self.d.emergency.failed(server(2))
        self.d.emergency.failed(server(3))
        self.assertTrue(self.d.emergency.needed())
        self.d._update_network(True, "wifi-b")
        self.assertFalse(self.d.emergency.needed())
        start = time.time()
        with mock.patch("time.time", return_value=start + 300):
            self.assertFalse(self.d.network.online())

    def test_full_emergency_cycle_requires_recovery_and_independent_standby(self):
        clock = [1000.0]
        manager = self.d.emergency.manager
        with mock.patch("time.time", side_effect=lambda: clock[0]), \
                mock.patch("time.monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.d.emergency, "event") as event, \
                mock.patch.object(emergency, "build_ssh_config_text", return_value="{}"), \
                mock.patch.object(self.d, "_apply_verified_config", return_value=True), \
                mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text"), \
                mock.patch.object(daemon, "commit_config"), \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch("xproxy.state._save_active"):
            self.d.network.update(True)
            self.d._record_active_health(True)
            self.d.emergency.failed(server(2))
            self.d.emergency.failed(server(3))
            self.assertTrue(self.d.emergency.intent().connect)
            manager._endpoint = A
            manager._publish("READY", ok=True)
            self.d.emergency.tick()
            self.assertEqual(self.d.state.transport, "vless")
            self.d._record_active_health(False)
            self.d.state.consecutive_proxy_failures = 1
            self.d.emergency.tick()
            self.assertEqual(self.d.state.transport, "ssh")
            self.assertEqual(self.d.state.last_vless.key(), server(1).key())
            self.d._standby = slot(server(2))
            self.d.emergency.prepared(self.d._standby)
            self.d.emergency.tick()
            self.assertEqual(self.d.state.transport, "ssh")  # one sample is insufficient
            clock[0] += 16
            self.d.emergency.prepared(self.d._standby)
            self.d.emergency.tick()
            self.assertEqual(self.d.state.transport, "vless")
            self.assertEqual(self.d.state.active.key(), server(2).key())
            self.assertTrue(self.d.emergency.intent().keep)
            self.assertFalse(self.d.emergency.intent().connect)
            self.d._standby = slot(server(3))
            for _ in range(9):
                self.d.network.update(True)
                self.d._record_active_health(True)
                self.d._standby.last_ok_at = clock[0]
                self.d.emergency.tick()
                clock[0] += 15
            self.assertFalse(self.d.emergency.intent().keep)
            with mock.patch.object(manager, "_attempt") as attempt:
                manager.step()
                attempt.assert_not_called()
            self.assertEqual(manager.snapshot().status, "IDLE")
            transport_events = [c.args[1] for c in event.call_args_list if c.args[0] == "transport"]
            self.assertEqual(len(transport_events), 3)


class NotificationTests(unittest.TestCase):
    def test_connecting_and_single_suspect_sample_do_not_spam_telegram(self):
        with mock.patch.object(daemon, "load_active", return_value=None):
            d = daemon.Daemon()
        with mock.patch.object(d.emergency, "event") as event:
            d.emergency.tunnel_changed(TunnelSnapshot("CONNECTING", A))
            d.emergency.tunnel_changed(TunnelSnapshot("CHECKING", A))
            event.assert_not_called()
            d.emergency.tunnel_changed(TunnelSnapshot("READY", A))
            d.emergency.tunnel_changed(TunnelSnapshot("READY", A))
            self.assertEqual(event.call_count, 1)
        d.emergency.manager._pool.shutdown(wait=False)

    def test_events_are_logged_without_telegram_delivery(self):
        with mock.patch.object(notifier, "log") as log:
            notifier.notify("offline", topic="network", urgent=True)
            log.warning.assert_called_once()



class ConfigTransactionTests(unittest.TestCase):
    def test_failed_ssh_activation_rolls_back_actual_file_and_clears_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, journal = root / "config.json", root / "transition.json"
            previous = json.dumps({"outbounds": [xray_config._build_proxy_outbound(server(1))]})
            config.write_text(previous)
            info = PlatformInfo("macos", config, [], False)
            with mock.patch.object(daemon, "load_active", return_value=server(1)):
                d = daemon.Daemon(platform=info)
            self.addCleanup(d.emergency.manager._pool.shutdown, wait=False)
            d.network.update(True)
            with mock.patch.object(xray_control, "TRANSACTION_PATH", journal), \
                    mock.patch.object(xray_control, "BACKUP_PATH", root / "backup.json"), \
                    mock.patch.object(xray_control, "validate_config_for_service", return_value=(True, "")), \
                    mock.patch.object(xray_control, "_platform_restart") as restart, \
                    mock.patch.object(xray_control, "wait_for_proxy_port", return_value=True), \
                    mock.patch.object(daemon, "proxy_alive", return_value=False), \
                    mock.patch.object(d.emergency, "event"):
                cfg = json.dumps({"outbounds": [{"tag": "proxy", "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.1", "port": 20808}]}}]})
                self.assertFalse(d._apply_verified_config(cfg, "test SSH"))
                self.assertEqual(config.read_text(), previous)
                self.assertFalse(journal.exists())
                self.assertEqual(restart.call_count, 2)
                self.assertEqual(d.state.transport, "vless")
                self.assertFalse(d._active_channel_ok)  # restored file alone is not healthy traffic

    def test_interrupted_transition_waits_for_network_before_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, journal = root / "config.json", root / "transition.json"
            config.write_text("old")
            info = PlatformInfo("linux", config, [], False)
            with mock.patch.object(xray_control, "TRANSACTION_PATH", journal), \
                    mock.patch.object(xray_control, "BACKUP_PATH", root / "backup.json"), \
                    mock.patch.object(xray_control, "_platform_restart") as restart:
                xray_control._backup_current_config(info, "new")
                config.write_text("new")
                self.assertFalse(xray_control.recover_interrupted_config(info, online=False))
                self.assertEqual(config.read_text(), "new")
                self.assertTrue(journal.exists())
                restart.assert_not_called()

    def test_lost_demand_during_validation_cancels_before_any_write(self):
        info = PlatformInfo("linux", Path("/unused"), [], False)
        with mock.patch.object(xray_control, "validate_config_for_service", return_value=(True, "")), \
                mock.patch.object(xray_control, "_backup_current_config") as backup, \
                mock.patch.object(xray_control, "write_xray_config") as write:
            with self.assertRaises(xray_control.XrayConfigError):
                xray_control.apply_config_text("{}", info=info, should_continue=lambda: False)
            backup.assert_not_called()
            write.assert_not_called()

    def test_backup_failure_never_writes_or_restarts(self):
        info = PlatformInfo("linux", Path("/unused"), [], False)
        with mock.patch.object(xray_control, "validate_config_for_service", return_value=(True, "")), \
                mock.patch.object(xray_control, "_config_matches_current", return_value=False), \
                mock.patch.object(xray_control, "_backup_current_config", side_effect=OSError("disk full")), \
                mock.patch.object(xray_control, "write_xray_config") as write, \
                mock.patch.object(xray_control, "_platform_restart") as restart:
            with self.assertRaises(OSError):
                xray_control.apply_config_text("{}", info=info)
            write.assert_not_called()
            restart.assert_not_called()

    def test_identical_config_starts_a_stopped_listener_on_both_platforms(self):
        for name in ("linux", "macos"):
            info = PlatformInfo(name, Path("/unused"), [], False)
            with self.subTest(platform=name), \
                    mock.patch.object(xray_control, "validate_config_for_service", return_value=(True, "")), \
                    mock.patch.object(xray_control, "_config_matches_current", return_value=True), \
                    mock.patch.object(xray_control, "is_running", return_value=False), \
                    mock.patch.object(xray_control, "_backup_current_config"), \
                    mock.patch.object(xray_control, "write_xray_config"), \
                    mock.patch.object(xray_control, "wait_for_proxy_port", return_value=True), \
                    mock.patch.object(xray_control, "_platform_restart") as restart:
                xray_control.apply_config_text("{}", info=info)
                restart.assert_called_once_with(info)

    def test_interrupted_write_is_restored_from_its_own_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, journal, backup = (root / name for name in ("config.json", "transition.json", "backup.json"))
            config.write_text('{"old":true}')
            info = PlatformInfo("linux", config, [], False)
            with mock.patch.object(xray_control, "TRANSACTION_PATH", journal), \
                    mock.patch.object(xray_control, "BACKUP_PATH", backup), \
                    mock.patch.object(xray_control, "validate_config_for_service", return_value=(True, "")), \
                    mock.patch.object(xray_control, "_platform_restart"), \
                    mock.patch.object(xray_control, "wait_for_proxy_port", return_value=True):
                xray_control._backup_current_config(info, '{"new":true}')
                config.write_text('{"new":true}')
                backup.write_text('{"unrelated":true}')
                self.assertTrue(xray_control.restore_backup(info))
                self.assertEqual(json.loads(config.read_text()), {"old": True})
                self.assertFalse(journal.exists())


class EmergencyConfigTests(unittest.TestCase):
    def test_dry_run_is_read_only_and_does_not_resolve_or_start_ssh(self):
        with mock.patch.object(daemon, "load_active", return_value=None), \
                mock.patch.object(daemon, "notify") as notify:
            d = daemon.Daemon(dry_run=True)
            self.addCleanup(d.emergency.manager._pool.shutdown, wait=False)
            with mock.patch.object(d.emergency.manager, "start") as start, \
                    mock.patch.object(daemon, "internet_alive") as internet, \
                    mock.patch.object(daemon, "expand_servers") as dns:
                d.run_once()
                d.run_forever()
                start.assert_not_called()
                internet.assert_not_called()
                dns.assert_not_called()
                notify.assert_not_called()

    def test_autoupdate_requests_main_thread_handoff_before_exec(self):
        from xproxy import autoupdate
        with mock.patch.object(daemon, "load_active", return_value=None):
            d = daemon.Daemon()
        self.addCleanup(d.emergency.manager._pool.shutdown, wait=False)
        d.network.update(True)
        d._runtime_started = True
        result = autoupdate.UpdateResult(True, old_head="old", new_head="new")
        with mock.patch.object(daemon, "too_many_restarts", return_value=False), \
                mock.patch.object(daemon, "check_and_pull", return_value=result), \
                mock.patch.object(daemon, "validate_new_code", return_value=(True, "")), \
                mock.patch.object(daemon, "notify"), \
                mock.patch.object(daemon, "restart_self") as restart, \
                mock.patch.object(d.emergency.manager, "close") as close:
            d.tick_autoupdate()
            self.assertTrue(d._restart_requested)
            self.assertTrue(d._wake_event.is_set())
            restart.assert_not_called()
            close.assert_not_called()

    def test_ssh_preserves_routing_and_logging_and_uses_tcp_dns(self):
        for dns_type in ("DoU", "DoQ", "DoH", "DoT"):
            with self.subTest(dns=dns_type), \
                    mock.patch.object(routing, "load_routing", return_value={
                        "RemoteDNSType": dns_type, "RemoteDNSIp": "1.1.1.1",
                        "DomesticDNSType": dns_type, "DomesticDNSIp": "8.8.8.8"}), \
                    mock.patch("xproxy.geo.load_geo_categories", return_value={"geosite": set(), "geoip": set()}), \
                    mock.patch.object(routing, "load_direct_extras", return_value=None), \
                    mock.patch.object(xray_config, "load_base_template", return_value={
                        "log": {"error": "/var/log/xray/error.log"}, "inbounds": []}):
                cfg = json.loads(xray_config.build_ssh_config_text(20808))
                self.assertEqual(cfg["outbounds"][0]["protocol"], "socks")
                self.assertEqual(cfg["outbounds"][0]["settings"]["servers"][0]["address"], "127.0.0.1")
                self.assertEqual(cfg["log"]["error"], "/var/log/xray/error.log")
                for dns in cfg["dns"]["servers"]:
                    address = dns["address"] if isinstance(dns, dict) else dns
                    self.assertTrue(address.startswith(("tcp://", "https://", "tls://")), address)

    def test_instance_lock_excludes_a_second_writer_and_releases_on_exit(self):
        from xproxy.instance_lock import InstanceLock
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock"
            with InstanceLock(path):
                with self.assertRaises(RuntimeError):
                    with InstanceLock(path):
                        self.fail("second writer acquired the lease")
            with InstanceLock(path):
                pass


if __name__ == "__main__":
    unittest.main()
