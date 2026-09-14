"""Publication is triggered by a committed VLESS change, never SSH routing."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import replace
from pathlib import Path
from unittest import mock

from xproxy import config_sync, daemon, emergency
from xproxy.emergency import candidate_key
from xproxy.tunnels import TunnelSnapshot
from test_emergency import A, server, slot
from test_review_regressions import ReviewFixture, SSH_CONFIG, vless_config


class ConfigPublicationTests(ReviewFixture):
    def prepare_promotion(self, new):
        prepared = slot(new)
        prepared.config_text = vless_config(new)
        self.d._standby = prepared
        self.patch(daemon, "standby_fingerprint", return_value="fp")
        self.patch(daemon, "apply_config_text")
        self.patch(daemon, "proxy_alive", return_value=True)
        self.patch(daemon, "target_alive", return_value=(True, ""))
        self.patch(daemon, "commit_config")
        return prepared

    def test_changed_vless_is_published_after_checks_and_commit_for_every_reason(self):
        for reason in ("proxy-failing", "target-blocked", "xray-not-running", "ssh-recovery"):
            with self.subTest(reason=reason):
                d = self.d
                d.state.active = None if reason == "ssh-recovery" else server(1)
                d.state.last_vless = server(1)
                d.state.transport = "ssh" if reason == "ssh-recovery" else "vless"
                prepared = self.prepare_promotion(server(2))
                order = []
                self.patch(daemon, "apply_config_text", side_effect=lambda *a, **kw: order.append("apply"))
                self.patch(daemon, "proxy_alive", side_effect=lambda: order.append("proxy") or True)
                self.patch(daemon, "target_alive", side_effect=lambda: (order.append("target") or True, ""))
                self.patch(daemon, "commit_config", side_effect=lambda info: order.append("commit"))
                def publish(**kwargs):
                    order.append("publish")
                    self.assertEqual(d.state.transport, "vless")
                    self.assertEqual(candidate_key(d.state.active), candidate_key(server(2)))
                    self.assertEqual(kwargs["config_text"], prepared.config_text)
                sync = self.patch(daemon, "sync_current_config", side_effect=publish)
                self.assertTrue(d._promote_standby(reason))
                self.assertEqual(order, ["apply", "proxy", "target", "commit", "publish"])
                sync.assert_called_once()

    def test_ssh_recovery_to_previous_vless_does_not_republish(self):
        d = self.d
        d.state.active = None
        d.state.transport = "ssh"
        d.state.last_vless = server(1)
        self.prepare_promotion(server(1))
        sync = self.patch(daemon, "sync_current_config")
        self.assertTrue(d._promote_standby("ssh-recovery"))
        self.assertEqual(d.state.transport, "vless")
        sync.assert_not_called()

    def test_new_credentials_at_same_endpoint_are_published(self):
        updated = replace(server(1), uuid=server(2).uuid, params={"security": "reality", "pbk": "new-key"})
        prepared = self.prepare_promotion(updated)
        sync = self.patch(daemon, "sync_current_config", return_value=None)
        self.assertTrue(self.d._promote_standby("proxy-failing"))
        sync.assert_called_once_with(info=self.info, config_text=prepared.config_text)

    def test_failed_commit_does_not_publish_candidate(self):
        self.prepare_promotion(server(2))
        self.patch(daemon, "commit_config", side_effect=OSError("cannot commit"))
        self.patch(self.d, "_rollback_failed_promotion")
        sync = self.patch(daemon, "sync_current_config")
        self.assertFalse(self.d._promote_standby("proxy-failing"))
        sync.assert_not_called()

    def test_emergency_activation_does_not_schedule_publication(self):
        d = self.d
        snapshot = TunnelSnapshot("READY", A, 20808, time.monotonic())
        self.patch(d.emergency.manager, "snapshot", return_value=snapshot)
        self.patch(d.emergency, "needed", return_value=True)
        self.patch(emergency, "build_ssh_config_text", return_value=SSH_CONFIG)
        self.patch(d, "_apply_verified_config", return_value=True)
        sync = self.patch(d, "_schedule_config_sync_after_vless_change")
        d._record_active_health(False)
        d.emergency._activate(snapshot)
        self.assertEqual(d.state.transport, "ssh")
        sync.assert_not_called()

    def test_cold_rotation_in_once_finishes_sync_after_committing_vless(self):
        d = self.d
        d.state.ranked = [server(2)]
        self.patch(d, "_geo_ready_for_rebuild", return_value=True)
        self.patch(daemon, "public_ips", return_value=("direct", "proxy"))
        self.patch(daemon, "tcp_probe", return_value=True)
        self.patch(daemon, "apply_server", side_effect=lambda s, **kw: self.config.write_text(vless_config(s)))
        self.patch(daemon, "proxy_alive", return_value=True)
        self.patch(daemon, "target_alive", return_value=(True, ""))
        commit = self.patch(daemon, "commit_config")
        def publish(**kwargs):
            commit.assert_called_once()
            self.assertEqual(kwargs["config_text"], vless_config(server(2)))
            self.assertTrue(d._active_channel_ok)
        sync = self.patch(daemon, "sync_current_config", side_effect=publish)
        thread = self.patch(daemon.threading, "Thread")
        d._rotate_until_working("proxy-failing")
        sync.assert_called_once()
        thread.assert_not_called()  # --once returns only after the copy finishes

    def test_health_standby_refresh_and_same_upstream_rebuild_do_not_publish(self):
        d = self.d
        self.patch(daemon, "is_running", return_value=True)
        self.patch(daemon, "proxy_alive", return_value=True)
        self.patch(daemon, "target_alive", return_value=(True, ""))
        self.patch(d, "_geo_ready_for_rebuild", return_value=True)
        self.patch(daemon, "build_xray_config_text", return_value=vless_config(server(1)))
        self.patch(d, "_apply_verified_config", return_value=True)
        sync = self.patch(daemon, "sync_current_config")
        with d._standby_cond:
            d._publish_standby_locked(slot(server(2)))
        d.tick_health(has_internet=True)
        d._rebuild_config_if_active()
        sync.assert_not_called()

    def test_queued_publication_is_dropped_if_ssh_or_another_vless_is_now_active(self):
        for active in (None, server(3)):
            with self.subTest(active=active):
                d = self.d
                d._runtime_started = True
                d.state.active, d.state.transport = server(2), "vless"
                sync = self.patch(daemon, "sync_current_config")
                thread = self.patch(daemon.threading, "Thread")
                d._schedule_config_sync_after_vless_change(
                    reason="proxy-failing", previous=server(1), promoted=server(2),
                    config_text=vless_config(server(2)),
                )
                thread.return_value.start.assert_called_once()
                d.state.active, d.state.transport = active, "vless" if active else "ssh"
                thread.call_args.kwargs["target"]()
                sync.assert_not_called()

    def test_concurrent_changes_publish_in_order_and_coalesce_waiting_versions(self):
        d = self.d
        d._runtime_started = True
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        published, errors = [], []
        def publish(**kwargs):
            try:
                text = kwargs["config_text"]
                if text == vless_config(server(2)):
                    entered.set()
                    if not release.wait(2):
                        raise AssertionError("SCP was not released")
                published.append(text)
                if text == vless_config(server(4)):
                    done.set()
            except BaseException as exc:
                errors.append(exc)
                raise
        self.patch(daemon, "sync_current_config", side_effect=publish)
        def schedule(n):
            d.state.active = server(n)
            d._schedule_config_sync_after_vless_change(
                reason="proxy-failing", previous=server(n - 1), promoted=server(n),
                config_text=vless_config(server(n)),
            )
        schedule(2)
        worker = d._config_sync_thread
        try:
            self.assertTrue(entered.wait(2))
            schedule(3)
            schedule(4)
            self.assertIs(d._config_sync_thread, worker)
            release.set()
            self.assertTrue(done.wait(2))
        finally:
            release.set()
            d._finish_config_sync()
        self.assertEqual(errors, [])
        self.assertFalse(worker.is_alive())
        self.assertEqual(published, [vless_config(server(2)), vless_config(server(4))])

    def test_scp_filters_emergency_config_and_uses_frozen_vless_snapshot_on_both_platforms(self):
        path = self.root / "sync.json"
        path.write_text(json.dumps({"host": "192.0.2.100", "port": 22, "user": "test", "path": "/srv/config.json"}))
        scp = self.patch(config_sync, "_run_scp", return_value="")
        self.patch(config_sync.shutil, "which", return_value="/usr/bin/scp")
        vless = vless_config(server(2))
        for name in ("linux", "macos"):
            info = replace(self.info, name=name)
            self.config.write_text(SSH_CONFIG)
            for payload in (None, SSH_CONFIG,
                    json.dumps({"outbounds": json.loads(vless)["outbounds"] + json.loads(SSH_CONFIG)["outbounds"]})):
                with self.subTest(platform=name, payload=payload):
                    self.assertIsNone(config_sync.sync_current_config(info=info, sync_path=path, config_text=payload))
                    scp.assert_not_called()
            copied = []
            scp.side_effect = lambda snapshot, *a, **kw: copied.append(Path(snapshot).read_text()) or ""
            self.assertIsNotNone(config_sync.sync_current_config(info=info, sync_path=path, config_text=vless))
            self.assertEqual(copied, [vless])
            scp.reset_mock()
