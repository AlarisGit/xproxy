from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from xproxy.platform_utils import _atomic_write_direct
from xproxy.routing import load_routing, validate_geo_categories_for_routing
from xproxy.geo import parse_geo_ref
from xproxy.servers import Server


class FailSafeTests(unittest.TestCase):
    def test_strict_geo_validation_reports_missing_route_category(self) -> None:
        routing = load_routing()
        geosite = set()
        geoip = set()
        for key in ("DirectSites", "ProxySites", "BlockSites"):
            for item in routing.get(key) or []:
                kind, code = parse_geo_ref(item)
                if kind == "geosite" and code:
                    geosite.add(code)
        for key in ("DirectIp", "ProxyIp", "BlockIp"):
            for item in routing.get(key) or []:
                kind, code = parse_geo_ref(item)
                if kind == "geoip" and code:
                    geoip.add(code)
        geosite.add("category-ru")
        geoip.add("ru")
        geosite.discard("category-medicine-ru")

        missing = validate_geo_categories_for_routing({
            "geosite": geosite,
            "geoip": geoip,
        })

        self.assertIn(("direct", "geosite:category-medicine-ru"), missing)

    def test_direct_list_entries_split_into_ip_and_domain_routes(self) -> None:
        from xproxy.routing import load_direct_extras

        with tempfile.TemporaryDirectory() as tmp_s:
            path = Path(tmp_s) / "direct.lst"
            path.write_text(
                "\n".join([
                    "example.com",
                    "80.67.40.0/22",
                    "2001:db8::1",
                    "example.com",
                    "# comment",
                ]),
                encoding="utf-8",
            )

            extras = load_direct_extras(path)

        self.assertEqual(extras.ips, ["80.67.40.0/22", "2001:db8::1"])
        self.assertEqual(extras.sites, ["example.com", "example.com"])

    def test_routing_onadd_link_merges_direct_list_without_duplicates(self) -> None:
        import base64
        import json
        from xproxy.routing_link import (
            HAPP_ROUTING_ONADD_PREFIX,
            build_routing_onadd_link,
        )

        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            routing_path = tmp / "routing.json"
            direct_path = tmp / "direct.lst"
            routing_path.write_text(
                json.dumps({
                    "Name": "test",
                    "DirectIp": ["10.0.0.0/8"],
                    "DirectSites": ["example.com"],
                }),
                encoding="utf-8",
            )
            direct_path.write_text(
                "\n".join([
                    "example.com",
                    "new.example",
                    "10.0.0.0/8",
                    "192.0.2.0/24",
                ]),
                encoding="utf-8",
            )

            link = build_routing_onadd_link(routing_path, direct_path)

        self.assertTrue(link.startswith(HAPP_ROUTING_ONADD_PREFIX))
        encoded = link.removeprefix(HAPP_ROUTING_ONADD_PREFIX)
        payload = base64.b64decode(encoded).decode("utf-8")
        self.assertNotIn("\n", payload)
        merged = json.loads(payload)
        self.assertEqual(merged["DirectIp"], ["10.0.0.0/8", "192.0.2.0/24"])
        self.assertEqual(merged["DirectSites"], ["example.com", "new.example"])

    def test_direct_list_rejects_invalid_ip_entries(self) -> None:
        from xproxy.routing import load_direct_extras

        with tempfile.TemporaryDirectory() as tmp_s:
            path = Path(tmp_s) / "direct.lst"
            path.write_text("999.999.999.999\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "invalid IP address"):
                load_direct_extras(path)

    def test_staged_geo_publish_is_blocked_on_missing_category(self) -> None:
        from xproxy import geo

        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            live = tmp / "geosite.dat"
            live.write_text("old", encoding="utf-8")

            def fake_download(_url: str, target: Path) -> None:
                target.write_text("new", encoding="utf-8")

            errors: dict[str, str] = {}
            with mock.patch.object(geo, "GEO_DIR", tmp), \
                    mock.patch.object(geo, "_download", side_effect=fake_download), \
                    mock.patch.object(geo, "load_geo_categories", return_value={
                        "geosite": set(),
                        "geoip": {"ru", "private"},
                    }):
                published = geo._stage_and_validate_geo(
                    [("geosite.dat", "https://example.invalid/geosite.dat", live, {})],
                    validation_server=None,
                    platform_info=None,
                    errors=errors,
                )

            self.assertEqual(published, set())
            self.assertEqual(live.read_text(encoding="utf-8"), "old")
            self.assertIn("geo-set", errors)

    def test_geo_download_falls_back_to_xray_http_route(self) -> None:
        from xproxy import geo

        with tempfile.TemporaryDirectory() as tmp_s:
            target = Path(tmp_s) / "geosite.dat"
            calls = []

            def fake_download_once(_url: str, route_target: Path, route) -> None:
                calls.append(route.name)
                if route.name == "direct":
                    raise IOError("direct timed out")
                route_target.write_bytes(b"ok")

            with mock.patch.object(
                geo,
                "_download_via_route",
                side_effect=fake_download_once,
            ):
                geo._download("https://example.invalid/geosite.dat", target)

            self.assertEqual(calls, ["direct", "xray-http"])
            self.assertEqual(target.read_bytes(), b"ok")

    def test_atomic_write_direct_replaces_complete_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_s:
            path = Path(tmp_s) / "config.json"
            _atomic_write_direct(path, "old")
            _atomic_write_direct(path, "new")

            self.assertEqual(path.read_text(encoding="utf-8"), "new")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_sudo_config_write_falls_back_to_legacy_sudoers(self) -> None:
        from xproxy import platform_utils
        from xproxy.platform_utils import PlatformInfo

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:3] == ["sudo", "-n", "tee"] and cmd[-1].endswith(".tmp"):
                return mock.Mock(returncode=1, stderr=b"not allowed", stdout=b"")
            return mock.Mock(returncode=0, stderr=b"", stdout=b"")

        with tempfile.TemporaryDirectory() as tmp_s, \
                mock.patch.object(platform_utils, "_atomic_write_direct",
                                  side_effect=OSError("denied")), \
                mock.patch.object(platform_utils.shutil, "which", return_value="/usr/bin/sudo"), \
                mock.patch.object(platform_utils.subprocess, "run",
                                  side_effect=fake_run):
            info = PlatformInfo(
                name="linux",
                xray_config=Path(tmp_s) / "config.json",
                restart_cmd=[],
                needs_sudo_write=True,
            )
            platform_utils.write_xray_config("{}", info)

        self.assertEqual(calls[0][:3], ["sudo", "-n", "tee"])
        self.assertTrue(calls[0][-1].endswith(".tmp"))
        self.assertEqual(calls[1], ["sudo", "-n", "tee", str(info.xray_config)])

    def test_validate_config_text_uses_explicit_asset_dir(self) -> None:
        from xproxy import xray_control

        seen = {}

        def fake_run(_text: str, *, env: dict[str, str]):
            seen["asset"] = env.get("XRAY_LOCATION_ASSET")
            return True, "ok"

        with tempfile.TemporaryDirectory() as tmp_s, \
                mock.patch.object(xray_control, "_run_xray_test", side_effect=fake_run):
            ok, _out = xray_control.validate_config_text(
                "{}",
                asset_dir=Path(tmp_s),
            )

        self.assertTrue(ok)
        self.assertEqual(seen["asset"], tmp_s)

    def test_validate_config_for_service_skips_service_test_when_asset_unknown(self) -> None:
        """When XRAY_LOCATION_ASSET is undetectable, skip service env test.

        Testing without the variable makes xray fall back to its built-in
        geosite.dat, which may lack custom categories — the test would fail
        even though the config is valid with xproxy's managed assets.
        """
        from xproxy import xray_control

        calls = []

        def fake_run(_text: str, *, env: dict[str, str]):
            calls.append(env.get("XRAY_LOCATION_ASSET"))
            return True, "ok"

        with mock.patch.object(xray_control, "_run_xray_test", side_effect=fake_run), \
                mock.patch.object(xray_control, "detect_xray_asset_env",
                                  return_value=(None, "test service env")):
            ok, out = xray_control.validate_config_for_service("{}")

        self.assertTrue(ok)
        # Only managed test runs; service test is skipped.
        self.assertEqual(len(calls), 1)

    def test_validate_config_for_service_fails_on_prod_env_mismatch(self) -> None:
        from xproxy import xray_control

        calls = []

        def fake_run(_text: str, *, env: dict[str, str]):
            calls.append(env.get("XRAY_LOCATION_ASSET"))
            if len(calls) == 1:
                return True, "managed ok"
            return False, "prod failed"

        with mock.patch.object(xray_control, "_run_xray_test", side_effect=fake_run), \
                mock.patch.object(xray_control, "detect_xray_asset_env",
                                  return_value=("/different/asset/dir", "test service env")):
            ok, out = xray_control.validate_config_for_service("{}")

        self.assertFalse(ok)
        self.assertIn("production xray validation failed", out)
        self.assertEqual(len(calls), 2)

    def test_validate_config_for_service_normalizes_matching_asset_paths(self) -> None:
        from xproxy import xray_control

        calls = []

        def fake_run(_text: str, *, env: dict[str, str]):
            calls.append(env.get("XRAY_LOCATION_ASSET"))
            return True, "ok"

        with tempfile.TemporaryDirectory() as tmp_s, \
                mock.patch.object(xray_control, "GEO_DIR", Path(tmp_s)), \
                mock.patch.object(xray_control, "_run_xray_test", side_effect=fake_run), \
                mock.patch.object(xray_control, "detect_xray_asset_env",
                                  return_value=(tmp_s + "/", "test service env")):
            ok, _out = xray_control.validate_config_for_service("{}")

        self.assertTrue(ok)
        self.assertEqual(calls, [tmp_s])

    def test_tail_configured_error_log_prefers_relevant_lines(self) -> None:
        from xproxy import xray_control

        with tempfile.TemporaryDirectory() as tmp_s:
            log_path = Path(tmp_s) / "error.log"
            log_path.write_text(
                "\n".join([
                    "old info",
                    "start failed: missing geosite",
                    "runtime noise",
                    "warning: retrying",
                    "last info",
                ]),
                encoding="utf-8",
            )
            cfg = f'{{"log": {{"error": "{log_path}"}}}}'

            tail = xray_control._tail_configured_error_log(cfg)

        self.assertIn("start failed: missing geosite", tail)
        self.assertIn("warning: retrying", tail)
        self.assertNotIn("last info", tail)

    def test_parse_env_assignment_handles_systemd_quoting(self) -> None:
        from xproxy.platform_utils import _parse_env_assignment

        self.assertEqual(
            _parse_env_assignment(
                "XRAY_LOCATION_ASSET=/usr/local/share/xray",
                "XRAY_LOCATION_ASSET",
            ),
            "/usr/local/share/xray",
        )
        self.assertEqual(
            _parse_env_assignment(
                "XRAY_LOCATION_ASSET=/usr/local/share/xray/ FOO=bar",
                "XRAY_LOCATION_ASSET",
            ),
            "/usr/local/share/xray/",
        )
        self.assertEqual(
            _parse_env_assignment(
                'XRAY_LOCATION_ASSET="/path with spaces/" FOO=bar',
                "XRAY_LOCATION_ASSET",
            ),
            "/path with spaces/",
        )
        self.assertEqual(
            _parse_env_assignment(
                'Environment=FOO=bar XRAY_LOCATION_ASSET="/path with spaces/"',
                "XRAY_LOCATION_ASSET",
            ),
            "/path with spaces/",
        )

    def test_autoupdate_continues_when_only_deploy_files_changed(self) -> None:
        from xproxy import daemon
        from xproxy.autoupdate import UpdateResult

        d = daemon.Daemon(dry_run=False)
        result = UpdateResult(
            updated=True,
            old_head="1111111111111111111111111111111111111111",
            new_head="2222222222222222222222222222222222222222",
            manual_deploy_changed=True,
            reason="ok",
        )

        with mock.patch.object(daemon, "too_many_restarts", return_value=False), \
                mock.patch.object(daemon, "check_and_pull", return_value=result), \
                mock.patch.object(daemon, "validate_new_code", return_value=(True, "")) as validate_mock, \
                mock.patch.object(daemon, "restart_self") as restart_mock, \
                mock.patch.object(daemon, "notify") as notify_mock:
            d.tick_autoupdate()

        validate_mock.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(notify_mock.call_count, 2)

    def test_autoupdate_installs_requirements_before_restart(self) -> None:
        from xproxy import daemon
        from xproxy.autoupdate import UpdateResult

        d = daemon.Daemon(dry_run=False)
        result = UpdateResult(
            updated=True,
            old_head="1111111111111111111111111111111111111111",
            new_head="2222222222222222222222222222222222222222",
            requirements_changed=True,
            reason="ok",
        )

        with mock.patch.object(daemon, "too_many_restarts", return_value=False), \
                mock.patch.object(daemon, "check_and_pull", return_value=result), \
                mock.patch.object(daemon, "install_requirements",
                                  return_value=(True, "")) as install_mock, \
                mock.patch.object(daemon, "validate_new_code",
                                  return_value=(True, "")) as validate_mock, \
                mock.patch.object(daemon, "restart_self") as restart_mock, \
                mock.patch.object(daemon, "notify"):
            d.tick_autoupdate()

        install_mock.assert_called_once()
        validate_mock.assert_called_once()
        restart_mock.assert_called_once()

    def test_autoupdate_rolls_back_when_requirements_install_fails(self) -> None:
        from xproxy import daemon
        from xproxy.autoupdate import UpdateResult

        d = daemon.Daemon(dry_run=False)
        result = UpdateResult(
            updated=True,
            old_head="1111111111111111111111111111111111111111",
            new_head="2222222222222222222222222222222222222222",
            requirements_changed=True,
            reason="ok",
        )

        with mock.patch.object(daemon, "too_many_restarts", return_value=False), \
                mock.patch.object(daemon, "check_and_pull", return_value=result), \
                mock.patch.object(daemon, "install_requirements",
                                  return_value=(False, "no matching distribution")), \
                mock.patch.object(daemon, "validate_new_code") as validate_mock, \
                mock.patch.object(daemon, "rollback_to",
                                  return_value=True) as rollback_mock, \
                mock.patch.object(daemon, "restart_self") as restart_mock, \
                mock.patch.object(daemon, "notify"):
            d.tick_autoupdate()

        validate_mock.assert_not_called()
        restart_mock.assert_not_called()
        rollback_mock.assert_called_once_with(result.old_head)

    def test_rotation_aborts_on_xray_start_error(self) -> None:
        from xproxy import daemon
        from xproxy.xray_control import XrayStartError

        srv = Server(
            uri="test",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="example.com",
            port=443,
            country="Test",
        )
        d = daemon.Daemon(dry_run=False)
        d.state.ranked = [srv]

        with mock.patch.object(d, "_geo_ready_for_rebuild", return_value=True), \
                mock.patch.object(daemon, "public_ips", return_value=("1.1.1.1", None)), \
                mock.patch.object(daemon, "tcp_probe", return_value=True), \
                mock.patch.object(daemon, "apply_server", side_effect=XrayStartError("boom")) as apply_mock, \
                mock.patch.object(daemon, "notify"):
            d._rotate_until_working("xray-not-running")

        self.assertEqual(apply_mock.call_count, 1)
        self.assertEqual(d.state.penalized_keys(), {})

    def test_proxy_alive_uses_custom_socks_endpoint(self) -> None:
        from xproxy import healthcheck

        with mock.patch.object(healthcheck, "_any_probe",
                               return_value="203.0.113.1") as any_probe:
            ok = healthcheck.proxy_alive(
                socks_host="127.0.0.1",
                socks_port=11808,
            )

        self.assertTrue(ok)
        self.assertEqual(
            any_probe.call_args.kwargs["proxies"],
            {
                "http": "socks5h://127.0.0.1:11808",
                "https": "socks5h://127.0.0.1:11808",
            },
        )

    def test_standby_test_config_rewrites_inbounds_and_logs(self) -> None:
        import json
        from xproxy.standby import build_standby_test_config_text

        prod = json.dumps({
            "log": {
                "access": "/var/log/xray/access.log",
                "error": "/var/log/xray/error.log",
            },
            "inbounds": [
                {
                    "tag": "socks-in",
                    "listen": "0.0.0.0",
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"auth": "noauth"},
                },
                {
                    "tag": "http-in",
                    "listen": "0.0.0.0",
                    "port": 10809,
                    "protocol": "http",
                    "settings": {"timeout": 300},
                },
            ],
            "outbounds": [],
        })

        test_text = build_standby_test_config_text(
            prod,
            socks_port=11808,
            http_port=11809,
        )
        cfg = json.loads(test_text)

        self.assertEqual(cfg["log"]["access"], "none")
        self.assertEqual(cfg["log"]["error"], "none")
        ports = {i["tag"]: i["port"] for i in cfg["inbounds"]}
        listens = {i["tag"]: i["listen"] for i in cfg["inbounds"]}
        self.assertEqual(ports["socks-in"], 11808)
        self.assertEqual(ports["http-in"], 11809)
        self.assertEqual(listens["socks-in"], "127.0.0.1")
        self.assertEqual(listens["http-in"], "127.0.0.1")

    def test_pre_stale_standby_is_usable_but_needs_refresh(self) -> None:
        from xproxy.standby import PreparedStandby

        srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
        )

        self.assertEqual(prepared.lifecycle_state(), "PRE_STALE")
        self.assertFalse(prepared.is_ready())
        self.assertTrue(prepared.is_usable())
        self.assertTrue(prepared.needs_refresh())

    def test_prepare_standby_rejects_fingerprint_drift(self) -> None:
        from xproxy import standby
        from xproxy.standby import StandbyError

        srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )

        with mock.patch.object(standby, "tcp_probe", return_value=True), \
                mock.patch.object(standby, "build_xray_config_text",
                                  return_value='{"inbounds":[],"outbounds":[]}'), \
                mock.patch.object(standby, "validate_config_for_service",
                                  return_value=(True, "ok")), \
                mock.patch.object(standby, "validate_standby_end_to_end"), \
                mock.patch.object(standby, "standby_fingerprint",
                                  side_effect=["before", "after"]):
            with self.assertRaisesRegex(StandbyError, "inputs changed"):
                standby.prepare_standby(srv)

    def test_standby_fingerprint_ignores_subscription_metadata(self) -> None:
        from xproxy import standby

        base = Server(
            uri="vless://token@standby.example.com:443?security=reality#Old",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            params={"security": "reality", "pbk": "public-key", "fp": "chrome"},
            fragment="Old label",
            country="Old Country",
            rank=10,
            resolved_ip="203.0.113.10",
        )
        relabeled = Server(
            uri="vless://token@standby.example.com:443?security=reality#New",
            protocol="vless",
            uuid=base.uuid,
            host=base.host,
            port=base.port,
            params=dict(base.params),
            fragment="New label",
            country="New Country",
            rank=20,
            resolved_ip=base.resolved_ip,
        )

        with mock.patch.object(standby, "detect_xray_asset_env",
                               return_value=("/var/lib/xproxy/geo", "test")), \
                mock.patch.object(standby, "_file_fingerprint",
                                  return_value={"exists": True, "size": 1, "mtime_ns": 1}):
            self.assertEqual(
                standby.standby_fingerprint(base),
                standby.standby_fingerprint(relabeled),
            )

    def test_pre_stale_standby_is_revalidated_before_replacement_search(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        replacement = Server(
            uri="replacement",
            protocol="vless",
            uuid="33333333-3333-3333-3333-333333333333",
            host="replacement.example.com",
            port=443,
            country="Replacement",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d.state.ranked = [active, standby_srv, replacement]
        d._standby = prepared
        d._standby_last_attempt = 0

        with d._standby_cond:
            candidate = d._select_standby_candidate_locked()

        self.assertEqual(candidate, standby_srv)
        self.assertIs(d._standby, prepared)
        self.assertTrue(d._standby.is_usable())

    def test_failed_current_standby_revalidation_discards_slot(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
            status="PRE_STALE",
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared
        d._standby_last_attempt = time.time()

        with d._standby_cond:
            discarded = d._discard_current_standby_locked(
                standby_srv,
                "test failure",
            )

        self.assertTrue(discarded)
        self.assertIsNone(d._standby)
        self.assertEqual(d._standby_last_attempt, 0)

    def test_stale_generation_standby_publish_is_discarded(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 60,
            expires_at=now + 120,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby_generation = 2

        with mock.patch.object(daemon, "notify") as notify_mock:
            with d._standby_cond:
                published = d._publish_standby_locked(prepared, generation=1)

        self.assertFalse(published)
        self.assertIsNone(d._standby)
        notify_mock.assert_not_called()

    def test_penalty_is_skipped_for_active_server(self) -> None:
        from xproxy import daemon

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active

        penalized = d._penalize_if_not_active(active, "test")

        self.assertFalse(penalized)
        self.assertEqual(d.state.penalized_keys(), {})

    def test_standby_candidate_prefers_country_different_from_active(self) -> None:
        from xproxy import daemon

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Germany",
        )
        same_country = Server(
            uri="same-country",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="same-country.example.com",
            port=443,
            country="Germany",
        )
        other_country = Server(
            uri="other-country",
            protocol="vless",
            uuid="33333333-3333-3333-3333-333333333333",
            host="other-country.example.com",
            port=443,
            country="Austria",
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d.state.ranked = [same_country, other_country]
        d._standby_last_attempt = 0

        with d._standby_cond:
            candidate = d._select_standby_candidate_locked()

        self.assertEqual(candidate, other_country)

    def test_standby_candidate_falls_back_to_active_country(self) -> None:
        from xproxy import daemon

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Germany",
        )
        same_country = Server(
            uri="same-country",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="same-country.example.com",
            port=443,
            country="Germany",
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d.state.ranked = [same_country]
        d._standby_last_attempt = 0

        with d._standby_cond:
            candidate = d._select_standby_candidate_locked()

        self.assertEqual(candidate, same_country)

    def test_same_standby_slot_refresh_is_not_notified(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        previous = PreparedStandby(
            server=srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
            status="PRE_STALE",
        )
        refreshed = PreparedStandby(
            server=srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 60,
            expires_at=now + 120,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = previous

        with mock.patch.object(daemon, "notify") as notify_mock:
            with d._standby_cond:
                d._publish_standby_locked(refreshed)

        self.assertIs(d._standby, refreshed)
        notify_mock.assert_not_called()

    def test_same_standby_endpoint_after_empty_slot_is_notified(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        srv = Server(
            uri="standby-refreshed",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        previous = PreparedStandby(
            server=srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="old-fingerprint",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
            status="PRE_STALE",
        )
        refreshed = PreparedStandby(
            server=srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="new-fingerprint",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 60,
            expires_at=now + 120,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = previous
        d._notified_standby_slot_key = srv.key()

        with mock.patch.object(daemon, "notify") as notify_mock:
            with d._standby_cond:
                d._invalidate_standby_locked("test-empty")
                d._publish_standby_locked(refreshed)

        self.assertIs(d._standby, refreshed)
        messages = [call.args[0] for call in notify_mock.call_args_list]
        self.assertEqual(len(messages), 2)
        self.assertIn(
            "🟠 standby EMPTY: Standby (standby.example.com:443) "
            "reason=test-empty — no usable standby",
            messages,
        )
        self.assertIn(
            "🟢 standby READY: Standby (standby.example.com:443)",
            messages[1],
        )

    def test_standby_slot_replacement_is_notified(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        old_srv = Server(
            uri="old",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="old.example.com",
            port=443,
            country="Old",
        )
        new_srv = Server(
            uri="new",
            protocol="vless",
            uuid="33333333-3333-3333-3333-333333333333",
            host="new.example.com",
            port=443,
            country="New",
        )
        now = time.time()
        previous = PreparedStandby(
            server=old_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="old-fingerprint",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
            status="PRE_STALE",
        )
        replacement = PreparedStandby(
            server=new_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="new-fingerprint",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 60,
            expires_at=now + 120,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = previous

        with mock.patch.object(daemon, "notify") as notify_mock:
            with d._standby_cond:
                d._publish_standby_locked(replacement)

        messages = [call.args[0] for call in notify_mock.call_args_list]
        self.assertEqual(len(messages), 1)
        self.assertIn("🟢 standby READY: New (new.example.com:443)", messages[0])
        self.assertIn("replaced=Old (old.example.com:443)", messages[0])

    def test_daemon_promotes_ready_standby(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d._standby = prepared
        d._notified_standby_slot_key = standby_srv.key()

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text") as apply_mock, \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(daemon, "notify") as notify_mock, \
                mock.patch("xproxy.state._save_active"):
            promoted = d._promote_standby("test-reason")

        self.assertTrue(promoted)
        apply_mock.assert_called_once()
        self.assertEqual(d.state.active, standby_srv)
        self.assertIsNone(d._standby)
        messages = [call.args[0] for call in notify_mock.call_args_list]
        self.assertIn(
            "🔄 standby PROMOTING: Standby (standby.example.com:443) "
            "reason=test-reason — from=READY",
            messages,
        )
        self.assertIn(
            "🔄 active PROMOTING: Active (active.example.com:443) "
            "reason=test-reason — next=Standby (standby.example.com:443)",
            messages,
        )
        self.assertIn(
            "🔄 standby promoted Active → Standby (standby.example.com:443) "
            "reason=test-reason",
            messages,
        )
        self.assertIn(
            "🟢 active OK: Standby (standby.example.com:443) "
            "reason=promoted:test-reason",
            messages,
        )
        self.assertIn(
            "🟠 standby EMPTY: Standby (standby.example.com:443) "
            "reason=test-reason — slot consumed by promotion",
            messages,
        )

    def test_daemon_promotes_pre_stale_standby(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now - 120,
            last_ok_at=now - 120,
            pre_stale_at=now - 1,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d._standby = prepared

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text") as apply_mock, \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(daemon, "notify") as notify_mock, \
                mock.patch("xproxy.state._save_active"):
            promoted = d._promote_standby("test-reason")

        self.assertTrue(promoted)
        apply_mock.assert_called_once()
        messages = [call.args[0] for call in notify_mock.call_args_list]
        self.assertIn(
            "🔄 standby PROMOTING: Standby (standby.example.com:443) "
            "reason=test-reason — from=PRE_STALE",
            messages,
        )

    def test_ready_standby_promotion_bypasses_rotation_cooldown(self) -> None:
        from xproxy import daemon
        from xproxy.settings import STANDBY_FAIL_THRESHOLD

        d = daemon.Daemon(dry_run=False)
        d.state.last_rotation = time.time()

        with mock.patch.object(daemon, "is_running", return_value=True), \
                mock.patch.object(daemon, "internet_alive", return_value=True), \
                mock.patch.object(daemon, "proxy_alive", return_value=False), \
                mock.patch.object(d, "_standby_ready_for_fast_path",
                                  return_value=True), \
                mock.patch.object(d, "_handle_rotation_needed") as handle_mock:
            d.tick_health()

        self.assertEqual(d.state.consecutive_proxy_failures, STANDBY_FAIL_THRESHOLD)
        handle_mock.assert_called_once_with(reason="proxy-failing")

    def test_standby_promotion_bypasses_cold_rotation_cooldown(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d.state.last_rotation = time.time()
        d._last_cold_rotation_attempt = time.time()

        with mock.patch.object(d, "_promote_standby", return_value=True) as promote_mock, \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("proxy-failing")

        promote_mock.assert_called_once_with("proxy-failing")
        waiting_mock.assert_not_called()
        rotate_mock.assert_not_called()

    def test_active_failure_without_standby_uses_cold_rotation_fallback(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d.state.consecutive_proxy_failures = 5

        with mock.patch.object(d, "_promote_standby", return_value=False), \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("proxy-failing")

        waiting_mock.assert_called_once_with("proxy-failing")
        rotate_mock.assert_called_once_with(reason="proxy-failing")

    def test_cold_rotation_fallback_respects_recent_attempt_cooldown(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d.state.active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        d._last_cold_rotation_attempt = time.time()
        d.state.consecutive_proxy_failures = 5

        with mock.patch.object(d, "_promote_standby", return_value=False), \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("proxy-failing")

        waiting_mock.assert_called_once_with("proxy-failing")
        rotate_mock.assert_not_called()

    def test_cold_rotation_fallback_respects_recent_successful_rotation(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d.state.active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        d.state.last_rotation = time.time()
        d.state.consecutive_proxy_failures = 5

        with mock.patch.object(d, "_promote_standby", return_value=False), \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("target-blocked")

        waiting_mock.assert_called_once_with("target-blocked")
        rotate_mock.assert_not_called()

    def test_xray_not_running_bypasses_cold_rotation_cooldown(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d._last_cold_rotation_attempt = time.time()
        d.state.last_rotation = time.time()

        with mock.patch.object(d, "_promote_standby", return_value=False), \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("xray-not-running")

        waiting_mock.assert_called_once_with("xray-not-running")
        rotate_mock.assert_called_once_with(reason="xray-not-running")

    def test_active_recovery_clears_waiting_for_standby(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d.state.consecutive_proxy_failures = 3
        with d._standby_cond:
            d._active_waiting_for_standby = True
            d._active_waiting_reason = "proxy-failing"
            d._active_waiting_generation = 7

        with mock.patch.object(daemon, "is_running", return_value=True), \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(daemon, "notify"):
            d.tick_health(has_internet=True)

        self.assertFalse(d._active_waiting_for_standby)
        self.assertEqual(d._active_waiting_reason, "")
        self.assertEqual(d._active_waiting_generation, 8)
        self.assertEqual(d.state.consecutive_proxy_failures, 0)

    def test_stale_wait_generation_does_not_promote_standby(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared
        d._active_waiting_for_standby = False
        d._active_waiting_generation = 2

        with mock.patch.object(daemon, "apply_config_text") as apply_mock:
            promoted = d._promote_standby(
                "standby-ready",
                expected_wait_generation=1,
                require_active_failure=True,
            )

        self.assertFalse(promoted)
        apply_mock.assert_not_called()
        self.assertIs(d._standby, prepared)

    def test_worker_promotion_recheck_keeps_ready_standby_if_active_recovered(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared
        d._active_waiting_for_standby = True
        d._active_waiting_reason = "proxy-failing"
        d._active_waiting_generation = 1

        with mock.patch.object(daemon, "is_running", return_value=True), \
                mock.patch.object(daemon, "internet_alive", return_value=True), \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(daemon, "apply_config_text") as apply_mock:
            promoted = d._promote_standby(
                "proxy-failing",
                expected_wait_generation=1,
                require_active_failure=True,
            )

        self.assertFalse(promoted)
        apply_mock.assert_not_called()
        self.assertIs(d._standby, prepared)
        self.assertFalse(d._active_waiting_for_standby)

    def test_promotion_in_progress_blocks_health_rotation(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d._promotion_in_progress = True

        with mock.patch.object(d, "_promote_standby") as promote_mock, \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("xray-not-running")

        promote_mock.assert_not_called()
        waiting_mock.assert_not_called()
        rotate_mock.assert_not_called()

    def test_stale_proxy_failure_request_after_switch_does_not_enter_waiting(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)
        d.state.consecutive_proxy_failures = 5

        def promote_side_effect(_reason: str) -> bool:
            d.state.note_proxy_ok()
            return False

        with mock.patch.object(d, "_promote_standby",
                               side_effect=promote_side_effect), \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("proxy-failing")

        waiting_mock.assert_not_called()
        rotate_mock.assert_not_called()

    def test_stale_xray_not_running_request_after_recovery_does_not_rotate(self) -> None:
        from xproxy import daemon

        d = daemon.Daemon(dry_run=False)

        with mock.patch.object(d, "_promote_standby", return_value=False), \
                mock.patch.object(daemon, "is_running", return_value=True), \
                mock.patch.object(d, "_enter_waiting_for_standby") as waiting_mock, \
                mock.patch.object(d, "_rotate_until_working") as rotate_mock:
            d._handle_rotation_needed("xray-not-running")

        waiting_mock.assert_not_called()
        rotate_mock.assert_not_called()

    def test_promotion_flag_is_visible_during_apply(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d._standby = prepared

        def apply_side_effect(*_args, **_kwargs):
            self.assertTrue(d._promotion_in_progress)
            with mock.patch.object(d, "_rotate_until_working") as rotate_mock:
                d._handle_rotation_needed("xray-not-running")
            rotate_mock.assert_not_called()

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text",
                                  side_effect=apply_side_effect), \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(d, "_schedule_config_sync_after_promotion"), \
                mock.patch.object(daemon, "notify"), \
                mock.patch("xproxy.state._save_active"):
            promoted = d._promote_standby("proxy-failing")

        self.assertTrue(promoted)
        self.assertFalse(d._promotion_in_progress)

    def test_waiting_standby_selection_backs_off_after_candidate_pass(self) -> None:
        from xproxy import daemon

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        one = Server(
            uri="one",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="one.example.com",
            port=443,
            country="One",
        )
        two = Server(
            uri="two",
            protocol="vless",
            uuid="33333333-3333-3333-3333-333333333333",
            host="two.example.com",
            port=443,
            country="Two",
        )
        d = daemon.Daemon(dry_run=False)
        d.state.set_ranked([active, one, two])
        d.state.active = active
        d._active_waiting_for_standby = True
        d._active_waiting_generation = 3
        d._standby_waiting_generation = 3

        with d._standby_cond:
            self.assertEqual(d._select_standby_candidate_locked(), one)
            self.assertEqual(d._select_standby_candidate_locked(), two)
            self.assertIsNone(d._select_standby_candidate_locked())

    def test_subscription_refresh_preserves_matching_standby_slot(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared
        d._standby_generation = 4

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"):
            with d._standby_cond:
                d._sync_standby_after_ranked_refresh_locked([standby_srv])

        self.assertIs(d._standby, prepared)
        self.assertEqual(d._standby_generation, 5)

    def test_subscription_refresh_preserves_matching_duplicate_endpoint(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby-austria",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="shared.example.com",
            port=443,
            params={"security": "reality", "sni": "austria.example.com"},
            country="Austria",
        )
        wrong_same_endpoint = Server(
            uri="standby-italy",
            protocol="vless",
            uuid=standby_srv.uuid,
            host=standby_srv.host,
            port=standby_srv.port,
            params={"security": "reality", "sni": "italy.example.com"},
            country="Italy",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="austria-fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared

        def fake_fingerprint(server: Server, **_: object) -> str:
            return "austria-fp" if server.country == "Austria" else "italy-fp"

        with mock.patch.object(daemon, "standby_fingerprint",
                               side_effect=fake_fingerprint):
            with d._standby_cond:
                d._sync_standby_after_ranked_refresh_locked([
                    standby_srv,
                    wrong_same_endpoint,
                ])

        self.assertIs(d._standby, prepared)
        self.assertIs(d._standby.server, standby_srv)

    def test_subscription_refresh_discards_same_endpoint_config_change(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby-old",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="shared.example.com",
            port=443,
            params={"security": "reality", "sni": "old.example.com"},
            country="Standby",
        )
        changed_same_endpoint = Server(
            uri="standby-new",
            protocol="vless",
            uuid=standby_srv.uuid,
            host=standby_srv.host,
            port=standby_srv.port,
            params={"security": "reality", "sni": "new.example.com"},
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="old-fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared
        d._notified_standby_slot_key = standby_srv.key()

        with mock.patch.object(daemon, "standby_fingerprint",
                               return_value="new-fp"), \
                mock.patch.object(daemon, "notify") as notify_mock:
            with d._standby_cond:
                d._sync_standby_after_ranked_refresh_locked([
                    changed_same_endpoint,
                ])

        self.assertIsNone(d._standby)
        notify_mock.assert_called_once()

    def test_subscription_refresh_discards_removed_standby_slot(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        replacement = Server(
            uri="replacement",
            protocol="vless",
            uuid="33333333-3333-3333-3333-333333333333",
            host="replacement.example.com",
            port=443,
            country="Replacement",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d._standby = prepared

        with d._standby_cond:
            d._sync_standby_after_ranked_refresh_locked([replacement])

        self.assertIsNone(d._standby)

    def test_failed_post_promotion_check_rolls_back_backup(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d._standby = prepared

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text"), \
                mock.patch.object(daemon, "proxy_alive", return_value=False), \
                mock.patch.object(daemon, "restore_backup",
                                  return_value=True) as restore_mock, \
                mock.patch.object(daemon, "notify"), \
                mock.patch("xproxy.state._save_active"):
            promoted = d._promote_standby("test-reason")

        self.assertFalse(promoted)
        restore_mock.assert_called_once_with(d.platform)
        self.assertEqual(d.state.active, active)
        self.assertTrue(d._active_waiting_for_standby)

    def test_promotion_xray_start_error_rolls_back_backup(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby
        from xproxy.xray_control import XrayStartError

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d._standby = prepared

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text",
                                  side_effect=XrayStartError("restart boom")), \
                mock.patch.object(daemon, "restore_backup",
                                  return_value=True) as restore_mock, \
                mock.patch.object(daemon, "notify"), \
                mock.patch("xproxy.state._save_active"):
            promoted = d._promote_standby("proxy-failing")

        self.assertFalse(promoted)
        restore_mock.assert_called_once_with(d.platform)
        self.assertEqual(d.state.active, active)
        self.assertTrue(d._active_waiting_for_standby)

    def test_restart_failure_after_config_write_is_xray_start_error(self) -> None:
        from xproxy import xray_control
        from xproxy.platform_utils import PlatformInfo
        from xproxy.xray_control import XrayStartError

        info = PlatformInfo(
            name="linux",
            xray_config=Path("/tmp/xray-config.json"),
            restart_cmd=["systemctl", "restart", "xray"],
            needs_sudo_write=False,
        )

        with mock.patch.object(xray_control, "validate_config_for_service",
                               return_value=(True, "")), \
                mock.patch.object(xray_control, "_config_matches_current",
                                  return_value=False), \
                mock.patch.object(xray_control, "_backup_current_config"), \
                mock.patch.object(xray_control, "write_xray_config") as write_mock, \
                mock.patch.object(xray_control, "_platform_restart",
                                  side_effect=RuntimeError("restart boom")) as restart_mock:
            with self.assertRaisesRegex(
                XrayStartError,
                "restart failed after writing config",
            ):
                xray_control.apply_config_text(
                    '{"inbounds":[],"outbounds":[]}',
                    label="standby test",
                    info=info,
                )

        write_mock.assert_called_once()
        restart_mock.assert_called_once_with(info)

    def test_config_sync_loads_json_and_runs_scp(self) -> None:
        from xproxy import config_sync
        from xproxy.platform_utils import PlatformInfo

        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            source = tmp / "config.json"
            source.write_text("{}", encoding="utf-8")
            sync = tmp / "sync.json"
            sync.write_text(
                '{"host":"quietharbor.net","port":57093,'
                '"user":"sergey",'
                '"path":"/var/www/quietharbor.net/config.json"}',
                encoding="utf-8",
            )
            info = PlatformInfo(
                name="linux",
                xray_config=source,
                restart_cmd=[],
                needs_sudo_write=False,
            )

            with mock.patch.object(config_sync.shutil, "which",
                                   return_value="/usr/bin/scp"), \
                    mock.patch.object(
                        config_sync.subprocess,
                        "run",
                        return_value=mock.Mock(returncode=0, stderr=b"", stdout=b""),
                    ) as run_mock:
                target = config_sync.sync_current_config(
                    info=info,
                    sync_path=sync,
                )

        self.assertIsNotNone(target)
        self.assertEqual(target.host, "quietharbor.net")
        self.assertEqual(target.port, 57093)
        self.assertEqual(target.user, "sergey")
        self.assertEqual(target.path, "/var/www/quietharbor.net/config.json")
        cmd = run_mock.call_args.args[0]
        self.assertEqual(cmd[:8], [
            "scp",
            "-P",
            "57093",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            str(source),
        ])
        self.assertEqual(
            cmd[-1],
            "sergey@quietharbor.net:/var/www/quietharbor.net/config.json",
        )

    def test_config_sync_missing_file_is_noop(self) -> None:
        from xproxy import config_sync
        from xproxy.platform_utils import PlatformInfo

        with tempfile.TemporaryDirectory() as tmp_s:
            info = PlatformInfo(
                name="linux",
                xray_config=Path(tmp_s) / "config.json",
                restart_cmd=[],
                needs_sudo_write=False,
            )

            with mock.patch.object(config_sync.subprocess, "run") as run_mock:
                target = config_sync.sync_current_config(
                    info=info,
                    sync_path=Path(tmp_s) / "missing-sync.json",
                )

        self.assertIsNone(target)
        run_mock.assert_not_called()

    def test_config_sync_retries_with_no_ssh_config_on_bad_permissions(self) -> None:
        from xproxy import config_sync
        from xproxy.platform_utils import PlatformInfo

        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            source = tmp / "config.json"
            source.write_text("{}", encoding="utf-8")
            sync = tmp / "sync.json"
            sync.write_text(
                '{"host":"quietharbor.net","port":57093,'
                '"user":"sergey",'
                '"path":"/var/www/quietharbor.net/config.json"}',
                encoding="utf-8",
            )
            info = PlatformInfo(
                name="linux",
                xray_config=source,
                restart_cmd=[],
                needs_sudo_write=False,
            )

            first = mock.Mock(
                returncode=1,
                stderr=(
                    b"Bad owner or permissions on "
                    b"/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf\n"
                ),
                stdout=b"",
            )
            second = mock.Mock(returncode=0, stderr=b"", stdout=b"")
            with mock.patch.object(config_sync.shutil, "which",
                                   return_value="/usr/bin/scp"), \
                    mock.patch.object(
                        config_sync.subprocess,
                        "run",
                        side_effect=[first, second],
                    ) as run_mock:
                target = config_sync.sync_current_config(
                    info=info,
                    sync_path=sync,
                )

        self.assertIsNotNone(target)
        self.assertEqual(run_mock.call_count, 2)
        self.assertNotIn("-F", run_mock.call_args_list[0].args[0])
        self.assertEqual(run_mock.call_args_list[1].args[0][:3],
                         ["scp", "-F", "none"])

    def test_config_sync_rejects_single_quoted_non_json_file(self) -> None:
        from xproxy import config_sync
        from xproxy.config_sync import ConfigSyncError

        with tempfile.TemporaryDirectory() as tmp_s:
            sync = Path(tmp_s) / "sync.json"
            sync.write_text(
                "{ 'host': 'quietharbor.net', 'port': 57093, "
                "'user': 'sergey', "
                "'path': '/var/www/quietharbor.net/config.json' }",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConfigSyncError, "cannot parse"):
                config_sync.load_config_sync(sync)

    def test_successful_blocked_standby_promotion_schedules_config_sync(self) -> None:
        from xproxy import daemon
        from xproxy.standby import PreparedStandby

        active = Server(
            uri="active",
            protocol="vless",
            uuid="11111111-1111-1111-1111-111111111111",
            host="active.example.com",
            port=443,
            country="Active",
        )
        standby_srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        now = time.time()
        prepared = PreparedStandby(
            server=standby_srv,
            config_text='{"inbounds":[],"outbounds":[]}',
            fingerprint="fp",
            created_at=now,
            last_ok_at=now,
            pre_stale_at=now + 30,
            expires_at=now + 60,
        )
        d = daemon.Daemon(dry_run=False)
        d.state.active = active
        d._standby = prepared

        class ImmediateThread:
            def __init__(self, *, target, args, name, daemon):
                self._target = target
                self._args = args
                self.name = name
                self.daemon = daemon

            def start(self):
                self._target(*self._args)

        target = mock.Mock()
        target.safe_label.return_value = (
            "sergey@quietharbor.net:/var/www/quietharbor.net/config.json"
        )

        with mock.patch.object(daemon, "standby_fingerprint", return_value="fp"), \
                mock.patch.object(daemon, "apply_config_text"), \
                mock.patch.object(daemon, "proxy_alive", return_value=True), \
                mock.patch.object(daemon, "target_alive", return_value=(True, "")), \
                mock.patch.object(daemon, "sync_current_config",
                                  return_value=target) as sync_mock, \
                mock.patch.object(daemon.threading, "Thread",
                                  side_effect=lambda **kwargs: ImmediateThread(**kwargs)) as thread_mock, \
                mock.patch.object(daemon, "notify") as notify_mock, \
                mock.patch("xproxy.state._save_active"):
            promoted = d._promote_standby("target-blocked")

        self.assertTrue(promoted)
        thread_mock.assert_called_once()
        self.assertEqual(thread_mock.call_args.kwargs["name"], "xproxy-config-sync")
        sync_mock.assert_called_once_with(info=d.platform)
        messages = [call.args[0] for call in notify_mock.call_args_list]
        self.assertIn(
            "🟢 config synced to "
            "sergey@quietharbor.net:/var/www/quietharbor.net/config.json "
            "after standby promotion Active (active.example.com:443) → "
            "Standby (standby.example.com:443) reason=target-blocked",
            messages,
        )

    def test_config_sync_not_scheduled_for_xray_not_running_promotion(self) -> None:
        from xproxy import daemon

        srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        d = daemon.Daemon(dry_run=False)

        with mock.patch.object(daemon.threading, "Thread") as thread_mock:
            d._schedule_config_sync_after_promotion(
                reason="xray-not-running",
                previous=None,
                promoted=srv,
            )

        thread_mock.assert_not_called()

    def test_state_machine_notifications_are_deduplicated(self) -> None:
        from xproxy import daemon

        srv = Server(
            uri="standby",
            protocol="vless",
            uuid="22222222-2222-2222-2222-222222222222",
            host="standby.example.com",
            port=443,
            country="Standby",
        )
        d = daemon.Daemon(dry_run=False)

        with mock.patch.object(daemon, "notify") as notify_mock:
            d._notify_standby_state("READY", server=srv, detail="ttl=60s")
            d._notify_standby_state("READY", server=srv, detail="ttl=60s")
            d._notify_active_state("WAITING_FOR_STANDBY", server=srv,
                                   reason="proxy-failing", urgent=True)
            d._notify_active_state("WAITING_FOR_STANDBY", server=srv,
                                   reason="proxy-failing", urgent=True)

        self.assertEqual(notify_mock.call_count, 2)


if __name__ == "__main__":
    unittest.main()
