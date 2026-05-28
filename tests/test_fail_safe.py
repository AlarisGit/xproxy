from __future__ import annotations

import tempfile
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


if __name__ == "__main__":
    unittest.main()
