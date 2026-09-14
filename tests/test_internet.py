"""Basic connectivity must be independent of proxy health and ICMP support."""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest import mock

import requests

from xproxy import daemon, emergency, healthcheck


class HeadersOnlyResponse:
    def __init__(self, status):
        self.status_code = status
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    @property
    def text(self):
        raise AssertionError("Basic connectivity must not download or parse response bodies")


class BasicInternetTests(unittest.TestCase):
    def test_first_ping_success_does_not_contact_sites_ip_checkers_or_proxy(self):
        with mock.patch.object(healthcheck.shutil, "which", return_value="/sbin/ping"), \
                mock.patch.object(healthcheck.subprocess, "run", return_value=mock.Mock(returncode=0)) as ping, \
                mock.patch.object(healthcheck, "_make_session") as session, \
                mock.patch.object(healthcheck, "_any_probe") as ip_check:
            self.assertTrue(healthcheck.internet_alive())
        self.assertEqual(ping.call_count, 1)
        self.assertEqual(ping.call_args.args[0][-1], healthcheck.INTERNET_PING_IPS[0])
        session.assert_not_called()
        ip_check.assert_not_called()

    def test_failed_first_ping_uses_next_ip_and_stops_after_success(self):
        with mock.patch.object(healthcheck.shutil, "which", return_value="/sbin/ping"), \
                mock.patch.object(healthcheck.subprocess, "run", side_effect=[
                    subprocess.TimeoutExpired("ping", 2), mock.Mock(returncode=0)]) as ping, \
                mock.patch.object(healthcheck, "_make_session") as session:
            self.assertTrue(healthcheck.internet_alive())
        self.assertEqual([c.args[0][-1] for c in ping.call_args_list],
                         list(healthcheck.INTERNET_PING_IPS[:2]))
        session.assert_not_called()

    def test_ping_uses_portable_flags_and_bounded_subprocess_on_macos_and_linux(self):
        for binary in ("/sbin/ping", "/usr/bin/ping"):
            with self.subTest(binary=binary), \
                    mock.patch.object(healthcheck.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
                self.assertTrue(healthcheck._internet_ping(binary, "8.8.8.8"))
                self.assertEqual(run.call_args.args[0], [binary, "-n", "-c", "1", "8.8.8.8"])
                self.assertEqual(run.call_args.kwargs["timeout"], healthcheck.INTERNET_PING_TIMEOUT)
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
                self.assertNotIn("shell", run.call_args.kwargs)

    def test_ping_is_located_even_when_launchd_path_omits_sbin(self):
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}), \
                mock.patch.object(healthcheck.shutil, "which", return_value="/sbin/ping") as which, \
                mock.patch.object(healthcheck, "_internet_ping", return_value=True):
            self.assertTrue(healthcheck.internet_alive())
        self.assertIn("/sbin", which.call_args.kwargs["path"].split(os.pathsep))

    def test_blocked_icmp_falls_back_to_https_and_closes_response_and_session(self):
        for failure in (mock.Mock(returncode=1), PermissionError("ICMP denied"),
                        subprocess.TimeoutExpired("ping", 2)):
            with self.subTest(failure=type(failure).__name__):
                response = HeadersOnlyResponse(200)
                session = mock.Mock()
                session.get.return_value = response
                with mock.patch.object(healthcheck.shutil, "which", return_value="/sbin/ping"), \
                        mock.patch.object(healthcheck.subprocess, "run", side_effect=[failure] * len(healthcheck.INTERNET_PING_IPS)) as ping, \
                        mock.patch.object(healthcheck, "_make_session", return_value=session) as make:
                    self.assertTrue(healthcheck.internet_alive())
                self.assertEqual(ping.call_count, len(healthcheck.INTERNET_PING_IPS))
                make.assert_called_once_with(None)
                self.assertTrue(response.closed)
                session.close.assert_called_once()
                session.get.assert_called_once()

    def test_missing_ping_still_checks_https_without_using_environment_proxy(self):
        response = HeadersOnlyResponse(204)
        with mock.patch.dict(os.environ, {
                "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
                "ALL_PROXY": "socks5://127.0.0.1:1", "NO_PROXY": "*"}), \
                mock.patch.object(healthcheck.shutil, "which", return_value=None), \
                mock.patch.object(healthcheck.subprocess, "run") as ping, \
                mock.patch.object(requests.Session, "get", autospec=True, return_value=response) as get:
            self.assertTrue(healthcheck.internet_alive())
            session = get.call_args.args[0]
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies, {})
        ping.assert_not_called()

    def test_site_failure_tries_next_site_but_does_not_contact_remaining_sites(self):
        response = HeadersOnlyResponse(200)
        session = mock.Mock()
        session.get.side_effect = [requests.exceptions.SSLError("TLS failure"), response]
        with mock.patch.object(healthcheck.shutil, "which", return_value=None), \
                mock.patch.object(healthcheck, "_make_session", return_value=session):
            self.assertTrue(healthcheck.internet_alive())
        self.assertEqual([c.args[0] for c in session.get.call_args_list],
                         list(healthcheck.INTERNET_HTTP_URLS[:2]))
        session.close.assert_called_once()

    def test_any_regular_https_response_proves_connectivity_without_body_or_redirect(self):
        for status in (200, 204, 301, 401, 403, 429, 500, 503):
            with self.subTest(status=status):
                session = mock.Mock()
                response = HeadersOnlyResponse(status)
                session.get.return_value = response
                self.assertTrue(healthcheck._internet_http_probe(session, "https://example.test/"))
                session.get.assert_called_once_with(
                    "https://example.test/", timeout=healthcheck.INTERNET_HTTP_TIMEOUT,
                    allow_redirects=False, stream=True, verify=True,
                )
                self.assertTrue(response.closed)

    def test_all_ping_and_https_failures_report_offline(self):
        session = mock.Mock()
        session.get.side_effect = [requests.ConnectionError("DNS failure"),
                                   requests.Timeout("no reply"), requests.exceptions.SSLError("bad TLS")]
        with mock.patch.object(healthcheck.shutil, "which", return_value="/sbin/ping"), \
                mock.patch.object(healthcheck.subprocess, "run", return_value=mock.Mock(returncode=1)), \
                mock.patch.object(healthcheck, "_make_session", return_value=session), \
                mock.patch.object(healthcheck, "proxy_alive") as proxy:
            self.assertFalse(healthcheck.internet_alive())
        self.assertEqual(session.get.call_count, len(healthcheck.INTERNET_HTTP_URLS))
        session.close.assert_called_once()
        proxy.assert_not_called()


class InternetGateTests(unittest.TestCase):
    def setUp(self):
        self.d = daemon.Daemon(dry_run=False)
        self.d._runtime_started = True
        for obj, name in ((daemon, "network_signature"), (emergency, "notify"),
                          (self.d, "_sample_global_status"), (self.d, "tick_heartbeat"),
                          (self.d.emergency, "reload"), (self.d.emergency, "tick")):
            patcher = mock.patch.object(obj, name)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_offline_gate_does_not_test_proxy_or_attempt_repairs(self):
        with mock.patch.object(daemon, "internet_alive", return_value=False), \
                mock.patch.object(daemon, "is_running", return_value=True) as running, \
                mock.patch.object(daemon, "proxy_alive", return_value=True) as proxy, \
                mock.patch.object(self.d, "tick_health") as health, \
                mock.patch.object(self.d, "_recover_interrupted_config") as recovery:
            self.d.tick()
        self.assertFalse(self.d.network.online())
        running.assert_not_called()
        proxy.assert_not_called()
        health.assert_not_called()
        recovery.assert_not_called()

    def test_main_loop_and_emergency_recheck_share_independent_base_internet(self):
        self.assertIs(daemon.internet_alive, emergency.internet_alive)
        with mock.patch.object(healthcheck.shutil, "which", return_value="/sbin/ping"), \
                mock.patch.object(healthcheck, "_internet_ping", return_value=True) as ping, \
                mock.patch.object(healthcheck, "_internet_http_probe", return_value=False), \
                mock.patch.object(daemon, "proxy_alive", return_value=False) as proxy, \
                mock.patch.object(self.d, "tick_health") as health, \
                mock.patch.object(self.d, "_recover_interrupted_config", return_value=True):
            self.d.tick()
            health.assert_called_once_with(has_internet=True)
            self.assertTrue(self.d.network.online())
            self.assertTrue(self.d.emergency.confirm_network())
            ping.return_value = False
            self.assertFalse(self.d.emergency.confirm_network())
            self.assertFalse(self.d.network.online())
            proxy.assert_not_called()
