from __future__ import annotations

import os
import subprocess
import unittest
from unittest import mock

from xproxy import autoupdate


class AutoupdateProxyFallbackTests(unittest.TestCase):
    def test_network_command_uses_direct_route_first(self) -> None:
        with mock.patch.object(autoupdate, "_git", return_value="ok") as git:
            output, used_proxy = autoupdate._git_network("fetch", "--quiet")

        self.assertEqual(output, "ok")
        self.assertFalse(used_proxy)
        git.assert_called_once_with(
            "fetch", "--quiet", timeout=60, network_proxy=False,
        )

    def test_network_command_falls_back_to_xray(self) -> None:
        with mock.patch.object(
            autoupdate,
            "_git",
            side_effect=[autoupdate.GitError("blocked"), "ok"],
        ) as git:
            output, used_proxy = autoupdate._git_network("fetch", "--quiet")

        self.assertEqual(output, "ok")
        self.assertTrue(used_proxy)
        self.assertEqual(git.call_args_list, [
            mock.call("fetch", "--quiet", timeout=60, network_proxy=False),
            mock.call("fetch", "--quiet", timeout=60, network_proxy=True),
        ])

    def test_proxy_first_skips_second_direct_wait(self) -> None:
        with mock.patch.object(autoupdate, "_git", return_value="ok") as git:
            _, used_proxy = autoupdate._git_network(
                "pull", "--ff-only", proxy_first=True,
            )

        self.assertTrue(used_proxy)
        git.assert_called_once_with(
            "pull", "--ff-only", timeout=60, network_proxy=True,
        )

    def test_git_routes_are_explicit_and_ignore_proxy_environment(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        polluted_env = {
            "HTTP_PROXY": "http://wrong.example:1",
            "https_proxy": "http://wrong.example:2",
            "ALL_PROXY": "socks5://wrong.example:3",
            "NO_PROXY": "github.com",
        }
        with mock.patch.dict(os.environ, polluted_env), \
                mock.patch.object(autoupdate.shutil, "which", return_value="/git"), \
                mock.patch.object(
                    autoupdate.subprocess, "run", return_value=completed,
                ) as run:
            autoupdate._git("fetch", network_proxy=False)
            direct_call = run.call_args
            autoupdate._git("fetch", network_proxy=True)
            proxy_call = run.call_args

        self.assertIn("http.proxy=", direct_call.args[0])
        self.assertNotIn(
            "http.proxy=http://127.0.0.1:10809", direct_call.args[0],
        )
        self.assertIn(
            "http.proxy=http://127.0.0.1:10809", proxy_call.args[0],
        )
        for call in (direct_call, proxy_call):
            for key in autoupdate._PROXY_ENV_KEYS:
                self.assertNotIn(key, call.kwargs["env"])

    def test_git_timeout_becomes_git_error_for_fallback(self) -> None:
        with mock.patch.object(autoupdate.shutil, "which", return_value="/git"), \
                mock.patch.object(
                    autoupdate.subprocess,
                    "run",
                    side_effect=subprocess.TimeoutExpired("git", 12),
                ):
            with self.assertRaisesRegex(
                autoupdate.GitError, "fetch timed out after 12s",
            ):
                autoupdate._git("fetch", timeout=12, network_proxy=False)


if __name__ == "__main__":
    unittest.main()
