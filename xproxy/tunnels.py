"""Demand-driven OpenSSH supervision. Unselected hosts are never probed."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import shlex
import signal
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Callable

from .fs_utils import secure_write
from .healthcheck import proxy_alive, target_alive
from .logger import get_logger
from .settings import (
    SSH_CONNECT_TIMEOUT, SSH_HEALTH_FAILURES, SSH_HEALTH_INTERVAL,
    SSH_LOCAL_PORT, SSH_READY_TTL, SSH_RETRY_SCHEDULE, SSH_START_TIMEOUT,
    STATE_DIR, TUNNELS_CONFIG,
)

log = get_logger("xproxy.tunnels")


class TunnelConfigError(ValueError):
    pass


class LocalTunnelError(RuntimeError):
    """A local fault must not disclose the next remote address."""


class AttemptResult(Enum):
    READY = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass(frozen=True)
class TunnelEndpoint:
    id: str
    host: str
    port: int
    user: str
    remote_socks_port: int = 10808
    identity_file: str | None = None
    known_hosts_file: str | None = None


@dataclass(frozen=True)
class TunnelConfig:
    tunnels: tuple[TunnelEndpoint, ...] = ()
    local_port: int = SSH_LOCAL_PORT


def _port(value: object, key: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise TunnelConfigError(f"{key} must be an integer in 1..65535")
    return value


def parse_tunnels(text: str) -> TunnelConfig:
    try:
        data = json.loads(text)
    except ValueError:
        raise TunnelConfigError("tunnels.json is not valid JSON") from None
    if not isinstance(data, dict) or type(data.get("version", 1)) is not int or data.get("version", 1) != 1:
        raise TunnelConfigError("expected an object with version=1")
    if set(data) - {"version", "local_port", "tunnels"}:
        raise TunnelConfigError("unknown top-level tunnels.json field")
    rows = data.get("tunnels", [])
    if not isinstance(rows, list):
        raise TunnelConfigError("tunnels must be an array")
    port = _port(data.get("local_port", SSH_LOCAL_PORT), "local_port")
    if port in (10808, 10809):
        raise TunnelConfigError("local_port must differ from the xray client ports")
    endpoints: list[TunnelEndpoint] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - set(TunnelEndpoint.__dataclass_fields__):
            raise TunnelConfigError("invalid tunnel entry or unknown field")
        ident, host, user = (row.get(k) for k in ("id", "host", "user"))
        if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ident):
            raise TunnelConfigError("each tunnel needs a simple, unique id")
        if ident in seen:
            raise TunnelConfigError("duplicate tunnel id")
        seen.add(ident)
        if not isinstance(host, str) or not host or host.startswith("-"):
            raise TunnelConfigError(f"{ident}: invalid host")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                         for label in host.rstrip(".").split(".")):
                raise TunnelConfigError(f"{ident}: invalid host") from None
        if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", user):
            raise TunnelConfigError(f"{ident}: invalid user")
        paths = {}
        for key in ("identity_file", "known_hosts_file"):
            value = row.get(key)
            if value is not None:
                if not isinstance(value, str) or not value or "\n" in value:
                    raise TunnelConfigError(f"{ident}: invalid {key}")
                path = Path(value).expanduser()
                if not path.is_absolute():
                    raise TunnelConfigError(f"{ident}: {key} must be absolute or start with ~/")
                paths[key] = str(path)
        endpoints.append(TunnelEndpoint(
            ident, host, _port(row.get("port", 22), "port"), user,
            _port(row.get("remote_socks_port", 10808), "remote_socks_port"), **paths,
        ))
    return TunnelConfig(tuple(endpoints), port)


class TunnelConfigFile:
    """Reload locally; invalid updates suspend new connections, retaining live SSH."""
    def __init__(self, path: Path = TUNNELS_CONFIG) -> None:
        self.path = path
        self.config = TunnelConfig()
        self.error = ""
        self._signature: str | None = None

    def reload(self) -> bool:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raw = '{"tunnels":[]}'
        except (OSError, UnicodeError):
            raw = "<unreadable>"
        signature = hashlib.sha256(raw.encode()).hexdigest()
        if signature == self._signature:
            return False
        self._signature = signature
        try:
            self.config = parse_tunnels(raw)
            self.error = ""
        except TunnelConfigError as exc:
            self.error = str(exc)
        return True

    @property
    def enabled(self) -> bool:
        return bool(self.config.tunnels) and not self.error


@dataclass(frozen=True)
class TunnelIntent:
    online: bool = False
    connect: bool = False
    keep: bool = False


@dataclass(frozen=True)
class TunnelSnapshot:
    status: str = "IDLE"
    endpoint: TunnelEndpoint | None = None
    local_port: int = SSH_LOCAL_PORT
    last_ok: float = 0.0
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.status == "READY" and time.monotonic() - self.last_ok <= SSH_READY_TTL


def ssh_command(endpoint: TunnelEndpoint, port: int, token: str) -> list[str]:
    """No shell, user ProxyCommand, extra forwards, DNS host-key lookups or prompts."""
    cmd = ["ssh", "-F", "/dev/null", "-N", "-T", "-n", "-p", str(endpoint.port)]
    options = (
        "BatchMode=yes", "StrictHostKeyChecking=yes", "ExitOnForwardFailure=yes",
        f"ConnectTimeout={SSH_CONNECT_TIMEOUT}", "ConnectionAttempts=1",
        "ServerAliveInterval=30", "ServerAliveCountMax=3",
        "ProxyCommand=none", "ProxyJump=none", "ForwardAgent=no",
        "ControlMaster=no", "ControlPersist=no", f"ControlPath={token}",
        "CanonicalizeHostname=no", "VerifyHostKeyDNS=no", "UpdateHostKeys=no",
        "GatewayPorts=no", "LogLevel=ERROR",
    )
    for option in options:
        cmd.extend(["-o", option])
    if endpoint.identity_file:
        cmd.extend(["-i", endpoint.identity_file, "-o", "IdentitiesOnly=yes"])
    if endpoint.known_hosts_file:
        cmd.extend(["-o", f"UserKnownHostsFile={endpoint.known_hosts_file}"])
    cmd.extend(["-L", f"127.0.0.1:{port}:127.0.0.1:{endpoint.remote_socks_port}",
                f"{endpoint.user}@{endpoint.host}"])
    return cmd


def _process_identity(pid: int) -> str:
    try:
        result = subprocess.run(
            ["ps", "-ww", "-p", str(pid), "-o", "lstart=", "-o", "args="],
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _listener(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _healthy(port: int, should_continue: Callable[[], bool]) -> bool:
    return proxy_alive(socks_port=port, should_continue=should_continue) and \
        should_continue() and target_alive(socks_port=port, should_continue=should_continue)[0]


def _legacy_matches(command: str, endpoint: TunnelEndpoint, port: int) -> bool:
    try:
        args = shlex.split(command)
        if not args or Path(args[0]).name != "ssh" or args[-1] != f"{endpoint.user}@{endpoint.host}":
            return False
        forwards = [args[i + 1] for i, value in enumerate(args[:-1]) if value == "-L"]
        ports = [args[i + 1] for i, value in enumerate(args[:-1]) if value == "-p"]
        return ports == [str(endpoint.port)] and \
            f"{port}:127.0.0.1:{endpoint.remote_socks_port}" in forwards and "-N" in args
    except (ValueError, IndexError):
        return False


def _legacy_loop_matches(path: Path, endpoint: TunnelEndpoint, port: int) -> bool:
    """Recognize the old generated script locally, including its backoff.

    A pathname alone is not sufficient authority to terminate a shell when
    there is no matching SSH child. Accept only the generated command shape.
    """
    try:
        if path.is_symlink() or path.stat().st_uid != os.getuid():
            return False
        lines = [line.strip() for line in path.read_text().replace("\\\n", " ").splitlines() if line.strip()]
        if len(lines) != 6 or lines[:3] != ["#!/bin/bash",
                "# авто-генерация start-fr-tunnel.sh — не редактировать", "while true; do"] or \
                lines[4:] != ["sleep 30", "done"]:
            return False
        args = shlex.split(lines[3])
        prefix = ["ssh", "-p", str(endpoint.port), "-o", "BatchMode=yes",
                  "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
                  "-o", "ExitOnForwardFailure=yes", "-L",
                  f"{port}:127.0.0.1:{endpoint.remote_socks_port}", "-L"]
        return args[:len(prefix)] == prefix and len(args) == len(prefix) + 4 and \
            re.fullmatch(r"\d{1,5}:127\.0\.0\.1:\d{1,5}", args[len(prefix)]) is not None and \
            args[-3:] == ["-N", f"{endpoint.user}@{endpoint.host}", f"2>{path.parent}/tunnel.log"]
    except (OSError, ValueError, UnicodeError):
        return False


class TunnelManager:
    """One worker, one owned SSH process, one outstanding e2e probe at most.

    intent() is read again before every attempt. confirm_network() is called
    after failures, before advancing to another host. Neither is called to
    probe remote SSH hosts when emergency demand is absent.
    """
    def __init__(self, intent: Callable[[], TunnelIntent],
                 confirm_network: Callable[[], bool],
                 changed: Callable[[TunnelSnapshot], None], *,
                 state_dir: Path = STATE_DIR,
                 preflight: Callable[[], None] | None = None) -> None:
        self.intent = intent
        self.confirm_network = confirm_network
        self.changed = changed
        self.state_dir = state_dir
        self.preflight = preflight
        self.config = TunnelConfig()
        self.enabled = False
        self._lock = threading.RLock()
        self._snapshot = TunnelSnapshot()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen | None = None
        self._pid: int | None = None
        self._identity = ""
        self._endpoint: TunnelEndpoint | None = None
        self._port = SSH_LOCAL_PORT
        self._queue: list[TunnelEndpoint] = []
        self._retry_at = 0.0
        self._retry_round = 0
        self._failures = 0
        self._next_check = 0.0
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ssh-probe")
        self._probe: Future | None = None

    def configure(self, config: TunnelConfig, enabled: bool) -> None:
        with self._lock:
            self.config, self.enabled = config, enabled
            self._queue = self._ordered_endpoints(self._endpoint)
            self._retry_at = 0
        self._wake.set()

    def _ordered_endpoints(self, current: TunnelEndpoint | None) -> list[TunnelEndpoint]:
        # Credentials can change without changing the exposed SSH address.
        # Reconnect that address with its latest settings before alternatives.
        preferred = next((e for e in self.config.tunnels if current is not None and
                          (e.id, e.host, e.port) == (current.id, current.host, current.port)), None)
        return ([preferred] if preferred else []) + [e for e in self.config.tunnels if e != preferred]

    def snapshot(self) -> TunnelSnapshot:
        with self._lock:
            return self._snapshot

    def _publish(self, status: str, detail: str = "", *, ok: bool = False) -> None:
        with self._lock:
            old = self._snapshot
            self._snapshot = TunnelSnapshot(
                status, self._endpoint, self._port,
                time.monotonic() if ok else old.last_ok, detail,
            )
            current = self._snapshot
        if (old.status, old.endpoint, old.detail) != (status, current.endpoint, detail):
            self.changed(current)

    def start(self) -> None:
        if not self.adopt() and self.enabled:
            self._adopt_legacy()
        self._thread = threading.Thread(target=self._run, name="xproxy-ssh", daemon=True)
        self._thread.start()

    def close(self, *, preserve: bool = False) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=40)
        if not preserve:
            self._terminate()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def adopt(self) -> bool:
        """Reattach after exec/crash using PID + creation identity + random token.

        This only inspects local process metadata; it never opens SSH.
        """
        path = self.state_dir / "ssh-process.json"
        try:
            data = json.loads(path.read_text())
            pid = int(data["pid"])
            identity = _process_identity(pid)
            if not identity or identity != data["identity"]:
                return False
            endpoint = TunnelEndpoint(**data["endpoint"])
            port = _port(data["local_port"], "local_port")
            if data.get("legacy_command"):
                command = data["legacy_command"]
                if not identity.endswith(command) or not _legacy_matches(command, endpoint, port):
                    return False
                parent = data.get("legacy_parent")
                if parent and _process_identity(parent) == data.get("legacy_parent_identity"):
                    os.kill(parent, signal.SIGTERM)
            elif f"ControlPath={data['token']}" not in identity:
                return False
        except (OSError, ValueError, KeyError, TypeError):
            return False
        self._pid, self._identity = pid, identity
        self._endpoint, self._port = endpoint, port
        self._publish("CHECKING", "adopted after restart")
        return True

    def _adopt_legacy(self) -> bool:
        """Migrate the exact old generated loop, never a generic `ssh -L` process.

        Only a same-user child of ~/.fr-tunnel/ssh-tunnel-fr.sh whose endpoint
        matches tunnels.json is eligible. Stop the loop, retain its SSH child.
        A sleeping loop is retired only after validating the generated script.
        No remote probes or new handshakes are performed during migration.
        """
        loop_path = str(Path.home() / ".fr-tunnel" / "ssh-tunnel-fr.sh")
        try:
            result = subprocess.run(["ps", "-ww", "-axo", "uid=,pid=,ppid=,command="],
                                    capture_output=True, text=True, timeout=3)
            rows = []
            loops = {}
            for line in result.stdout.splitlines():
                fields = line.strip().split(None, 3)
                if len(fields) != 4 or int(fields[0]) != os.getuid():
                    continue
                pid, parent, command = int(fields[1]), int(fields[2]), fields[3]
                rows.append((pid, parent, command))
                args = shlex.split(command)
                if len(args) == 2 and Path(args[0]).name in ("bash", "sh") and args[1] == loop_path:
                    loops[pid] = _process_identity(pid)
            for pid, parent, command in rows:
                if parent not in loops or not loops[parent]:
                    continue
                for endpoint in self.config.tunnels:
                    if not _legacy_matches(command, endpoint, self.config.local_port):
                        continue
                    identity = _process_identity(pid)
                    if not identity or not identity.endswith(command) or _process_identity(parent) != loops[parent]:
                        continue
                    # Persist ownership before stopping the loop, so a crash in
                    # migration cannot leave an unidentifiable SSH process.
                    secure_write(self.state_dir / "ssh-process.json", json.dumps({
                        "pid": pid, "identity": identity, "endpoint": asdict(endpoint),
                        "local_port": self.config.local_port, "legacy_command": command,
                        "legacy_parent": parent, "legacy_parent_identity": loops[parent],
                    }))
                    os.kill(parent, signal.SIGTERM)
                    self._pid, self._identity = pid, identity
                    self._endpoint, self._port = endpoint, self.config.local_port
                    self._publish("CHECKING", "legacy loop replaced by supervisor")
                    return True
            # The old loop sleeps after a failed handshake. Leaving it alive
            # here would allow autonomous reconnects outside emergency policy.
            if any(_legacy_loop_matches(Path(loop_path), e, self.config.local_port)
                   for e in self.config.tunnels):
                for pid, parent, command in rows:
                    if parent in loops and loops[parent] and shlex.split(command) == ["sleep", "30"]:
                        if _process_identity(parent) == loops[parent]:
                            os.kill(parent, signal.SIGTERM)
                            log.info("retired legacy SSH reconnect loop during backoff")
        except (OSError, ValueError, subprocess.TimeoutExpired):
            log.warning("could not adopt legacy tunnel; unrelated processes left intact")
        return False

    def _alive(self) -> bool:
        if self._proc is not None:
            return self._proc.poll() is None
        return self._pid is not None and _process_identity(self._pid) == self._identity

    def _terminate(self) -> None:
        owned_pid = self._pid
        if self._pid is not None and self._alive():
            try:
                os.kill(self._pid, signal.SIGTERM)
                deadline = time.monotonic() + 2
                while self._alive() and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self._alive():
                    os.kill(self._pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self._proc is not None:
            try:
                self._proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        self._proc, self._pid, self._identity = None, None, ""
        if owned_pid is not None:
            (self.state_dir / "ssh-process.json").unlink(missing_ok=True)

    def _allowed(self, endpoint: TunnelEndpoint | None = None) -> bool:
        request = self.intent()
        with self._lock:
            configured = self.enabled and (endpoint is None or endpoint in self.config.tunnels)
        return not self._stop.is_set() and request.online and request.connect and configured

    def _spawn(self, endpoint: TunnelEndpoint, port: int) -> bool:
        if shutil.which("ssh") is None:
            raise LocalTunnelError("OpenSSH is not installed")
        for name in (endpoint.identity_file, endpoint.known_hosts_file):
            if name and not os.access(name, os.R_OK):
                raise LocalTunnelError("SSH key or known_hosts file is not readable")
        known_hosts = endpoint.known_hosts_file or str(Path.home() / ".ssh" / "known_hosts")
        if not os.access(known_hosts, os.R_OK) or shutil.which("ssh-keygen") is None:
            raise LocalTunnelError("readable known_hosts and ssh-keygen are required")
        lookup = endpoint.host if endpoint.port == 22 else f"[{endpoint.host}]:{endpoint.port}"
        known = subprocess.run(["ssh-keygen", "-F", lookup, "-f", known_hosts],
                               capture_output=True, timeout=5)
        if known.returncode != 0:
            raise LocalTunnelError("SSH host key is not provisioned in known_hosts")
        if _listener(port):
            raise LocalTunnelError("local tunnel port is occupied by an unowned process")
        token = "xproxy-" + uuid.uuid4().hex
        self.state_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.state_dir / "ssh.log"
        if log_path.exists() and log_path.stat().st_size > 64 * 1024:
            log_path.replace(self.state_dir / "ssh.log.1")
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            if not self._allowed(endpoint) or not self.confirm_network() or not self._allowed(endpoint):
                return False
            self._proc = subprocess.Popen(
                ssh_command(endpoint, port, token), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=fd, start_new_session=True,
            )
        except OSError as exc:
            raise LocalTunnelError(f"cannot start OpenSSH: {exc.strerror}") from exc
        finally:
            os.close(fd)
        self._pid = self._proc.pid
        self._identity = _process_identity(self._pid)
        if not self._identity:
            return True  # an early SSH failure is handled by the attempt loop
        secure_write(self.state_dir / "ssh-process.json", json.dumps({
            "pid": self._pid, "identity": self._identity, "token": token,
            "endpoint": asdict(endpoint), "local_port": port,
        }))
        return True

    def _check(self, deadline: float, *, connecting: bool = False) -> bool:
        if self._probe is not None and not self._probe.done():
            return False
        def current():
            request = self.intent()
            return not self._stop.is_set() and request.online and request.keep and \
                (not connecting or self._allowed(self._endpoint))
        if not current():
            return False
        self._probe = self._pool.submit(_healthy, self._port, current)
        while not self._probe.done():
            request = self.intent()
            if self._stop.wait(0.1) or not request.online or not request.keep or \
                    (connecting and not self._allowed(self._endpoint)) or \
                    time.monotonic() >= deadline:
                return False
        return bool(self._probe.result()) and self._alive()

    def _attempt(self, endpoint: TunnelEndpoint, port: int) -> AttemptResult:
        self._endpoint, self._port = endpoint, port
        self._publish("CONNECTING")
        if not self._allowed(endpoint):
            return AttemptResult.CANCELLED
        if not self._spawn(endpoint, port):
            return AttemptResult.CANCELLED
        deadline = time.monotonic() + SSH_START_TIMEOUT
        while self._alive() and time.monotonic() < deadline and self._allowed(endpoint):
            if _listener(port):
                if self._check(deadline, connecting=True) and self._allowed(endpoint):
                    self._failures = self._retry_round = 0
                    self._next_check = time.monotonic() + SSH_HEALTH_INTERVAL
                    self._publish("READY", ok=True)
                    return AttemptResult.READY
                break
            self._stop.wait(0.2)
        failed = self._allowed(endpoint)
        self._terminate()
        return AttemptResult.FAILED if failed else AttemptResult.CANCELLED

    def _backoff(self) -> None:
        delay = SSH_RETRY_SCHEDULE[min(self._retry_round, len(SSH_RETRY_SCHEDULE) - 1)]
        self._retry_round += 1
        self._retry_at = time.monotonic() + delay

    def step(self) -> None:
        request = self.intent()
        if not request.online and request.keep:
            # Keep an existing process/config intact across sleep or an expired
            # connectivity sample. No new probes or reconnects while offline.
            self._publish("SUSPENDED" if request.keep else "IDLE")
            self._next_check = 0
            return
        if not request.keep:
            if self._pid is not None:
                self._terminate()
            self._queue = []
            self._retry_at = 0
            if not request.keep:
                self._endpoint = None
                self._retry_round = 0
            self._publish("SUSPENDED" if request.keep and not request.online else "IDLE")
            return
        if self._pid is not None:
            alive = self._alive()
            if alive and time.monotonic() < self._next_check:
                return
            healthy = alive and self._check(time.monotonic() + SSH_START_TIMEOUT)
            if self._stop.is_set():
                return
            self._next_check = time.monotonic() + SSH_HEALTH_INTERVAL
            if healthy:
                self._failures = 0
                self._publish("READY", ok=True)
                return
            if not self.intent().online:
                return
            self._failures += 1
            if alive and self._failures < SSH_HEALTH_FAILURES:
                self._publish("CHECKING", "confirming failed traffic check")
                self._next_check = time.monotonic() + 3
                return
            # A direct network recheck prevents a Wi-Fi outage from disclosing
            # every SSH host. A lost process alone is not network evidence.
            if not self.confirm_network():
                return
            current = self._endpoint
            self._terminate()
            self._publish("FAILED", "SSH transport or remote SOCKS failed")
            with self._lock:
                self._queue = self._ordered_endpoints(current)
            self._retry_at = 0
        if not self._allowed() or time.monotonic() < self._retry_at:
            return
        # Do not rebind the SOCKS port under an unfinished probe from a previous
        # process; it must never validate another host by accident.
        if self._probe is not None and not self._probe.done():
            return
        with self._lock:
            if not self._queue:
                self._queue = list(self.config.tunnels)
            endpoint = self._queue[0]
            port = self.config.local_port
        if not self._allowed(endpoint):
            return
        try:
            if self.preflight is not None:
                self.preflight()
            result = self._attempt(endpoint, port)
            if result is AttemptResult.READY:
                self._queue = []
                return
        except LocalTunnelError as exc:
            self._terminate()
            self._publish("LOCAL_ERROR", str(exc))
            # Retry this same priority position after local repair/backoff.
            # A missing key on the current backup is no reason to contact A.
            self._backoff()
            return
        if result is AttemptResult.CANCELLED or not self._allowed(endpoint):
            self._publish("IDLE", "emergency demand withdrawn")
            return
        if not self.confirm_network() or not self._allowed(endpoint):
            return
        with self._lock:
            # Only confirmed remote failure consumes a priority position.
            # configure() may have replaced the queue during the attempt.
            if self._queue and self._queue[0] == endpoint:
                self._queue.pop(0)
        self._publish("FAILED", "connection or end-to-end check failed")
        if not self._queue:
            self._backoff()
        # One attempt per step. The gate is read again before touching the next
        # host, including after config reload and VLESS recovery.

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.step()
            except Exception:
                log.exception("SSH supervisor failed")
                self._terminate()
                self._publish("LOCAL_ERROR", "supervisor error; see local log")
                self._backoff()
            self._wake.wait(1)
            self._wake.clear()
