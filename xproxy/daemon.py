"""Главный цикл демона и one-shot итерация."""
from __future__ import annotations

import random
import json
import signal
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .connectivity import Connectivity
from .emergency import EmergencyController, candidate_key
from .instance_lock import InstanceLock

from .autoupdate import (
    FAILURE_REASONS,
    autoupdate_enabled,
    check_and_pull,
    install_requirements,
    post_restart_banner,
    restart_self,
    rollback_to,
    too_many_restarts,
    validate_new_code,
)
from .config_sync import ConfigSyncError, sync_current_config
from .geo import ensure_geo_assets
from .routing import build_xray_sections
from .healthcheck import internet_alive, proxy_alive, target_alive, public_ips
from .logger import get_logger
from .notifier import drain_queue, is_configured as tg_configured, notify, set_status_provider, set_network_provider, start_queue
from .platform_utils import PlatformInfo, detect_platform, network_signature
from .servers import Server, expand_servers, filter_and_sort, load_country_ranks, parse_subscription, tcp_probe
from .settings import (
    FAIL_THRESHOLD,
    GEO_REFRESH,
    GIT_PULL_INTERVAL,
    HEALTH_INTERVAL,
    HEARTBEAT_HOUR,
    HEARTBEAT_JITTER_MIN,
    ROTATION_COOLDOWN,
    SERVERS_CACHE,
    STALE_SUBSCRIPTION_SEC,
    SCHEDULE_JITTER_RATIO,
    STARTUP_JITTER,
    STATUS_NOTIFY_SAMPLE_INTERVAL,
    STATUS_NOTIFY_STABLE_SAMPLES,
    STANDBY_FAIL_THRESHOLD,
    STANDBY_RETRY_INTERVAL,
    VLESS_RECOVERY_INTERVAL,
    SUBSCR_REFRESH,
)
from .standby import PreparedStandby, StandbyError, StandbyLocalError, prepare_standby, standby_fingerprint, stop_probes
from .state import DaemonState, load_active
from .subscription import SubscriptionError, fetch_subscription_text
from .xray_control import (
    ConfigUnchanged,
    XrayStartError,
    apply_config_text,
    apply_server,
    is_running,
    restore_backup,
    commit_config,
    recover_interrupted_config,
)
from .xray_config import build_xray_config_text, build_ssh_config_text
from .xray_config import build_xray_config

log = get_logger("xproxy.daemon")

@dataclass(frozen=True)
class _ConfigPublication:
    reason: str
    previous_label: str
    promoted_label: str
    upstream_key: str
    config_text: str


def _jittered(interval: float, ratio: float = SCHEDULE_JITTER_RATIO) -> float:
    """Вернуть interval с равномерным jitter'ом ±ratio.

    ratio=0.15, interval=1800 → uniformly in [1530, 2070].
    Нулевой/отрицательный interval возвращается как есть (отключённая задача).
    """
    if interval <= 0 or ratio <= 0:
        return interval
    return interval * random.uniform(1.0 - ratio, 1.0 + ratio)


class Daemon:
    def __init__(self, dry_run: bool = False,
                 platform: Optional[PlatformInfo] = None):
        self.dry_run = dry_run
        self.platform = platform or detect_platform()
        self.state = DaemonState()
        self._stop = False
        self._stop_signal: Optional[int] = None
        self.network = Connectivity()
        self._network_generation = 0
        self._network_announced: bool | None = None
        self._wake_event = threading.Event()
        self._maintenance_wake = threading.Event()
        self._maintenance_thread: threading.Thread | None = None
        self._config_sync_cond = threading.Condition()
        self._config_sync_thread: threading.Thread | None = None
        self._config_sync_pending: _ConfigPublication | None = None
        self._runtime_started = False
        self._restart_requested = False
        self._health_checked_at = 0.0
        self._next_health_at = 0.0
        self._rebuild_pending = True
        self._scan_attempted: set[str] = set()
        self._scan_retry_at = 0.0
        self._scan_started_at = 0.0
        self._country_ranks = load_country_ranks()
        # --- Jitter / анти-стампед ---
        # Каждый инстанс получает СВОИ периоды для периодических задач.
        # Перерисовываются после каждого успешного события в tick().
        self._subscr_period = _jittered(SUBSCR_REFRESH)
        self._geo_period = _jittered(GEO_REFRESH)
        self._git_period = _jittered(GIT_PULL_INTERVAL)
        # Следующий геопулл планируем в будущем — первый запуск сделает
        # run_once()/run_forever() после startup-jitter'а, здесь не стартуем.
        self._next_geo_at: float = 0.0
        # Подпись последнего набора отброшенных geo-записей. Меняется при
        # изменении geosite.dat/geoip.dat или routing.json — только тогда
        # нужно повторно уведомлять пользователя.
        self._last_removed_geo_sig: Optional[str] = None
        # Флаг «тупик»: xray не работает/отвалился, а geo-assets нечитаемы
        # (ротация заблокирована, см. _rotate_until_working). Нужен только
        # чтобы не спамить уведомлениями — сбрасывается при первой успешной
        # проверке geo-assets.
        self._stuck_notified: bool = False
        # Отдельный флаг для аварии "xray не стартует после записи конфига".
        # Такая ошибка обычно общая для всех кандидатов (env, geo, launchd,
        # права на лог/порт), поэтому нельзя перебирать серверы как будто
        # проблема в конкретном outbound.
        self._xray_start_failure_notified: bool = False
        # Минутный offset для heartbeat: HEARTBEAT_HOUR + 0..HEARTBEAT_JITTER_MIN мин,
        # фиксируется на весь процесс (чтобы не дрейфовать в течение дня).
        self._heartbeat_minute_offset = random.randint(0, max(0, HEARTBEAT_JITTER_MIN))
        log.debug("jitter init: subscr=%.0fs geo=%.0fs git=%.0fs hb_offset=%dmin",
                  self._subscr_period, self._geo_period, self._git_period,
                  self._heartbeat_minute_offset)
        # Standby worker state. The worker prepares a validated config in the
        # background; the health loop promotes a READY/PRE_STALE snapshot.
        self._standby_lock = threading.RLock()
        self._standby_cond = threading.Condition(self._standby_lock)
        self._apply_lock = threading.RLock()
        self._standby: Optional[PreparedStandby] = None
        self._standby_preparing: bool = False
        self._standby_prepare_is_refresh: bool = False
        self._standby_refresh_candidate: Optional[Server] = None
        self._promotion_in_progress: bool = False
        self._standby_stop: bool = False
        self._standby_thread: Optional[threading.Thread] = None
        self._standby_last_attempt: float = 0.0
        self._standby_generation: int = 0
        self._active_waiting_for_standby: bool = False
        self._active_waiting_reason: str = ""
        self._active_waiting_generation: int = 0
        self._standby_waiting_generation: int = 0
        self._standby_waiting_attempted: set[tuple[str, int]] = set()
        self._notified_standby_slot_key: Optional[tuple[str, int]] = None
        self._active_channel_ok: Optional[bool] = None
        self._status_last_sample_at: float = 0.0
        self._status_candidate_key: tuple | None = None
        self._status_candidate_count: int = 0
        self._status_stable_key: tuple | None = None
        self._last_cold_rotation_attempt: float = 0.0
        self.emergency = EmergencyController(self)
        # Восстановить активный сервер, если был сохранён.
        # DNS выполняется позже, только после подтверждения наличия интернета.
        prev = load_active()
        if prev is not None:
            self.state.active = prev
            self.state.last_vless = prev
            log.info("restored active server: %s", _fmt(prev))
        # Инициализировать время последнего live-фетча подписки из mtime кэша.
        # Если сервер был выключен >24ч и кэш устарел — staleness обнаружится
        # сразу при первой же попытке refresh_subscription().
        if SERVERS_CACHE.exists():
            try:
                self.state.last_live_fetch = SERVERS_CACHE.stat().st_mtime
            except OSError:
                pass

    def _load_cached_servers(self) -> None:
        try:
            body = SERVERS_CACHE.read_text(encoding="utf-8")
            ranked = filter_and_sort(parse_subscription(body), self._country_ranks)
        except (OSError, ValueError):
            ranked = []
        previous = self.state.last_vless or self.state.active
        if previous is not None and not any(candidate_key(s) == candidate_key(previous) for s in ranked):
            ranked.append(previous)
        self.state.set_ranked(ranked)

    def _repair_xray_listener(self) -> None:
        with self._apply_lock:
            # A maintenance restart may have completed while we waited.
            if is_running() or (self._runtime_started and not self.network.online()):
                return
            self._repair_xray_listener_with_apply_lock()

    def _repair_xray_listener_with_apply_lock(self) -> None:
        now = time.monotonic()
        if now < getattr(self, "_local_repair_at", 0):
            return
        self._local_repair_at = now + 60
        if self._standby_ready_for_fast_path():
            self._promote_standby("xray-not-running", require_active_failure=True)
            return
        from .xray_control import validate_config_for_service, wait_for_proxy_port
        from .platform_utils import restart_xray
        with self._apply_lock:
            try:
                text = self.platform.xray_config.read_text()
                valid, detail = validate_config_for_service(text, self.platform)
                if not valid:
                    raise RuntimeError(detail)
                restart_xray(self.platform)
                if not wait_for_proxy_port():
                    raise RuntimeError("xray listener did not start")
                self._local_repair_at = 0
            except Exception:
                log.exception("local xray repair failed")
                self.emergency.local_failure()
                self.emergency.event("config", "🔴 Local xray startup failed; SSH hosts are not "
                                     "contacted for this fault", urgent=True)
        self._wake_standby_worker()

    def _update_network(self, online: bool, signature: str | None = None) -> None:
        snapshot = self.network.update(online, signature)
        if snapshot.generation != self._network_generation:
            self._network_generation = snapshot.generation
            with self._standby_cond:
                self._invalidate_standby_locked("network changed or resumed")
                self._scan_attempted.clear()
                self._scan_retry_at = 0
                self._standby_waiting_attempted.clear()
            self.emergency.reset_evidence()
            self.state.note_proxy_ok()
            self._health_checked_at = 0
            self._active_channel_ok = None
            self._next_health_at = 0
        if self._network_announced is not None and online != self._network_announced:
            self.emergency.event("network", "🟢 Internet restored; checking routes" if online else
                                 "🟠 Internet unavailable; route checks and SSH reconnect paused")
        self._network_announced = online
        if online:
            self._wake_standby_worker()

    def _maintenance_loop(self) -> None:
        # Startup jitter belongs to optional downloads, never to recovery.
        self._maintenance_wake.wait(random.uniform(0, STARTUP_JITTER))
        self._maintenance_wake.clear()
        while not self._stop:
            if self.network.online() and not self._restart_requested:
                try:
                    now = time.time()
                    if now - self.state.last_subscription_refresh >= self._subscr_period:
                        self.refresh_subscription()
                        self._subscr_period = _jittered(SUBSCR_REFRESH)
                    if not self._stop and self.network.online() and now >= self._next_geo_at:
                        self.refresh_geo(force=False)
                    if not self._stop and self.network.online() and self._rebuild_pending and self._active_channel_ok is True:
                        self._rebuild_config_if_active()
                    if not self._stop and self.network.online() and GIT_PULL_INTERVAL > 0 and autoupdate_enabled() and \
                            now - self.state.last_git_pull >= self._git_period:
                        self.tick_autoupdate()
                        self._git_period = _jittered(GIT_PULL_INTERVAL)
                except Exception:
                    log.exception("maintenance failed")
            if self._restart_requested:
                return
            self._maintenance_wake.wait(HEALTH_INTERVAL)
            self._maintenance_wake.clear()

    def _apply_verified_config(self, text: str, label: str, *, guard=None) -> bool:
        # Caller owns _apply_lock. No other writer may replace this snapshot.
        if self.dry_run or self._stop:
            return False
        if guard is not None and not guard():
            return False
        generation = self.network.snapshot().generation
        def current():
            return not self._stop and self.network.online() and \
                self.network.snapshot().generation == generation and (guard is None or guard())
        try:
            try:
                apply_config_text(text, label=label, info=self.platform, should_continue=current)
            except ConfigUnchanged:
                pass
            if not current():
                raise RuntimeError("activation cancelled: network or demand changed")
            if not proxy_alive() or not target_alive()[0]:
                raise RuntimeError("post-activation traffic check failed")
            if not current():
                raise RuntimeError("activation cancelled after traffic check")
            commit_config(self.platform)
            return True
        except Exception:
            log.exception("config activation failed: %s", label)
            from .xray_control import TRANSACTION_PATH
            if TRANSACTION_PATH.exists():
                try:
                    restored = restore_backup(self.platform)
                    healthy = restored and self.network.online() and proxy_alive() and target_alive()[0]
                    self.emergency.reconcile()
                    self._record_active_health(bool(healthy))
                    self.emergency.event("config", f"⚠️ {label} rolled back: config_restored={restored}, "
                                         f"traffic_healthy={bool(healthy)}", urgent=True)
                except Exception:
                    self.emergency.reconcile()
                    self._record_active_health(False)
                    self.emergency.event("config", f"🔴 {label}: rollback failed; see local log", urgent=True)
                    log.exception("config rollback failed")
            return False

    # ---------- lifecycle ----------
    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                pass  # напр. внутри потока — не страшно

    def _on_signal(self, signum, _frame) -> None:
        log.info("signal %d received, stopping", signum)
        self._stop_signal = signum
        self._stop = True
        self._wake_event.set()
        self._maintenance_wake.set()

    def run_forever(self) -> None:
        if self.dry_run:
            self.run_once()
            return
        with InstanceLock():
            self.install_signal_handlers()
            post_restart_banner()
            if not autoupdate_enabled():
                log.info("automatic code updates disabled by local XPROXY_AUTOUPDATE=0")
            self._runtime_started = True
            self._load_cached_servers()
            self.emergency.reload()
            self.emergency.reconcile()
            set_status_provider(self._build_status_suffix)
            set_network_provider(self.network.online)
            start_queue()
            notify(f"🟢 xproxy started (transport={self.state.transport}, active={_fmt(self.state.active)})",
                      topic="lifecycle",
                  )
            try:
                self.tick()  # establish network state before adopting SSH
                self.emergency.manager.start()
                self._start_standby_worker()
                self._maintenance_thread = threading.Thread(
                    target=self._maintenance_loop, name="xproxy-maintenance", daemon=True,
                )
                self._maintenance_thread.start()
                while not self._stop and not self._restart_requested:
                    try:
                        self.tick()
                    except Exception:
                        log.exception("tick failed")
                    self._wake_event.wait(HEALTH_INTERVAL)
                    self._wake_event.clear()
            finally:
                self._stop = True
                self._maintenance_wake.set()
                self._stop_standby_worker()
                # Keep the instance lease until all configuration writers exit.
                if self._maintenance_thread:
                    self._maintenance_thread.join()
                self._finish_config_sync()
                self.emergency.manager.close(preserve=self._restart_requested)
                if not self._restart_requested:
                    notify(f"🛑 xproxy stopped ({_signal_name(self._stop_signal) if self._stop_signal else 'manual'})",
                              topic="lifecycle",
                          )
                drain_queue(timeout=3)
                set_network_provider(None)
                log.info("daemon stopped")
        if self._restart_requested:
            try:
                restart_self()
            except Exception:
                self.emergency.manager.close()
                raise

    def run_once(self) -> None:
        # One-shot is deliberately VLESS-only: it must never leave an
        # unsupervised SSH process. Dry-run is entirely local/read-only.
        if self.dry_run:
            self._load_cached_servers()
            self.emergency.reload()
            log.info("[dry-run] cached VLESS=%d, configured SSH=%d, error=%s; no network or writes",
                     len(self.state.ranked), len(self.emergency.file.config.tunnels), self.emergency.file.error or "none")
            return
        with InstanceLock():
            self._load_cached_servers()
            self.emergency.reload()
            self.emergency.reconcile()
            set_network_provider(self.network.online)
            set_status_provider(self._build_status_suffix)
            start_queue()
            try:
                online = internet_alive()
                self._update_network(online)
                if online:
                    if not self._recover_interrupted_config():
                        return
                    self.refresh_subscription(force=True)
                    if self.state.transport != "ssh":
                        self.tick_health(has_internet=True)
                    else:
                        log.info("SSH routing present: use --daemon for supervised recovery")
            finally:
                drain_queue(timeout=3)
                set_network_provider(None)

    def _build_status_suffix(self) -> Optional[str]:
        """Построить строку статуса для добавления к сообщению.

        Вызывается notifier'ом при каждой отправке (в sender-треде).
        Daemon-состояние всегда свежее, hardware-метрики — через
        hardware_status() с 5-минутным кэшем. HTTP-пробы не делаются:
        proxy_ok берётся из daemon-состояния, public_ip не нужен
        (include_identity=False).
        """
        if self.dry_run:
            return None
        tunnel = self.emergency.manager.snapshot()
        active_country = (f"SSH/{tunnel.endpoint.id if tunnel.endpoint else '-'}"
                          if self.state.transport == "ssh" else
                          self.state.active.country if self.state.active else "-")
        proxy_ok = self._active_channel_ok is True
        uptime = _format_uptime(time.time() - self.state.start_time)

        from .sysinfo import system_report
        return system_report(
            public_ip=None,
            active_server=active_country,
            proxy_ok=proxy_ok,
            uptime=uptime,
            rotations_today=self.state.rotations_today,
            include_identity=False,
        )

    def tick(self) -> None:
        self.emergency.reload()
        now = time.monotonic()
        if now < self._next_health_at:
            self.emergency.tick()
            return
        signature = network_signature() if self._runtime_started else None
        online = internet_alive()
        # The same independent base-internet probe gates routine work and
        # emergency rechecks. Proxy health never overrides this network state.
        self._update_network(online, signature)
        if online:
            with self._apply_lock:
                if not self._recover_interrupted_config():
                    self._next_health_at = time.monotonic() + HEALTH_INTERVAL
                    return
            self.tick_health(has_internet=True)
            self.emergency.tick()
            self._maintenance_wake.set()
        else:
            self._health_checked_at = 0
            self._active_channel_ok = None
            self.state.note_proxy_ok()
        self._sample_global_status(has_internet=online)
        self.tick_heartbeat()
        self._next_health_at = time.monotonic() + HEALTH_INTERVAL

    def _recover_interrupted_config(self) -> bool:
        from .xray_control import TRANSACTION_PATH
        with self._apply_lock:
            pending = TRANSACTION_PATH.exists()
            if not recover_interrupted_config(self.platform, online=self.network.online()):
                return False
            if pending:
                # Recovery may have rolled back to the opposite transport.
                # Reconcile before health, SSH release, or maintenance writers.
                self.emergency.reconcile()
                with self._standby_cond:
                    self._invalidate_standby_locked("interrupted configuration recovered")
                    self._clear_waiting_for_standby_locked("configuration recovered")
                    self._scan_attempted.clear()
                    self._scan_started_at = self._scan_retry_at = 0
                self.emergency.reset_evidence()
                self.state.note_proxy_ok()
                self._active_channel_ok = None
                self._health_checked_at = 0
                self._rebuild_pending = True
            return True

    def tick_heartbeat(self) -> None:
        """Один раз в сутки (локальное время >= HEARTBEAT_HOUR) посылаем статус.

        Статус системы добавляется автоматически через notifier (суффикс
        обновляется в _refresh_status_suffix каждый tick).
        """
        if self.dry_run:
            return
        now_struct = time.localtime()
        today = time.strftime("%Y-%m-%d", now_struct)
        if now_struct.tm_hour < HEARTBEAT_HOUR:
            return
        if now_struct.tm_hour == HEARTBEAT_HOUR and \
                now_struct.tm_min < self._heartbeat_minute_offset:
            return
        if self.state.last_heartbeat_date == today:
            return

        log.info("daily heartbeat triggered")
        notify("💚 daily heartbeat", urgent=True, topic="heartbeat")
        self.state.last_heartbeat_date = today

    def refresh_subscription(self, force: bool = False) -> None:
        if self._stop or not self.network.online():
            return
        generation = self.network.snapshot().generation
        now = time.time()
        # Внутренний guard согласован с jittered-периодом из tick(): если
        # tick решил, что пора — мы здесь точно пропускаем проверку (period
        # уже истёк). Force=True (стартовый fetch) проходит всегда.
        if not force and now - self.state.last_subscription_refresh < self._subscr_period:
            return
        # Для не-force вызовов: обновляем timestamp ДО попытки фетча,
        # чтобы при неудаче следующий retry был не раньше subscr_period,
        # а не каждый HEALTH_INTERVAL. Для force=True (стартовый fetch)
        # не обновляем заранее — при кратковременном сбое сети демон
        # быстро восстановится на следующей итерации. Успешный фетч
        # обновит timestamp ниже, независимо от force.
        if not force:
            self.state.last_subscription_refresh = now
        try:
            source, body = fetch_subscription_text(should_continue=lambda: not self._stop and
                self.network.online() and self.network.snapshot().generation == generation)
        except SubscriptionError as exc:
            log.warning("subscription unavailable: %s", exc)
            notify(f"⚠️ subscription unavailable: {exc}", topic="subscription")
            return
        # Фетч прошёл (live или cache) — обновляем timestamp для всех
        # путей, включая force=True, чтобы следующий плановый refresh
        # был через subscr_period, а не почти сразу после старта.
        self.state.last_subscription_refresh = now
        if source == "cache":
            stale_sec = now - self.state.last_live_fetch
            if stale_sec >= STALE_SUBSCRIPTION_SEC and not self.state._stale_notified:
                hours = int(stale_sec // 3600)
                log.warning("subscription stale for %dh (live fetch keeps failing)", hours)
                notify(
                    f"🔴 subscription stale for {hours}h — live fetch keeps failing",
                    urgent=True,
                    topic="subscription",
                )
                self.state._stale_notified = True
            else:
                log.info("subscription served from cache (live fetch failed; will retry next cycle)")
        else:
            self.state.last_live_fetch = now
            self.state._stale_notified = False
        servers = parse_subscription(body)
        if self._stop or not self.network.online():
            return
        expanded = expand_servers(servers)
        ranked = filter_and_sort(expanded, self._country_ranks)
        if not ranked:
            log.warning("subscription returned 0 allowed servers")
            return
        with self._standby_cond:
            if self._stop or not self.network.online() or self.network.snapshot().generation != generation:
                return
            self.state.set_ranked(ranked)
            self._sync_standby_after_ranked_refresh_locked(ranked)
        log.info("subscription refreshed, %d eligible servers", len(ranked))

    def tick_autoupdate(self) -> None:
        """Попытка git pull --ff-only и рестарт процесса при новом коде.

        Уведомления в Telegram:
        - успешный non-empty pull (rebase/restart/requirements/validate) — уже ниже;
        - неудача (rate-limit, exception, fetch/pull failed) — тоже уведомляем;
        - стабильные no-op (up to date, no upstream, tree not clean, detached HEAD,
          not a git repo) — silent (это ожидаемые стабильные состояния).
        """
        self.state.last_git_pull = time.time()
        if too_many_restarts():
            log.warning("autoupdate paused: too many recent restarts "
                        "(rate-limit); will retry next interval")
            notify("⚠️ autoupdate paused: too many recent restarts "
                   "(rate-limit), will retry next interval", urgent=True, topic="update")
            return
        try:
            result = check_and_pull(should_continue=lambda: not self._stop and self.network.online())
        except Exception as exc:  # noqa: BLE001
            log.exception("autoupdate: check_and_pull failed")
            notify(f"⚠️ autoupdate failed (check_and_pull exception): "
                   f"{type(exc).__name__}: {exc}", urgent=True, topic="update")
            return
        if not result.updated:
            if result.reason in FAILURE_REASONS:
                log.warning("autoupdate failed: %s — %s",
                            result.reason, result.error)
                notify(f"⚠️ autoupdate failed: {result.reason} — {result.error}",
                       urgent=True, topic="update")
            else:
                # up to date / tree not clean / no upstream / и т.п. — молча
                log.debug("autoupdate: no-op (%s)", result.reason)
            return

        if result.requirements_changed:
            if self._stop or not self.network.online():
                rolled_back = rollback_to(result.old_head)
                notify(f"⚠️ autoupdate dependencies deferred: network/shutdown; rollback={rolled_back}",
                       urgent=True, topic="update")
                return
            log.warning(
                "autoupdate pulled new code and requirements.txt changed "
                "(%s → %s). Installing dependencies before validation.",
                result.old_head[:7], result.new_head[:7],
            )
            notify(
                f"⚠️ autoupdate pulled {result.old_head[:7]} → "
                f"{result.new_head[:7]} with requirements.txt changes; "
                f"installing dependencies before restart.",
                urgent=True,
                topic="update",
            )
            ok, err = install_requirements()
            if not ok:
                last = err.splitlines()[-1] if err else "unknown error"
                log.error("autoupdate: requirements install failed for new code "
                          "%s, staying on %s. Error: %s",
                          result.new_head[:7], result.old_head[:7], last)
                rolled_back = rollback_to(result.old_head)
                if rolled_back:
                    notify(
                        f"🔴 autoupdate: requirements install failed for "
                        f"{result.new_head[:7]}, rolled back to "
                        f"{result.old_head[:7]}: {last}",
                        urgent=True,
                        topic="update",
                    )
                else:
                    notify(
                        f"🔴 autoupdate: requirements install failed for "
                        f"{result.new_head[:7]} and rollback FAILED: {last}",
                        urgent=True,
                        topic="update",
                    )
                return

        if result.manual_deploy_changed:
            log.warning(
                "autoupdate pulled new code and deploy service/sudoers files "
                "changed (%s → %s). Continuing with validated self-restart; "
                "runtime code remains responsible for backward compatibility.",
                result.old_head[:7], result.new_head[:7],
            )
            notify(
                f"⚠️ autoupdate pulled {result.old_head[:7]} → "
                f"{result.new_head[:7]} with deploy file changes; continuing "
                f"self-update after validation.",
                urgent=True,
                topic="update",
            )

        ok, err = validate_new_code()
        if not ok:
            log.error("autoupdate: new code (%s) failed import check, "
                      "staying on %s. Error: %s",
                      result.new_head[:7], result.old_head[:7],
                      err.splitlines()[-1] if err else "?")
            rolled_back = rollback_to(result.old_head)
            if rolled_back:
                notify(
                    f"🔴 autoupdate: new code {result.new_head[:7]} failed "
                    f"import check, rolled back to {result.old_head[:7]}",
                    urgent=True,
                    topic="update",
                )
            else:
                notify(
                    f"🔴 autoupdate: new code {result.new_head[:7]} failed "
                    f"import check, rollback FAILED — working tree stuck on bad commit!",
                    urgent=True,
                    topic="update",
                )
            return

        log.info("autoupdate: new code %s validated, restarting self",
                 result.new_head[:7])
        notify(
            f"🆙 xproxy updating {result.old_head[:7]} → "
            f"{result.new_head[:7]}, restarting",
            blocking=True,
            topic="update",
        )
        if self._stop:
            return
        if self._runtime_started:
            self._restart_requested = True
            self._wake_event.set()
        else:
            restart_self()

    def refresh_geo(self, force: bool) -> None:
        # Файлы кладутся в GEO_DIR. xray видит их через XRAY_LOCATION_ASSET.
        # Замена файла только атомарна и только после полного скачивания —
        # при обрыве соединения остаётся работать старая копия.
        try:
            def config_builder(categories):
                if self.state.transport == "ssh":
                    cfg = build_xray_config(None, ssh_port=self.emergency._applied_port,
                                            categories=categories)
                    return json.dumps(cfg, ensure_ascii=False, indent=2)
                server = self.state.active or next(iter(self.state.ranked_snapshot()), None)
                if server is None:
                    raise RuntimeError("no VLESS candidate for staged geo validation")
                return build_xray_config_text(server, categories=categories)
            validation_server = self.state.active
            if validation_server is None and self.state.ranked:
                validation_server = self.state.ranked[0]
            result = ensure_geo_assets(
                force=force,
                validation_server=validation_server,
                platform_info=self.platform,
                publish_lock=self._apply_lock,
                should_continue=lambda: self.network.online() and not self._stop,
                config_builder=config_builder,
            )
        except Exception:  # noqa: BLE001
            log.exception("geo refresh failed")
            # Жёсткое падение — перепланируем через самый короткий бэкофф,
            # чтобы не зацикливаться на каждой итерации health-loop.
            self._next_geo_at = time.time() + 60.0
            return

        # Планируем следующую попытку по данным ensure_geo_assets.
        delay = _jittered(result.next_attempt_in)
        self._next_geo_at = time.time() + max(10.0, delay)
        self._geo_period = delay

        if result.errors:
            # Не спамим пользователя на каждый ретрай: throttle notifier
            # отфильтрует одинаковые сообщения. Сообщаем факт ошибок.
            errs = ", ".join(f"{n}: {e}" for n, e in result.errors.items())
            notify(f"⚠️ geo download error ({errs}); working copy kept, "
                   f"next retry in {int(delay)}s", topic="geo")

        # После скачивания: проверим, какие geo-ссылки в routing.json теперь
        # не резолвятся, и, если набор изменился, уведомим пользователя.
        # Параллельно получим флаг geo_readable — он управляет решением о
        # ребилде: если хотя бы один .dat нечитаем/отсутствует, мы НЕ
        # трогаем live-конфиг (см. дефект #2 предыдущей итерации: иначе
        # любой parser mismatch превращался в живую смену маршрутизации).
        geo_readable = self._check_and_notify_removed_geo()

        if not geo_readable:
            log.warning("geo assets not all readable — skipping config rebuild "
                        "to preserve last-known-good routing")
            return

        # Geo вернулись — если раньше сидели в «тупике», расклеиваем флаг,
        # чтобы следующий реальный stuck-случай снова поднял уведомление.
        self._stuck_notified = False

        # Если файлы обновились и есть активный сервер — пересобрать конфиг,
        # чтобы xray подхватил новые geo-данные без ожидания ротации.
        # geo_ready=True передаём, чтобы не парсить .dat второй раз: мы
        # только что валидировали их внутри _check_and_notify_removed_geo().
        if result.freshly_downloaded and (self.state.active is not None or self.state.transport == "ssh"):
            self._invalidate_standby("geo files updated")
            log.info("geo files updated (%s) — rebuilding xray config",
                     ",".join(sorted(result.freshly_downloaded)))
            self._rebuild_config_if_active(
                context="post-download rebuild",
                geo_ready=True,
            )

    def _check_and_notify_removed_geo(self) -> bool:
        """Проверить routing против актуальных .dat и уведомить пользователя.

        Возвращает True, если все geo-файлы читаемы (и, значит, список
        выкинутых записей достоверный). False означает: как минимум один
        .dat нечитаем — решения об «удалённых категориях» принимать
        нельзя, уведомление не шлём, чтобы не дергать пользователя на
        временные FS/парсерные сбои.
        """
        try:
            sections = build_xray_sections()
        except Exception:  # noqa: BLE001
            log.exception("failed to validate routing against geo data")
            return False
        geo_readable = bool(sections.get("geo_readable"))
        if not geo_readable:
            # Не обновляем подпись: когда файлы снова станут читаемы,
            # последует честное сравнение с предыдущим валидным набором.
            return False

        removed = sections.get("removed_geo") or []
        # Подпись: набор групп+записей. Если не изменился — не уведомляем.
        sig = ";".join(f"{g}:{e}" for g, e in sorted(removed))
        if sig == self._last_removed_geo_sig:
            return True
        self._last_removed_geo_sig = sig

        if not removed:
            # Если раньше что-то было — сообщим, что всё восстановилось.
            log.info("routing: no missing geo categories")
            return True

        # Группируем для компактного отчёта.
        by_group: dict[str, list[str]] = {}
        for group, entry in removed:
            by_group.setdefault(group, []).append(entry)
        lines = [f"  {g}: {', '.join(sorted(set(items)))}"
                 for g, items in sorted(by_group.items())]
        log.warning("routing: dropped %d entries referencing missing geo "
                    "categories:\n%s", len(removed), "\n".join(lines))
        notify(
            "⚠️ routing: dropped entries referencing missing geo "
            f"categories ({len(removed)} total):\n" + "\n".join(lines),
            urgent=True,
            topic="geo",
        )
        return True

    def _geo_ready_for_rebuild(self, context: str) -> bool:
        """Guard: безопасно ли сейчас собирать и писать новый xray-конфиг.

        «Безопасно» ≡ в итоговом построенном routing+dns не осталось
        geosite:*/geoip:* ссылок на нечитаемые .dat. Это точнее, чем
        проверка «все .dat на диске»: если routing.json, к примеру, не
        использует geoip:*, отсутствие geoip.dat не должно блокировать
        rebuild (build_xray_sections сам это понимает и вернёт
        geo_readable=True).

        Если нужные .dat нечитаемы — ничего не трогаем: текущий xray
        (если был жив) продолжает работать, refresh_geo ретраится по
        бэкоффу.
        """
        try:
            sections = build_xray_sections()
        except Exception as exc:  # noqa: BLE001
            log.warning("%s: skipped — routing build failed: %s", context, exc)
            return False
        if not sections.get("geo_readable"):
            missing = sections.get("unreadable_needed") or ["?"]
            log.warning("%s: skipped — needed geo assets unreadable (%s), "
                        "preserving last-known-good xray config",
                        context, ", ".join(missing))
            return False
        return True

    def _rebuild_config_if_active(self, context: str = "configuration rebuild",
                                  geo_ready: Optional[bool] = None) -> None:
        if self.dry_run or self._stop or not self.network.online() or self._active_channel_ok is not True:
            return
        with self._apply_lock:
            if geo_ready is not True and not self._geo_ready_for_rebuild(context):
                return
            if self.state.transport == "ssh":
                port = self.emergency._applied_port
                if port is None:
                    return
                text = build_ssh_config_text(port)
            elif self.state.active is not None:
                text = build_xray_config_text(self.state.active)
            else:
                return
            transport = self.state.transport
            if self._apply_verified_config(text, context, guard=lambda: self.state.transport == transport):
                self._rebuild_pending = False

    def _start_standby_worker(self) -> None:
        if self.dry_run:
            return
        with self._standby_cond:
            if self._standby_thread and self._standby_thread.is_alive():
                return
            self._standby_stop = False
            self._standby_thread = threading.Thread(
                target=self._standby_worker_loop,
                name="xproxy-standby-worker",
                daemon=True,
            )
            self._standby_thread.start()
            self._standby_cond.notify_all()
        log.info("standby worker started")

    def _stop_standby_worker(self) -> None:
        thread: Optional[threading.Thread]
        with self._standby_cond:
            self._standby_stop = True
            self._standby_cond.notify_all()
            thread = self._standby_thread
        stop_probes()
        if thread and thread.is_alive():
            thread.join(timeout=3.0)

    def _wake_standby_worker(self) -> None:
        with self._standby_cond:
            self._standby_cond.notify_all()

    def _penalize_if_not_active(self, server: Server, reason: str) -> bool:
        penalized = self.state.penalize_if_not_active(server)
        if not penalized:
            log.info("skip penalty for active server %s (%s)",
                     _fmt(server), reason)
        return penalized

    def _notify_active_state(
        self,
        state: str,
        *,
        server: Optional[Server] = None,
        reason: str = "",
        detail: str = "",
        urgent: bool = False,
    ) -> None:
        if self.dry_run:
            return
        server = server if server is not None else self.state.active
        log.info("active state event: %s %s reason=%s detail=%s urgent=%s",
                 state, _fmt(server), reason, detail, urgent)

    def _notify_standby_state(
        self,
        state: str,
        *,
        server: Optional[Server] = None,
        reason: str = "",
        detail: str = "",
        urgent: bool = False,
    ) -> None:
        if self.dry_run:
            return
        target = _fmt(server)
        log.info("standby state event: %s %s reason=%s detail=%s urgent=%s",
                 state, target, reason, detail, urgent)

    def _record_active_health(self, ok: bool) -> None:
        self._active_channel_ok = ok
        self._health_checked_at = time.monotonic()
        if ok:
            with self._standby_cond:
                active = self.state.active_snapshot()
                if self._standby is not None and active is not None and \
                        self._standby.server.key() == active.key():
                    self._discard_current_standby_locked(active, "active endpoint recovered")

    def _sample_global_status(
        self,
        *,
        has_internet: bool,
        now: float | None = None,
    ) -> None:
        if self.dry_run or not has_internet:
            if not self.dry_run and not has_internet:
                self._status_last_sample_at = 0.0
                self._status_candidate_key = None
                self._status_candidate_count = 0
            return
        if self._active_channel_ok is None:
            return

        ts = time.time() if now is None else now
        interval = max(0.0, STATUS_NOTIFY_SAMPLE_INTERVAL)
        if self._status_last_sample_at and \
                ts - self._status_last_sample_at < interval:
            return
        self._status_last_sample_at = ts

        snapshot_key, text = self._global_status_snapshot()
        if snapshot_key == self._status_candidate_key:
            self._status_candidate_count += 1
        else:
            self._status_candidate_key = snapshot_key
            self._status_candidate_count = 1

        required = max(1, STATUS_NOTIFY_STABLE_SAMPLES)
        if self._status_candidate_count < required:
            log.debug("global status candidate %s sample %d/%d",
                      snapshot_key, self._status_candidate_count, required)
            return

        if self._status_stable_key is None:
            self._status_stable_key = snapshot_key
            log.info("global status baseline established: %s", text)
            if not snapshot_key[0]:
                notify(text, urgent=True, topic="routes")
            return

        if snapshot_key == self._status_stable_key:
            return

        self._status_stable_key = snapshot_key
        notify(text, urgent=not snapshot_key[0] or not snapshot_key[1], topic="routes")

    def _global_status_snapshot(
        self,
    ) -> tuple[tuple, str]:
        active = self.state.active_snapshot()
        active_ok = bool(self._active_channel_ok and (active is not None or self.state.transport == "ssh"))
        active_country = active.country if active_ok and active is not None else None
        with self._standby_cond:
            standby = self._standby
            standby_ok = standby is not None and standby.is_usable()
            standby_server = standby.server if standby is not None else None

        tunnel = self.emergency.manager.snapshot()
        active_label = (f"SSH/{tunnel.endpoint.id if tunnel.endpoint else 'existing'}"
                        if self.state.transport == "ssh" else _fmt(active))
        key = (active_ok, standby_ok, active_country, _server_key(active),
               _server_key(standby_server) if standby_ok else None, self.state.transport)
        if active_ok and standby_ok:
            emoji = "🟢"
            status = "READY"
        elif active_ok:
            emoji = "🟠"
            status = "DEGRADED"
        elif standby_ok:
            emoji = "🔴"
            status = "ACTIVE_FAILED"
        else:
            emoji = "🔴"
            status = "DOWN"

        active_state = "OK" if active_ok else "FAILED"
        standby_state = "READY" if standby_ok else "EMPTY"
        text = (
            f"{emoji} xproxy status {status}: "
            f"active={active_state} {active_label}; "
            f"standby={standby_state} {_fmt(standby_server)}"
        )
        return key, text

    def _notify_standby_empty_locked(
        self,
        reason: str,
        previous: PreparedStandby,
        *,
        detail: str = "no usable standby",
    ) -> None:
        if self._notified_standby_slot_key is None:
            return
        self._notified_standby_slot_key = None
        self._notify_standby_state(
            "EMPTY",
            server=previous.server,
            reason=reason,
            detail=detail,
            urgent=True,
        )

    def _invalidate_standby(self, reason: str) -> None:
        with self._standby_cond:
            self._invalidate_standby_locked(reason)

    def _invalidate_standby_locked(self, reason: str) -> None:
        self._standby_generation += 1
        self._scan_attempted.clear()
        self._scan_retry_at = 0
        self._scan_started_at = 0
        self.emergency.reset_evidence()
        previous = self._standby
        if previous is not None:
            log.info("standby invalidated: %s (%s)",
                     reason, _fmt(previous.server))
            previous.status = "STALE"
        self._standby = None
        self._standby_refresh_candidate = None
        if previous is not None:
            self._notify_standby_empty_locked(reason, previous)
        self._standby_cond.notify_all()

    def _sync_standby_after_ranked_refresh_locked(
        self,
        ranked: list[Server],
    ) -> None:
        self._standby_generation += 1
        self._scan_attempted.clear()
        self._scan_retry_at = 0
        self.emergency.reset_evidence()
        if self._standby is None:
            self._standby_refresh_candidate = None
            self._standby_cond.notify_all()
            return

        standby = self._standby
        # The same endpoint can appear multiple times with different VLESS
        # parameters, so endpoint key alone is not enough to preserve a slot.
        endpoint_matches = [
            server for server in ranked
            if server.key() == standby.server.key()
        ]
        if not endpoint_matches:
            log.info("standby invalidated: subscription removed %s",
                     _fmt(standby.server))
            standby.status = "STALE"
            self._standby = None
            self._standby_refresh_candidate = None
            self._notify_standby_empty_locked(
                "subscription-removed",
                standby,
            )
            self._standby_cond.notify_all()
            return

        matched: tuple[Server, str] | None = None
        fingerprint_errors: list[Exception] = []
        last_state: str | None = None
        for refreshed_server in endpoint_matches:
            try:
                current_fp = standby_fingerprint(refreshed_server, info=self.platform)
            except Exception as exc:  # noqa: BLE001
                fingerprint_errors.append(exc)
                continue
            state = standby.lifecycle_state(current_fp)
            last_state = state
            if state in ("READY", "PRE_STALE"):
                matched = (refreshed_server, state)
                break

        if matched is not None:
            matched_server, matched_state = matched
            standby.server = matched_server
            self._standby_refresh_candidate = None
            log.info("standby preserved after subscription refresh: %s state=%s "
                     "endpoint_matches=%d",
                     _fmt(matched_server), matched_state, len(endpoint_matches))
            self._standby_cond.notify_all()
            return

        if fingerprint_errors and len(fingerprint_errors) == len(endpoint_matches):
            exc = fingerprint_errors[-1]
            log.warning("standby fingerprint check after subscription refresh "
                        "failed for %d endpoint matches: %s",
                        len(endpoint_matches), exc)
            standby.status = "STALE"
            self._standby = None
            self._standby_refresh_candidate = None
            self._notify_standby_empty_locked(
                "subscription-fingerprint",
                standby,
                detail=str(exc),
            )
            self._standby_cond.notify_all()
            return

        if fingerprint_errors:
            log.warning("standby fingerprint check after subscription refresh "
                        "failed for %d/%d endpoint matches; no matching "
                        "fingerprint found",
                        len(fingerprint_errors), len(endpoint_matches))

        if last_state is None:
            log.warning("standby fingerprint check after subscription refresh "
                        "produced no lifecycle state; invalidating slot")
            last_state = "UNKNOWN"

        current_state = standby.lifecycle_state()
        if current_state in ("READY", "PRE_STALE"):
            same_country = [
                server for server in endpoint_matches
                if server.country == standby.server.country
            ]
            self._standby_refresh_candidate = same_country[0] \
                if same_country else endpoint_matches[0]
            self._standby_last_attempt = 0
            log.info("standby config changed after subscription refresh; "
                     "preserving current usable slot and scheduling refresh: "
                     "%s -> %s state=%s current_state=%s endpoint_matches=%d",
                     _fmt(standby.server),
                     _fmt(self._standby_refresh_candidate),
                     last_state,
                     current_state,
                     len(endpoint_matches))
            self._standby_cond.notify_all()
            return

        log.info("standby invalidated after subscription refresh: %s state=%s "
                 "endpoint_matches=%d",
                 _fmt(standby.server), last_state, len(endpoint_matches))
        standby.status = "STALE"
        self._standby = None
        self._standby_refresh_candidate = None
        self._notify_standby_empty_locked(
            "subscription-refresh",
            standby,
            detail=f"state={last_state}",
        )
        self._standby_cond.notify_all()

    def _handle_prepare_failure_locked(
        self,
        candidate: Server,
        reason: str,
        prepare_is_refresh: bool,
    ) -> bool:
        """Decide whether to discard the current standby after a prepare failure.

        A failed config-refresh attempt shares the current slot's endpoint key,
        so the usual discard-by-key path would drop a still-usable slot. When
        refreshing and the current slot remains usable, keep it and clear the
        pending refresh candidate instead. Returns True if the current standby
        was discarded.
        """
        if prepare_is_refresh and self._standby is not None and \
                self._standby.is_usable():
            log.info("standby refresh candidate failed; keeping current usable "
                     "slot: %s failed=%s reason=%s",
                     _fmt(self._standby.server), _fmt(candidate), reason)
            self._standby_refresh_candidate = None
            return False
        return self._discard_current_standby_locked(candidate, reason)

    def _discard_current_standby_locked(self, candidate: Server, reason: str) -> bool:
        if self._standby is None:
            return False
        if self._standby.server.key() != candidate.key():
            return False
        self._standby_generation += 1
        log.info("standby slot discarded: %s (%s)", reason, _fmt(candidate))
        previous = self._standby
        previous.status = "STALE"
        self._standby = None
        self._standby_refresh_candidate = None
        self._standby_last_attempt = 0
        self._notify_standby_empty_locked(reason, previous)
        self._standby_cond.notify_all()
        return True

    def _publish_standby_locked(
        self,
        prepared: PreparedStandby,
        *,
        generation: int | None = None,
    ) -> bool:
        if generation is not None and generation != self._standby_generation:
            log.info("discard standby prepared on stale generation: %s "
                     "(prepared=%d current=%d)",
                     _fmt(prepared.server), generation, self._standby_generation)
            return False
        previous = self._standby
        previous_state = "EMPTY"
        prepared_key = _server_key(prepared.server)
        previous_key = None
        if previous is not None:
            previous_state = previous.lifecycle_state()
            previous_key = _server_key(previous.server)

        self._standby = prepared
        # A successful reserve closes this search episode. Failures from
        # before it cannot complete a new all-reserves-failed pass later.
        self._scan_attempted.clear()
        self._scan_started_at = 0
        self._scan_retry_at = 0
        self._standby_refresh_candidate = None
        detail = f"{prepared.ttl_detail()} slot={prepared.fingerprint[:8]}"
        same_usable_endpoint = (
            previous is not None and
            previous_state in ("READY", "PRE_STALE") and
            previous_key == prepared_key
        )
        should_notify = (
            prepared_key != self._notified_standby_slot_key and
            not same_usable_endpoint
        )
        if previous_key is not None and previous_key != prepared_key:
            detail = f"{detail}; replaced={_fmt(previous.server)}"

        if should_notify:
            self._notify_standby_state(
                "READY",
                server=prepared.server,
                detail=detail,
            )
        else:
            log.info("standby refreshed silently: %s %s",
                     _fmt(prepared.server), prepared.ttl_detail())
        self._notified_standby_slot_key = prepared_key
        return True

    def _standby_worker_loop(self) -> None:
        while not self._standby_stop and not self._stop:
            with self._standby_cond:
                if not self.network.online():
                    self._standby_cond.wait(timeout=HEALTH_INTERVAL)
                    continue
                candidate = self._select_standby_candidate_locked()
                if candidate is None:
                    self._standby_cond.wait(timeout=VLESS_RECOVERY_INTERVAL)
                    continue
                self._standby_preparing = True
                refreshing = self._standby_prepare_is_refresh
                self._standby_last_attempt = time.time()
                generation = self._standby_generation
            def current():
                return not self._standby_stop and not self._stop and self.network.online() and \
                    generation == self._standby_generation
            try:
                prepared = prepare_standby(candidate, info=self.platform, should_continue=current)
            except Exception as exc:
                remote_failure = isinstance(exc, StandbyError) and not isinstance(exc, StandbyLocalError)
                # Never count an interrupted network probe as route blocking.
                if remote_failure and current():
                    remote_failure = self.emergency.confirm_network() and current()
                with self._standby_cond:
                    self._standby_preparing = False
                    if current():
                        if remote_failure:
                            self._handle_prepare_failure_locked(candidate, str(exc), refreshing)
                            self.emergency.failed(candidate)
                            self._penalize_if_not_active(candidate, "standby end-to-end failure")
                        else:
                            self.emergency.local_failure()
                        log.info("standby preparation failed (%s): %s", _fmt(candidate), exc)
                    self._standby_cond.notify_all()
                self._wake_event.set()
                continue
            with self._standby_cond:
                self._standby_preparing = False
                if not current() or not self._eligible_preparation(prepared.server):
                    self._standby_cond.notify_all()
                    continue
                if self._publish_standby_locked(prepared, generation=generation):
                    self.emergency.prepared(prepared)
                self._standby_cond.notify_all()
            # The main guard is the sole decision maker for promotions.
            self._wake_event.set()

    def _select_standby_candidate_locked(self) -> Optional[Server]:
        if self._standby_preparing:
            return None
        self._standby_prepare_is_refresh = False
        if self._standby is not None:
            state = self._standby.lifecycle_state()
            if self._standby_refresh_candidate is not None:
                if state in ("READY", "PRE_STALE"):
                    if not self._active_waiting_for_standby and \
                            time.time() - self._standby_last_attempt < \
                            STANDBY_RETRY_INTERVAL:
                        return None
                    candidate = self._standby_refresh_candidate
                    log.info("standby config refresh pending, preparing updated "
                             "slot: %s (current=%s state=%s)",
                             _fmt(candidate), _fmt(self._standby.server), state)
                    self._standby_prepare_is_refresh = True
                    return candidate
                self._standby_refresh_candidate = None
            if state == "READY":
                if self.emergency.needs_fresh_standby(self._standby):
                    return self._standby.server
                return None
            if state == "PRE_STALE":
                if self._standby.status != "PRE_STALE":
                    log.info("standby pre-stale, revalidating current slot: %s",
                             _fmt(self._standby.server))
                self._standby.status = "PRE_STALE"
                return self._standby.server
            else:
                log.info("standby no longer usable: %s state=%s",
                         _fmt(self._standby.server), state)
                previous = self._standby
                previous.status = "STALE"
                self._standby = None
                self._notify_standby_empty_locked(
                    "standby-stale",
                    previous,
                    detail=f"state={state}",
                )
        active = self.state.active_snapshot()
        if not self.state.ranked_snapshot():
            return None
        now = time.monotonic()
        if now < self._scan_retry_at:
            return None
        candidates = [s for s in self.state.next_candidates() if self._eligible_preparation(s)]
        if active is not None and active.country:
            candidates.sort(key=lambda s: s.country == active.country)
        for candidate in candidates:
            token = candidate_key(candidate)
            if token in self._scan_attempted:
                continue
            if not self._scan_attempted:
                self._scan_started_at = now
            self._scan_attempted.add(token)
            return candidate
        if self._scan_attempted:
            self.emergency.complete_pass(candidates, self._scan_started_at)
            log.info("standby pass exhausted; next pass in %ss", STANDBY_RETRY_INTERVAL)
            self._scan_attempted.clear()
            self._scan_started_at = 0
            self._standby_waiting_attempted.clear()
            self._scan_retry_at = now + STANDBY_RETRY_INTERVAL
        return None

    def _eligible_preparation(self, candidate: Server) -> bool:
        active = self.state.active_snapshot()
        if active is None or candidate.key() != active.key():
            return True
        # A changed UUID/Reality configuration can repair a failed endpoint,
        # but it is never an independent reserve for a healthy active route.
        return self._active_channel_ok is False and candidate_key(candidate) != candidate_key(active)

    def _enter_waiting_for_standby(self, reason: str) -> None:
        with self._standby_cond:
            if not self._active_waiting_for_standby:
                self._active_waiting_generation += 1
                self._standby_waiting_generation = self._active_waiting_generation
                self._standby_waiting_attempted.clear()
                log.warning("active failed (%s), waiting for standby", reason)
                self._notify_active_state(
                    "WAITING_FOR_STANDBY",
                    reason=reason,
                    urgent=True,
                )
            self._active_waiting_for_standby = True
            self._active_waiting_reason = reason
            self._standby_cond.notify_all()

    def _clear_waiting_for_standby(self, reason: str) -> None:
        with self._standby_cond:
            self._clear_waiting_for_standby_locked(reason)

    def _clear_waiting_for_standby_locked(self, reason: str) -> None:
        if not self._active_waiting_for_standby:
            return
        log.info("active standby wait cleared: %s", reason)
        self._active_waiting_for_standby = False
        self._active_waiting_reason = ""
        self._active_waiting_generation += 1
        self._standby_waiting_generation = self._active_waiting_generation
        self._standby_waiting_attempted.clear()
        self._standby_cond.notify_all()

    def _promotion_running(self) -> bool:
        with self._standby_cond:
            return self._promotion_in_progress

    def _active_still_needs_standby(self, reason: str) -> bool:
        if self.dry_run:
            return True
        try:
            if not internet_alive():
                if self._runtime_started:
                    self._update_network(False)
                log.info("skip standby promotion for %s: direct internet unavailable",
                         reason)
                return False
            if not is_running():
                return True
            if not proxy_alive():
                return True
            target_ok, target_detail = target_alive()
            if not target_ok:
                log.info("standby promotion still needed for %s: %s",
                         reason, target_detail)
                return True
        except Exception as exc:  # noqa: BLE001
            log.warning("active failure recheck failed before standby promotion "
                        "(%s): %s", reason, exc)
            return True
        log.info("skip standby promotion for %s: active recovered", reason)
        self.state.note_proxy_ok()
        self._record_active_health(True)
        return False

    def _rollback_failed_promotion(
        self,
        prepared: PreparedStandby,
        previous: Optional[Server],
        *,
        reason: str,
        failure: str,
        detail: str = "",
        applied: bool = True,
    ) -> None:
        if not applied or self.dry_run:
            return

        try:
            restored = restore_backup(self.platform)
        except Exception as exc:  # noqa: BLE001
            log.exception("promotion rollback crashed: %s", exc)
            restored = False

        if restored:
            healthy = self.network.online() and proxy_alive() and target_alive()[0]
            self._record_active_health(bool(healthy))
            log.warning("rolled back failed standby promotion to %s "
                        "(failed=%s, standby=%s)",
                        _fmt(previous), failure, _fmt(prepared.server))
            notify(
                f"🟠 standby promotion rolled back to {_fmt(previous)} "
                f"after {failure} on {_fmt(prepared.server)}"
                f"{f' — {detail}' if detail else ''}",
                urgent=True, topic="config",
            )
            self._notify_active_state(
                "FAILED",
                server=previous,
                reason=f"promotion-rollback:{reason}",
                detail=f"restored_previous_config; standby_failed={failure}",
                urgent=True,
            )
            return

        log.error("promotion rollback failed; live xray may still use failed "
                  "standby %s (previous active was %s)",
                  _fmt(prepared.server), _fmt(previous))
        self.emergency.reconcile()
        self._record_active_health(False)
        self.emergency.event("config", "🔴 Config rollback failed; inspecting the actual active transport",
                             urgent=True)
        self._notify_active_state(
            "FAILED",
            server=prepared.server,
            reason=f"promotion-applied-failed:{reason}",
            detail=f"{failure}; rollback_failed; previous={_fmt(previous)}",
            urgent=True,
        )

    def _promote_standby(
        self,
        reason: str,
        *,
        expected_wait_generation: Optional[int] = None,
        require_active_failure: bool = False,
    ) -> bool:
        if not self.dry_run and not self.network.online():
            return False
        with self._apply_lock:
            return self._promote_standby_with_apply_lock(
                reason,
                expected_wait_generation=expected_wait_generation,
                require_active_failure=require_active_failure,
            )

    def _promote_standby_with_apply_lock(
        self,
        reason: str,
        *,
        expected_wait_generation: Optional[int],
        require_active_failure: bool,
    ) -> bool:
        if expected_wait_generation is not None:
            with self._standby_cond:
                if not self._active_waiting_for_standby or \
                        self._active_waiting_generation != expected_wait_generation:
                    log.info("skip standby promotion for stale wait generation "
                             "(reason=%s expected=%s current=%s waiting=%s)",
                             reason,
                             expected_wait_generation,
                             self._active_waiting_generation,
                             self._active_waiting_for_standby)
                    return False

        if require_active_failure and not self._active_still_needs_standby(reason):
            self._clear_waiting_for_standby("active-recovered-before-promotion")
            return False

        with self._standby_cond:
            if self._promotion_in_progress:
                log.info("standby promotion already in progress; skip %s", reason)
                return False
            if expected_wait_generation is not None and (
                not self._active_waiting_for_standby or
                self._active_waiting_generation != expected_wait_generation
            ):
                log.info("skip standby promotion for stale wait generation "
                         "after recheck (reason=%s expected=%s current=%s waiting=%s)",
                         reason,
                         expected_wait_generation,
                         self._active_waiting_generation,
                         self._active_waiting_for_standby)
                return False
            prepared = self._standby
            if prepared is None:
                return False
            try:
                current_fp = standby_fingerprint(prepared.server, info=self.platform)
            except Exception as exc:  # noqa: BLE001
                log.warning("standby fingerprint check failed: %s", exc)
                current_fp = None
            promotion_state = prepared.lifecycle_state(current_fp) if current_fp is not None else "STALE"
            if promotion_state not in ("READY", "PRE_STALE"):
                log.warning("standby not ready for promotion: %s",
                            _fmt(prepared.server))
                prepared.status = "STALE"
                self._standby = None
                self._notify_standby_empty_locked(
                    "promotion-not-ready",
                    prepared,
                    detail=f"state={promotion_state}",
                )
                self._standby_cond.notify_all()
                return False
            prepared.status = "PROMOTING"
            self._standby = None
            self._standby_refresh_candidate = None
            self._promotion_in_progress = True
            self._clear_waiting_for_standby_locked(f"promotion-start:{reason}")

        try:
            prev = self.state.active
            previous_vless = prev or self.state.last_vless
            network_generation = self.network.snapshot().generation
            log.warning("promoting standby %s (reason=%s)",
                        _fmt(prepared.server), reason)
            self._notify_standby_state(
                "PROMOTING",
                server=prepared.server,
                reason=reason,
                detail=f"from={promotion_state}",
            )
            with self._standby_cond:
                self._notify_standby_empty_locked(
                    reason,
                    prepared,
                    detail="slot consumed by promotion",
                )
            self._notify_active_state(
                "PROMOTING",
                server=prev,
                reason=reason,
                detail=f"next={_fmt(prepared.server)}",
            )
            applied = False
            def current():
                return self.dry_run or (not self._stop and self.network.online() and
                    self.network.snapshot().generation == network_generation and
                    standby_fingerprint(prepared.server, info=self.platform) == prepared.fingerprint)
            try:
                apply_config_text(
                    prepared.config_text,
                    label=f"standby {_fmt(prepared.server)}",
                    dry_run=self.dry_run,
                    info=self.platform,
                    should_continue=current,
                )
                applied = True
            except ConfigUnchanged:
                log.info("standby promotion config unchanged")
            except XrayStartError as exc:
                log.error("standby promotion aborted: xray did not start: %s", exc)
                self._notify_standby_state(
                    "FAILED",
                    server=prepared.server,
                    reason="promotion-xray-start",
                    detail=str(exc),
                    urgent=True,
                )
                self.emergency.local_failure()
                self._rollback_failed_promotion(
                    prepared,
                    prev,
                    reason=reason,
                    failure="promotion-xray-start",
                    detail=str(exc),
                    applied=True,
                )
                self._enter_waiting_for_standby(reason)
                return False
            except Exception as exc:  # noqa: BLE001
                log.warning("standby promotion failed for %s: %s",
                            _fmt(prepared.server), exc)
                self._notify_standby_state(
                    "FAILED",
                    server=prepared.server,
                    reason="promotion",
                    detail=f"{type(exc).__name__}: {exc}",
                    urgent=True,
                )
                self.emergency.local_failure()
                from .xray_control import TRANSACTION_PATH
                if TRANSACTION_PATH.exists():
                    self._rollback_failed_promotion(prepared, prev, reason=reason,
                                                    failure="promotion-write", detail=str(exc))
                self._enter_waiting_for_standby(reason)
                return False

            if not self.dry_run:
                if not self.network.online() or self.network.snapshot().generation != network_generation:
                    self._rollback_failed_promotion(prepared, prev, reason=reason,
                                                    failure="network-changed", applied=applied)
                    return False
                if not proxy_alive():
                    log.warning("promoted standby failed proxy healthcheck: %s",
                                _fmt(prepared.server))
                    self._notify_standby_state(
                        "FAILED",
                        server=prepared.server,
                        reason="post-promotion-proxy",
                        urgent=True,
                    )
                    if self._runtime_started:
                        self.emergency.confirm_network()
                    if self.network.online() and self.network.snapshot().generation == network_generation:
                        self.state.penalize(prepared.server)
                    self._rollback_failed_promotion(
                        prepared,
                        prev,
                        reason=reason,
                        failure="post-promotion-proxy",
                        applied=applied,
                    )
                    self._enter_waiting_for_standby(reason)
                    return False
                target_ok, target_detail = target_alive()
                if not target_ok:
                    log.warning("promoted standby blocks target %s: %s",
                                target_detail, _fmt(prepared.server))
                    self._notify_standby_state(
                        "FAILED",
                        server=prepared.server,
                        reason="post-promotion-target",
                        detail=target_detail,
                        urgent=True,
                    )
                    if self._runtime_started:
                        self.emergency.confirm_network()
                    if self.network.online() and self.network.snapshot().generation == network_generation:
                        self.state.penalize(prepared.server)
                    self._rollback_failed_promotion(
                        prepared,
                        prev,
                        reason=reason,
                        failure="post-promotion-target",
                        detail=target_detail,
                        applied=applied,
                    )
                    self._enter_waiting_for_standby(reason)
                    return False

            if not self.dry_run:
                if not self.network.online() or self.network.snapshot().generation != network_generation:
                    self._rollback_failed_promotion(prepared, prev, reason=reason,
                                                    failure="network-changed", applied=applied)
                    return False
                try:
                    if not current():
                        raise RuntimeError("prepared configuration changed during promotion")
                    commit_config(self.platform)
                except Exception as exc:
                    self._rollback_failed_promotion(prepared, prev, reason=reason,
                                                    failure="commit", detail=str(exc), applied=applied)
                    return False
            prev_country = prev.country if prev else "-"
            if prev is not None:
                self.state.penalize(prev)
            self.state.set_active(prepared.server)
            self._record_active_health(True)
            with self._standby_cond:
                self._standby_generation += 1
                self._scan_attempted.clear()
                self._scan_retry_at = 0
            self.emergency.reset_evidence()
            log.info("standby promoted %s -> %s reason=%s",
                     prev_country, _fmt(prepared.server), reason)
            self._notify_active_state(
                "OK",
                server=prepared.server,
                reason=f"promoted:{reason}",
            )
            self._xray_start_failure_notified = False
            self._schedule_config_sync_after_vless_change(
                reason=reason,
                previous=previous_vless,
                promoted=prepared.server,
                config_text=prepared.config_text,
            )
            self._wake_standby_worker()
            return True
        finally:
            with self._standby_cond:
                self._promotion_in_progress = False
                self._standby_cond.notify_all()

    def _schedule_config_sync_after_vless_change(
        self,
        *,
        reason: str,
        previous: Optional[Server],
        promoted: Server,
        config_text: str | None = None,
    ) -> None:
        if self.dry_run or self._stop or promoted.protocol != "vless":
            return
        if previous is not None and candidate_key(previous) == candidate_key(promoted):
            log.debug("config sync skipped: VLESS upstream unchanged (%s)", reason)
            return
        # Caller still owns the apply lock. Capture the committed VLESS config
        # now; the sender must never reread a subsequently installed SSH config.
        try:
            text = config_text if config_text is not None else self.platform.xray_config.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("cannot capture VLESS config for sync: %s", exc)
            notify(f"⚠️ cannot capture VLESS config for sync: {exc}", urgent=True, topic="sync")
            return
        publication = _ConfigPublication(
            reason, _fmt(previous), _fmt(promoted), candidate_key(promoted), text,
        )
        if not self._runtime_started:
            # --once must finish publication before exiting its instance lease.
            self._run_config_sync(publication)
            return
        with self._config_sync_cond:
            # One sender preserves publication order; only the latest waiting
            # change matters to clients fetching the shared config.json.
            self._config_sync_pending = publication
            if self._config_sync_thread is None:
                self._config_sync_thread = threading.Thread(
                    target=self._config_sync_loop, args=(), name="xproxy-config-sync", daemon=True,
                )
                self._config_sync_thread.start()

    def _config_sync_loop(self) -> None:
        while True:
            with self._config_sync_cond:
                publication = self._config_sync_pending
                self._config_sync_pending = None
                if self._stop or publication is None:
                    self._config_sync_thread = None
                    return
            self._run_config_sync(publication)

    def _finish_config_sync(self) -> None:
        with self._config_sync_cond:
            self._config_sync_pending = None
            thread = self._config_sync_thread
        if thread is not None:
            thread.join()  # SCP has a bounded timeout; no old sender after exec.

    def _run_config_sync(self, publication: _ConfigPublication) -> None:
        active = self.state.active_snapshot()
        if self._stop or not self.network.online() or self.state.transport != "vless" or \
                active is None or candidate_key(active) != publication.upstream_key:
            return
        reason = publication.reason
        previous_label, promoted_label = publication.previous_label, publication.promoted_label
        try:
            target = sync_current_config(info=self.platform, config_text=publication.config_text)
        except ConfigSyncError as exc:
            log.warning("config sync failed after VLESS upstream change "
                        "%s → %s reason=%s: %s",
                        previous_label, promoted_label, reason, exc)
            notify(
                f"⚠️ config sync failed after VLESS upstream change "
                f"{previous_label} → {promoted_label}: {exc}",
                urgent=True,
                topic="sync",
            )
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("config sync crashed after VLESS upstream change "
                          "%s → %s reason=%s",
                          previous_label, promoted_label, reason)
            notify(
                f"⚠️ config sync crashed after VLESS upstream change "
                f"{previous_label} → {promoted_label}: "
                f"{type(exc).__name__}: {exc}",
                urgent=True,
                topic="sync",
            )
            return

        if target is None:
            return
        log.info("config sync completed after VLESS upstream change %s → %s "
                 "reason=%s target=%s",
                 previous_label, promoted_label, reason, target.safe_label())
        notify(
            f"🟢 config synced to {target.safe_label()} after VLESS upstream change "
            f"{previous_label} → {promoted_label} reason={reason}"
        , topic="sync")

    def _standby_ready_for_fast_path(self) -> bool:
        with self._standby_cond:
            return self._standby is not None and self._standby.is_usable()

    def _fail_threshold_for_current_state(self) -> int:
        if self._standby_ready_for_fast_path() or self.emergency.manager.snapshot().ready:
            return max(1, STANDBY_FAIL_THRESHOLD)
        return FAIL_THRESHOLD

    # ---------- health / rotation ----------
    def tick_health(self, *, has_internet: bool | None = None) -> None:
        # The sample and its routing decision belong to one loaded config.
        # A maintenance restart cannot masquerade as an upstream failure.
        with self._apply_lock:
            self._tick_health_with_apply_lock(has_internet=has_internet)

    def _tick_health_with_apply_lock(self, *, has_internet: bool | None = None) -> None:
        if has_internet is None:
            has_internet = internet_alive()
        if not has_internet:
            self._active_channel_ok = None
            self._health_checked_at = 0
            self.state.note_proxy_ok()
            return
        generation = self.network.snapshot().generation
        def current():
            return not self._runtime_started or (not self._stop and self.network.online() and
                self.network.snapshot().generation == generation)
        if not current():
            return
        running = is_running()
        if not current():
            return
        if not running:
            self._record_active_health(False)
            # A local service failure is not evidence of a blocked VLESS route.
            if self._runtime_started:
                self._repair_xray_listener()
            else:
                self._handle_rotation_needed(reason="xray-not-running")
            return

        proxy_ok = proxy_alive()
        if not current():
            return
        if not proxy_ok:
            self._record_active_health(False)
            # --- Прокси совсем не работает (даже IP-чекеры не проходят) ---
            fails = self.state.note_proxy_fail()
            threshold = self._fail_threshold_for_current_state()
            log.warning("proxy probe failed (%d/%d)", fails, threshold)
            if fails < threshold:
                return

            self._handle_rotation_needed(reason="proxy-failing")
            return

        # Прокси работает (IP-чекеры прошли). Проверяем целевые ресурсы.
        target_ok, target_detail = target_alive()
        if not current():
            return
        if not target_ok:
            self._record_active_health(False)
            # Целевой ресурс недоступен через этот прокси.
            # Считаем proxy fail — сервер блокирует нужные ресурсы.
            fails = self.state.note_proxy_fail()
            threshold = self._fail_threshold_for_current_state()
            log.warning("target check failed: %s unreachable via %s "
                        "(proxy failures: %d/%d)",
                        target_detail, _fmt(self.state.active),
                        fails, threshold)
            if fails < threshold:
                return

            self._handle_rotation_needed(reason="target-blocked")
            return

        if self.state.consecutive_proxy_failures:
            log.info("proxy recovered (active: %s)", _fmt(self.state.active))
            self._notify_active_state(
                "OK",
                reason="recovered",
            )
        self._clear_waiting_for_standby("active-health-ok")
        self.state.note_proxy_ok()
        self._record_active_health(True)
        # Если активный сервер неизвестен, но сам xray proxy работает,
        # не трогаем live-config. Потеря state/active.json или ручной
        # конфиг не являются внешним условием, которое оправдывает
        # перезапись работающего xray.
        if self.state.active is None:
            log.warning("proxy alive but active server unknown — preserving "
                        "current xray config")

    def _handle_rotation_needed(self, reason: str) -> None:
        if self.state.transport == "ssh":
            self._wake_standby_worker()
            return
        if self._promotion_running():
            log.info("rotation needed (%s) while standby promotion is in progress; "
                     "skip fallback", reason)
            return
        if self._promote_standby(reason, require_active_failure=self._runtime_started):
            return
        if self._rotation_request_is_stale(reason):
            return
        self._enter_waiting_for_standby(reason)
        if self._runtime_started:
            # Every daemon-mode candidate is tested in an isolated xray.
            # The one-shot fallback below retains bounded VLESS-only behavior.
            self._wake_standby_worker()
            return
        if not self._cold_rotation_allowed(reason):
            return

        # Standby is the low-latency path, but cold rotation remains the
        # fail-safe fallback when the slot is empty, stale, or promotion failed.
        log.warning("standby unavailable for %s; using cold rotation fallback",
                    reason)
        self._last_cold_rotation_attempt = time.time()
        self._rotate_until_working(reason=reason)

    def _rotation_request_is_stale(self, reason: str) -> bool:
        if reason == "xray-not-running" and is_running():
            log.info("rotation request %s skipped: xray already running", reason)
            return True
        if reason in ("proxy-failing", "target-blocked") and \
                self.state.proxy_failures_snapshot() == 0:
            log.info("rotation request %s skipped: active already recovered "
                     "or switched", reason)
            return True
        return False

    def _cold_rotation_allowed(self, reason: str) -> bool:
        if reason == "xray-not-running" or self.state.active is None:
            return True
        if reason not in ("proxy-failing", "target-blocked"):
            return True

        last_attempt = max(
            self._last_cold_rotation_attempt,
            self.state.last_rotation,
        )
        if last_attempt <= 0:
            return True

        since_attempt = time.time() - last_attempt
        if since_attempt >= ROTATION_COOLDOWN:
            return True

        log.info("cold rotation cooldown (%.1fs left), skip fallback for %s",
                 ROTATION_COOLDOWN - since_attempt, reason)
        return False

    def _rotate_until_working(self, reason: str) -> None:
        with self._apply_lock:
            self._rotate_until_working_with_apply_lock(reason)

    def _rotate_until_working_with_apply_lock(self, reason: str) -> None:
        if not self.state.ranked:
            log.error("cannot rotate: server list is empty")
            return

        # Тот же guard, что на startup rebuild: если geo-assets нечитаемы,
        # apply_server всё равно не пройдёт xray -test (в конфиге останутся
        # ссылки на geosite:/geoip:), но зато мы гарантированно не затрём
        # уже работающий live-конфиг. Лучше продолжить пробовать старый
        # сервер, чем остаться без xray вообще.
        if not self._geo_ready_for_rebuild(f"rotation ({reason})"):
            # Осознанный trade-off: ротация заблокирована, пока не
            # вернутся валидные .dat. Если в этот момент xray тоже лежит —
            # мы в тупике и ни одно «no working server found» уведомление
            # не уйдёт. Отдельным сообщением поднимаем пользователю флаг
            # (один раз, пока geo не починится).
            if not self._stuck_notified:
                log.error("STUCK: rotation blocked (reason=%s) AND geo assets "
                          "unreadable — cannot switch servers until geo "
                          "recovers", reason)
                notify(
                    f"🔴 xproxy stuck: rotation needed ({reason}) but geo "
                    f"assets unreadable — cannot rebuild xray config. "
                    f"Manual intervention may be required.",
                    urgent=True, blocking=True,
                    topic="config",
                )
                self._stuck_notified = True
            return

        direct, via = public_ips()
        log.info("rotation triggered (%s). leaving=%s direct_ip=%s proxy_ip=%s",
                 reason, _fmt(self.state.active), direct, via)

        # Если текущий активный перестал работать — штрафуем его сразу, чтобы
        # альтернативы были выше в очереди. set_active() снимет штраф, если он
        # снова окажется активным (например, все остальные тоже упали).
        if self.state.active is not None and reason in ("proxy-failing", "target-blocked"):
            self.state.penalize(self.state.active)

        tried = 0
        for candidate in self.state.next_candidates():
            if self._stop or not self.network.online():
                return
            if candidate is self.state.active:
                continue
            tried += 1
            if not tcp_probe(candidate.address, candidate.port):
                log.info("skip %s — tcp probe failed", _fmt(candidate))
                self.state.penalize(candidate)
                continue

            log.info("try candidate → %s", _fmt(candidate))
            try:
                apply_server(candidate, dry_run=self.dry_run, info=self.platform)
            except XrayStartError as exc:
                from .xray_control import TRANSACTION_PATH
                if TRANSACTION_PATH.exists():
                    restore_backup(self.platform)
                log.error("rotation aborted: xray failed to start after applying "
                          "%s: %s", _fmt(candidate), exc)
                if not self._xray_start_failure_notified:
                    notify(
                        f"🔴 xproxy stopped rotation: xray did not start after "
                        f"applying {_fmt(candidate)}. "
                        f"Reason: {exc}",
                        urgent=True,
                        blocking=True,
                        topic="config",
                    )
                    self._xray_start_failure_notified = True
                return
            except ConfigUnchanged:
                pass
            except Exception as exc:  # noqa: BLE001
                log.warning("apply_server failed: %s", exc)
                from .xray_control import TRANSACTION_PATH
                if TRANSACTION_PATH.exists():
                    restore_backup(self.platform)
                self.emergency.local_failure()
                return

            if self.dry_run:
                log.info("[dry-run] would switch to %s", _fmt(candidate))
                return

            if proxy_alive():
                # IP-чекеры прошли. Проверяем целевые ресурсы.
                tgt_ok, tgt_detail = target_alive()
                if not tgt_ok:
                    log.info("candidate %s passes proxy probe but blocks %s",
                             _fmt(candidate), tgt_detail)
                    self.state.penalize(candidate)
                    restore_backup(self.platform)
                    continue

                commit_config(self.platform)
                previous_vless = self.state.active or self.state.last_vless
                prev_country = self.state.active.country if self.state.active else None
                self.state.set_active(candidate)
                self._record_active_health(True)
                with self._standby_cond:
                    self._active_waiting_for_standby = False
                    self._active_waiting_reason = ""
                log.info("switched %s → %s", prev_country or "-", _fmt(candidate))
                self._notify_active_state(
                    "OK",
                    server=candidate,
                    reason=f"switched:{reason}",
                )
                self._xray_start_failure_notified = False
                self._schedule_config_sync_after_vless_change(
                    reason=reason, previous=previous_vless, promoted=candidate,
                )
                self._wake_standby_worker()
                return
            log.info("candidate %s did not pass proxy probe after restart",
                     _fmt(candidate))
            self.state.penalize(candidate)
            if not restore_backup(self.platform):
                self.emergency.reconcile()
                return

        # Никто не прошёл. Это важное событие — используем blocking-отправку,
        # чтобы максимально увеличить шансы доставки (сообщение всё ещё может
        # не дойти, если и SOCKS, и direct заблокированы).
        penalties = len(self.state.penalized_keys())
        log.error("no working server found (tried=%d, ranked=%d, in_penalty=%d)",
                  tried, len(self.state.ranked), penalties)
        try:
            notify(
                f"🔴 no working server found (tried {tried} of "
                f"{len(self.state.ranked)}, {penalties} in penalty box, "
                f"reason={reason})",
                urgent=True, topic="routes",
            )
        except Exception:  # noqa: BLE001
            log.exception("alert notify failed")


def _fmt(server: Optional[Server]) -> str:
    """Человекочитаемое имя сервера для логов.

    Для резолвленных: 'Германия (cdn9-33.vk-cdnvideo.com:8443 / 82.202.156.248)'
    Для обычных: 'Германия (cdn9-33.vk-cdnvideo.com:8443)'
    """
    if server is None:
        return "-"
    return f"{server.country} ({server.display_name})"


def _server_key(server: Optional[Server]) -> tuple[str, int] | None:
    if server is None:
        return None
    return server.key()


def _format_uptime(seconds: float) -> str:
    """Компактная запись аптайма: '2d 3h 14m' / '45m 12s' / '8s'."""
    s = int(max(0, seconds))
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def _signal_name(signum: Optional[int]) -> str:
    if signum is None:
        return "?"
    try:
        return signal.Signals(signum).name
    except ValueError:
        return str(signum)


def _sleep_interruptible(duration: float, should_stop) -> None:
    """Sleep кусочками, чтобы быстрее реагировать на SIGTERM."""
    step = 0.5
    remaining = duration
    while remaining > 0 and not should_stop():
        time.sleep(min(step, remaining))
        remaining -= step
