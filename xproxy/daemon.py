"""Главный цикл демона и one-shot итерация."""
from __future__ import annotations

import random
import signal
import threading
import time
from typing import Optional

from .autoupdate import (
    FAILURE_REASONS,
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
from .notifier import drain_queue, is_configured as tg_configured, notify, set_status_provider, start_queue
from .platform_utils import PlatformInfo, detect_platform
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
    STANDBY_FAIL_THRESHOLD,
    STANDBY_RETRY_INTERVAL,
    SUBSCR_REFRESH,
)
from .standby import PreparedStandby, StandbyError, prepare_standby, standby_fingerprint
from .state import DaemonState, load_active
from .subscription import SubscriptionError, fetch_subscription_text
from .xray_control import (
    ConfigUnchanged,
    XrayStartError,
    apply_config_text,
    apply_server,
    is_running,
    restore_backup,
)

log = get_logger("xproxy.daemon")

_CONFIG_SYNC_PROMOTION_REASONS = {"proxy-failing", "target-blocked"}


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
        self._notify_state_lock = threading.RLock()
        self._last_active_state_notify: Optional[tuple] = None
        self._last_standby_state_notify: Optional[tuple] = None
        self._last_cold_rotation_attempt: float = 0.0
        # Восстановить активный сервер, если был сохранён.
        # Если сервер не имеет resolved_ip (старый формат или hostname),
        # резолвим hostname в IP при запуске.
        prev = load_active()
        if prev is not None:
            if prev.resolved_ip is None:
                from .dns_resolver import resolve_host
                ips = resolve_host(prev.host)
                if ips:
                    prev.resolved_ip = ips[0]
                    log.info("resolved active server %s → %s",
                             prev.host, prev.resolved_ip)
                else:
                    log.warning("DNS resolve failed for active server %s, "
                                "using hostname as-is", prev.host)
            self.state.active = prev
            log.info("restored active server: %s", _fmt(prev))
        # Инициализировать время последнего live-фетча подписки из mtime кэша.
        # Если сервер был выключен >24ч и кэш устарел — staleness обнаружится
        # сразу при первой же попытке refresh_subscription().
        if SERVERS_CACHE.exists():
            try:
                self.state.last_live_fetch = SERVERS_CACHE.stat().st_mtime
            except OSError:
                pass

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

    def run_forever(self) -> None:
        self.install_signal_handlers()
        post_restart_banner()
        log.info("daemon start (dry_run=%s, platform=%s, active=%s)",
                 self.dry_run, self.platform.name, _fmt(self.state.active))
        if tg_configured():
            log.info("telegram notifications enabled")
        set_status_provider(self._build_status_suffix)
        start_queue()
        notify(f"🟢 xproxy started (active: {_fmt(self.state.active)})")
        # Startup jitter: рандомная пауза перед первым обращением к внешним
        # ресурсам, чтобы несколько хостов, перезапущенных одновременно
        # (после ребута / сетевого сбоя / деплоя), не стучали в subscription/
        # GitHub/Telegram в одну и ту же секунду. SIGTERM во время паузы
        # прерывает её штатно.
        if STARTUP_JITTER > 0 and not self.dry_run:
            delay = random.uniform(0, STARTUP_JITTER)
            log.info("startup jitter: sleeping %.1fs before first external fetch",
                     delay)
            _sleep_interruptible(delay, lambda: self._stop)
        if self._stop:
            return
        # Первый проход — немедленно (после startup jitter'а).
        # Порядок важен:
        #   1) autoupdate — если есть новый код, restart_self() сделает
        #      os.execv и мы не вернёмся; на следующем витке новый процесс
        #      снова зайдёт сюда и продолжит со свежим кодом. Любая ошибка
        #      pull'а не критична (остаёмся на старом коде, tick_autoupdate
        #      сам уведомит пользователя).
        #   2) подписка и geo — уже в «новом» (или old-but-good) коде.
        # Без этого блока первый git pull случался только через один
        # HEALTH_INTERVAL (~15с), а geo — через startup jitter, но
        # семантика «при рестарте берём самое свежее» была неявной.
        if GIT_PULL_INTERVAL > 0 and not self.dry_run:
            try:
                self.tick_autoupdate()
            except Exception:  # noqa: BLE001
                log.exception("startup autoupdate failed (continuing on old code)")
        self.refresh_subscription(force=True)
        self.refresh_geo(force=False)
        # Следующий geo-фетч планирует сама refresh_geo() (учитывает бэкофф).
        # Пересобрать конфиг при старте, чтобы подхватить изменения routing/
        # direct.lst/config.tmpl, полученные через git pull (или сделанные вручную).
        # Без этого новые маршруты не попадут в xray до следующей ротации сервера.
        self._rebuild_config_if_active()
        self._start_standby_worker()
        self.tick_health()

        while not self._stop:
            _sleep_interruptible(HEALTH_INTERVAL, lambda: self._stop)
            if self._stop:
                break
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                log.exception("tick failed")

        self._stop_standby_worker()
        log.info("daemon stopped")
        # Оповестить о остановке и дождаться отправки всех отложенных
        # уведомлений (включая это). drain_queue() внутри сделает
        # финальную попытку отправить всё из очереди, а что не ушло —
        # сохранит на диск для следующего запуска.
        sig_name = _signal_name(self._stop_signal) if self._stop_signal else "manual"
        try:
            notify(f"🛑 xproxy stopped (signal {sig_name}, last active: {_fmt(self.state.active)})",
                   urgent=True, blocking=True)
        except Exception:  # noqa: BLE001
            log.exception("shutdown notify failed")
        # Drain: фоновый sender-тред получает stopping-флаг,
        # делает финальные попытки, несённое — на диск.
        drain_queue()

    def run_once(self) -> None:
        # В one-shot режиме sender-тред нужен для отправки уведомлений
        # из refresh_subscription / refresh_geo / tick_health.
        # Без него notify() только ставит в очередь, и всё теряется на выходе.
        set_status_provider(self._build_status_suffix)
        start_queue()
        try:
            self.refresh_subscription(force=True)
            self.refresh_geo(force=False)
            self._rebuild_config_if_active()
            self.tick_health()
        finally:
            drain_queue()

    # ---------- periodic tasks ----------
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
        active_country = self.state.active.country if self.state.active else "-"
        proxy_ok = self.state.consecutive_proxy_failures < FAIL_THRESHOLD
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
        now = time.time()
        # Проверка доступности интернет-канала — один раз за tick.
        # Если сети нет (хост в suspend / автономном режиме), все сетевые
        # задачи теряют смысл: подписка, geo, autoupdate — пропускаем.
        # Результат передаём в tick_health(), чтобы не делать повторный HTTP-
        # запрос (internet_alive() уже выполнен здесь).
        has_internet = internet_alive()
        if not has_internet:
            log.info("no direct internet — skipping subscription, geo, autoupdate")
        else:
            # Все периоды — jittered. После каждого срабатывания перерисовываем
            # интервал, чтобы при множественной установке на нескольких хостах
            # события не слипались в одну секунду.
            if now - self.state.last_subscription_refresh >= self._subscr_period:
                self.refresh_subscription()
                self._subscr_period = _jittered(SUBSCR_REFRESH)
            if now >= self._next_geo_at:
                self.refresh_geo(force=False)
            if GIT_PULL_INTERVAL > 0 and \
                    now - self.state.last_git_pull >= self._git_period:
                self.tick_autoupdate()
                self._git_period = _jittered(GIT_PULL_INTERVAL)
        self.tick_health(has_internet=has_internet)
        self.tick_heartbeat()

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
        notify("💚 daily heartbeat", urgent=True)
        self.state.last_heartbeat_date = today

    def refresh_subscription(self, force: bool = False) -> None:
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
            source, body = fetch_subscription_text()
        except SubscriptionError as exc:
            log.warning("subscription unavailable: %s", exc)
            notify(f"⚠️ subscription unavailable: {exc}")
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
                )
                self.state._stale_notified = True
            else:
                log.info("subscription served from cache (live fetch failed; will retry next cycle)")
        else:
            self.state.last_live_fetch = now
            self.state._stale_notified = False
        servers = parse_subscription(body)
        expanded = expand_servers(servers)
        ranked = filter_and_sort(expanded, self._country_ranks)
        if not ranked:
            log.warning("subscription returned 0 allowed servers")
            return
        with self._standby_cond:
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
                   "(rate-limit), will retry next interval", urgent=True)
            return
        try:
            result = check_and_pull()
        except Exception as exc:  # noqa: BLE001
            log.exception("autoupdate: check_and_pull failed")
            notify(f"⚠️ autoupdate failed (check_and_pull exception): "
                   f"{type(exc).__name__}: {exc}", urgent=True)
            return
        if not result.updated:
            if result.reason in FAILURE_REASONS:
                log.warning("autoupdate failed: %s — %s",
                            result.reason, result.error)
                notify(f"⚠️ autoupdate failed: {result.reason} — {result.error}",
                       urgent=True)
            else:
                # up to date / tree not clean / no upstream / и т.п. — молча
                log.debug("autoupdate: no-op (%s)", result.reason)
            return

        if result.requirements_changed:
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
                    )
                else:
                    notify(
                        f"🔴 autoupdate: requirements install failed for "
                        f"{result.new_head[:7]} and rollback FAILED: {last}",
                        urgent=True,
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
                )
            else:
                notify(
                    f"🔴 autoupdate: new code {result.new_head[:7]} failed "
                    f"import check, rollback FAILED — working tree stuck on bad commit!",
                    urgent=True,
                )
            return

        log.info("autoupdate: new code %s validated, restarting self",
                 result.new_head[:7])
        notify(
            f"🆙 xproxy updating {result.old_head[:7]} → "
            f"{result.new_head[:7]}, restarting",
            blocking=True,
        )
        restart_self()  # не вернётся при успехе

    def refresh_geo(self, force: bool) -> None:
        # Файлы кладутся в GEO_DIR. xray видит их через XRAY_LOCATION_ASSET.
        # Замена файла только атомарна и только после полного скачивания —
        # при обрыве соединения остаётся работать старая копия.
        try:
            validation_server = self.state.active
            if validation_server is None and self.state.ranked:
                validation_server = self.state.ranked[0]
            result = ensure_geo_assets(
                force=force,
                validation_server=validation_server,
                platform_info=self.platform,
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
                   f"next retry in {int(delay)}s")

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
        if result.freshly_downloaded and self.state.active is not None:
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

    def _rebuild_config_if_active(
        self,
        context: str = "startup rebuild",
        geo_ready: Optional[bool] = None,
    ) -> None:
        """Пересобрать xray config, если активный сервер известен.

        Нужно при старте/после autoupdate/после успешного geo-refresh:
        конфиг пересобирается из шаблона, routing.json, direct.lst и
        параметров сервера. Если любой из этих файлов изменился (git pull,
        ручная правка, свежий .dat), изменения попадут в xray. Если конфиг
        не прошёл xray -test — боевой config.json не трогается.

        `context` — короткая строка для логов (кто инициировал rebuild).
        `geo_ready` — если вызывающий уже только что проверил geo-assets,
        пусть передаст True, чтобы избежать повторного парсинга .dat.
        """
        if self.state.active is None:
            return
        if self.dry_run:
            log.info("[dry-run] would rebuild config for %s", _fmt(self.state.active))
            return
        if geo_ready is not True and not self._geo_ready_for_rebuild(context):
            return
        try:
            apply_server(self.state.active, dry_run=False, info=self.platform)
            log.info("%s: config rebuilt for %s",
                     context, _fmt(self.state.active))
        except ConfigUnchanged:
            log.info("%s: config unchanged, skip rebuild", context)
        except Exception as exc:  # noqa: BLE001
            log.warning("%s: failed (keeping current config): %s", context, exc)

    # ---------- standby ----------
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
        if thread and thread.is_alive():
            thread.join(timeout=2.0)

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
        key = (state, _server_key(server), reason, detail)
        with self._notify_state_lock:
            if key == self._last_active_state_notify:
                return
            self._last_active_state_notify = key

        suffix = f" reason={reason}" if reason else ""
        detail_part = f" — {detail}" if detail else ""
        if state == "OK":
            text = f"🟢 active OK: {_fmt(server)}{suffix}{detail_part}"
        elif state == "WAITING_FOR_STANDBY":
            text = f"🟠 active WAITING_FOR_STANDBY: {_fmt(server)}{suffix}{detail_part}"
        elif state == "PROMOTING":
            text = f"🔄 active PROMOTING: {_fmt(server)}{suffix}{detail_part}"
        elif state == "FAILED":
            text = f"🔴 active FAILED: {_fmt(server)}{suffix}{detail_part}"
        else:
            text = f"ℹ️ active {state}: {_fmt(server)}{suffix}{detail_part}"
        notify(text, urgent=urgent)

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
        suffix = f" reason={reason}" if reason else ""
        detail_part = f" — {detail}" if detail else ""
        if state == "READY":
            text = f"🟢 standby READY: {target}{suffix}{detail_part}"
        elif state == "FAILED":
            text = f"🔴 standby FAILED: {target}{suffix}{detail_part}"
        elif state == "PROMOTING":
            text = f"🔄 standby PROMOTING: {target}{suffix}{detail_part}"
        else:
            log.debug("standby notification suppressed: state=%s target=%s%s%s",
                      state, target, suffix, detail_part)
            return

        key = (state, _server_key(server), reason, detail)
        with self._notify_state_lock:
            if key == self._last_standby_state_notify:
                return
            self._last_standby_state_notify = key
        notify(text, urgent=urgent)

    def _invalidate_standby(self, reason: str) -> None:
        with self._standby_cond:
            self._invalidate_standby_locked(reason)

    def _invalidate_standby_locked(self, reason: str) -> None:
        self._standby_generation += 1
        if self._standby is not None:
            log.info("standby invalidated: %s (%s)",
                     reason, _fmt(self._standby.server))
            self._standby.status = "STALE"
        self._standby = None
        self._standby_cond.notify_all()

    def _sync_standby_after_ranked_refresh_locked(
        self,
        ranked: list[Server],
    ) -> None:
        self._standby_generation += 1
        if self._standby is None:
            self._standby_cond.notify_all()
            return

        standby = self._standby
        by_key = {server.key(): server for server in ranked}
        refreshed_server = by_key.get(standby.server.key())
        if refreshed_server is None:
            log.info("standby invalidated: subscription removed %s",
                     _fmt(standby.server))
            standby.status = "STALE"
            self._standby = None
            self._standby_cond.notify_all()
            return

        try:
            current_fp = standby_fingerprint(refreshed_server, info=self.platform)
        except Exception as exc:  # noqa: BLE001
            log.warning("standby fingerprint check after subscription refresh "
                        "failed: %s", exc)
            standby.status = "STALE"
            self._standby = None
            self._standby_cond.notify_all()
            return

        state = standby.lifecycle_state(current_fp)
        if state in ("READY", "PRE_STALE"):
            standby.server = refreshed_server
            log.info("standby preserved after subscription refresh: %s state=%s",
                     _fmt(refreshed_server), state)
            self._standby_cond.notify_all()
            return

        log.info("standby invalidated after subscription refresh: %s state=%s",
                 _fmt(standby.server), state)
        standby.status = "STALE"
        self._standby = None
        self._standby_cond.notify_all()

    def _discard_current_standby_locked(self, candidate: Server, reason: str) -> bool:
        if self._standby is None:
            return False
        if self._standby.server.key() != candidate.key():
            return False
        self._standby_generation += 1
        log.info("standby slot discarded: %s (%s)", reason, _fmt(candidate))
        self._standby.status = "STALE"
        self._standby = None
        self._standby_last_attempt = 0
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
        content_changed = True
        if previous is not None:
            previous_state = previous.lifecycle_state()
            content_changed = previous.slot_key() != prepared.slot_key()

        self._standby = prepared
        detail = f"{prepared.ttl_detail()} slot={prepared.fingerprint[:8]}"
        should_notify = (
            previous is None or
            previous_state not in ("READY", "PRE_STALE") or
            content_changed
        )
        if content_changed and previous is not None:
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
        return True

    def _standby_worker_loop(self) -> None:
        while True:
            with self._standby_cond:
                if self._standby_stop:
                    return
                candidate = self._select_standby_candidate_locked()
                if candidate is None:
                    self._standby_cond.wait(timeout=STANDBY_RETRY_INTERVAL)
                    continue
                self._standby_preparing = True
                self._standby_last_attempt = time.time()
                generation = self._standby_generation

            log.info("standby prepare started: %s", _fmt(candidate))
            try:
                prepared = prepare_standby(candidate, info=self.platform)
            except StandbyError as exc:
                log.info("standby candidate failed %s: %s", _fmt(candidate), exc)
                with self._standby_cond:
                    generation_changed = generation != self._standby_generation
                    active_waiting = self._active_waiting_for_standby
                    if generation_changed:
                        log.info("discard standby failure from stale generation: "
                                 "%s (prepared=%d current=%d)",
                                 _fmt(candidate), generation, self._standby_generation)
                        discarded_current = False
                    else:
                        discarded_current = self._discard_current_standby_locked(
                            candidate,
                            "revalidation failed",
                        )
                if active_waiting and not generation_changed:
                    self._notify_standby_state(
                        "FAILED",
                        server=candidate,
                        detail=str(exc),
                        urgent=True,
                    )
                if not generation_changed:
                    self._penalize_if_not_active(candidate, "standby prepare failed")
                with self._standby_cond:
                    self._standby_preparing = False
                    if generation_changed or discarded_current or \
                            self._active_waiting_for_standby:
                        self._standby_cond.notify_all()
                    else:
                        self._standby_cond.wait(timeout=STANDBY_RETRY_INTERVAL)
                continue
            except Exception as exc:  # noqa: BLE001
                log.exception("standby prepare crashed for %s: %s",
                              _fmt(candidate), exc)
                with self._standby_cond:
                    generation_changed = generation != self._standby_generation
                    active_waiting = self._active_waiting_for_standby
                    if generation_changed:
                        log.info("discard standby crash from stale generation: "
                                 "%s (prepared=%d current=%d)",
                                 _fmt(candidate), generation, self._standby_generation)
                        discarded_current = False
                    else:
                        discarded_current = self._discard_current_standby_locked(
                            candidate,
                            f"revalidation crashed: {type(exc).__name__}",
                        )
                if active_waiting and not generation_changed:
                    self._notify_standby_state(
                        "FAILED",
                        server=candidate,
                        detail=f"{type(exc).__name__}: {exc}",
                        urgent=True,
                    )
                if not generation_changed:
                    self._penalize_if_not_active(candidate, "standby prepare crashed")
                with self._standby_cond:
                    self._standby_preparing = False
                    if generation_changed or discarded_current or \
                            self._active_waiting_for_standby:
                        self._standby_cond.notify_all()
                    else:
                        self._standby_cond.wait(timeout=STANDBY_RETRY_INTERVAL)
                continue

            promote_now = False
            promote_reason = ""
            promote_wait_generation = 0
            with self._standby_cond:
                self._standby_preparing = False
                if generation != self._standby_generation:
                    log.info("discard prepared standby from stale generation: %s "
                             "(prepared=%d current=%d)",
                             _fmt(prepared.server),
                             generation,
                             self._standby_generation)
                    self._standby_cond.notify_all()
                    continue
                active = self.state.active_snapshot()
                if active is not None and active.key() == prepared.server.key():
                    log.info("standby candidate became active while preparing; "
                             "discarding %s", _fmt(prepared.server))
                    self._standby_cond.notify_all()
                    continue
                promote_now = self._active_waiting_for_standby
                promote_reason = self._active_waiting_reason or "standby-ready"
                promote_wait_generation = self._active_waiting_generation
                log.info("standby ready: %s %s",
                         _fmt(prepared.server), prepared.ttl_detail())
                if not self._publish_standby_locked(
                    prepared,
                    generation=generation,
                ):
                    self._standby_cond.notify_all()
                    continue
                self._standby_cond.notify_all()

            if promote_now:
                self._promote_standby(
                    promote_reason,
                    expected_wait_generation=promote_wait_generation,
                    require_active_failure=True,
                )

    def _select_standby_candidate_locked(self) -> Optional[Server]:
        if self._standby_preparing:
            return None
        if self._standby is not None:
            state = self._standby.lifecycle_state()
            if state == "READY":
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
                self._standby.status = "STALE"
                self._standby = None
        active = self.state.active_snapshot()
        if not self.state.ranked_snapshot() or active is None:
            return None
        if not self._active_waiting_for_standby and \
                time.time() - self._standby_last_attempt < STANDBY_RETRY_INTERVAL:
            return None
        active_waiting = self._active_waiting_for_standby
        if active_waiting and \
                self._standby_waiting_generation != self._active_waiting_generation:
            self._standby_waiting_generation = self._active_waiting_generation
            self._standby_waiting_attempted.clear()

        active_key = active.key()
        active_country = active.country
        same_country_fallback: Optional[Server] = None
        for candidate in self.state.next_candidates():
            candidate_key = candidate.key()
            if candidate_key == active_key:
                continue
            if active_waiting and candidate_key in self._standby_waiting_attempted:
                continue
            if active_country and candidate.country == active_country:
                if same_country_fallback is None:
                    same_country_fallback = candidate
                continue
            if active_waiting:
                self._standby_waiting_attempted.add(candidate_key)
            return candidate
        if same_country_fallback is not None:
            log.info("standby fallback uses active country %s: %s",
                     active_country, _fmt(same_country_fallback))
            if active_waiting:
                self._standby_waiting_attempted.add(same_country_fallback.key())
            return same_country_fallback
        if active_waiting and self._standby_waiting_attempted:
            log.info("standby waiting pass exhausted; backing off for %.0fs",
                     STANDBY_RETRY_INTERVAL)
        return None

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
        if not is_running():
            return True
        try:
            if not internet_alive():
                log.info("skip standby promotion for %s: direct internet unavailable",
                         reason)
                return False
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
            log.warning("rolled back failed standby promotion to %s "
                        "(failed=%s, standby=%s)",
                        _fmt(previous), failure, _fmt(prepared.server))
            notify(
                f"🟠 standby promotion rolled back to {_fmt(previous)} "
                f"after {failure} on {_fmt(prepared.server)}"
                f"{f' — {detail}' if detail else ''}",
                urgent=True,
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
        self.state.set_active(prepared.server)
        self.state.penalize(prepared.server)
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
            promotion_state = prepared.lifecycle_state(current_fp)
            if promotion_state not in ("READY", "PRE_STALE"):
                log.warning("standby not ready for promotion: %s",
                            _fmt(prepared.server))
                prepared.status = "STALE"
                self._standby = None
                self._standby_cond.notify_all()
                return False
            prepared.status = "PROMOTING"
            self._standby = None
            self._promotion_in_progress = True
            self._clear_waiting_for_standby_locked(f"promotion-start:{reason}")

        try:
            prev = self.state.active
            if prev is not None:
                self.state.penalize(prev)
            log.warning("promoting standby %s (reason=%s)",
                        _fmt(prepared.server), reason)
            self._notify_standby_state(
                "PROMOTING",
                server=prepared.server,
                reason=reason,
                detail=f"from={promotion_state}",
            )
            self._notify_active_state(
                "PROMOTING",
                server=prev,
                reason=reason,
                detail=f"next={_fmt(prepared.server)}",
            )
            applied = False
            try:
                apply_config_text(
                    prepared.config_text,
                    label=f"standby {_fmt(prepared.server)}",
                    dry_run=self.dry_run,
                    info=self.platform,
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
                self.state.penalize(prepared.server)
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
                self.state.penalize(prepared.server)
                self._enter_waiting_for_standby(reason)
                return False

            if not self.dry_run:
                if not proxy_alive():
                    log.warning("promoted standby failed proxy healthcheck: %s",
                                _fmt(prepared.server))
                    self._notify_standby_state(
                        "FAILED",
                        server=prepared.server,
                        reason="post-promotion-proxy",
                        urgent=True,
                    )
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

            prev_country = prev.country if prev else "-"
            self.state.set_active(prepared.server)
            notify(
                f"🔄 standby promoted {prev_country} → "
                f"{_fmt(prepared.server)} reason={reason}"
            )
            self._notify_active_state(
                "OK",
                server=prepared.server,
                reason=f"promoted:{reason}",
            )
            self._xray_start_failure_notified = False
            self._schedule_config_sync_after_promotion(
                reason=reason,
                previous=prev,
                promoted=prepared.server,
            )
            self._wake_standby_worker()
            return True
        finally:
            with self._standby_cond:
                self._promotion_in_progress = False
                self._standby_cond.notify_all()

    def _schedule_config_sync_after_promotion(
        self,
        *,
        reason: str,
        previous: Optional[Server],
        promoted: Server,
    ) -> None:
        if self.dry_run:
            return
        if reason not in _CONFIG_SYNC_PROMOTION_REASONS:
            log.debug("config sync skipped after promotion: reason=%s", reason)
            return

        previous_label = _fmt(previous)
        promoted_label = _fmt(promoted)
        thread = threading.Thread(
            target=self._run_config_sync_after_promotion,
            name="xproxy-config-sync",
            args=(reason, previous_label, promoted_label),
            daemon=True,
        )
        thread.start()

    def _run_config_sync_after_promotion(
        self,
        reason: str,
        previous_label: str,
        promoted_label: str,
    ) -> None:
        try:
            target = sync_current_config(info=self.platform)
        except ConfigSyncError as exc:
            log.warning("config sync failed after standby promotion "
                        "%s → %s reason=%s: %s",
                        previous_label, promoted_label, reason, exc)
            notify(
                f"⚠️ config sync failed after standby promotion "
                f"{previous_label} → {promoted_label}: {exc}",
                urgent=True,
            )
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("config sync crashed after standby promotion "
                          "%s → %s reason=%s",
                          previous_label, promoted_label, reason)
            notify(
                f"⚠️ config sync crashed after standby promotion "
                f"{previous_label} → {promoted_label}: "
                f"{type(exc).__name__}: {exc}",
                urgent=True,
            )
            return

        if target is None:
            return
        log.info("config sync completed after standby promotion %s → %s "
                 "reason=%s target=%s",
                 previous_label, promoted_label, reason, target.safe_label())
        notify(
            f"🟢 config synced to {target.safe_label()} after standby promotion "
            f"{previous_label} → {promoted_label} reason={reason}"
        )

    def _standby_ready_for_fast_path(self) -> bool:
        with self._standby_cond:
            return self._standby is not None and self._standby.is_usable()

    def _fail_threshold_for_current_state(self) -> int:
        if self._standby_ready_for_fast_path():
            return max(1, STANDBY_FAIL_THRESHOLD)
        return FAIL_THRESHOLD

    # ---------- health / rotation ----------
    def tick_health(self, *, has_internet: bool | None = None) -> None:
        if not is_running():
            log.warning("xray is not running; trying to start with best server")
            self._handle_rotation_needed(reason="xray-not-running")
            return

        # Переиспользуем результат internet_alive() из tick(), если он
        # передан; иначе проверяем сами (для run_once / run_forever startup).
        if has_internet is None:
            has_internet = internet_alive()
        if not has_internet:
            log.info("no direct internet — skipping proxy health check")
            return

        if not proxy_alive():
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
        if not target_ok:
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
        # Если активный сервер неизвестен, но сам xray proxy работает,
        # не трогаем live-config. Потеря state/active.json или ручной
        # конфиг не являются внешним условием, которое оправдывает
        # перезапись работающего xray.
        if self.state.active is None:
            log.warning("proxy alive but active server unknown — preserving "
                        "current xray config")

    def _handle_rotation_needed(self, reason: str) -> None:
        if self._promotion_running():
            log.info("rotation needed (%s) while standby promotion is in progress; "
                     "skip fallback", reason)
            return
        if self._promote_standby(reason):
            return
        if self._rotation_request_is_stale(reason):
            return
        self._enter_waiting_for_standby(reason)
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
                log.error("rotation aborted: xray failed to start after applying "
                          "%s: %s", _fmt(candidate), exc)
                if not self._xray_start_failure_notified:
                    notify(
                        f"🔴 xproxy stopped rotation: xray did not start after "
                        f"applying {_fmt(candidate)}. "
                        f"Reason: {exc}",
                        urgent=True,
                        blocking=True,
                    )
                    self._xray_start_failure_notified = True
                return
            except Exception as exc:  # noqa: BLE001
                log.warning("apply_server failed: %s", exc)
                self.state.penalize(candidate)
                continue

            if self.dry_run:
                log.info("[dry-run] would switch to %s", _fmt(candidate))
                self.state.set_active(candidate)
                self._notify_active_state(
                    "OK",
                    server=candidate,
                    reason=f"dry-run-switch:{reason}",
                )
                self._wake_standby_worker()
                return

            if proxy_alive():
                # IP-чекеры прошли. Проверяем целевые ресурсы.
                tgt_ok, tgt_detail = target_alive()
                if not tgt_ok:
                    log.info("candidate %s passes proxy probe but blocks %s",
                             _fmt(candidate), tgt_detail)
                    self.state.penalize(candidate)
                    continue

                prev_country = self.state.active.country if self.state.active else None
                self.state.set_active(candidate)
                with self._standby_cond:
                    self._active_waiting_for_standby = False
                    self._active_waiting_reason = ""
                log.info("switched %s → %s", prev_country or "-", _fmt(candidate))
                notify(
                    f"🔄 switched {prev_country or '-'} → "
                    f"{_fmt(candidate)} reason={reason}"
                )
                self._notify_active_state(
                    "OK",
                    server=candidate,
                    reason=f"switched:{reason}",
                )
                self._xray_start_failure_notified = False
                self._wake_standby_worker()
                return
            log.info("candidate %s did not pass proxy probe after restart",
                     _fmt(candidate))
            self.state.penalize(candidate)

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
                urgent=True, blocking=True,
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
