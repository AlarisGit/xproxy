"""Главный цикл демона и one-shot итерация."""
from __future__ import annotations

import random
import signal
import time
from typing import Optional

from .autoupdate import (
    FAILURE_REASONS,
    check_and_pull,
    post_restart_banner,
    restart_self,
    too_many_restarts,
    validate_new_code,
)
from .geo import ensure_geo_assets
from .healthcheck import internet_alive, proxy_alive, public_ips
from .logger import get_logger
from .notifier import is_configured as tg_configured, notify
from .platform_utils import PlatformInfo, detect_platform
from .servers import Server, filter_and_sort, load_country_ranks, parse_subscription, tcp_probe
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
    SUBSCR_REFRESH,
)
from .state import DaemonState, load_active
from .subscription import SubscriptionError, fetch_subscription_text
from .xray_control import apply_server, is_running

log = get_logger("xproxy.daemon")


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
        # Минутный offset для heartbeat: HEARTBEAT_HOUR + 0..HEARTBEAT_JITTER_MIN мин,
        # фиксируется на весь процесс (чтобы не дрейфовать в течение дня).
        self._heartbeat_minute_offset = random.randint(0, max(0, HEARTBEAT_JITTER_MIN))
        log.debug("jitter init: subscr=%.0fs geo=%.0fs git=%.0fs hb_offset=%dmin",
                  self._subscr_period, self._geo_period, self._git_period,
                  self._heartbeat_minute_offset)
        # Восстановить активный сервер, если был сохранён.
        prev = load_active()
        if prev is not None:
            self.state.active = prev
            log.info("restored active server: %s:%d (%s)",
                     prev.host, prev.port, prev.country)
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
        self.refresh_subscription(force=True)
        self.refresh_geo(force=False)
        # Следующий geo-фетч — не раньше, чем через jittered период.
        self._next_geo_at = time.time() + self._geo_period
        # Пересобрать конфиг при старте, чтобы подхватить изменения routing/
        # direct.lst/config.tmpl, полученные через git pull (или сделанные вручную).
        # Без этого новые маршруты не попадут в xray до следующей ротации сервера.
        self._rebuild_config_if_active()
        self.tick_health()

        while not self._stop:
            _sleep_interruptible(HEALTH_INTERVAL, lambda: self._stop)
            if self._stop:
                break
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                log.exception("tick failed")

        log.info("daemon stopped")
        # blocking=True: основной тред сейчас уйдёт на return, daemon-треды будут
        # убиты процессом — поэтому синхронно дожидаемся отправки.
        sig_name = _signal_name(self._stop_signal) if self._stop_signal else "manual"
        try:
            notify(f"🛑 xproxy stopped (signal {sig_name}, last active: {_fmt(self.state.active)})",
                   urgent=True, blocking=True)
        except Exception:  # noqa: BLE001
            log.exception("shutdown notify failed")

    def run_once(self) -> None:
        self.refresh_subscription(force=True)
        self.refresh_geo(force=False)
        self._rebuild_config_if_active()
        self.tick_health()

    # ---------- periodic tasks ----------
    def tick(self) -> None:
        now = time.time()
        # Все периоды — jittered. После каждого срабатывания перерисовываем
        # интервал, чтобы при множественной установке на нескольких хостах
        # события не слипались в одну секунду.
        if now - self.state.last_subscription_refresh >= self._subscr_period:
            self.refresh_subscription()
            self._subscr_period = _jittered(SUBSCR_REFRESH)
        if now >= self._next_geo_at:
            self.refresh_geo(force=False)
            self._geo_period = _jittered(GEO_REFRESH)
            self._next_geo_at = time.time() + self._geo_period
        self.tick_health()
        self.tick_heartbeat()
        if GIT_PULL_INTERVAL > 0 and \
                now - self.state.last_git_pull >= self._git_period:
            self.tick_autoupdate()
            self._git_period = _jittered(GIT_PULL_INTERVAL)

    def tick_heartbeat(self) -> None:
        """Один раз в сутки (локальное время >= HEARTBEAT_HOUR) посылаем статус.

        Без уведомлений в dry-run. Если heartbeat пропал — значит инстанс
        умер или потерял и прокси, и direct-канал одновременно.
        """
        if self.dry_run:
            return
        now_struct = time.localtime()
        today = time.strftime("%Y-%m-%d", now_struct)
        # Триггер: локальное время >= HEARTBEAT_HOUR:MM, где MM — случайное
        # число минут, зафиксированное при старте (см. __init__). Это
        # размазывает суточные heartbeat'ы от разных хостов по окну в час,
        # вместо того чтобы все били в Telegram ровно в HH:00.
        if now_struct.tm_hour < HEARTBEAT_HOUR:
            return
        if now_struct.tm_hour == HEARTBEAT_HOUR and \
                now_struct.tm_min < self._heartbeat_minute_offset:
            return
        if self.state.last_heartbeat_date == today:
            return

        uptime = _format_uptime(time.time() - self.state.start_time)
        proxy_status = "ok" if proxy_alive() else "DOWN"
        msg = (f"💚 daily heartbeat: active={_fmt(self.state.active)}, "
               f"proxy={proxy_status}, uptime={uptime}, "
               f"rotations_today={self.state.rotations_today}")
        log.info("heartbeat: %s", msg)
        # urgent=True — throttle не должен мешать; без blocking, чтоб не замедлять tick.
        notify(msg, urgent=True)
        self.state.last_heartbeat_date = today

    def refresh_subscription(self, force: bool = False) -> None:
        now = time.time()
        # Внутренний guard согласован с jittered-периодом из tick(): если
        # tick решил, что пора — мы здесь точно пропускаем проверку (period
        # уже истёк). Force=True (стартовый fetch) проходит всегда.
        if not force and now - self.state.last_subscription_refresh < self._subscr_period:
            return
        try:
            source, body = fetch_subscription_text()
        except SubscriptionError as exc:
            log.warning("subscription unavailable: %s", exc)
            notify(f"⚠️ subscription unavailable: {exc}", urgent=True)
            return
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
        ranked = filter_and_sort(servers, self._country_ranks)
        if not ranked:
            log.warning("subscription returned 0 allowed servers")
            return
        self.state.ranked = ranked
        self.state.last_subscription_refresh = now
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
                "autoupdate pulled new code BUT requirements.txt changed "
                "(%s → %s). NOT restarting automatically — please run "
                "`pip install -r requirements.txt` and restart the service.",
                result.old_head[:7], result.new_head[:7],
            )
            notify(
                f"⚠️ autoupdate pulled {result.old_head[:7]} → "
                f"{result.new_head[:7]}, but requirements.txt changed. "
                f"Manual `pip install -r requirements.txt` and restart required.",
                urgent=True,
            )
            return

        ok, err = validate_new_code()
        if not ok:
            log.error("autoupdate: new code (%s) failed import check, "
                      "staying on %s. Error: %s",
                      result.new_head[:7], result.old_head[:7],
                      err.splitlines()[-1] if err else "?")
            notify(
                f"🔴 autoupdate: new code {result.new_head[:7]} failed "
                f"import check, staying on {result.old_head[:7]}",
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
        # Файлы кладутся в GEO_DIR (~/.config/xproxy/geo). xray видит их через
        # XRAY_LOCATION_ASSET, которая прописана в юните xray при установке.
        # Мы НЕ пишем в системные asset-директории xray.
        try:
            ensure_geo_assets(force=force)
        except Exception:  # noqa: BLE001
            log.exception("geo refresh failed")

    def _rebuild_config_if_active(self) -> None:
        """Пересобрать xray config, если активный сервер известен.

        Нужно при старте/после autoupdate: конфиг пересобирается из шаблона,
        routing.json, direct.lst и параметров сервера. Если любой из этих
        файлов изменился (git pull, ручная правка), изменения попадут в xray.
        Если конфиг не прошёл xray -test — боевой config.json не трогается.
        """
        if self.state.active is None:
            return
        if self.dry_run:
            log.info("[dry-run] would rebuild config for %s", _fmt(self.state.active))
            return
        try:
            apply_server(self.state.active, dry_run=False, info=self.platform)
            log.info("config rebuilt on startup for %s", _fmt(self.state.active))
        except Exception as exc:  # noqa: BLE001
            log.warning("config rebuild on startup failed (keeping current config): %s", exc)

    # ---------- health / rotation ----------
    def tick_health(self) -> None:
        if not is_running():
            log.warning("xray is not running; trying to start with best server")
            self._rotate_until_working(reason="xray-not-running")
            return

        if not internet_alive():
            log.info("no direct internet — skipping proxy health check")
            return

        if proxy_alive():
            if self.state.consecutive_proxy_failures:
                log.info("proxy recovered (active: %s)", _fmt(self.state.active))
            self.state.note_proxy_ok()
            # Если активный сервер неизвестен — прокси работает, но мы не управляем
            # выбором сервера (например, xray был сконфигурирован вручную до xproxy).
            # Ротируем, чтобы xproxy взял управление на себя.
            if self.state.active is None:
                log.warning("proxy alive but active server unknown — rotating to take control")
                self._rotate_until_working(reason="active-unknown")
            return

        fails = self.state.note_proxy_fail()
        log.warning("proxy probe failed (%d/%d)", fails, FAIL_THRESHOLD)
        if fails < FAIL_THRESHOLD:
            return

        # Анти-флаппинг: не ротируем чаще ROTATION_COOLDOWN.
        since_rot = time.time() - self.state.last_rotation
        if since_rot < ROTATION_COOLDOWN:
            log.info("rotation cooldown (%.1fs left), skip", ROTATION_COOLDOWN - since_rot)
            return

        self._rotate_until_working(reason="proxy-failing")

    def _rotate_until_working(self, reason: str) -> None:
        if not self.state.ranked:
            log.error("cannot rotate: server list is empty")
            return

        direct, via = public_ips()
        log.info("rotation triggered (%s). leaving=%s direct_ip=%s proxy_ip=%s",
                 reason, _fmt(self.state.active), direct, via)

        # Если текущий активный перестал работать — штрафуем его сразу, чтобы
        # альтернативы были выше в очереди. set_active() снимет штраф, если он
        # снова окажется активным (например, все остальные тоже упали).
        if self.state.active is not None and reason == "proxy-failing":
            self.state.penalize(self.state.active)

        tried = 0
        for candidate in self.state.next_candidates():
            if candidate is self.state.active:
                continue
            tried += 1
            if not tcp_probe(candidate.host, candidate.port):
                log.info("skip %s:%d (%s) — tcp probe failed",
                         candidate.host, candidate.port, candidate.country)
                self.state.penalize(candidate)
                continue

            log.info("try candidate → %s (%s:%d)",
                     candidate.country, candidate.host, candidate.port)
            try:
                apply_server(candidate, dry_run=self.dry_run, info=self.platform)
            except Exception as exc:  # noqa: BLE001
                log.warning("apply_server failed: %s", exc)
                self.state.penalize(candidate)
                continue

            if self.dry_run:
                log.info("[dry-run] would switch to %s (%s:%d)",
                         candidate.country, candidate.host, candidate.port)
                self.state.set_active(candidate)
                return

            if proxy_alive():
                prev_country = self.state.active.country if self.state.active else None
                self.state.set_active(candidate)
                log.info("switched %s → %s (%s:%d)",
                         prev_country or "-", candidate.country,
                         candidate.host, candidate.port)
                notify(
                    f"🔄 switched {prev_country or '-'} → "
                    f"{candidate.country} ({candidate.host}:{candidate.port}) "
                    f"reason={reason}"
                )
                return
            log.info("candidate %s (%s:%d) did not pass proxy probe after restart",
                     candidate.country, candidate.host, candidate.port)
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
    """Человекочитаемое имя сервера для логов: 'Германия (cdn3-70...:8443)' или '-'."""
    if server is None:
        return "-"
    return f"{server.country} ({server.host}:{server.port})"


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
