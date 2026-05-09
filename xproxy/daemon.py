"""Главный цикл демона и one-shot итерация."""
from __future__ import annotations

import random
import signal
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
from .geo import ensure_geo_assets
from .routing import build_xray_sections
from .healthcheck import internet_alive, proxy_alive, public_ips
from .logger import get_logger
from .notifier import drain_queue, is_configured as tg_configured, notify, start_queue
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
from .xray_control import ConfigUnchanged, XrayStartError, apply_server, is_running

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
        start_queue()
        try:
            self.refresh_subscription(force=True)
            self.refresh_geo(force=False)
            self._rebuild_config_if_active()
            self.tick_health()
        finally:
            drain_queue()

    # ---------- periodic tasks ----------
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

        # Системные метрики
        try:
            from .sysinfo import system_report
            sys = system_report()
        except Exception:  # noqa: BLE001
            log.debug("sysinfo collection failed, skipping system metrics")
            sys = None

        msg = (f"💚 daily heartbeat: active={_fmt(self.state.active)}, "
               f"proxy={proxy_status}, uptime={uptime}, "
               f"rotations_today={self.state.rotations_today}")
        if sys:
            msg += f"\n⚙️ {sys}"
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
        ranked = filter_and_sort(servers, self._country_ranks)
        if not ranked:
            log.warning("subscription returned 0 allowed servers")
            return
        self.state.ranked = ranked
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

    # ---------- health / rotation ----------
    def tick_health(self, *, has_internet: bool | None = None) -> None:
        if not is_running():
            log.warning("xray is not running; trying to start with best server")
            self._rotate_until_working(reason="xray-not-running")
            return

        # Переиспользуем результат internet_alive() из tick(), если он
        # передан; иначе проверяем сами (для run_once / run_forever startup).
        if has_internet is None:
            has_internet = internet_alive()
        if not has_internet:
            log.info("no direct internet — skipping proxy health check")
            return

        if proxy_alive():
            if self.state.consecutive_proxy_failures:
                log.info("proxy recovered (active: %s)", _fmt(self.state.active))
            self.state.note_proxy_ok()
            # Если активный сервер неизвестен, но сам xray proxy работает,
            # не трогаем live-config. Потеря state/active.json или ручной
            # конфиг не являются внешним условием, которое оправдывает
            # перезапись работающего xray.
            if self.state.active is None:
                log.warning("proxy alive but active server unknown — preserving "
                            "current xray config")
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
            except XrayStartError as exc:
                log.error("rotation aborted: xray failed to start after applying "
                          "%s (%s:%d): %s",
                          candidate.country, candidate.host, candidate.port, exc)
                if not self._xray_start_failure_notified:
                    notify(
                        f"🔴 xproxy stopped rotation: xray did not start after "
                        f"applying {candidate.country} "
                        f"({candidate.host}:{candidate.port}). "
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
                self._xray_start_failure_notified = False
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
