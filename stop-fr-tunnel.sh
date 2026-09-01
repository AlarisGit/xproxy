#!/bin/bash
#
# stop-fr-tunnel.sh — выход из аварийного режима (пара к start-fr-tunnel.sh).
#
# Что делает:
#   1. Останавливает xproxy (если вдруг запущен — чтобы не конкурировать
#      за config.json на время restore).
#   2. Восстанавливает config.json из бэкапа ~/.fr-tunnel/xray-config.pre-emergency.json
#      (последний конфиг xproxy перед переходом в аварийный режим).
#   3. Рестартует xray с восстановленным конфигом.
#   4. Убивает SSH-туннель (цикл + ssh), чистит маркер.
#   5. Запускает xproxy — тот при старте сам пересоберёт конфиг из
#      routing.json/direct.lst/geo и подберёт сервер, если VLESS ожил.
#
# Порядок важен: xproxy стартует ПОСЛЕДНИМ, когда тоннель уже вниз —
# иначе его healthcheck увидит «прокси работает» через тоннель.
#
# Запуск: bash stop-fr-tunnel.sh
# Только Linux (systemctl, /usr/local/etc/xray).
#

set -euo pipefail

STATE_DIR="$HOME/.fr-tunnel"
BACKUP="$STATE_DIR/xray-config.pre-emergency.json"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_TMP="/usr/local/etc/xray/.config.json.xproxy.fr-tunnel.tmp"
GEO_DIR="/var/lib/xproxy/geo"
LOCAL_SOCKS=20808
LOCAL_HTTP=20809

[ "$(uname -s)" = "Linux" ] || { echo "!! только Linux (systemctl)" >&2; exit 1; }

log()  { printf '    %s\n' "$*"; }
fail() { printf '    !! %s\n' "$*" >&2; exit 1; }

# ── 1. xproxy вниз (если был) ─────────────────────────────────
# Bounded stop: при зависшем graceful-stop (mid-rotation + retry-queue)
# не ждём TimeoutStopSec=90s — добиваем и чистим failed-статус.
echo "[1/5] Останавливаю xproxy…"
sudo -n timeout 25 systemctl stop xproxy 2>/dev/null || \
    sudo -n systemctl kill --signal=SIGKILL xproxy 2>/dev/null || true
sudo -n systemctl reset-failed xproxy 2>/dev/null || true

# ── 2. Restore config.json ────────────────────────────────────
echo "[2/5] Восстанавливаю config.json из бэкапа…"
if [ -f "$BACKUP" ]; then
    # xray -test от пользователя падает на боевых путях логов
    # (принадлежат root) — тестируем temp-копию с логами "none",
    # как делает xproxy. Записываем оригинал с боевыми путями.
    TEST_TMP=$(mktemp /tmp/fr-restore-test.XXXXXX.json)
    python3 - "$BACKUP" "$TEST_TMP" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg.setdefault("log", {})
cfg["log"]["access"] = "none"
cfg["log"]["error"] = "none"
json.dump(cfg, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PYEOF
    if XRAY_LOCATION_ASSET="$GEO_DIR" xray -test -c "$TEST_TMP" >/dev/null 2>&1; then
        sudo -n tee "$XRAY_TMP" < "$BACKUP" > /dev/null
        sudo -n mv -f "$XRAY_TMP" "$XRAY_CONFIG"
        log "бэкап восстановлен (прошёл xray -test)"
    else
        fail "бэкап не проходит xray -test (geo могли измениться) — ${XRAY_CONFIG} не тронут"
    fi
    rm -f "$TEST_TMP"
else
    # Бэкапа нет: мы либо не в аварийном режиме, либо бэкап утерян.
    # xproxy при старте сам пересоберёт конфиг — просто идём дальше.
    log "бэкапа нет (${BACKUP}) — xproxy пересоберёт конфиг сам"
fi

# ── 3. Тоннель вниз ───────────────────────────────────────────
echo "[3/5] Останавливаю SSH-туннель…"
pkill -f "ssh-tunnel-fr" 2>/dev/null || true
pkill -f "ssh.*-L ${LOCAL_SOCKS}:" 2>/dev/null || true
pkill -f "ssh.*-L 10808:" 2>/dev/null || true
sleep 1
# Цикл мог зареспавнить ssh за эту секунду — финальная зачистка.
pkill -f "ssh-tunnel-fr" 2>/dev/null || true
rm -f "$STATE_DIR/emergency.active" 2>/dev/null || true
log "тоннель остановлен, порты ${LOCAL_SOCKS}/${LOCAL_HTTP} освобождены"

# ── 4. xray рестарт с восстановленным конфигом ────────────────
echo "[4/5] Рестартую xray…"
sudo systemctl restart xray
sleep 3
# xray должен подняться на 10808 независимо от того, VLESS-конфиг это
# или emergency (тоннель уже мёртв, но listener поднимается в любом случае).
ss -tln 2>/dev/null | grep -qE ":10808\b" || \
    fail "xray не поднял 10808 — journalctl -u xray; VLESS может быть ещё заблокирован: bash start-fr-tunnel.sh вернёт аварийный режим"
log "xray рестартован (listener 10808 жив)"

# ── 5. xproxy старт ───────────────────────────────────────────
echo "[5/5] Запускаю xproxy…"
sudo systemctl start xproxy
sleep 2
systemctl is-active xproxy >/dev/null 2>&1 || fail "xproxy не запустился — systemctl status xproxy"
log "xproxy запущен; при первом успешном healthcheck пересоберёт конфиг сам"

echo ""
echo "✓ Штатный режим восстановлен."
echo "  Если VLESS ещё заблокирован — xproxy сообщит 'no working server found'"
echo "  и аварийный режим можно вернуть: bash start-fr-tunnel.sh"