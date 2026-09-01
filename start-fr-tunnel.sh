#!/bin/bash
#
# start-fr-tunnel.sh — аварийный режим при блокировке протокола VLESS.
#
# Что делает:
#   1. Останавливает xproxy (его healthcheck через тоннель сочтёт прокси
#      живым, а при падении тоннеля начнёт ротацию и затрёт emergency-конфиг).
#   2. Поднимает SSH-туннель до online-fr (scaleway):
#      127.0.0.1:20808 → SOCKS, 127.0.0.1:20809 → HTTP на сервере,
#      с авто-reconnect циклом.
#   3. Бэкапит текущий config.json xray (если он не emergency).
#   4. Делает emergency-конфиг: outbound «proxy» (vless) → socks
#      127.0.0.1:20808; DNS DoU (UDP, через TCP-туннель не ходит) → DoH.
#      Routing / fakedns / sniffing / inbounds — бит-в-бит от xproxy.
#   5. Прогоняет xray -test, атомарно записывает, рестартует xray (БЕЗ xproxy).
#
# Запуск:
#   bash start-fr-tunnel.sh            # полный аварийный режим
#   bash start-fr-tunnel.sh --tunnel-only   # только тоннель, xray не трогать
#
# Повторный запуск безопасен: тоннель перезаподнимается, бэкап не затирается.
#
# Возврат в штатный режим: stop-fr-tunnel.sh
#   (restore бэкапа → xray restart → тоннель вниз → xproxy start).
#
# Только Linux (systemctl, /usr/local/etc/xray).
#

set -euo pipefail

# ── Параметры тоннеля ─────────────────────────────────────────
FR_HOST=163.172.162.45
FR_PORT=57093
FR_USER=sergey
LOCAL_SOCKS=20808          # локальный порт SSH-туннеля (SOCKS)
LOCAL_HTTP=20809           # локальный порт SSH-туннеля (HTTP)
REMOTE_SOCKS=10808         # порт SOCKS на scaleway (её xray)
REMOTE_HTTP=10809          # порт HTTP на scaleway (её xray)
RECONNECT_SLEEP=30
STATE_DIR="$HOME/.fr-tunnel"
BACKUP="$STATE_DIR/xray-config.pre-emergency.json"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_TMP="/usr/local/etc/xray/.config.json.xproxy.fr-tunnel.tmp"  # паттерн из sudoers xproxy
GEO_DIR="/var/lib/xproxy/geo"

[ "$(uname -s)" = "Linux" ] || { echo "!! только Linux (systemctl)" >&2; exit 1; }

TUNNEL_ONLY=0
[ "${1:-}" = "--tunnel-only" ] && TUNNEL_ONLY=1

log()  { printf '    %s\n' "$*"; }
fail() { printf '    !! %s\n' "$*" >&2; exit 1; }

# ── 1. Остановить xproxy ──────────────────────────────────────
# ВНИМАНИЕ: если xproxy в середине cold-rotation (VLESS мёртв, перебор
# кандидатов), graceful stop может висеть до TimeoutStopSec=90s —
# daemon проверяет _stop только между тиками, а sender-тред с retry-
# очередью не выходит пока очередь непуста. Поэтому: ждём stop
# ограниченно, остатки добиваем SIGKILL, чистим failed-статус.
_stop_xproxy_bounded() {
    sudo -n timeout 25 systemctl stop xproxy 2>/dev/null || \
        sudo -n systemctl kill --signal=SIGKILL xproxy 2>/dev/null || true
    sudo -n systemctl reset-failed xproxy 2>/dev/null || true
}

if [ "$TUNNEL_ONLY" -eq 0 ]; then
    echo "[1/2] Останавливаю xproxy…"
    _stop_xproxy_bounded
    log "xproxy остановлен (xray пока работает на старом конфиге)"
else
    echo "[1/2] [--tunnel-only] xproxy не трогаю"
fi

# ── 2. SSH-туннель ────────────────────────────────────────────
echo "[1/2] Поднимаю SSH-туннель 127.0.0.1:${LOCAL_SOCKS}/${LOCAL_HTTP} → ${FR_USER}@${FR_HOST}:${FR_PORT}…"

# Сначала убить циклы (иначе respawn), затем сами ssh-процессы.
# Паттерны ловят и старый 10808-тоннель от прежней версии скрипта,
# и 20808-тоннель от повторного запуска.
pkill -f "ssh-tunnel-fr" 2>/dev/null || true
pkill -f "ssh.*-L ${LOCAL_SOCKS}:" 2>/dev/null || true
pkill -f "ssh.*-L 10808:" 2>/dev/null || true
sleep 1

# Порты должны быть свободны.
for _ in $(seq 1 10); do
    ss -tln 2>/dev/null | grep -qE ":(${LOCAL_SOCKS}|${LOCAL_HTTP})\b" || break
    sleep 1
done
ss -tln 2>/dev/null | grep -qE ":(${LOCAL_SOCKS}|${LOCAL_HTTP})\b" && \
    fail "порты ${LOCAL_SOCKS}/${LOCAL_HTTP} заняты — тоннель не поднять"

# Цикл переподключения. Живёт в $STATE_DIR (переживает очистку /tmp,
# не переживает ребут — после ребута запуск повторить).
mkdir -p "$STATE_DIR"
TUNNEL_SCRIPT="$STATE_DIR/ssh-tunnel-fr.sh"
cat > "$TUNNEL_SCRIPT" << TUNNEL
#!/bin/bash
# авто-генерация start-fr-tunnel.sh — не редактировать
while true; do
    ssh -p ${FR_PORT} -o BatchMode=yes \\
        -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
        -o ExitOnForwardFailure=yes \\
        -L ${LOCAL_SOCKS}:127.0.0.1:${REMOTE_SOCKS} \\
        -L ${LOCAL_HTTP}:127.0.0.1:${REMOTE_HTTP} \\
        -N ${FR_USER}@${FR_HOST} 2>${STATE_DIR}/tunnel.log
    sleep ${RECONNECT_SLEEP}
done
TUNNEL
chmod +x "$TUNNEL_SCRIPT"
log "цикл тоннеля: ${TUNNEL_SCRIPT}"

setsid "$TUNNEL_SCRIPT" > /dev/null 2>&1 < /dev/null &
log "PID цикла: $!"

# Ждём listener (до ~20 сек).
for _ in $(seq 1 20); do
    ss -tln 2>/dev/null | grep -qE ":${LOCAL_SOCKS}\b" && break
    sleep 1
done
ss -tln 2>/dev/null | grep -qE ":${LOCAL_SOCKS}\b" || fail "тоннель не поднялся (порт ${LOCAL_SOCKS} не слушает)"

SOCKS_IP=$(curl -s -m 12 --socks5-hostname 127.0.0.1:"${LOCAL_SOCKS}" \
    https://icanhazip.com 2>/dev/null || echo "FAIL")
[ "$SOCKS_IP" != "FAIL" ] || fail "SOCKS-проверка через тоннель (${LOCAL_SOCKS}) не прошла"
log "тоннель активен, egress: ${SOCKS_IP}"

if [ "$TUNNEL_ONLY" -eq 1 ]; then
    echo ""
    echo "✓ Тоннель работает (только тоннель, xray не тронут)."
    echo "  SOCKS: 127.0.0.1:${LOCAL_SOCKS}   HTTP: 127.0.0.1:${LOCAL_HTTP}"
    exit 0
fi

# ── 3. Бэкап текущего конфига ─────────────────────────────────
echo "[2/2] Emergency-конфиг xray (upstream = SSH-тоннель)…"

# Emergency-детект: xproxy генерирует outbound tag=proxy ТОЛЬКО с vless.
# Если там socks — мы уже в аварийном режиме, бэкап не трогаем.
if python3 -c "
import json, sys
cfg = json.load(open('${XRAY_CONFIG}'))
ob = next((o for o in cfg.get('outbounds', []) if o.get('tag') == 'proxy'), None)
sys.exit(0 if ob and ob.get('protocol') == 'socks' else 1)
"; then
    log "текущий конфиг уже emergency — бэкап не трогаю: ${BACKUP}"
else
    [ -f "$XRAY_CONFIG" ] || fail "нет ${XRAY_CONFIG} — нечего бэкапить"
    cp "$XRAY_CONFIG" "$BACKUP"
    log "бэкап сохранён: ${BACKUP}"
fi

# ── 4. Трансформация ──────────────────────────────────────────
EMERGENCY_TMP=$(mktemp /tmp/fr-emergency.XXXXXX.json)
trap 'rm -f "$EMERGENCY_TMP"' EXIT

# outbound «proxy» → socks 127.0.0.1:${LOCAL_SOCKS};
# DNS DoU → DoH (UDP через TCP-туннель не ходит):
#   remote  1.1.1.1 → https://cloudflare-dns.com/dns-query
#   domestic 1.0.0.1 → https://dns.google/dns-query (domains/expectIPs как были)
# Оба DoH-домена уже есть в dns.hosts (→ 1.1.1.1 / 8.8.8.8) — bootstrap
# без рекурсии. Routing/fakedns/sniffing/inbounds — без изменений.
python3 - "$XRAY_CONFIG" "$LOCAL_SOCKS" "$EMERGENCY_TMP" <<'PYEOF'
import json, sys

src, socks_port, dst = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cfg = json.load(open(src))

found = False
for i, ob in enumerate(cfg.get("outbounds", [])):
    if ob.get("tag") == "proxy":
        cfg["outbounds"][i] = {
            "tag": "proxy",
            "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": socks_port}]},
        }
        found = True
        break
if not found:
    sys.exit("нет outbound с tag=proxy — конфиг не от xproxy?")

dns = cfg.get("dns") or {}
for i, s in enumerate(dns.get("servers") or []):
    if isinstance(s, dict):
        if str(s.get("address")) == "1.0.0.1":
            s["address"] = "https://dns.google/dns-query"
    elif s == "1.1.1.1":
        dns["servers"][i] = "https://cloudflare-dns.com/dns-query"

json.dump(cfg, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PYEOF
[ -s "$EMERGENCY_TMP" ] || fail "трансформация не удалась"

# ── 5. Валидация (в geo-окружении xray-сервиса) ───────────────
# log.access/log.error → "none" на время теста (файлы принадлежат root;
# боевой конфиг записываем с оригинальными путями — как делает xproxy).
python3 - "$EMERGENCY_TMP" <<'PYEOF'
import json, sys
p = sys.argv[1]
cfg = json.load(open(p))
cfg.setdefault("log", {})
cfg["log"]["access"] = "none"
cfg["log"]["error"] = "none"
json.dump(cfg, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PYEOF

if ! XRAY_LOCATION_ASSET="$GEO_DIR" xray -test -c "$EMERGENCY_TMP" >/dev/null 2>&1; then
    echo "    !! emergency-конфиг не прошёл xray -test:" >&2
    XRAY_LOCATION_ASSET="$GEO_DIR" xray -test -c "$EMERGENCY_TMP" 2>&1 | tail -5 >&2
    fail "отказываюсь записывать невалидный конфиг"
fi
log "emergency-конфиг прошёл xray -test"

# ── 6. Атомарная запись + рестарт xray ────────────────────────
# Паттерн xproxy из sudoers: tee во временный файл + mv поверх боевого.
sudo -n tee "$XRAY_TMP" < "$EMERGENCY_TMP" > /dev/null
sudo -n mv -f "$XRAY_TMP" "$XRAY_CONFIG"

sudo systemctl restart xray
sleep 3
ss -tln 2>/dev/null | grep -qE ":10808\b" || \
    fail "xray не поднял 10808 после emergency-конфига — journalctl -u xray"
log "xray рестартован с emergency-конфигом, listener 10808 жив"

# Маркер аварийного режима (для stop-скрипта и диагностики).
printf '%s\n' "$(date '+%Y-%m-%d %H:%M:%S') ports=${LOCAL_SOCKS}/${LOCAL_HTTP} egress=${SOCKS_IP}" \
    > "$STATE_DIR/emergency.active"

# ── 7. Верификация через xray (10808) ─────────────────────────
XRAY_IP=$(curl -s -m 12 --socks5-hostname 127.0.0.1:10808 \
    https://icanhazip.com 2>/dev/null || echo "FAIL")
[ "$XRAY_IP" != "FAIL" ] || fail "SOCKS-проверка через xray(10808) не прошла"
log "xray egress: ${XRAY_IP}"

TARGET=$(curl -s -m 12 -o /dev/null -w "%{http_code}" \
    --socks5-hostname 127.0.0.1:10808 \
    "https://api.telegram.org/bot0000000000:AAHw000000000000000000000000/getMe" \
    2>/dev/null || echo "000")
case "$TARGET" in
    200|401) log "target-check: Telegram API доступен (HTTP ${TARGET})" ;;
    *) fail "target-check через xray не прошёл (HTTP ${TARGET}) — конфиг применён, но Telegram API недоступен" ;;
esac

echo ""
echo "✓ Аварийный режим активен."
echo "  Тоннель: 127.0.0.1:${LOCAL_SOCKS}/${LOCAL_HTTP} → ${FR_HOST} (цикл: ${TUNNEL_SCRIPT})"
echo "  xray:    127.0.0.1:10808/10809 → upstream=тоннель (routing от xproxy сохранён)"
echo "  Бэкап:   ${BACKUP}"
echo "  Возврат: bash stop-fr-tunnel.sh"