#!/usr/bin/env bash
# Установка xproxy в автозапуск. macOS: launchd. Linux: systemd.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
python_bin="${PYTHON:-$(command -v python3)}"
user_home="$HOME"
user_name="$(id -un)"

render() {
    sed \
        -e "s|__PROJECT_DIR__|$root|g" \
        -e "s|__PYTHON__|$python_bin|g" \
        -e "s|__HOME__|$user_home|g" \
        -e "s|__USER__|$user_name|g" \
        "$1"
}

ensure_log_dir() {
    local log_dir="/var/log/xproxy"
    if [ -d "$log_dir" ] && [ -w "$log_dir" ]; then
        echo "log dir $log_dir OK"
        return
    fi
    echo "Creating $log_dir (requires sudo)..."
    sudo install -d -m 0755 -o "$user_name" -g "$(id -gn)" "$log_dir"
    echo "log dir $log_dir created"
}

ensure_log_dir

os="$(uname -s)"
case "$os" in
    Darwin)
        plist_target="$user_home/Library/LaunchAgents/com.xproxy.daemon.plist"
        mkdir -p "$(dirname "$plist_target")"
        render "$here/com.xproxy.daemon.plist" > "$plist_target"
        echo "wrote $plist_target"
        echo
        echo "=== Шаг 1: загрузить launchd-агент xproxy ==="
        echo "  launchctl unload  $plist_target 2>/dev/null || true"
        echo "  launchctl load -w $plist_target"
        echo
        echo "=== Шаг 2 (ОБЯЗАТЕЛЬНО): указать xray путь к geo-файлам ==="
        echo "xproxy скачивает geosite.dat/geoip.dat в ~/.config/xproxy/geo."
        echo "Без этой переменной xray использует устаревшие geo-файлы из своего пакета."
        echo "  launchctl setenv XRAY_LOCATION_ASSET $user_home/.config/xproxy/geo"
        echo "  brew services restart xray"
        ;;
    Linux)
        unit_target="/etc/systemd/system/xproxy.service"
        tmp="$(mktemp)"
        render "$here/xproxy.service" > "$tmp"
        echo "rendered unit → $tmp"
        echo
        echo "=== Шаг 1: установить юнит xproxy.service ==="
        echo "  sudo install -m 0644 $tmp $unit_target"
        echo "  sudo systemctl daemon-reload"
        echo "  sudo systemctl enable --now xproxy.service"
        echo
        sudoers_tmp="$(mktemp)"
        render "$here/sudoers.xproxy" > "$sudoers_tmp"
        echo "=== Шаг 2: установить sudoers для xproxy (restart xray + write config) ==="
        echo "Rendered → $sudoers_tmp"
        echo "  sudo install -m 0440 $sudoers_tmp /etc/sudoers.d/xproxy"
        echo "  sudo visudo -c"
        echo
        echo "=== Шаг 3 (ОБЯЗАТЕЛЬНО): указать xray путь к geo-файлам ==="
        echo "xproxy скачивает geosite.dat/geoip.dat в $user_home/.config/xproxy/geo."
        echo "Без этой переменной xray использует устаревшие geo-файлы из своего пакета."
        echo "  sudo systemctl edit xray"
        echo "  # и вставьте:"
        echo "  # [Service]"
        echo "  # Environment=XRAY_LOCATION_ASSET=$user_home/.config/xproxy/geo"
        echo "  sudo systemctl daemon-reload"
        echo "  sudo systemctl restart xray"
        ;;
    *)
        echo "Unsupported OS: $os" >&2
        exit 1
        ;;
esac
