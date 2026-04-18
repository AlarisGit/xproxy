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
        echo "Next steps:"
        echo "  launchctl unload  $plist_target 2>/dev/null || true"
        echo "  launchctl load -w $plist_target"
        echo
        echo "Также убедитесь, что xray видит geosite.dat/geoip.dat из ~/.config/xproxy/geo."
        echo "Для xray, запущенного через 'brew services', задайте ассет-директорию:"
        echo "  launchctl setenv XRAY_LOCATION_ASSET $user_home/.config/xproxy/geo"
        echo "  brew services restart xray"
        ;;
    Linux)
        unit_target="/etc/systemd/system/xproxy.service"
        tmp="$(mktemp)"
        render "$here/xproxy.service" > "$tmp"
        echo "rendered unit → $tmp"
        echo "Install as root:"
        echo "  sudo install -m 0644 $tmp $unit_target"
        echo "  sudo systemctl daemon-reload"
        echo "  sudo systemctl enable --now xproxy.service"
        echo
        sudoers_tmp="$(mktemp)"
        render "$here/sudoers.xproxy" > "$sudoers_tmp"
        echo "Sudoers snippet rendered → $sudoers_tmp"
        echo "Install with:"
        echo "  sudo install -m 0440 $sudoers_tmp /etc/sudoers.d/xproxy"
        echo "  sudo visudo -c"
        echo
        echo "Для XRAY_LOCATION_ASSET в systemd-юните xray.service:"
        echo "  sudo systemctl edit xray"
        echo "  # и добавьте:"
        echo "  # [Service]"
        echo "  # Environment=XRAY_LOCATION_ASSET=$user_home/.config/xproxy/geo"
        ;;
    *)
        echo "Unsupported OS: $os" >&2
        exit 1
        ;;
esac
