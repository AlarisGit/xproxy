#!/usr/bin/env bash
# Установка xproxy в автозапуск. macOS: launchd. Linux: systemd.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

# Выбор интерпретатора: приоритет — venv в проекте, чтобы зависимости из
# requirements.txt (PySocks и т.п.) были гарантированно доступны демону.
# Поведение:
#   - PYTHON=/path/to/python ./install.sh  → использовать указанный интерпретатор
#   - иначе: если есть .venv/ или venv/    → использовать его python3
#   - иначе: создать .venv/ из системного python3 и установить requirements.txt
venv_dir=""
if [ -n "${PYTHON:-}" ]; then
    python_bin="$PYTHON"
    echo "using PYTHON override: $python_bin"
elif [ -x "$root/.venv/bin/python3" ]; then
    venv_dir="$root/.venv"
    python_bin="$venv_dir/bin/python3"
    echo "using existing venv: $venv_dir"
elif [ -x "$root/venv/bin/python3" ]; then
    venv_dir="$root/venv"
    python_bin="$venv_dir/bin/python3"
    echo "using existing venv: $venv_dir"
else
    sys_py="$(command -v python3 || true)"
    if [ -z "$sys_py" ]; then
        echo "ERROR: python3 не найден в PATH" >&2
        exit 1
    fi
    venv_dir="$root/.venv"
    echo "creating fresh venv at $venv_dir (using $sys_py)"
    "$sys_py" -m venv "$venv_dir"
    python_bin="$venv_dir/bin/python3"
fi

# Установить/обновить зависимости, если у нас venv и есть requirements.txt.
if [ -n "$venv_dir" ] && [ -f "$root/requirements.txt" ]; then
    echo "installing requirements from $root/requirements.txt"
    "$python_bin" -m pip install --upgrade pip --quiet
    "$python_bin" -m pip install -r "$root/requirements.txt" --quiet
    echo "dependencies OK"
fi

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

# На Linux geo-файлы лежат в системном shared-каталоге, чтобы xray-сервис
# (обычно запущен от nobody) мог их читать, не требуя ослабления прав на $HOME.
ensure_geo_dir_linux() {
    local geo_dir="/var/lib/xproxy/geo"
    if [ -d "$geo_dir" ] && [ -w "$geo_dir" ]; then
        echo "geo dir $geo_dir OK"
        return
    fi
    echo "Creating $geo_dir (requires sudo)..."
    sudo install -d -m 0755 -o "$user_name" -g "$(id -gn)" "$geo_dir"
    # Убедимся, что промежуточная /var/lib/xproxy существует с нормальными правами
    # (install -d создаст её автоматически как 0755 root:root — это то, что нужно).
    echo "geo dir $geo_dir created"
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
        ensure_geo_dir_linux
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
        echo "=== Шаг 3: override xray.service → XRAY_LOCATION_ASSET ==="
        echo "xproxy скачивает geosite.dat/geoip.dat в /var/lib/xproxy/geo"
        echo "(shared-каталог 0755, читается любым пользователем, в т.ч. nobody"
        echo " под которым обычно запущен xray-сервис). Без этой переменной"
        echo "xray использует устаревшие geo-файлы из своего пакета."
        echo
        xray_dropin_dir="/etc/systemd/system/xray.service.d"
        xray_override="$xray_dropin_dir/xproxy-geo.conf"
        xray_override_tmp="$(mktemp)"
        cat > "$xray_override_tmp" <<EOF
# Managed by xproxy deploy/install.sh.
# Без этой директивы xray не увидит свежие geo-файлы, скачанные xproxy.
[Service]
Environment=XRAY_LOCATION_ASSET=/var/lib/xproxy/geo
EOF
        echo "xray override rendered → $xray_override_tmp"
        echo "Install with:"
        echo "  sudo install -d -m 0755 $xray_dropin_dir"
        echo "  sudo install -m 0644 $xray_override_tmp $xray_override"
        echo "  sudo systemctl daemon-reload"
        echo "  sudo systemctl restart xray"
        ;;
    *)
        echo "Unsupported OS: $os" >&2
        exit 1
        ;;
esac
