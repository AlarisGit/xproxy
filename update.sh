#!/usr/bin/env bash
# Обновить xproxy через локальный Xray и перезапустить systemd-сервис.
set -euo pipefail

main() {
    if [ "$(uname -s)" != "Linux" ]; then
        echo "ERROR: update.sh поддерживает только Linux" >&2
        exit 1
    fi

    local here branch proxy_url repository
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    branch="main"
    proxy_url="http://127.0.0.1:10809"
    repository="https://github.com/AlarisGit/xproxy.git"

    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: git не найден в PATH" >&2
        exit 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "ERROR: systemctl не найден в PATH" >&2
        exit 1
    fi
    if [ "$(git -C "$here" branch --show-current)" != "$branch" ]; then
        echo "ERROR: update.sh должен запускаться на ветке $branch" >&2
        exit 1
    fi

    echo "Updating $here from $repository/$branch via $proxy_url"
    env \
        -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY \
        -u all_proxy -u https_proxy -u http_proxy -u no_proxy \
        git -C "$here" -c "http.proxy=$proxy_url" \
        pull --ff-only "$repository" "$branch"

    echo "Restarting xproxy.service"
    sudo systemctl restart xproxy.service
    sudo systemctl --no-pager --full status xproxy.service
}

# Функция целиком разбирается bash до запуска: git pull может безопасно
# обновить сам update.sh, не меняя уже выполняемый сценарий.
main "$@"
