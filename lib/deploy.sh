#!/usr/bin/env bash

INSTALL_DIR=/opt/cheburcheck-watchdog
COMMAND_LINK=/usr/local/bin/cheburcheck-watchdog
UNIT=cheburcheck-watchdog.service
UNIT_PATH=/etc/systemd/system/$UNIT
LOCK_FILE=/run/lock/cheburcheck-watchdog.lock
GITHUB_REPO=obkaiter/cheburcheck-watchdog
GITHUB_BRANCH=${CHEBURCHECK_WATCHDOG_BRANCH:-main}

ensure_dependencies() {
    local -a packages=()
    if [[ ! -d /run/systemd/system ]]; then
        printf '[x] Для работы нужен Linux с запущенным systemd.\n' >&2
        return 1
    fi
    [[ -x /usr/bin/python3 ]] || packages+=(python3)
    command -v systemctl >/dev/null || packages+=(systemd)
    command -v flock >/dev/null || packages+=(util-linux)
    command -v curl >/dev/null || packages+=(curl)
    command -v tar >/dev/null || packages+=(tar)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
    if (( ${#packages[@]} )); then
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || return 1
    fi
    if ! /usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
        printf '[x] Требуется Python 3.9 или новее.\n' >&2
        return 1
    fi
    systemctl show --property=Version --value >/dev/null
}

read_version() {
    local version
    version=$(tr -d '[:space:]' < "$1") && [[ $version =~ ^[0-9]+(\.[0-9]+)+$ ]] || return 1
    printf '%s\n' "$version"
}

version_gt() {
    [[ $1 != "$2" && $(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1) == "$2" ]]
}

install_payload() (
    local src=$1 expected=${2:-} file version installed stage unit_stage
    local old_app=0 new_app=0 old_unit=0 new_unit=0 new_link=0 active=0 committed=0
    local -a scripts=(cheburcheck-watchdog install.sh)
    local -a files=(VERSION README.md menu.py watchdog.py lib/deploy.sh "systemd/$UNIT")

    for file in "${scripts[@]}" "${files[@]}"; do
        if [[ ! -f $src/$file || -L $src/$file ]]; then
            printf '[x] В дистрибутиве отсутствует обязательный файл %s.\n' "$file" >&2
            return 1
        fi
    done
    version=$(read_version "$src/VERSION") || return 1
    if [[ -n $expected && $version != "$expected" ]]; then
        printf '[x] Ветка GitHub изменилась при скачивании. Обновление отложено.\n' >&2
        return 1
    fi

    umask 022
    exec 9>>"$LOCK_FILE" || return 1
    flock -x 9 || return 1
    if [[ -n $expected && -f $INSTALL_DIR/VERSION ]]; then
        installed=$(read_version "$INSTALL_DIR/VERSION") || return 1
        version_gt "$version" "$installed" || return 0
    fi

    if [[ -L $INSTALL_DIR || ( -e $INSTALL_DIR && ! -d $INSTALL_DIR ) ||
          -L $UNIT_PATH || ( -e $UNIT_PATH && ! -f $UNIT_PATH ) ]]; then
        printf '[x] Проверьте существующие пути %s и %s.\n' "$INSTALL_DIR" "$UNIT_PATH" >&2
        return 1
    fi
    if [[ -e $COMMAND_LINK || -L $COMMAND_LINK ]]; then
        if [[ $(readlink -- "$COMMAND_LINK") != "$INSTALL_DIR/cheburcheck-watchdog" ]]; then
            printf '[x] Путь команды уже занят: %s.\n' "$COMMAND_LINK" >&2
            return 1
        fi
    fi

    stage=$(mktemp -d /opt/.cheburcheck-watchdog.XXXXXXXX) || return 1
    unit_stage=
    cleanup_install() {
        local recover=0
        if (( ! committed )); then
            (( ! new_link )) || rm -f -- "$COMMAND_LINK" || recover=1
            (( ! new_app )) || rm -rf -- "$INSTALL_DIR" || recover=1
            (( ! old_app )) || mv -T -- "$stage/previous" "$INSTALL_DIR" || recover=1
            if (( new_unit )); then
                if (( old_unit )); then
                    install -m 0644 "$stage/previous.service" "$unit_stage" &&
                        mv -fT -- "$unit_stage" "$UNIT_PATH" || recover=1
                else
                    rm -f -- "$UNIT_PATH" || recover=1
                fi
                systemctl daemon-reload || recover=1
                (( ! active )) || systemctl restart "$UNIT" || recover=1
            fi
        fi
        [[ -z $unit_stage ]] || rm -f -- "$unit_stage"
        if (( recover )); then
            printf '[x] Не удалось восстановить установку. Проверьте файлы в %s.\n' "$stage" >&2
        else
            rm -rf -- "$stage"
        fi
    }
    trap cleanup_install EXIT
    trap 'exit 1' HUP INT TERM

    for file in "${scripts[@]}"; do
        install -Dm 0755 "$src/$file" "$stage/app/$file" || return 1
    done
    for file in "${files[@]}"; do
        install -Dm 0644 "$src/$file" "$stage/app/$file" || return 1
    done
    unit_stage=$(mktemp /etc/systemd/system/.cheburcheck-watchdog.XXXXXXXX) || return 1
    install -m 0644 "$stage/app/systemd/$UNIT" "$unit_stage" || return 1
    if [[ -f $UNIT_PATH ]]; then
        cp -p -- "$UNIT_PATH" "$stage/previous.service" || return 1
        old_unit=1
    fi
    systemctl is-active --quiet "$UNIT" && active=1
    if [[ -d $INSTALL_DIR ]]; then
        mv -T -- "$INSTALL_DIR" "$stage/previous" || return 1
        old_app=1
    fi
    mv -T -- "$stage/app" "$INSTALL_DIR" || return 1
    new_app=1
    mv -fT -- "$unit_stage" "$UNIT_PATH" || return 1
    new_unit=1
    if [[ ! -L $COMMAND_LINK ]]; then
        ln -s -- "$INSTALL_DIR/cheburcheck-watchdog" "$COMMAND_LINK" || return 1
        new_link=1
    fi
    systemctl daemon-reload || return 1
    if (( active )); then
        systemctl restart "$UNIT" || return 1
    fi
    committed=1
    printf '[ok] Установлен Cheburcheck Watchdog v%s. Команда запуска: sudo cheburcheck-watchdog\n' "$version"
)

download_update() (
    local version=$1 tmp_dir
    local -a sources
    cd / || return 1
    tmp_dir=$(mktemp -d) || return 1
    trap 'rm -rf -- "$tmp_dir"' EXIT
    printf '[>] Скачивание Cheburcheck Watchdog v%s…\n' "$version"
    curl -q -fL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 \
        -o "$tmp_dir/source.tar.gz" \
        "https://codeload.github.com/$GITHUB_REPO/tar.gz/refs/heads/$GITHUB_BRANCH" || return 1
    mkdir "$tmp_dir/source" && tar -xzf "$tmp_dir/source.tar.gz" -C "$tmp_dir/source" || return 1
    sources=("$tmp_dir/source"/*)
    (( ${#sources[@]} == 1 )) && install_payload "${sources[0]}" "$version"
)

check_for_updates() {
    local current=$1 remote
    if [[ ${CHEBURCHECK_WATCHDOG_SKIP_UPDATE:-0} == 1 ]]; then
        printf '[i] Проверка обновлений пропущена.\n'
        return
    fi
    if [[ ! $GITHUB_BRANCH =~ ^[a-zA-Z0-9._/-]+$ ]] ||
        ! remote=$(curl -q -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 10 \
            "https://raw.githubusercontent.com/$GITHUB_REPO/$GITHUB_BRANCH/VERSION" 2>/dev/null |
            tr -d '[:space:]') || [[ ! $remote =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
        printf '[!] Не удалось проверить версию на GitHub.\n' >&2
        return 1
    fi
    if version_gt "$remote" "$current"; then
        printf '[i] Доступна версия %s. Текущая версия %s.\n' "$remote" "$current"
        if download_update "$remote"; then
            printf '[i] Перезапуск меню…\n'
            cd / || return
            exec "$COMMAND_LINK"
        fi
        printf '[!] Не удалось установить обновление.\n' >&2
        return 1
    else
        printf '[ok] Версия актуальна: %s.\n' "$current"
    fi
}
