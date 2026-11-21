#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
    printf '[x] Запустите установщик через sudo.\n' >&2
    exit 1
fi

if [[ ${1:-} == --local && $# == 1 ]]; then
    src_dir=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
    exec bash "$src_dir/cheburcheck-watchdog" --install
fi
if (( $# )); then
    printf 'Использование: bash install.sh [--local]\n' >&2
    exit 1
fi

branch=${CHEBURCHECK_WATCHDOG_BRANCH:-main}
if [[ ! $branch =~ ^[a-zA-Z0-9._/-]+$ ]]; then
    printf '[x] Недопустимое имя ветки GitHub.\n' >&2
    exit 1
fi

packages=()
command -v curl >/dev/null || packages+=(curl)
command -v tar >/dev/null || packages+=(tar)
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
if (( ${#packages[@]} )); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
fi

cd /
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
printf '[>] Скачивание Cheburcheck Watchdog…\n'
curl -q -fL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 \
    -o "$tmp_dir/source.tar.gz" \
    "https://codeload.github.com/obkaiter/cheburcheck-watchdog/tar.gz/refs/heads/$branch"
mkdir "$tmp_dir/source"
tar -xzf "$tmp_dir/source.tar.gz" -C "$tmp_dir/source"
sources=("$tmp_dir/source"/*)
if (( ${#sources[@]} != 1 )) || [[ ! -f ${sources[0]}/cheburcheck-watchdog ]]; then
    printf '[x] В архиве отсутствует скрипт Cheburcheck Watchdog.\n' >&2
    exit 1
fi
bash "${sources[0]}/cheburcheck-watchdog" --install
