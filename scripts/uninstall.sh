#!/usr/bin/env bash
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf 'Usage: bash uninstall.sh [--purge]\nUse --purge to also delete the configuration and persisted data.\n'
    exit 0
fi
[[ $# -eq 0 || ( $# -eq 1 && $1 == --purge ) ]] || fail 'Usage: bash uninstall.sh [--purge]'
[[ $EUID -eq 0 ]] || fail 'Run the uninstaller with sudo or as root.'
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || fail 'A Linux host running systemd is required.'

binary=/usr/local/bin/talkthattalk
unit=/etc/systemd/system/talkthattalk.service
if [[ -e $unit || -L $unit ]]; then
    grep -Fxq '# Managed by the TalkThatTalk installer.' "$unit" || fail "The service at $unit is unmanaged."
    systemctl disable --now talkthattalk.service
    rm -f -- "$binary" "$unit"
    systemctl daemon-reload
elif [[ -e $binary || -L $binary ]]; then
    fail "The executable at $binary is unmanaged."
fi

if [[ ${1:-} == --purge ]]; then
    rm -rf -- /etc/talkthattalk /var/lib/talkthattalk
    printf 'TalkThatTalk and its configuration and data were removed.\n'
else
    printf 'TalkThatTalk was removed. Configuration and data are retained under /etc/talkthattalk and /var/lib/talkthattalk.\n'
fi
