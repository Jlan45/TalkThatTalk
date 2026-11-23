#!/usr/bin/env bash
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf 'Usage: bash install.sh [vX.Y.Z]\nInstalls the latest release when no version is supplied.\n'
    exit 0
fi
[[ $# -le 1 ]] || fail 'Usage: bash install.sh [vX.Y.Z]'
[[ $EUID -eq 0 ]] || fail 'Run the installer with sudo or as root.'
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || fail 'A Linux host running systemd is required.'

case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) fail "Unsupported architecture: $(uname -m)" ;;
esac
for dependency in curl tar sha256sum systemctl getent useradd groupadd; do
    command -v "$dependency" >/dev/null || fail "Required command not found: $dependency"
done

repository=Jlan45/TalkThatTalk
releases="https://github.com/$repository/releases"
binary=/usr/local/bin/talkthattalk
unit=/etc/systemd/system/talkthattalk.service
config_dir=/etc/talkthattalk
marker='# Managed by the TalkThatTalk installer.'
version=${1:-}
if [[ -n $version && ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail 'Use a release tag such as v0.0.1.'
fi
if [[ -e $unit || -L $unit ]]; then
    grep -Fxq "$marker" "$unit" || fail "An unmanaged service already exists at $unit."
elif [[ -e $binary || -L $binary ]]; then
    fail "An unmanaged executable already exists at $binary."
fi

work_dir=$(mktemp -d)
staged_binary=
staged_unit=
cleanup() {
    rm -rf -- "$work_dir"
    if [[ -n $staged_binary ]]; then rm -f -- "$staged_binary"; fi
    if [[ -n $staged_unit ]]; then rm -f -- "$staged_unit"; fi
}
trap cleanup EXIT

asset="talkthattalk-linux-$arch.tar.gz"
if [[ -n ${GH_TOKEN:-} ]]; then
    command -v gh >/dev/null || fail 'GitHub CLI is required when GH_TOKEN is set.'
    tag=()
    if [[ -n $version ]]; then tag=("$version"); fi
    gh release download "${tag[@]}" --repo "$repository" --dir "$work_dir" \
        --pattern "$asset" --pattern SHA256SUMS
else
    curl_args=(--fail --silent --show-error --location --retry 3 --proto '=https' --proto-redir '=https')
    if [[ -z $version ]]; then
        latest=$(curl "${curl_args[@]}" --output /dev/null --write-out '%{url_effective}' "$releases/latest")
        version=${latest##*/}
        [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Could not resolve the latest TalkThatTalk release.'
    fi
    release="$releases/download/$version"
    curl "${curl_args[@]}" "$release/$asset" --output "$work_dir/$asset"
    curl "${curl_args[@]}" "$release/SHA256SUMS" --output "$work_dir/SHA256SUMS"
fi
awk -v name="$asset" '$2 == name { print; found = 1 } END { exit !found }' \
    "$work_dir/SHA256SUMS" > "$work_dir/asset.sha256"
(cd "$work_dir" && sha256sum --check asset.sha256)
tar -xOzf "$work_dir/$asset" talkthattalk > "$work_dir/talkthattalk"
chmod 0755 "$work_dir/talkthattalk"
installed_version=$("$work_dir/talkthattalk" --version)
if [[ -n $version && $installed_version != "talkthattalk ${version#v}" ]]; then
    fail "The downloaded binary reports an unexpected version: $installed_version"
fi

getent group talkthattalk >/dev/null || groupadd --system talkthattalk
if ! getent passwd talkthattalk >/dev/null; then
    useradd --system --gid talkthattalk --home-dir /var/lib/talkthattalk \
        --no-create-home --shell /usr/sbin/nologin talkthattalk
fi
install -d -m 0755 /usr/local/bin
install -d -m 0750 -o root -g talkthattalk "$config_dir"
if [[ ! -e $config_dir/config.toml ]]; then
    cat > "$work_dir/config.toml" <<'CONFIG'
[server]
listen_addr = "127.0.0.1:18080"

[storage]
db_path = "/var/lib/talkthattalk/talkthattalk.db"
store_path = "/var/lib/talkthattalk/oauth-tokens.enc"
CONFIG
    install -m 0640 -o root -g talkthattalk "$work_dir/config.toml" "$config_dir/config.toml"
fi

cat > "$work_dir/talkthattalk.service" <<'UNIT'
# Managed by the TalkThatTalk installer.
[Unit]
Description=TalkThatTalk AI Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=talkthattalk
Group=talkthattalk
StateDirectory=talkthattalk
StateDirectoryMode=0700
WorkingDirectory=/var/lib/talkthattalk
EnvironmentFile=-/etc/talkthattalk/environment
ExecStart=/usr/local/bin/talkthattalk serve --config /etc/talkthattalk/config.toml
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT

staged_binary=$(mktemp /usr/local/bin/.talkthattalk.XXXXXX)
staged_unit=$(mktemp /etc/systemd/system/.talkthattalk.XXXXXX)
install -m 0755 "$work_dir/talkthattalk" "$staged_binary"
install -m 0644 "$work_dir/talkthattalk.service" "$staged_unit"
mv -f -- "$staged_unit" "$unit"
staged_unit=
mv -f -- "$staged_binary" "$binary"
staged_binary=
systemctl daemon-reload
systemctl enable talkthattalk.service
systemctl restart talkthattalk.service
printf 'Installed %s. Configuration: %s/config.toml\n' "$installed_version" "$config_dir"
