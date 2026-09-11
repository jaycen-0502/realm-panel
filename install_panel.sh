#!/usr/bin/env bash
set -Eeuo pipefail

# Debian/Ubuntu one-click installer for the Realm control panel.
# Interactive by default. Backward-compatible optional usage:
# sudo bash install_panel.sh [TOKEN] [PANEL_PASSWORD] [PANEL_USERNAME]

REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/jaycen-0502/realm-panel/main}"
TOKEN="${1:-${REALM_TOKEN:-}}"
PANEL_PASSWORD="${2:-${PANEL_PASSWORD:-}}"
PANEL_USERNAME="${3:-${PANEL_USERNAME:-}}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (or with sudo)." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot identify this Linux distribution." >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *) echo "Only Debian and Ubuntu are supported (detected: ${ID:-unknown})." >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl jq openssl tar

machine_arch="$(uname -m)"
if [[ "$machine_arch" != "x86_64" && "$machine_arch" != "amd64" ]]; then
  echo "This installer currently supports Linux x86_64 only (detected: $machine_arch)." >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then TOKEN="$(openssl rand -hex 32)"; fi
if [[ -z "$PANEL_USERNAME" && -t 1 ]]; then
  read -r -p "Administrator username [admin]: " PANEL_USERNAME </dev/tty
  PANEL_USERNAME="${PANEL_USERNAME:-admin}"
fi
if [[ -z "$PANEL_PASSWORD" && -t 1 ]]; then
  while true; do
    read -r -s -p "Administrator password (at least 12 characters): " PANEL_PASSWORD </dev/tty
    printf '\n'
    read -r -s -p "Confirm password: " panel_password_confirm </dev/tty
    printf '\n'
    if (( ${#PANEL_PASSWORD} < 12 )); then
      echo "Password is too short; please try again." >&2
    elif [[ "$PANEL_PASSWORD" == "$panel_password_confirm" ]]; then
      break
    else
      echo "Passwords do not match; please try again." >&2
    fi
  done
fi
if [[ -z "$PANEL_USERNAME" ]]; then PANEL_USERNAME="admin"; fi
if [[ -z "$PANEL_PASSWORD" ]]; then PANEL_PASSWORD="$(openssl rand -base64 18 | tr -d '\n=/+')"; fi
if [[ "$TOKEN" == *$'\n'* || "$PANEL_USERNAME" == *$'\n'* || "$PANEL_PASSWORD" == *$'\n'* ]]; then
  echo "Username, token and password cannot contain newlines." >&2
  exit 2
fi
if (( ${#PANEL_USERNAME} < 3 || ${#PANEL_USERNAME} > 64 || ${#TOKEN} < 32 || ${#PANEL_PASSWORD} < 12 )); then
  echo "Username must be 3-64 characters, token at least 32, and password at least 12." >&2
  exit 2
fi

source_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$source_dir"; }
trap cleanup EXIT

echo "Downloading and building Realm Panel..."
curl --fail --location "$REPO_RAW_URL/main.go" -o "$source_dir/main.go"
curl --fail --location "$REPO_RAW_URL/agent.go" -o "$source_dir/agent.go"

# Use the current official Go toolchain so older Debian/Ubuntu releases are not
# limited by the old compiler in their package repositories.
go_metadata="$(curl --fail --silent --show-error --location 'https://go.dev/dl/?mode=json')"
go_version="$(printf '%s' "$go_metadata" | jq -r 'map(select(.stable))[0].version')"
go_sha256="$(printf '%s' "$go_metadata" | jq -r 'map(select(.stable))[0].files[] | select(.os=="linux" and .arch=="amd64" and .kind=="archive") | .sha256')"
if [[ ! "$go_version" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "Could not determine the current stable Go version." >&2
  exit 1
fi
curl --fail --location "https://go.dev/dl/${go_version}.linux-amd64.tar.gz" -o "$source_dir/go.tar.gz"
printf '%s  %s\n' "$go_sha256" "$source_dir/go.tar.gz" | sha256sum --check --status || {
  echo "Go toolchain checksum verification failed." >&2
  exit 1
}
tar -xzf "$source_dir/go.tar.gz" -C "$source_dir"
go_binary="$source_dir/go/bin/go"

CGO_ENABLED=0 "$go_binary" build -trimpath -ldflags='-s -w' -o "$source_dir/realm-panel" "$source_dir/main.go"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_binary" build -trimpath -ldflags='-s -w' -o "$source_dir/agent-linux-amd64" "$source_dir/agent.go"

install -d -m 0755 /opt/realm-panel
if ! id realm-panel >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /var/lib/realm-panel --shell /usr/sbin/nologin realm-panel
fi
install -d -o realm-panel -g realm-panel -m 0700 /var/lib/realm-panel
install -m 0755 "$source_dir/realm-panel" /usr/local/bin/.realm-panel.new
mv -f /usr/local/bin/.realm-panel.new /usr/local/bin/realm-panel
install -m 0755 "$source_dir/agent-linux-amd64" /opt/realm-panel/agent-linux-amd64

quote_env() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

umask 077
{
  printf 'PANEL_USERNAME=%s\n' "$(quote_env "$PANEL_USERNAME")"
  printf 'PANEL_PASSWORD=%s\n' "$(quote_env "$PANEL_PASSWORD")"
  printf 'REALM_TOKEN=%s\n' "$(quote_env "$TOKEN")"
  printf 'PANEL_ADDR=":6800"\n'
  printf 'DATA_DIR="/var/lib/realm-panel"\n'
  printf 'AGENT_BINARY="/opt/realm-panel/agent-linux-amd64"\n'
} > /etc/realm-panel.env
chmod 0600 /etc/realm-panel.env

cat > /etc/systemd/system/realm-panel.service <<'UNIT'
[Unit]
Description=Realm distributed management panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=realm-panel
Group=realm-panel
EnvironmentFile=/etc/realm-panel.env
ExecStart=/usr/local/bin/realm-panel
WorkingDirectory=/var/lib/realm-panel
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ReadWritePaths=/var/lib/realm-panel
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable realm-panel.service
systemctl restart realm-panel.service

panel_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
panel_ip="${panel_ip:-MASTER_IP}"

echo
echo "Realm Panel is installed and listening on port 6800."
echo "Panel URL: http://${panel_ip}:6800"
echo "Panel username: ${PANEL_USERNAME}"
echo "Panel password: ${PANEL_PASSWORD}"
echo "Shared token: ${TOKEN}"
echo
echo "Bind a Debian/Ubuntu node with:"
echo "curl -fsSL ${REPO_RAW_URL}/install_agent.sh -o /tmp/install_agent.sh && sudo bash /tmp/install_agent.sh 'http://${panel_ip}:6800' '${TOKEN}' 'node-a'"
echo
echo "Save the password and token now. They are also stored root-only in /etc/realm-panel.env."
