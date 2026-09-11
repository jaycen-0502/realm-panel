#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: sudo bash install_agent.sh MASTER_URL TOKEN NODE_NAME
# Example: sudo bash install_agent.sh https://panel.example.com 'long-random-secret' node-a

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 MASTER_URL TOKEN NODE_NAME" >&2
  exit 2
fi

MASTER_URL="${1%/}"
TOKEN="$2"
NODE_NAME="$3"

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
if [[ ! "$MASTER_URL" =~ ^https?:// ]]; then
  echo "MASTER_URL must begin with http:// or https://" >&2
  exit 2
fi
if [[ -z "$TOKEN" || -z "$NODE_NAME" || "$NODE_NAME" == *$'\n'* ]]; then
  echo "TOKEN and NODE_NAME must be non-empty." >&2
  exit 2
fi
if (( ${#TOKEN} < 32 )); then
  echo "TOKEN must contain at least 32 characters." >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates coreutils curl findutils openssl passwd tar

for command_name in awk curl find install openssl sha256sum systemctl tar useradd; do
  command -v "$command_name" >/dev/null || { echo "Missing command: $command_name" >&2; exit 1; }
done

machine_arch="$(uname -m)"
if [[ "$machine_arch" != "x86_64" && "$machine_arch" != "amd64" ]]; then
  echo "This installer supports Linux x86_64 only (detected: $machine_arch)." >&2
  exit 1
fi

work_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT

echo "Downloading official Realm release..."
realm_version="v2.9.6"
realm_sha256="b9efc8ccbab5c9f0602ab5ba0a2e00311e7b773944533a8373c00811fb6a1a6b"
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/zhboner/realm/releases/download/${realm_version}/realm-x86_64-unknown-linux-gnu.tar.gz" \
  --output "$work_dir/realm.tar.gz"
printf '%s  %s\n' "$realm_sha256" "$work_dir/realm.tar.gz" | sha256sum --check --status || {
  echo "Realm archive checksum verification failed." >&2
  exit 1
}
tar -xzf "$work_dir/realm.tar.gz" -C "$work_dir"
realm_file="$(find "$work_dir" -type f -name realm -print -quit)"
if [[ -z "$realm_file" ]]; then
  echo "Realm archive did not contain the realm binary." >&2
  exit 1
fi

echo "Downloading the prebuilt agent from the panel..."
curl --fail --location \
  --dump-header "$work_dir/agent.headers" \
  "$MASTER_URL/downloads/agent-linux-amd64" \
  --output "$work_dir/realm-agent"
expected_agent_hmac="$(awk 'tolower($1)=="x-realm-binary-hmac:" {gsub("\\r", "", $2); print $2}' "$work_dir/agent.headers" | tail -n 1)"
actual_agent_hmac="$(openssl dgst -sha256 -hmac "$TOKEN" "$work_dir/realm-agent" | awk '{print $NF}')"
if [[ -z "$expected_agent_hmac" || "$actual_agent_hmac" != "$expected_agent_hmac" ]]; then
  echo "Agent binary authentication failed; refusing to install it." >&2
  exit 1
fi

install -d -m 0755 /etc/realm
if ! id realm >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin realm
fi
# Rename-over replacement is safe while an older binary is still executing.
install -m 0755 "$realm_file" /usr/local/bin/.realm.new
mv -f /usr/local/bin/.realm.new /usr/local/bin/realm
install -m 0755 "$work_dir/realm-agent" /usr/local/bin/.realm-agent.new
mv -f /usr/local/bin/.realm-agent.new /usr/local/bin/realm-agent

# EnvironmentFile avoids fragile shell quoting in the unit itself. Values are JSON
# string literals, which systemd accepts as quoted EnvironmentFile values.
json_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '"%s"' "$value"
}

umask 077
{
  printf 'MASTER_URL=%s\n' "$(json_quote "$MASTER_URL")"
  printf 'REALM_TOKEN=%s\n' "$(json_quote "$TOKEN")"
  printf 'NODE_NAME=%s\n' "$(json_quote "$NODE_NAME")"
  printf 'AGENT_ADDR=":6800"\n'
} > /etc/realm/agent.env
chmod 0600 /etc/realm/agent.env

cat > /etc/systemd/system/realm.service <<'UNIT'
[Unit]
Description=Realm port forwarding service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=realm
Group=realm
ExecStart=/usr/local/bin/realm -c /etc/realm/config.toml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/realm-agent.service <<'UNIT'
[Unit]
Description=Realm management agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/realm/agent.env
ExecStart=/usr/local/bin/realm-agent
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ReadWritePaths=/etc/realm
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

if [[ ! -f /etc/realm/config.toml ]]; then
  cat > /etc/realm/config.toml <<'CONF'
# Managed by realm-agent.
[network]
no_tcp = false
use_udp = true
CONF
fi

systemctl daemon-reload
systemctl enable realm.service
# A fresh managed config has no endpoints yet, so Realm is started by the first
# successful add-rule operation. On reinstall, start it immediately if rules exist.
if grep -q '^\[\[endpoints\]\]' /etc/realm/config.toml; then
  systemctl restart realm.service
fi
systemctl enable realm-agent.service
systemctl restart realm-agent.service

echo "Installed successfully. Node '$NODE_NAME' will register with $MASTER_URL."
echo "Agent status: systemctl status realm-agent --no-pager"
