#!/usr/bin/env bash
# ==============================================================================
# Kelvin Rootless Podman & Host Worker Setup Script
# Targets: Oracle Linux Server 9.8 (ARM64 / aarch64)
# Implements: ADR-0008 Option A (Dedicated Unprivileged Host Worker)
#
# Idempotent setup script. Never restarts or modifies existing API, Caddy,
# or database services.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> [Kelvin Setup] Initializing Rootless Podman & Host Worker Configuration..."

# 1. Require root execution for system-level provisioning
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: setup-rootless-podman.sh must be executed with root/sudo privileges." >&2
  exit 1
fi

# 2. Verify Architecture (Strictly require aarch64/arm64)
ARCH="$(uname -m)"
echo "Host architecture detected: $ARCH"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "ERROR: Unsupported host architecture '$ARCH'. Oracle Linux staging strictly requires aarch64 or arm64 per ADR-0008." >&2
  exit 1
fi
echo "Verified host architecture: $ARCH"

# 3. Verify cgroups v2 and controllers
if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "ERROR: cgroups v2 is required by ADR-0008 but not enabled on this system." >&2
  exit 1
fi
CONTROLLERS="$(cat /sys/fs/cgroup/cgroup.controllers)"
echo "Active cgroup v2 controllers: $CONTROLLERS"
for ctrl in cpu memory pids; do
  if ! echo "$CONTROLLERS" | grep -qw "$ctrl"; then
    echo "ERROR: Required cgroup controller '$ctrl' missing from /sys/fs/cgroup/cgroup.controllers" >&2
    exit 1
  fi
done
echo "Verified cgroups v2 with cpu, memory, and pids controllers."

# 4. Verify Podman and crun installation
if ! command -v podman >/dev/null 2>&1; then
  echo "ERROR: podman is not installed. Install via: dnf install -y podman crun" >&2
  exit 1
fi
if ! command -v crun >/dev/null 2>&1; then
  echo "ERROR: crun OCI runtime is required by ADR-0008. Install via: dnf install -y crun" >&2
  exit 1
fi
echo "Verified podman and crun are installed."

# 5. Create unprivileged group and user kelvin-worker (UID/GID 10001)
if ! getent group kelvin-worker >/dev/null 2>&1; then
  echo "Creating group kelvin-worker (GID 10001)..."
  groupadd -g 10001 kelvin-worker
else
  EXISTING_GID="$(getent group kelvin-worker | cut -d: -f3)"
  if [[ "$EXISTING_GID" -ne 10001 ]]; then
    echo "ERROR: Group kelvin-worker exists with GID $EXISTING_GID (expected 10001)" >&2
    exit 1
  fi
  echo "Group kelvin-worker (GID 10001) verified."
fi

if ! id -u kelvin-worker >/dev/null 2>&1; then
  echo "Creating user kelvin-worker (UID 10001)..."
  useradd -u 10001 -g 10001 -m -d /var/lib/kelvin-worker -s /bin/bash kelvin-worker
else
  EXISTING_UID="$(id -u kelvin-worker)"
  if [[ "$EXISTING_UID" -ne 10001 ]]; then
    echo "ERROR: User kelvin-worker exists with UID $EXISTING_UID (expected 10001)" >&2
    exit 1
  fi
  echo "User kelvin-worker (UID 10001) verified."
fi

# 6. Configure subuid and subgid for rootless container user namespaces (100000:65536)
echo "Configuring /etc/subuid and /etc/subgid for kelvin-worker..."
validate_or_add_subid() {
  local id_file="$1"
  local expected="kelvin-worker:100000:65536"

  if [[ ! -f "$id_file" ]]; then
    touch "$id_file"
  fi

  local existing_lines
  existing_lines="$(grep "^kelvin-worker:" "$id_file" 2>/dev/null || true)"

  if [[ -z "$existing_lines" ]]; then
    echo "Adding '$expected' to $id_file..."
    echo "$expected" >> "$id_file"
  else
    local count
    count="$(echo "$existing_lines" | wc -l)"
    if [[ "$count" -eq 1 && "$existing_lines" == "$expected" ]]; then
      echo "Verified existing subordinate ID mapping in $id_file ($expected)."
    else
      echo "ERROR: Conflicting subordinate ID configuration found in $id_file for kelvin-worker." >&2
      echo "Found:" >&2
      echo "$existing_lines" >&2
      echo "Expected exactly: '$expected'" >&2
      echo "Automatic overwrite or appending conflicting mappings is prohibited. Remediate manually." >&2
      exit 1
    fi
  fi
}

validate_or_add_subid "/etc/subuid"
validate_or_add_subid "/etc/subgid"

# 7. Enable systemd user session lingering
echo "Enabling systemd linger for kelvin-worker..."
loginctl enable-linger kelvin-worker

# 8. Create standard directories with hardened permissions
echo "Creating Kelvin host directories with hardened permissions..."
mkdir -p /opt/kelvin/bin
mkdir -p /var/lib/kelvin-worker
mkdir -p /var/log/kelvin
mkdir -p /etc/kelvin
mkdir -p /etc/kelvin/certs

chown root:root /opt/kelvin/bin
chmod 0755 /opt/kelvin/bin

chown kelvin-worker:kelvin-worker /var/lib/kelvin-worker
chmod 0750 /var/lib/kelvin-worker

chown kelvin-worker:kelvin-worker /var/log/kelvin
chmod 0755 /var/log/kelvin

chown root:kelvin-worker /etc/kelvin
chmod 0750 /etc/kelvin

chown root:kelvin-worker /etc/kelvin/certs
chmod 0750 /etc/kelvin/certs

# 9. Install worker environment template safely (never copy placeholder as active config)
echo "Installing non-deployable configuration template to /etc/kelvin/worker.env.template..."
cp "$REPO_ROOT/deploy/systemd/worker.env.example" /etc/kelvin/worker.env.template
chown root:kelvin-worker /etc/kelvin/worker.env.template
chmod 0640 /etc/kelvin/worker.env.template

if [[ ! -f /etc/kelvin/worker.env ]]; then
  echo "ATTENTION: /etc/kelvin/worker.env does not yet exist."
  echo "To configure: copy /etc/kelvin/worker.env.template to /etc/kelvin/worker.env, populate verified credentials, and chmod 0600."
fi

# 10. Provision dedicated internal scanner network in rootless Podman
echo "Provisioning and validating internal scanner network (kelvin-scanner-net) as kelvin-worker..."
runuser -u kelvin-worker -- bash -c '
  set -euo pipefail
  export XDG_RUNTIME_DIR="/run/user/10001"
  NET_NAME="kelvin-scanner-net"
  REQ_INTERNAL="true"
  REQ_SUBNET="10.89.10.0/24"
  REQ_GATEWAY="10.89.10.1"

  inspect_and_validate_network() {
    local net_name="$1"
    local name internal subnets mismatches=()

    name="$(podman network inspect "$net_name" --format "{{.Name}}" 2>/dev/null || echo "")"
    internal="$(podman network inspect "$net_name" --format "{{.Internal}}" 2>/dev/null || echo "")"
    subnets="$(podman network inspect "$net_name" --format "{{range .Subnets}}{{.Subnet}} {{.Gateway}}{{end}}" 2>/dev/null || echo "")"

    if [[ "$name" != "$net_name" ]]; then
      mismatches+=("name=\x27$name\x27 (expected \x27$net_name\x27)")
    fi
    if [[ "$internal" != "$REQ_INTERNAL" ]]; then
      mismatches+=("internal=\x27$internal\x27 (expected \x27$REQ_INTERNAL\x27)")
    fi
    if ! echo "$subnets" | grep -qw "$REQ_SUBNET"; then
      mismatches+=("subnet missing \x27$REQ_SUBNET\x27 (got \x27$subnets\x27)")
    fi
    if ! echo "$subnets" | grep -qw "$REQ_GATEWAY"; then
      mismatches+=("gateway missing \x27$REQ_GATEWAY\x27 (got \x27$subnets\x27)")
    fi

    if [[ ${#mismatches[@]} -gt 0 ]]; then
      echo "${mismatches[*]}"
      return 1
    fi
    return 0
  }

  if podman network exists "$NET_NAME" 2>/dev/null; then
    echo "Network $NET_NAME exists. Inspecting all four properties..."
    if errs="$(inspect_and_validate_network "$NET_NAME")"; then
      echo "Network $NET_NAME verified untouched: internal=true, subnet=$REQ_SUBNET, gateway=$REQ_GATEWAY."
    else
      echo "ERROR: Network $NET_NAME exists but is misconfigured: $errs" >&2
      echo "ERROR: Automatic removal or recreation of existing network is strictly prohibited." >&2
      echo "Please resolve the network configuration manually." >&2
      exit 1
    fi
  else
    echo "Network $NET_NAME does not exist. Creating with internal=true, subnet=$REQ_SUBNET, gateway=$REQ_GATEWAY..."
    podman network create \
      --internal \
      --gateway "$REQ_GATEWAY" \
      --subnet "$REQ_SUBNET" \
      "$NET_NAME"

    echo "Verifying network configuration after creation..."
    if errs="$(inspect_and_validate_network "$NET_NAME")"; then
      echo "Network $NET_NAME created and verified successfully."
    else
      echo "ERROR: Network verification failed immediately after creation: $errs" >&2
      exit 1
    fi
  fi
'

# 11. Install systemd service unit
echo "Installing systemd service unit /etc/systemd/system/kelvin-worker.service..."
cp "$REPO_ROOT/deploy/systemd/kelvin-worker.service" /etc/systemd/system/kelvin-worker.service
chmod 0644 /etc/systemd/system/kelvin-worker.service
systemctl daemon-reload

echo "==> [Kelvin Setup] Host setup completed successfully."
echo "NOTE: Existing API, Caddy, and database services were untouched."
