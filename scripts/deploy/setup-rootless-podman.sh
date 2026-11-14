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
# Checks for subordinate range collisions across all existing users before appending.
echo "Configuring /etc/subuid and /etc/subgid for kelvin-worker..."
validate_or_add_subid() {
  local id_file="$1"
  local target_user="kelvin-worker"
  local target_start=100000
  local target_count=65536
  local target_end=$((target_start + target_count - 1)) # 165535
  local expected="$target_user:$target_start:$target_count"

  if [[ ! -f "$id_file" ]]; then
    touch "$id_file"
  fi

  # Check every existing line for range collisions
  while IFS=: read -r user start count extra || [[ -n "${user:-}" ]]; do
    user="$(echo "${user:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [[ -z "$user" || "$user" =~ ^# ]]; then
      continue
    fi
    start="$(echo "${start:-}" | tr -d ' ')"
    count="$(echo "${count:-}" | tr -d ' ')"

    if [[ "$start" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]]; then
      local other_end=$((start + count - 1))
      if [[ "$user" != "$target_user" ]]; then
        if (( start <= target_end && other_end >= target_start )); then
          echo "ERROR: Subordinate ID range collision in $id_file:" >&2
          echo "User '$user' has range $start:$count [$start-$other_end] which overlaps with required $target_user range $target_start:$target_count [$target_start-$target_end]." >&2
          echo "Aborting setup to prevent container user namespace collision." >&2
          exit 1
        fi
      fi
    fi
  done < "$id_file"

  # Validate kelvin-worker's own mapping
  local existing_lines
  existing_lines="$(grep "^${target_user}:" "$id_file" 2>/dev/null || true)"

  if [[ -z "$existing_lines" ]]; then
    echo "Adding '$expected' to $id_file..."
    echo "$expected" >> "$id_file"
  else
    local count_lines
    count_lines="$(echo "$existing_lines" | wc -l)"
    if [[ "$count_lines" -eq 1 && "$existing_lines" == "$expected" ]]; then
      echo "Verified existing subordinate ID mapping in $id_file ($expected)."
    else
      echo "ERROR: Conflicting subordinate ID configuration found in $id_file for $target_user." >&2
      echo "Found: '$existing_lines'" >&2
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
runuser -u kelvin-worker -- bash << 'EOF_RUNUSER'
  set -euo pipefail
  export XDG_RUNTIME_DIR="/run/user/10001"
  NET_NAME="kelvin-scanner-net"
  REQ_INTERNAL="true"
  REQ_SUBNET="10.89.10.0/24"
  REQ_GATEWAY="10.89.10.1"

  inspect_and_validate_network() {
    local net_name="$1"
    local raw_json
    if ! raw_json="$(podman network inspect "$net_name" 2>&1)"; then
      echo "INSPECT_FAILED: $raw_json"
      return 1
    fi

    if [[ -z "${raw_json//[[:space:]]/}" ]]; then
      echo "MALFORMED: Inspection output is empty"
      return 1
    fi

    # Structural validation via Python 3 if available, or structural Go template inspection
    if command -v python3 >/dev/null 2>&1; then
      python3 -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    if isinstance(data, list):
        if len(data) != 1:
            print(f"MALFORMED: expected 1 network record, found {len(data)}")
            sys.exit(1)
        net = data[0]
    elif isinstance(data, dict):
        net = data
    else:
        print("MALFORMED: unexpected root type")
        sys.exit(1)

    name = net.get("name") or net.get("Name")
    internal = net.get("internal")
    if internal is None:
        internal = net.get("Internal")
    subnets = net.get("subnets") or net.get("Subnets")

    mismatches = []
    if name != "kelvin-scanner-net":
        mismatches.append(f"name={name} (expected kelvin-scanner-net)")
    if internal is not True:
        mismatches.append(f"internal={internal} (expected true)")
    if subnets is None or not isinstance(subnets, list):
        mismatches.append("missing or invalid subnets list")
    elif len(subnets) != 1:
        mismatches.append(f"expected exactly 1 configured subnet, got {len(subnets)}")
    else:
        s0 = subnets[0]
        sub = s0.get("subnet") or s0.get("Subnet")
        gw = s0.get("gateway") or s0.get("Gateway")
        if sub != "10.89.10.0/24":
            mismatches.append(f"subnet={sub} (expected 10.89.10.0/24)")
        if gw != "10.89.10.1":
            mismatches.append(f"gateway={gw} (expected 10.89.10.1)")

    if mismatches:
        print("MISCONFIGURED: " + "; ".join(mismatches))
        sys.exit(1)
    print("OK")
    sys.exit(0)
except Exception as e:
    print(f"MALFORMED: {e}")
    sys.exit(1)
' <<< "$raw_json"
    else
      local name internal subnets_len sub0 gw0 mismatches=()
      name="$(podman network inspect "$net_name" --format "{{.Name}}" 2>/dev/null || echo "")"
      internal="$(podman network inspect "$net_name" --format "{{.Internal}}" 2>/dev/null || echo "")"
      subnets_len="$(podman network inspect "$net_name" --format "{{len .Subnets}}" 2>/dev/null || echo "0")"

      if [[ "$name" != "$net_name" ]]; then
        mismatches+=("name='$name' (expected '$net_name')")
      fi
      if [[ "$internal" != "$REQ_INTERNAL" ]]; then
        mismatches+=("internal='$internal' (expected '$REQ_INTERNAL')")
      fi
      if [[ "$subnets_len" != "1" ]]; then
        mismatches+=("expected exactly 1 configured subnet, got $subnets_len")
      else
        sub0="$(podman network inspect "$net_name" --format "{{(index .Subnets 0).Subnet}}" 2>/dev/null || echo "")"
        gw0="$(podman network inspect "$net_name" --format "{{(index .Subnets 0).Gateway}}" 2>/dev/null || echo "")"
        if [[ "$sub0" != "$REQ_SUBNET" ]]; then
          mismatches+=("subnet='$sub0' (expected '$REQ_SUBNET')")
        fi
        if [[ "$gw0" != "$REQ_GATEWAY" ]]; then
          mismatches+=("gateway='$gw0' (expected '$REQ_GATEWAY')")
        fi
      fi
      if [[ ${#mismatches[@]} -gt 0 ]]; then
        echo "MISCONFIGURED: ${mismatches[*]}"
        return 1
      fi
      echo "OK"
      return 0
    fi
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
EOF_RUNUSER

# 11. Install systemd service unit
echo "Installing systemd service unit /etc/systemd/system/kelvin-worker.service..."
cp "$REPO_ROOT/deploy/systemd/kelvin-worker.service" /etc/systemd/system/kelvin-worker.service
chmod 0644 /etc/systemd/system/kelvin-worker.service
systemctl daemon-reload

echo "==> [Kelvin Setup] Host setup completed successfully."
echo "NOTE: Existing API, Caddy, and database services were untouched."
