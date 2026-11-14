#!/usr/bin/env bash
# ==============================================================================
# Kelvin Rootless Podman & Host Worker Setup Script
# Targets: Oracle Linux Server 9.8 (ARM64 / aarch64)
# Implements: ADR-0008 Option A (Dedicated Unprivileged Host Worker)
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

# 2. Verify Architecture
ARCH="$(uname -m)"
echo "Host architecture detected: $ARCH"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "WARNING: Host architecture is $ARCH. Production staging is certified for aarch64/arm64."
fi

# 3. Verify cgroups v2
if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "ERROR: cgroups v2 is required by ADR-0008 but not enabled on this system." >&2
  exit 1
fi
echo "Verified cgroups v2 enabled."

# 4. Verify Podman and crun installation
if ! command -v podman >/dev/null 2>&1; then
  echo "ERROR: podman is not installed. Install via: dnf install -y podman crun" >&2
  exit 1
fi
if ! command -v crun >/dev/null 2>&1; then
  echo "WARNING: crun not found in PATH. Ensure crun is installed for optimal cgroups v2 performance."
fi

# 5. Create unprivileged group and user kelvin-worker (UID/GID 10001)
if ! getent group kelvin-worker >/dev/null 2>&1; then
  echo "Creating group kelvin-worker (GID 10001)..."
  groupadd -g 10001 kelvin-worker
else
  echo "Group kelvin-worker already exists."
fi

if ! id -u kelvin-worker >/dev/null 2>&1; then
  echo "Creating user kelvin-worker (UID 10001)..."
  useradd -u 10001 -g 10001 -m -d /var/lib/kelvin-worker -s /bin/bash kelvin-worker
else
  echo "User kelvin-worker already exists."
fi

# 6. Configure subuid and subgid for rootless container user namespaces
echo "Configuring /etc/subuid and /etc/subgid for kelvin-worker..."
if ! grep -q "^kelvin-worker:" /etc/subuid 2>/dev/null; then
  echo "kelvin-worker:100000:65536" >> /etc/subuid
fi
if ! grep -q "^kelvin-worker:" /etc/subgid 2>/dev/null; then
  echo "kelvin-worker:100000:65536" >> /etc/subgid
fi

# 7. Enable systemd user session lingering
echo "Enabling systemd linger for kelvin-worker..."
loginctl enable-linger kelvin-worker

# 8. Create standard directories with hardened permissions
echo "Creating Kelvin host directories..."
mkdir -p /opt/kelvin/bin
mkdir -p /var/lib/kelvin-worker
mkdir -p /var/log/kelvin
mkdir -p /etc/kelvin

chown -R root:root /opt/kelvin/bin
chmod 0755 /opt/kelvin/bin

chown -R kelvin-worker:kelvin-worker /var/lib/kelvin-worker
chmod 0750 /var/lib/kelvin-worker

chown -R kelvin-worker:kelvin-worker /var/log/kelvin
chmod 0755 /var/log/kelvin

chown root:kelvin-worker /etc/kelvin
chmod 0750 /etc/kelvin

# 9. Install worker environment template if not present
if [[ ! -f /etc/kelvin/worker.env ]]; then
  echo "Installing default /etc/kelvin/worker.env from template..."
  cp "$REPO_ROOT/deploy/systemd/worker.env.example" /etc/kelvin/worker.env
  chown kelvin-worker:kelvin-worker /etc/kelvin/worker.env
  chmod 0600 /etc/kelvin/worker.env
  echo "NOTE: Configure /etc/kelvin/worker.env with real credentials before starting worker."
fi

# 10. Provision dedicated internal scanner network in rootless Podman
echo "Provisioning internal scanner network (kelvin-scanner-net) as kelvin-worker..."
runuser -u kelvin-worker -- bash -c '
  export XDG_RUNTIME_DIR="/run/user/10001"
  if ! podman network exists kelvin-scanner-net 2>/dev/null; then
    podman network create --internal --gateway 10.89.10.1 --subnet 10.89.10.0/24 kelvin-scanner-net
    echo "Created internal network kelvin-scanner-net."
  else
    echo "Network kelvin-scanner-net already exists."
  fi
'

# 11. Install systemd service unit
echo "Installing systemd service unit /etc/systemd/system/kelvin-worker.service..."
cp "$REPO_ROOT/deploy/systemd/kelvin-worker.service" /etc/systemd/system/kelvin-worker.service
chmod 0644 /etc/systemd/system/kelvin-worker.service
systemctl daemon-reload

echo "==> [Kelvin Setup] Rootless Podman and Host Worker configuration completed successfully!"
echo "Next step: populate /etc/kelvin/worker.env and execute 'scripts/deploy/staging-deploy.sh'."
