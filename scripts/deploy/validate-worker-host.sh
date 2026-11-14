#!/usr/bin/env bash
# ==============================================================================
# Kelvin Host Worker Environment Validation Script
# Targets: Oracle Linux Server 9.8 (ARM64 / aarch64)
# Verifies all prerequisites mandated by ADR-0008 Option A
# ==============================================================================
set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

check_pass() {
  echo "  [PASS] $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

check_fail() {
  echo "  [FAIL] $1" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

check_warn() {
  echo "  [WARN] $1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

echo "=============================================================================="
echo "Kelvin Host Execution Worker Environment Audit (ADR-0008)"
echo "=============================================================================="

# 1. Operating System
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  echo "Operating System: $NAME $VERSION"
  if [[ "$ID" == "ol" || "$ID_LIKE" =~ "rhel" || "$ID_LIKE" =~ "fedora" ]]; then
    check_pass "Operating system is enterprise Linux 9 compatible ($PRETTY_NAME)"
  else
    check_warn "OS is $PRETTY_NAME; staging target is Oracle Linux 9.8"
  fi
else
  check_fail "/etc/os-release not found"
fi

# 2. CPU Architecture
ARCH="$(uname -m)"
echo "Architecture: $ARCH"
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  check_pass "CPU architecture is ARM64 ($ARCH)"
else
  check_warn "CPU architecture is $ARCH (staging certified for aarch64)"
fi

# 3. Kernel cgroups v2
if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  CONTROLLERS="$(cat /sys/fs/cgroup/cgroup.controllers)"
  echo "Available cgroup controllers: $CONTROLLERS"
  if echo "$CONTROLLERS" | grep -qw "cpu" && echo "$CONTROLLERS" | grep -qw "memory" && echo "$CONTROLLERS" | grep -qw "pids"; then
    check_pass "Cgroups v2 active with cpu, memory, and pids controllers"
  else
    check_fail "Cgroups v2 missing required controllers: $CONTROLLERS"
  fi
else
  check_fail "cgroups v2 not active (/sys/fs/cgroup/cgroup.controllers missing)"
fi

# 4. Dedicated Unprivileged Execution Identity
if id -u kelvin-worker >/dev/null 2>&1; then
  WORKER_UID="$(id -u kelvin-worker)"
  WORKER_GID="$(id -g kelvin-worker)"
  if [[ "$WORKER_UID" -eq 10001 && "$WORKER_GID" -eq 10001 ]]; then
    check_pass "User kelvin-worker exists with dedicated UID/GID 10001:10001"
  else
    check_fail "User kelvin-worker exists but UID:GID is $WORKER_UID:$WORKER_GID (expected 10001:10001)"
  fi
else
  check_fail "User kelvin-worker does not exist. Run scripts/deploy/setup-rootless-podman.sh."
fi

# 5. Subuid and Subgid Configuration
if [[ -f /etc/subuid ]] && grep -q "^kelvin-worker:" /etc/subuid; then
  check_pass "/etc/subuid configured for kelvin-worker: $(grep '^kelvin-worker:' /etc/subuid)"
else
  check_fail "/etc/subuid missing configuration for kelvin-worker"
fi

if [[ -f /etc/subgid ]] && grep -q "^kelvin-worker:" /etc/subgid; then
  check_pass "/etc/subgid configured for kelvin-worker: $(grep '^kelvin-worker:' /etc/subgid)"
else
  check_fail "/etc/subgid missing configuration for kelvin-worker"
fi

# 6. Systemd User Session Linger
if command -v loginctl >/dev/null 2>&1; then
  LINGER_STATUS="$(loginctl show-user kelvin-worker --property=Linger 2>/dev/null || echo 'Linger=no')"
  if [[ "$LINGER_STATUS" == "Linger=yes" ]]; then
    check_pass "Systemd linger is enabled for kelvin-worker ($LINGER_STATUS)"
  else
    check_fail "Systemd linger not enabled for kelvin-worker ($LINGER_STATUS). Run: loginctl enable-linger kelvin-worker"
  fi
else
  check_warn "loginctl not available to verify user linger"
fi

# 7. Podman Executable & crun Runtime
if command -v podman >/dev/null 2>&1; then
  PODMAN_BIN="$(command -v podman)"
  PODMAN_VER="$(podman --version 2>/dev/null || echo 'unknown')"
  check_pass "Podman available: $PODMAN_BIN ($PODMAN_VER)"
else
  check_fail "Podman binary not found in PATH"
fi

if command -v crun >/dev/null 2>&1; then
  CRUN_BIN="$(command -v crun)"
  CRUN_VER="$(crun --version 2>/dev/null | head -n 1 || echo 'unknown')"
  check_pass "crun runtime available: $CRUN_BIN ($CRUN_VER)"
else
  check_warn "crun binary not found in PATH (ensure default OCI runtime is crun)"
fi

# 8. Internal Scanner Network (kelvin-scanner-net)
NETWORK_CHECK_CMD='
  export XDG_RUNTIME_DIR="/run/user/10001"
  if podman network inspect kelvin-scanner-net >/dev/null 2>&1; then
    IS_INTERNAL="$(podman network inspect kelvin-scanner-net --format "{{.Internal}}" 2>/dev/null || echo "false")"
    if [[ "$IS_INTERNAL" == "true" ]]; then
      echo "NET_INTERNAL_OK"
    else
      echo "NET_EXISTS_NOT_INTERNAL"
    fi
  else
    echo "NET_NOT_FOUND"
  fi
'

if id -u kelvin-worker >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
  if [[ "$(id -u)" -eq 0 ]]; then
    NET_RESULT="$(runuser -u kelvin-worker -- bash -c "$NETWORK_CHECK_CMD" 2>/dev/null || echo "NET_CHECK_ERROR")"
  elif [[ "$(id -u)" -eq 10001 ]]; then
    NET_RESULT="$(eval "$NETWORK_CHECK_CMD")"
  else
    NET_RESULT="CANNOT_RUN_AS_WORKER"
  fi

  case "$NET_RESULT" in
    "NET_INTERNAL_OK")
      check_pass "Internal scanner network kelvin-scanner-net exists with internal=true"
      ;;
    "NET_EXISTS_NOT_INTERNAL")
      check_fail "Network kelvin-scanner-net exists but is NOT configured with internal=true"
      ;;
    "NET_NOT_FOUND")
      check_fail "Network kelvin-scanner-net not found. Run scripts/deploy/setup-rootless-podman.sh."
      ;;
    *)
      check_warn "Unable to verify kelvin-scanner-net directly ($NET_RESULT)"
      ;;
  esac
fi

# 9. Database CA Certificate
CA_PATH="${SUPABASE_CA_CERT_PATH:-/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem}"
if [[ -f "$CA_PATH" && -r "$CA_PATH" ]]; then
  check_pass "Database CA certificate verified and readable at $CA_PATH"
else
  check_fail "Database CA certificate missing or unreadable at $CA_PATH"
fi

# 10. Worker Environment File Permissions
if [[ -f /etc/kelvin/worker.env ]]; then
  PERMS="$(stat -c '%a' /etc/kelvin/worker.env 2>/dev/null || stat -f '%Lp' /etc/kelvin/worker.env 2>/dev/null || echo 'unknown')"
  if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
    check_pass "Worker configuration /etc/kelvin/worker.env has strict permissions ($PERMS)"
  else
    check_warn "Worker configuration /etc/kelvin/worker.env has permissions $PERMS (recommend 0600)"
  fi
else
  check_warn "/etc/kelvin/worker.env does not yet exist. Copy deploy/systemd/worker.env.example."
fi

# 11. Systemd Service Unit File
if [[ -f /etc/systemd/system/kelvin-worker.service ]]; then
  check_pass "Systemd service unit installed at /etc/systemd/system/kelvin-worker.service"
else
  check_fail "Systemd service unit not installed at /etc/systemd/system/kelvin-worker.service"
fi

echo "------------------------------------------------------------------------------"
echo "Host Audit Summary: $PASS_COUNT PASSED, $FAIL_COUNT FAILED, $WARN_COUNT WARNINGS"
echo "------------------------------------------------------------------------------"

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo "ERROR: Host audit failed with $FAIL_COUNT errors. Remediate issues before deployment." >&2
  exit 1
fi

echo "Host environment validation successful!"
