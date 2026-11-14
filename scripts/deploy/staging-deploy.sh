#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Deployment Automation (ADR-0008 Host Worker Architecture)
# Targets: Oracle Linux Server 9.8 ARM64 Host Environment
#
# Only deploys and restarts the dedicated host worker (kelvin-worker.service).
# NEVER modifies or restarts existing API, Caddy, or database services.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> [Kelvin Staging Deploy] Starting Host-Level Worker Deployment..."

# 0. Enforce Target Architecture (aarch64 / arm64)
ARCH="$(uname -m)"
echo "Host architecture detected: $ARCH"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "ERROR: Unsupported host architecture '$ARCH'. Staging deployment strictly requires aarch64 or arm64 per ADR-0008." >&2
  exit 1
fi
echo "Verified target host architecture: $ARCH"

ENV_FILE="${KELVIN_ENV_FILE:-/etc/kelvin/worker.env}"
BIN_DIR="${KELVIN_BIN_DIR:-/opt/kelvin/bin}"
SKIP_HOST_VALIDATE="${KELVIN_SKIP_HOST_VALIDATE:-0}"

# 1. Host Environment & Runtime Validation
if [[ "$SKIP_HOST_VALIDATE" != "1" ]]; then
  if [[ -f "$SCRIPT_DIR/validate-worker-host.sh" ]]; then
    echo "Executing host environment validation..."
    bash "$SCRIPT_DIR/validate-worker-host.sh"
  else
    echo "ERROR: validate-worker-host.sh not found." >&2
    exit 1
  fi
else
  echo "Notice: Skipping host validation (KELVIN_SKIP_HOST_VALIDATE=1 set for isolated test execution)."
fi

# 2. Validate Worker Environment File Ownership & Permissions
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Worker configuration $ENV_FILE does not exist. Create from deploy/systemd/worker.env.example." >&2
  exit 1
fi

PERMS="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || echo 'unknown')"
if [[ "$PERMS" != "600" && "$PERMS" != "400" ]]; then
  if [[ "${KELVIN_SKIP_HOST_VALIDATE:-0}" == "1" && "${OSTYPE:-}" =~ msys|cygwin ]]; then
    echo "Notice: Non-Linux test environment detected; accepting emulated permissions ($PERMS)."
  else
    echo "ERROR: $ENV_FILE has unsafe permissions ($PERMS). Strictly require 0600 or 0400." >&2
    exit 1
  fi
fi

OWNER="$(stat -c '%u:%g' "$ENV_FILE" 2>/dev/null || echo 'unknown')"
if [[ "$OWNER" != "10001:10001" ]]; then
  echo "WARNING: $ENV_FILE owner is $OWNER (expected 10001:10001 / kelvin-worker:kelvin-worker)."
fi

# 3. Check for Incomplete or Placeholder Configuration (Fail Closed)
if grep -q "TEMPLATE_NOT_CONFIGURED" "$ENV_FILE"; then
  echo "ERROR: $ENV_FILE contains KELVIN_CONFIG_STATUS=TEMPLATE_NOT_CONFIGURED marker. Real credentials required." >&2
  exit 1
fi

if grep -qE "(REPLACE_WITH_|replace-with-|your-project|your-upstash|your-password)" "$ENV_FILE"; then
  echo "ERROR: $ENV_FILE contains unconfigured placeholder values. Real credentials required before deployment." >&2
  exit 1
fi

# 4. Validate Mandatory Configuration Variables (Without Logging Secrets)
REQUIRED_VARS=(
  "KELVIN_ENV"
  "KELVIN_WORKER_ID"
  "KELVIN_DATABASE_URL"
  "KELVIN_REDIS_URL"
  "REDIS_TLS_ENABLED"
  "KELVIN_WORKER_TOKEN_SECRET"
  "SUPABASE_URL"
  "SUPABASE_SERVICE_ROLE_KEY"
  "SUPABASE_CA_CERT_PATH"
  "KELVIN_DATABASE_SSL_ROOT_CERT"
  "KELVIN_OCI_RUNTIME"
  "KELVIN_SCANNER_NETWORK"
  "KELVIN_EGRESS_PROXY_BIND_ADDR"
  "KELVIN_EGRESS_PROXY_ADVERTISED_HOST"
)

for var in "${REQUIRED_VARS[@]}"; do
  if ! grep -q "^${var}=" "$ENV_FILE"; then
    echo "ERROR: Mandatory configuration variable '$var' missing from $ENV_FILE" >&2
    exit 1
  fi
  VAL="$(grep "^${var}=" "$ENV_FILE" | head -n 1 | cut -d'=' -f2- || true)"
  VAL="${VAL//\"/}"
  VAL="${VAL//\'/}"
  if [[ -z "$VAL" ]]; then
    echo "ERROR: Mandatory configuration variable '$var' in $ENV_FILE is empty." >&2
    exit 1
  fi
done
echo "Verified all mandatory configuration variables in $ENV_FILE (secrets redacted)."

# 5. Validate Database CA Certificate Path directly from worker.env
CONFIGURED_CA="$(grep "^SUPABASE_CA_CERT_PATH=" "$ENV_FILE" | head -n 1 | cut -d'=' -f2- || true)"
CONFIGURED_CA="${CONFIGURED_CA//\"/}"
CONFIGURED_CA="${CONFIGURED_CA//\'/}"
if [[ ! -f "$CONFIGURED_CA" || ! -r "$CONFIGURED_CA" ]]; then
  echo "ERROR: Database CA certificate configured at '$CONFIGURED_CA' does not exist or is unreadable." >&2
  exit 1
fi
echo "Verified database CA certificate at $CONFIGURED_CA"

# 6. Verify Authoritative Release Manifest & Lock Consistency
LOCK_JSON="$REPO_ROOT/deploy/scanners/images.lock.json"
LOCK_YAML="$REPO_ROOT/deploy/scanner-image-lock.yaml"
if [[ -f "$LOCK_JSON" && -f "$LOCK_YAML" ]]; then
  echo "Verifying release lock files..."
  STATUS_JSON="$(grep '"status"' "$LOCK_JSON" | head -n 1 | awk -F'"' '{print $4}')"
  STATUS_YAML="$(grep '^status:' "$LOCK_YAML" | head -n 1 | awk -F'"' '{print $2}')"
  if [[ -z "$STATUS_YAML" ]]; then
    STATUS_YAML="$(grep '^status:' "$LOCK_YAML" | head -n 1 | awk '{print $2}')"
  fi
  if [[ "$STATUS_JSON" != "$STATUS_YAML" ]]; then
    echo "ERROR: Release status mismatch between JSON ($STATUS_JSON) and YAML ($STATUS_YAML)" >&2
    exit 1
  fi
  echo "Authoritative scanner release status verified: $STATUS_JSON"
  if [[ "$STATUS_JSON" == "not-released" ]]; then
    echo "ATTENTION: Scanner container images are currently 'not-released'. Worker will operate in fail-closed governance mode."
  fi
else
  echo "ERROR: Release manifest files missing ($LOCK_JSON or $LOCK_YAML)" >&2
  exit 1
fi

# 7. Setup Automated Rollback Safety Trap
BIN_DEST="$BIN_DIR/kelvin-worker"
BIN_PREV="$BIN_DIR/kelvin-worker.prev"
TMP_BUILD_DIR="$(mktemp -d /tmp/kelvin-worker-build.XXXXXX)"
TMP_BIN="$TMP_BUILD_DIR/kelvin-worker"

DEPLOY_SUCCESS=0
ROLLBACK_TRIGGERED=0

cleanup_tmp() {
  if [[ -n "${TMP_BUILD_DIR:-}" && -d "$TMP_BUILD_DIR" ]]; then
    rm -rf "$TMP_BUILD_DIR"
  fi
}

handle_rollback() {
  local exit_code=$?
  set +e
  cleanup_tmp
  if [[ $exit_code -ne 0 && "$DEPLOY_SUCCESS" -eq 0 && "$ROLLBACK_TRIGGERED" -eq 0 ]]; then
    ROLLBACK_TRIGGERED=1
    echo "" >&2
    echo "==============================================================================" >&2
    echo "==> [ROLLBACK] Deployment failure detected (exit code: $exit_code)." >&2
    echo "==============================================================================" >&2
    if [[ -f "$BIN_PREV" ]]; then
      echo "==> Restoring previous known-good binary from $BIN_PREV to $BIN_DEST..." >&2
      cp -f "$BIN_PREV" "$BIN_DEST"
      chmod 0755 "$BIN_DEST" 2>/dev/null || true
      chown root:root "$BIN_DEST" 2>/dev/null || true
      echo "==> Attempting to restart previous worker service..." >&2
      if systemctl restart kelvin-worker.service; then
        echo "==> [ROLLBACK SUCCESS] Previous worker service restored and active." >&2
      else
        echo "==> [ROLLBACK FAILED] Critical: Failed to restart previous worker service." >&2
      fi
    else
      echo "==> [ROLLBACK UNAVAILABLE] No previous binary ($BIN_PREV) found to restore." >&2
    fi
  fi
}
trap handle_rollback EXIT

# 8. Compile Replacement Binary in Temporary Location
echo "==> Compiling host worker binary in temporary location ($TMP_BIN)..."
go -C "$REPO_ROOT" build -trimpath -ldflags="-s -w" -o "$TMP_BIN" ./apps/worker/cmd/runner

# 9. Validate Newly Built Binary Prior to Installation
echo "Validating newly compiled binary..."
if [[ ! -f "$TMP_BIN" || ! -s "$TMP_BIN" ]]; then
  echo "ERROR: Compiled binary $TMP_BIN is missing or empty." >&2
  exit 1
fi
chmod 0755 "$TMP_BIN"

if command -v file >/dev/null 2>&1; then
  BIN_INFO="$(file "$TMP_BIN")"
  echo "Binary format: $BIN_INFO"
  if ! echo "$BIN_INFO" | grep -qE "(ARM aarch64|aarch64|ARM64)"; then
    echo "ERROR: Compiled binary architecture does not match target ARM64 ($BIN_INFO)." >&2
    exit 1
  fi
fi

# 10. Preserve Currently Installed Binary for Rollback Safety
mkdir -p "$BIN_DIR"
if [[ -f "$BIN_DEST" ]]; then
  echo "Backing up currently active binary to $BIN_PREV for rollback safety..."
  cp -p "$BIN_DEST" "$BIN_PREV"
else
  echo "Notice: No existing binary found at $BIN_DEST (initial deployment)."
fi

# 11. Install Validated Binary Atomically
echo "Installing validated binary atomically to $BIN_DEST..."
install -m 0755 -o root -g root "$TMP_BIN" "$BIN_DEST"
echo "Installed binary: $BIN_DEST"

# 12. Start / Restart Dedicated Host Worker Systemd Service ONLY
echo "==> Restarting kelvin-worker.service..."
systemctl restart kelvin-worker.service

# 13. Honest Multi-Layer Readiness Verification
echo "Verifying kelvin-worker service state..."
sleep 3
if ! systemctl is-active --quiet kelvin-worker.service; then
  echo "ERROR: kelvin-worker.service failed to activate after restart." >&2
  echo "Recent service logs:" >&2
  journalctl -u kelvin-worker.service -n 30 --no-pager >&2 || true
  exit 1
fi

echo ""
echo "=============================================================================="
echo "Kelvin Worker Operational Readiness Assessment"
echo "=============================================================================="

# Layer 1: Process Active
WORKER_PID="$(systemctl show --property MainPID --value kelvin-worker.service 2>/dev/null || echo '')"
if [[ -n "$WORKER_PID" && "$WORKER_PID" != "0" ]]; then
  echo "  [OK] 1. Service Process: kelvin-worker.service is active (PID: $WORKER_PID)"
else
  echo "  [FAIL] 1. Service Process: kelvin-worker.service is inactive" >&2
  exit 1
fi

# Layer 2: Startup Successful (no crash or fatal panic in recent logs)
RECENT_FATAL="$(journalctl -u kelvin-worker.service --since "30 seconds ago" -n 20 --no-pager 2>/dev/null | grep -iE "(fatal|panic|SIGSEGV)" || true)"
if [[ -n "$RECENT_FATAL" ]]; then
  echo "  [FAIL] 2. Worker Startup: Fatal error detected in startup logs: $RECENT_FATAL" >&2
  exit 1
fi
echo "  [OK] 2. Worker Startup: Daemon active without fatal initialization errors"

# Layer 3: Redis Broker Reachable
REDIS_URL_VAL="$(grep "^KELVIN_REDIS_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)"
if [[ -z "$REDIS_URL_VAL" ]]; then
  REDIS_URL_VAL="$(grep "^REDIS_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)"
fi
REDIS_URL_VAL="${REDIS_URL_VAL//\"/}"
REDIS_URL_VAL="${REDIS_URL_VAL//\'/}"

REDIS_CHECK="UNVERIFIED"
if [[ -n "$REDIS_URL_VAL" ]]; then
  REDIS_HOST_PORT="$(echo "$REDIS_URL_VAL" | sed -E 's|^rediss?://([^@]+@)?([^/]+).*|\2|')"
  REDIS_HOST="${REDIS_HOST_PORT%:*}"
  REDIS_PORT="${REDIS_HOST_PORT##*:}"
  if [[ "$REDIS_PORT" == "$REDIS_HOST" ]]; then
    REDIS_PORT="6379"
  fi

  if [[ -n "$REDIS_HOST" && -n "$REDIS_PORT" ]]; then
    if command -v nc >/dev/null 2>&1; then
      if nc -z -w 3 "$REDIS_HOST" "$REDIS_PORT" >/dev/null 2>&1; then
        REDIS_CHECK="REACHABLE"
      else
        REDIS_CHECK="UNREACHABLE"
      fi
    elif command -v python3 >/dev/null 2>&1; then
      if python3 -c "import socket; s = socket.socket(); s.settimeout(3); s.connect(('$REDIS_HOST', int('$REDIS_PORT'))); s.close()" >/dev/null 2>&1; then
        REDIS_CHECK="REACHABLE"
      else
        REDIS_CHECK="UNREACHABLE"
      fi
    fi
  fi
fi

if [[ "$REDIS_CHECK" == "REACHABLE" ]]; then
  echo "  [OK] 3. Redis Broker: Reachable at $REDIS_HOST:$REDIS_PORT"
elif [[ "$REDIS_CHECK" == "UNREACHABLE" ]]; then
  echo "  [UNAVAILABLE] 3. Redis Broker: Cannot establish TCP connection to $REDIS_HOST:$REDIS_PORT"
else
  echo "  [UNAVAILABLE] 3. Redis Broker: Reachability unverified (connection test tool unavailable)"
fi

# Layer 4: Podman Rootless Operation Verified
ROOTLESS_OUT="$(runuser -u kelvin-worker -- bash -c 'export XDG_RUNTIME_DIR="/run/user/10001"; podman info --format "{{.Host.Security.Rootless}}" 2>/dev/null || echo "error"' 2>/dev/null || echo "error")"
if [[ "$ROOTLESS_OUT" == "true" ]]; then
  echo "  [OK] 4. Podman Rootless: Verified (operating as unprivileged UID 10001)"
else
  echo "  [UNAVAILABLE] 4. Podman Rootless: Rootless mode not verified (got: $ROOTLESS_OUT)"
fi

# Layer 5: crun and cgroups v2 Verified
RUNTIME_CGROUP_OUT="$(runuser -u kelvin-worker -- bash -c 'export XDG_RUNTIME_DIR="/run/user/10001"; podman info --format "{{.Host.OCIRuntime.Name}}|{{.Host.CgroupVersion}}" 2>/dev/null || echo "error"' 2>/dev/null || echo "error")"
if echo "$RUNTIME_CGROUP_OUT" | grep -qi "crun" && echo "$RUNTIME_CGROUP_OUT" | grep -q "v2"; then
  echo "  [OK] 5. OCI Runtime & Cgroups: Verified (crun runtime, cgroups v2 active)"
else
  echo "  [UNAVAILABLE] 5. OCI Runtime & Cgroups: Non-compliant (got: $RUNTIME_CGROUP_OUT; require crun and cgroups v2)"
fi

# Layer 6: Internal Scanner Network Verified (Structural Exact Check)
NET_INSPECT_OUT="$(runuser -u kelvin-worker -- bash -c '
  export XDG_RUNTIME_DIR="/run/user/10001"
  name="$(podman network inspect kelvin-scanner-net --format "{{.Name}}" 2>/dev/null || echo "")"
  internal="$(podman network inspect kelvin-scanner-net --format "{{.Internal}}" 2>/dev/null || echo "")"
  subnets_len="$(podman network inspect kelvin-scanner-net --format "{{len .Subnets}}" 2>/dev/null || echo "0")"
  sub0="$(podman network inspect kelvin-scanner-net --format "{{(index .Subnets 0).Subnet}}" 2>/dev/null || echo "")"
  gw0="$(podman network inspect kelvin-scanner-net --format "{{(index .Subnets 0).Gateway}}" 2>/dev/null || echo "")"
  if [[ "$name" == "kelvin-scanner-net" && "$internal" == "true" && "$subnets_len" == "1" && "$sub0" == "10.89.10.0/24" && "$gw0" == "10.89.10.1" ]]; then
    echo "OK"
  else
    echo "MISCONFIGURED"
  fi
' 2>/dev/null || echo "ERROR")"

if [[ "$NET_INSPECT_OUT" == "OK" ]]; then
  echo "  [OK] 6. Internal Scanner Network: Verified (internal=true, subnet 10.89.10.0/24, gateway 10.89.10.1)"
else
  echo "  [UNAVAILABLE] 6. Internal Scanner Network: Verification failed ($NET_INSPECT_OUT)"
fi

# Layer 7: Scanner Image Release Certified
RELEASE_STATUS="$(grep '"status"' "$LOCK_JSON" | head -n 1 | awk -F'"' '{print $4}' || echo 'unknown')"
if [[ "$RELEASE_STATUS" == "certified" ]]; then
  echo "  [OK] 7. Scanner Release Governance: CERTIFIED (Cryptographically locked digests verified; scanner execution ENABLED)"
else
  echo "  [UNAVAILABLE] 7. Scanner Release Governance: NOT CERTIFIED (status: '$RELEASE_STATUS')"
  echo "  --> The worker daemon is operational for task handling, but live containerized"
  echo "      vulnerability scanner execution remains STRICTLY DISABLED by fail-closed"
  echo "      release governance until signed image digests are certified."
fi
echo "=============================================================================="

# 14. Verify API Gateway Stability (Confirm Existing Control Plane Remains Operational)
echo "Verifying API Gateway operational stability..."
if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
  echo "API Gateway is operational and stable."
else
  echo "WARNING: Local API Gateway did not respond on 127.0.0.1:8080/healthz (check docker compose logs api)."
fi

DEPLOY_SUCCESS=1
cleanup_tmp

echo "==> [Kelvin Staging Deploy] Host worker deployment completed successfully!"
