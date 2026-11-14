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

ENV_FILE="/etc/kelvin/worker.env"

# 1. Host Environment & Runtime Validation
if [[ -f "$SCRIPT_DIR/validate-worker-host.sh" ]]; then
  echo "Executing host environment validation..."
  bash "$SCRIPT_DIR/validate-worker-host.sh"
else
  echo "ERROR: validate-worker-host.sh not found." >&2
  exit 1
fi

# 2. Validate Worker Environment File Ownership & Permissions
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Worker configuration $ENV_FILE does not exist. Create from deploy/systemd/worker.env.example." >&2
  exit 1
fi

PERMS="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || echo 'unknown')"
if [[ "$PERMS" != "600" && "$PERMS" != "400" ]]; then
  echo "ERROR: $ENV_FILE has unsafe permissions ($PERMS). Strictly require 0600 or 0400." >&2
  exit 1
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
  VAL="$(grep "^${var}=" "$ENV_FILE" | head -n 1 | cut -d'=' -f2- | tr -d '"'"'"')"
  if [[ -z "$VAL" ]]; then
    echo "ERROR: Mandatory configuration variable '$var' in $ENV_FILE is empty." >&2
    exit 1
  fi
done
echo "Verified all mandatory configuration variables in $ENV_FILE (secrets redacted)."

# 5. Validate Database CA Certificate Path directly from worker.env
CONFIGURED_CA="$(grep "^SUPABASE_CA_CERT_PATH=" "$ENV_FILE" | head -n 1 | cut -d'=' -f2- | tr -d '"'"'"')"
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

# 7. Build and Install Host Worker Binary
echo "==> Building host worker binary for ARM64..."
mkdir -p /opt/kelvin/bin
BIN_DEST="/opt/kelvin/bin/kelvin-worker"
BIN_NEW="/opt/kelvin/bin/kelvin-worker.new"
BIN_PREV="/opt/kelvin/bin/kelvin-worker.prev"

go -C "$REPO_ROOT" build -trimpath -ldflags="-s -w" -o "$BIN_NEW" ./apps/worker/cmd/runner

# 8. Preserve Previous Known-Good Binary for Genuine Rollback
if [[ -f "$BIN_DEST" ]]; then
  echo "Backing up active binary to $BIN_PREV for rollback safety..."
  cp -p "$BIN_DEST" "$BIN_PREV"
fi

mv -f "$BIN_NEW" "$BIN_DEST"
chmod 0755 "$BIN_DEST"
chown root:root "$BIN_DEST"
echo "Installed updated binary to $BIN_DEST"

# 9. Start / Restart Dedicated Host Worker Systemd Service ONLY
echo "==> Restarting kelvin-worker.service..."
systemctl restart kelvin-worker.service

# 10. Verify Worker Service Readiness
echo "Verifying kelvin-worker service state..."
sleep 2
if systemctl is-active --quiet kelvin-worker.service; then
  echo "Worker service is ACTIVE and operational."
else
  echo "ERROR: kelvin-worker.service failed to activate. Inspect logs: journalctl -u kelvin-worker -n 50" >&2
  exit 1
fi

# 11. Verify API Gateway Stability (Confirm Existing Control Plane Remains Operational)
echo "Verifying API Gateway operational stability..."
if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
  echo "API Gateway is operational and stable."
else
  echo "WARNING: Local API Gateway did not respond on 127.0.0.1:8080/healthz (check docker compose logs api)."
fi

echo "==> [Kelvin Staging Deploy] Host worker deployment completed successfully!"
