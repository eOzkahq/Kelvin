#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Deployment Automation (ADR-0008 Host Worker Architecture)
# Targets: Oracle Linux Server 9.8 ARM64 Host Environment
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> [Kelvin Staging Deploy] Starting Host-Level Worker Deployment..."

# 1. Host Environment & Runtime Validation
if [[ -f "$SCRIPT_DIR/validate-worker-host.sh" ]]; then
  echo "Executing host environment validation..."
  bash "$SCRIPT_DIR/validate-worker-host.sh"
fi

# 2. Verify Database CA Certificate
CA_PATH="${SUPABASE_CA_CERT_PATH:-/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem}"
if [[ ! -f "$CA_PATH" ]]; then
  echo "ERROR: Database CA certificate not found at $CA_PATH" >&2
  exit 1
fi
echo "Verified CA certificate at $CA_PATH"

# 3. Verify Authoritative Release Manifest & Lock Consistency
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
    echo "NOTE: Scanner container images are currently 'not-released'. Worker will operate in fail-closed governance mode."
  fi
fi

# 4. Verify Worker Environment Configuration without Logging Secrets
ENV_FILE="/etc/kelvin/worker.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Worker configuration $ENV_FILE does not exist. Copy deploy/systemd/worker.env.example." >&2
  exit 1
fi

REQUIRED_VARS=("KELVIN_ENV" "KELVIN_WORKER_ID" "KELVIN_DATABASE_URL" "REDIS_TLS_ENABLED")
for var in "${REQUIRED_VARS[@]}"; do
  if ! grep -q "^${var}=" "$ENV_FILE"; then
    echo "ERROR: Mandatory configuration variable '$var' missing from $ENV_FILE" >&2
    exit 1
  fi
done
echo "Verified mandatory configuration variables in $ENV_FILE (secrets redacted)."

# 5. Build and Install Host Worker Binary
echo "==> Building host worker binary for ARM64..."
mkdir -p /opt/kelvin/bin
BIN_DEST="/opt/kelvin/bin/kelvin-worker"
BIN_NEW="/opt/kelvin/bin/kelvin-worker.new"
BIN_PREV="/opt/kelvin/bin/kelvin-worker.prev"

go -C "$REPO_ROOT" build -trimpath -ldflags="-s -w" -o "$BIN_NEW" ./apps/worker/cmd/runner

# 6. Preserve Previous Known-Good Binary for Genuine Rollback
if [[ -f "$BIN_DEST" ]]; then
  echo "Backing up active binary to $BIN_PREV for rollback safety..."
  cp -p "$BIN_DEST" "$BIN_PREV"
fi

mv -f "$BIN_NEW" "$BIN_DEST"
chmod 0755 "$BIN_DEST"
chown root:root "$BIN_DEST"
echo "Installed updated binary to $BIN_DEST"

# 7. Start / Restart Dedicated Host Worker Systemd Service
echo "==> Restarting kelvin-worker.service..."
systemctl restart kelvin-worker.service

# 8. Verify Worker Service Readiness
echo "Verifying kelvin-worker service state..."
sleep 2
if systemctl is-active --quiet kelvin-worker.service; then
  echo "Worker service is ACTIVE and healthy."
else
  echo "ERROR: kelvin-worker.service failed to activate. Inspect logs: journalctl -u kelvin-worker -n 50" >&2
  exit 1
fi

# 9. Verify API Gateway Stability (Preserve Existing Docker API)
echo "Verifying API Gateway operational stability..."
if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
  echo "API Gateway is healthy."
else
  echo "WARNING: Local API Gateway did not respond on 127.0.0.1:8080/healthz; check docker compose logs api."
fi

echo "==> [Kelvin Staging Deploy] Host worker deployment completed successfully!"
