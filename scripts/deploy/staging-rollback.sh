#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Rollback Automation (ADR-0008 Host Worker Architecture)
# Restores previous known-good host worker binary on deployment failure
# ==============================================================================
set -euo pipefail

BIN_DEST="/opt/kelvin/bin/kelvin-worker"
BIN_PREV="/opt/kelvin/bin/kelvin-worker.prev"

echo "==> [Kelvin Staging Rollback] Initiating host worker rollback..."

# 1. Stop active worker service immediately to prevent uncertified scans
echo "Stopping active kelvin-worker service..."
systemctl stop kelvin-worker.service || true

# 2. Check if a previous known-good worker binary was preserved
if [[ -f "$BIN_PREV" ]]; then
  echo "Restoring previous known-good worker binary from $BIN_PREV..."
  cp -fp "$BIN_PREV" "$BIN_DEST"
  chmod 0755 "$BIN_DEST"
  
  echo "Restarting kelvin-worker service with restored binary..."
  systemctl start kelvin-worker.service
  
  sleep 2
  if systemctl is-active --quiet kelvin-worker.service; then
    echo "Restored worker service is ACTIVE and operational."
  else
    echo "ERROR: Restored worker failed to activate; inspect journalctl -u kelvin-worker -n 50" >&2
    exit 1
  fi
else
  echo "No previous worker binary found at $BIN_PREV."
  echo "Worker service has been stopped safely. No uncertified scans can execute."
fi

# 3. Verify API Gateway Stability Remains Intact
echo "Verifying API gateway operational status..."
if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
  echo "API Gateway remains operational and healthy."
else
  echo "WARNING: API Gateway not responding on loopback; inspect: docker compose logs api" >&2
fi

echo "==> [Kelvin Staging Rollback] Rollback procedure finished."
