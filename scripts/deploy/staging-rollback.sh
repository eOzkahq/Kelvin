#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Rollback Automation (ADR-0008 Host Worker Architecture)
# Restores previous known-good host worker binary on deployment failure
# ==============================================================================
set -euo pipefail

BIN_DEST="/opt/kelvin/bin/kelvin-worker"
BIN_PREV="/opt/kelvin/bin/kelvin-worker.prev"

echo "==> [Kelvin Staging Rollback] Initiating host worker rollback..."

# 0. Preserve logs, audit records, reports, and evidence before touching service or containers
LOG_DIR="${KELVIN_LOG_DIR:-/var/log/kelvin}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ROLLBACK_ARCHIVE_DIR="$LOG_DIR/rollback-$TIMESTAMP"
mkdir -p "$ROLLBACK_ARCHIVE_DIR" 2>/dev/null || ROLLBACK_ARCHIVE_DIR="/tmp/kelvin-rollback-$TIMESTAMP"
mkdir -p "$ROLLBACK_ARCHIVE_DIR"

echo "Preserving systemd journal logs to $ROLLBACK_ARCHIVE_DIR/systemd-journal.log..."
journalctl -u kelvin-worker.service -n 500 --no-pager > "$ROLLBACK_ARCHIVE_DIR/systemd-journal.log" 2>/dev/null || true

echo "Preserving reports, evidence, and audit logs..."
if [[ -d "/var/lib/kelvin-worker/reports" || -d "/var/lib/kelvin-worker/evidence" ]]; then
  tar -czf "$ROLLBACK_ARCHIVE_DIR/reports-and-evidence.tar.gz" -C /var/lib/kelvin-worker reports evidence 2>/dev/null || true
fi

echo "Preserving container status and inspection logs..."
if command -v podman >/dev/null 2>&1; then
  PODMAN_USER_RUN=(podman)
  if [[ "$(id -u)" -eq 0 && -d "/run/user/10001" ]]; then
    PODMAN_USER_RUN=(sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman)
  fi
  "${PODMAN_USER_RUN[@]}" ps -a --format "{{.ID}} {{.Names}} {{.Image}} {{.Status}}" > "$ROLLBACK_ARCHIVE_DIR/containers.txt" 2>/dev/null || true
  for cid in $("${PODMAN_USER_RUN[@]}" ps -a -q 2>/dev/null || true); do
    "${PODMAN_USER_RUN[@]}" logs "$cid" > "$ROLLBACK_ARCHIVE_DIR/container-${cid}.log" 2>&1 || true
    "${PODMAN_USER_RUN[@]}" inspect "$cid" > "$ROLLBACK_ARCHIVE_DIR/container-${cid}-inspect.json" 2>&1 || true
  done
fi
echo "Audit evidence preserved in: $ROLLBACK_ARCHIVE_DIR"

# 1. Stop active worker service gracefully
echo "Stopping active kelvin-worker service..."
systemctl stop kelvin-worker.service || true

# Gracefully stop running scanner containers (do not blindly remove)
if command -v podman >/dev/null 2>&1; then
  PODMAN_USER_RUN=(podman)
  if [[ "$(id -u)" -eq 0 && -d "/run/user/10001" ]]; then
    PODMAN_USER_RUN=(sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman)
  fi
  RUNNING_CONTAINERS="$("${PODMAN_USER_RUN[@]}" ps -q 2>/dev/null || true)"
  if [[ -n "$RUNNING_CONTAINERS" ]]; then
    echo "Gracefully stopping active scanner containers..."
    "${PODMAN_USER_RUN[@]}" stop --time 10 $RUNNING_CONTAINERS 2>/dev/null || true
  fi
fi

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
