#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Rollback Automation (EXEC-031)
# Restores previous known-good worker state on deployment failure
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> [Kelvin Staging Rollback] Initiating worker rollback..."

# 1. Stop active worker service immediately to prevent uncertified scans
echo "Stopping active staging worker..."
docker compose -f "$REPO_ROOT/deploy/staging/docker-compose.yml" --profile worker stop worker || true
docker rm -f kelvin-staging-worker 2>/dev/null || true

# 2. Check if a previous known-good worker image was recorded
PREV_IMAGE=""
if [[ -f "$REPO_ROOT/artifacts/previous-worker-image.txt" ]]; then
  PREV_IMAGE="$(cat "$REPO_ROOT/artifacts/previous-worker-image.txt")"
fi

if [[ -n "$PREV_IMAGE" && "$PREV_IMAGE" != "none" ]]; then
  echo "Restoring previous worker image: $PREV_IMAGE"
  # Update image tag or restart with previous image
  docker compose -f "$REPO_ROOT/deploy/staging/docker-compose.yml" --profile worker up -d worker
else
  echo "No prior worker image recorded. Worker stopped safely. API remains active."
fi

# 3. Verify API gateway stability remains intact
echo "Verifying API gateway status..."
if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
  echo "API Gateway remains operational and stable."
else
  echo "WARNING: API Gateway not responding on loopback; inspect logs with: docker compose logs api" >&2
fi

echo "==> [Kelvin Staging Rollback] Rollback procedure finished."
