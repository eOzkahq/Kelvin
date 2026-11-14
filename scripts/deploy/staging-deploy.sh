#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Deployment Automation (EXEC-031)
# Targets Oracle Linux 9.8 ARM64 Host Environment
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> [Kelvin Staging Deploy] Validating environment and prerequisites..."

# 1. Architecture check
ARCH="$(uname -m)"
echo "Host architecture detected: $ARCH"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "WARNING: Target host architecture is $ARCH; staging certified for aarch64/arm64."
fi

# 2. Verify CA Certificate path exists if configured
if [[ -n "${SUPABASE_CA_CERT_PATH:-}" ]]; then
  if [[ ! -f "$SUPABASE_CA_CERT_PATH" ]]; then
    echo "ERROR: SUPABASE_CA_CERT_PATH is set to '$SUPABASE_CA_CERT_PATH' but file does not exist." >&2
    exit 1
  fi
  echo "CA certificate verified at $SUPABASE_CA_CERT_PATH"
fi

# 3. Verify release manifests
if [[ -f "$REPO_ROOT/deploy/scanners/images.lock.json" ]]; then
  echo "Authoritative release manifest found: deploy/scanners/images.lock.json"
fi

# 4. Record current worker state for rollback
CURRENT_WORKER_IMG="$(docker inspect --format='{{.Config.Image}}' kelvin-staging-worker 2>/dev/null || echo '')"
echo "Current running worker image: ${CURRENT_WORKER_IMG:-none}"
echo "$CURRENT_WORKER_IMG" > "$REPO_ROOT/artifacts/previous-worker-image.txt" 2>/dev/null || true

# 5. Start API service
echo "==> [Kelvin Staging Deploy] Starting Kelvin API Gateway..."
docker compose -f "$REPO_ROOT/deploy/staging/docker-compose.yml" up -d api

# Wait for API healthiness
echo "Waiting for API readiness (/healthz)..."
for i in {1..30}; do
  if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
    echo "API is healthy!"
    break
  fi
  sleep 2
  if [[ $i -eq 30 ]]; then
    echo "ERROR: API failed to reach healthy state within 60s" >&2
    exit 1
  fi
done

# 6. Start Worker service under explicit profile
echo "==> [Kelvin Staging Deploy] Starting Kelvin Scanner Execution Worker..."
docker compose -f "$REPO_ROOT/deploy/staging/docker-compose.yml" --profile worker up -d worker

echo "==> [Kelvin Staging Deploy] Deployment completed successfully!"
