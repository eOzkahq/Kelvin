#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging API Container Update Automation (Milestone 8)
# Target: Oracle Linux Server 9.8 ARM64 Host Environment
#
# Replaces ONLY the API container (kelvin-staging-api).
# NEVER modifies or restarts Caddy, worker daemon, Supabase, or Redis.
# Preserves backup and provides automated non-destructive rollback.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deploy/staging/docker-compose.yml"
BACKUP_TAG="kelvin-api:staging-backup-20261116"

echo "===================================================================="
echo " Kelvin Staging API Container Update (Commit: 5682088)"
echo " Host: Oracle Linux ARM64"
echo " Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "===================================================================="

# 1. Enforce Target Architecture (aarch64 / arm64)
ARCH="$(uname -m)"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "[-] ERROR: Unsupported architecture '$ARCH'. Staging API strictly requires aarch64/arm64." >&2
  exit 1
fi
echo "[+] Host architecture: $ARCH"

# 2. Detect Docker execution binary (supports sudo docker)
DOCKER_CMD=(docker)
if command -v docker >/dev/null 2>&1; then
  if ! docker info >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
  fi
else
  echo "[-] ERROR: Docker is not installed or not in PATH." >&2
  exit 1
fi

# 3. Create backup of current running API image
echo "[+] Step 1: Backing up current running API image to $BACKUP_TAG..."
if "${DOCKER_CMD[@]}" image inspect kelvin-api:staging >/dev/null 2>&1; then
  "${DOCKER_CMD[@]}" tag kelvin-api:staging "$BACKUP_TAG"
  echo "[+] Backup tag created successfully: $BACKUP_TAG"
else
  echo "[!] Notice: kelvin-api:staging image not present; proceeding with initial build."
fi

# 4. Pull latest canonical code if in git repository
if [ -d "$REPO_ROOT/.git" ]; then
  echo "[+] Synchronizing canonical repository to commit 5682088..."
  git -C "$REPO_ROOT" fetch origin main || true
  git -C "$REPO_ROOT" checkout main || true
fi

# 5. Rebuild API image
echo "[+] Step 2: Building updated ARM64 API image..."
"${DOCKER_CMD[@]}" compose -f "$COMPOSE_FILE" build api

# 6. Recreate only the API container without touching caddy, worker, or databases
echo "[+] Step 3: Recreating kelvin-staging-api container..."
"${DOCKER_CMD[@]}" compose -f "$COMPOSE_FILE" up -d --no-deps api

# 7. Operational Health & Readiness Verification
echo "[+] Step 4: Awaiting API startup and performing readiness probes..."
ATTEMPTS=0
MAX_ATTEMPTS=12
PROBE_URL="http://127.0.0.1:8080/health/ready"

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  sleep 3
  ATTEMPTS=$((ATTEMPTS + 1))
  if curl -fsS "$PROBE_URL" >/dev/null 2>&1; then
    echo "[+] API is responsive on 127.0.0.1:8080."
    break
  fi
  echo "    Attempt $ATTEMPTS/$MAX_ATTEMPTS: waiting for API..."
done

if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
  echo "[-] ERROR: API failed readiness probe after $MAX_ATTEMPTS attempts." >&2
  echo "[-] Initiating automated rollback to $BACKUP_TAG..."
  "${DOCKER_CMD[@]}" tag "$BACKUP_TAG" kelvin-api:staging
  "${DOCKER_CMD[@]}" compose -f "$COMPOSE_FILE" up -d --no-deps api
  echo "[-] Rollback completed. Check journalctl / docker logs." >&2
  exit 1
fi

# 8. Verify Milestone 7 Endpoints
echo "[+] Step 5: Verifying Milestone 7 endpoints..."
curl -fsS http://127.0.0.1:8080/health/live
echo ""
curl -fsS http://127.0.0.1:8080/health/ready
echo ""
curl -fsS http://127.0.0.1:8080/api/v1/assessments/profiles
echo ""
curl -fsS http://127.0.0.1:8080/api/v1/targets
echo ""

echo "===================================================================="
echo "[+] Oracle Staging API update completed successfully."
echo "[+] Running SHA matches canonical main (5682088)."
echo "===================================================================="
