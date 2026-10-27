#!/usr/bin/env bash
# ==============================================================================
# Kelvin Security Platform — Local Environment Reset Script (Linux / macOS)
# Stops local containers, removes data volumes, and re-provisions clean stack.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "=========================================================="
echo " [Kelvin] Resetting Local Development Environment Stack..."
echo "=========================================================="

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
  echo "Error: Docker daemon is not running. Please start Docker first." >&2
  exit 1
fi

echo "[1/4] Stopping and removing containers, networks, and volumes..."
docker compose down -v --remove-orphans

echo "[2/4] Ensuring .env file exists from .env.example..."
if [ ! -f ".env" ]; then
  echo "      Creating .env from .env.example"
  cp .env.example .env
fi

echo "[3/4] Starting fresh container stack..."
docker compose up -d --build

echo "[4/4] Awaiting container healthchecks..."
SERVICES=("postgres" "redis" "minio" "mock-target")
for SERVICE in "${SERVICES[@]}"; do
  echo "      Checking health of ${SERVICE}..."
  COUNT=0
  MAX_TRIES=30
  until [ "$(docker compose ps --format '{{.Health}}' "${SERVICE}" 2>/dev/null || true)" == "healthy" ]; do
    sleep 1
    COUNT=$((COUNT + 1))
    if [ ${COUNT} -ge ${MAX_TRIES} ]; then
      echo "Warning: Service ${SERVICE} did not report healthy within ${MAX_TRIES}s."
      break
    fi
  done
  echo "      -> ${SERVICE} is ready!"
done

echo ""
echo "=========================================================="
echo " [Kelvin] Local environment reset complete & clean!"
echo " - PostgreSQL:     localhost:5432 (database: kelvin_dev, auto-migrated)"
echo " - Redis:          localhost:6379"
echo " - MinIO S3:       localhost:9000 (Console: localhost:9001)"
echo " - Mock Lab:       http://localhost:8081 (safe test target)"
echo "=========================================================="

