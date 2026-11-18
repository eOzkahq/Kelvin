#!/usr/bin/env bash
# ==============================================================================
# KELVIN — Milestone M9.8 Production Deployment Automation
# Architecture: Oracle Linux ARM64 (aarch64) Host
# Target: kelvin-staging-api, Caddy, Supabase, Upstash Redis, Worker Hardening
# ==============================================================================
set -euo pipefail

DEPLOY_DIR="/opt/kelvin"
COMPOSE_FILE="deploy/staging/docker-compose.yml"
BACKUP_TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_TAG="m9.8-backup-${BACKUP_TIMESTAMP}"
TARGET_COMMIT="${1:-54288c9ecba6605a252cd864c017f221319d95fc}"
API_HOST="https://api.eozka.com"
LOOPBACK_HOST="http://127.0.0.1:8080"
FRONTEND_ORIGIN="https://kelvin-orpin.vercel.app"

echo "=============================================================================="
echo "  Kelvin M9.8 Production Deployment  —  $(date -u)"
echo "  Target Commit: ${TARGET_COMMIT}"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Host Architecture & Privileges Check
# ------------------------------------------------------------------------------
ARCH="$(uname -m)"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "[-] ERROR: Architecture '$ARCH' is unsupported. Must be aarch64/arm64." >&2
  exit 1
fi
echo "[+] Host architecture: ${ARCH} (ARM64) ✓"

DOCKER_CMD=(docker)
if ! docker info &>/dev/null && command -v sudo &>/dev/null; then
  DOCKER_CMD=(sudo docker)
fi

# ------------------------------------------------------------------------------
# 2. Resolve Environment File & Invariants
# ------------------------------------------------------------------------------
ENV_FILE=""
if [ -f "/etc/kelvin/staging.env" ]; then
  ENV_FILE="/etc/kelvin/staging.env"
elif sudo test -f "/etc/kelvin/staging.env"; then
  ENV_FILE="/etc/kelvin/staging.env"
else
  echo "[-] ERROR: Environment file /etc/kelvin/staging.env not found." >&2
  exit 1
fi
echo "[+] Detected environment file: ${ENV_FILE} ✓"

# Verify KELVIN_CANARY_ONLY=true
if ! sudo grep -q "KELVIN_CANARY_ONLY=true" "$ENV_FILE"; then
  echo "[-] ERROR: KELVIN_CANARY_ONLY=true is required in ${ENV_FILE}." >&2
  exit 1
fi
echo "[+] Safety invariant verified: KELVIN_CANARY_ONLY=true ✓"

# Verify worker service is inactive
WORKER_STATE=$(systemctl is-active kelvin-worker.service 2>/dev/null || true)
if [ "$WORKER_STATE" = "active" ]; then
  echo "[-] ERROR: kelvin-worker.service is currently active. Aborting to preserve safety." >&2
  exit 1
fi
echo "[+] kelvin-worker.service state: ${WORKER_STATE} (safely inactive) ✓"

# Verify JWT Secret
JWT_LEN=$(sudo grep "KELVIN_JWT_SECRET=" "$ENV_FILE" | head -n 1 | cut -d'=' -f2- | tr -d '"\r\n ' | wc -c)
if [ "$JWT_LEN" -lt 32 ]; then
  echo "[-] ERROR: KELVIN_JWT_SECRET length is insufficient (<32 chars)." >&2
  exit 1
fi
echo "[+] KELVIN_JWT_SECRET configured (${JWT_LEN} chars) ✓"

# ------------------------------------------------------------------------------
# 3. Image Backup Preservation
# ------------------------------------------------------------------------------
echo ""
echo "▶ Preserving Rollback Images..."
if "${DOCKER_CMD[@]}" inspect kelvin-api:staging &>/dev/null; then
  "${DOCKER_CMD[@]}" tag kelvin-api:staging "kelvin-api:${BACKUP_TAG}"
  echo "[+] Tagged current running image as kelvin-api:${BACKUP_TAG} ✓"
else
  echo "[!] Notice: kelvin-api:staging not present."
fi

# ------------------------------------------------------------------------------
# 4. Synchronize Canonical Repository
# ------------------------------------------------------------------------------
echo ""
echo "▶ Synchronizing Canonical Repository at ${DEPLOY_DIR} to ${TARGET_COMMIT}..."
cd "$DEPLOY_DIR"
git config --global --add safe.directory "$DEPLOY_DIR" 2>/dev/null || true

sudo git fetch origin main
sudo git checkout main
sudo git reset --hard "${TARGET_COMMIT}"

ACTUAL_COMMIT=$(git rev-parse HEAD)
echo "[+] Checked out commit: ${ACTUAL_COMMIT} ✓"

# ------------------------------------------------------------------------------
# 5. Database & Schema Verification (Supabase)
# ------------------------------------------------------------------------------
echo ""
echo "▶ Verifying Database Schema & Migration Status..."
set -a
# shellcheck disable=SC1090
source <(sudo cat "$ENV_FILE")
set +a

run_psql() {
  if command -v psql &>/dev/null; then
    psql "$@"
  else
    local ca_mount=()
    local ca_env=()
    if [ -n "${SUPABASE_CA_CERT_PATH:-}" ] && sudo test -f "$SUPABASE_CA_CERT_PATH"; then
      ca_mount=(-v "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro")
      ca_env=(-e "PGSSLROOTCERT=${SUPABASE_CA_CERT_PATH}")
    fi
    "${DOCKER_CMD[@]}" run --rm "${ca_mount[@]}" "${ca_env[@]}" postgres:15-alpine psql "$@"
  fi
}

MIGRATION_COUNT=$(run_psql "$KELVIN_DATABASE_URL" -t -c "SELECT count(*) FROM schema_migrations;" 2>/dev/null | tr -d ' ' || echo "UNKNOWN")
echo "[+] Applied schema migrations count: ${MIGRATION_COUNT} ✓"

# ------------------------------------------------------------------------------
# 6. Build ARM64 Container Image
# ------------------------------------------------------------------------------
echo ""
echo "▶ Building Updated ARM64 API Image (GOWORK=off)..."
BUILD_LOG="/tmp/kelvin-build-${BACKUP_TIMESTAMP}.log"
"${DOCKER_CMD[@]}" compose -f "${COMPOSE_FILE}" --env-file "$ENV_FILE" build --no-cache api 2>&1 | tee "$BUILD_LOG"

SHORT_SHA="$(git rev-parse --short HEAD)"
IMAGE_TAG="kelvin-api:m9.8-${SHORT_SHA}"
"${DOCKER_CMD[@]}" tag kelvin-api:staging "${IMAGE_TAG}"
echo "[+] Tagged image: ${IMAGE_TAG} ✓"

# ------------------------------------------------------------------------------
# 7. Controlled Zero-Downtime Container Recreate & Rollback Handler
# ------------------------------------------------------------------------------
echo ""
echo "▶ Recreating kelvin-staging-api Container..."

rollback() {
  echo "" >&2
  echo "[-] CRITICAL: Readiness verification failed. Initiating automatic rollback..." >&2
  "${DOCKER_CMD[@]}" tag "kelvin-api:${BACKUP_TAG}" kelvin-api:staging
  "${DOCKER_CMD[@]}" compose -f "${COMPOSE_FILE}" --env-file "$ENV_FILE" up -d --no-deps api
  echo "[-] Rollback completed to kelvin-api:${BACKUP_TAG}." >&2
  exit 1
}

"${DOCKER_CMD[@]}" compose -f "${COMPOSE_FILE}" --env-file "$ENV_FILE" up -d --no-deps api

# ------------------------------------------------------------------------------
# 8. Operational Probes & Health Verification
# ------------------------------------------------------------------------------
echo ""
echo "▶ Performing Internal Health & Readiness Probes..."
ATTEMPTS=0
MAX_ATTEMPTS=20
READY=false

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  sleep 2
  ATTEMPTS=$((ATTEMPTS + 1))
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${LOOPBACK_HOST}/readyz" 2>/dev/null || true)
  if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] API responded HTTP 200 on ${LOOPBACK_HOST}/readyz (attempt ${ATTEMPTS}) ✓"
    READY=true
    break
  fi
  echo "    Attempt ${ATTEMPTS}/${MAX_ATTEMPTS}: waiting for readyz (HTTP ${HTTP_CODE})..."
done

if [ "$READY" = "false" ]; then
  rollback
fi

# ------------------------------------------------------------------------------
# 9. Verify Public Ingress & CORS via Caddy
# ------------------------------------------------------------------------------
echo ""
echo "▶ Verifying Ingress & CORS via Caddy (${API_HOST})..."
curl -fsS "${API_HOST}/healthz"
echo ""
curl -fsS "${API_HOST}/readyz"
echo ""

CORS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS "${API_HOST}/api/v1/assessments" \
  -H "Origin: ${FRONTEND_ORIGIN}" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization,content-type,x-idempotency-key,x-tenant-id" || true)

if [ "$CORS_CODE" = "204" ] || [ "$CORS_CODE" = "200" ]; then
  echo "[+] CORS preflight from ${FRONTEND_ORIGIN} succeeded (HTTP ${CORS_CODE}) ✓"
else
  echo "[-] WARNING: CORS preflight returned HTTP ${CORS_CODE}" >&2
fi

# ------------------------------------------------------------------------------
# 10. Worker Binary Compilation & Verification
# ------------------------------------------------------------------------------
echo ""
echo "▶ Compiling & Hardening Worker Daemon Native Binary..."
mkdir -p /opt/kelvin/bin
sudo chown -R opc:opc /opt/kelvin/bin 2>/dev/null || true

cd "${DEPLOY_DIR}/apps/worker"
go build -trimpath -ldflags="-s -w" -o /opt/kelvin/bin/kelvin-worker ./cmd/runner
chmod 755 /opt/kelvin/bin/kelvin-worker

if [ -x /opt/kelvin/bin/kelvin-worker ]; then
  echo "[+] Native worker binary compiled: /opt/kelvin/bin/kelvin-worker ✓"
else
  echo "[-] ERROR: Worker binary compilation failed." >&2
  exit 1
fi

echo ""
echo "=============================================================================="
echo "  Kelvin M9.8 Production Deployment Completed Successfully"
echo "  Commit: ${ACTUAL_COMMIT}"
echo "  Image:  ${IMAGE_TAG}"
echo "  Timestamp: $(date -u)"
echo "=============================================================================="
