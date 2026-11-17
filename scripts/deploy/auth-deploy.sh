#!/usr/bin/env bash
# =============================================================================
# Kelvin PR #637 — Authentication Release Deployment Script (Hardened)
# Run in: Oracle Cloud Shell (or directly on the Oracle host as opc)
# Target: kelvin-staging-api  |  Merge commit: be05a80
# =============================================================================
set -euo pipefail

DEPLOY_DIR="/opt/kelvin"
COMPOSE_FILE="deploy/staging/docker-compose.yml"
MERGE_COMMIT="be05a80ddc674cdacf01c5e38b58ddf187b8a449"
BACKUP_TAG="pre-auth-$(date +%Y%m%d-%H%M)"
API_HOST="https://api.eozka.com"
LOOPBACK_HOST="http://127.0.0.1:8080"

echo "================================================================"
echo "  Kelvin Auth Deployment (Hardened)  —  $(date -u)"
echo "  Merge commit: ${MERGE_COMMIT}"
echo "================================================================"

# ---------------------------------------------------------------------------
# STEP 0: Resolve environment file path dynamically
# ---------------------------------------------------------------------------
ENV_FILE=""
if [ -f "/etc/kelvin/api.env" ]; then
  ENV_FILE="/etc/kelvin/api.env"
elif [ -f "/etc/kelvin/staging.env" ]; then
  ENV_FILE="/etc/kelvin/staging.env"
else
  echo "ERROR: Neither /etc/kelvin/api.env nor /etc/kelvin/staging.env was found." >&2
  exit 1
fi
echo "[+] Detected environment file: ${ENV_FILE}"

# ---------------------------------------------------------------------------
# STEP A: Verify worker is inactive before touching anything
# ---------------------------------------------------------------------------
echo ""
echo "▶ [A] Verifying kelvin-worker.service is inactive..."
WORKER_STATE=$(systemctl is-active kelvin-worker.service 2>/dev/null || true)
if [ "$WORKER_STATE" = "active" ]; then
  echo "ERROR: kelvin-worker.service is active — aborting to preserve constraint." >&2
  exit 1
fi
echo "  kelvin-worker.service state: ${WORKER_STATE} ✓"

# ---------------------------------------------------------------------------
# STEP B: Verify KELVIN_CANARY_ONLY is set
# ---------------------------------------------------------------------------
echo ""
echo "▶ [B] Verifying KELVIN_CANARY_ONLY=true in ${ENV_FILE}..."
if ! grep -q "KELVIN_CANARY_ONLY=true" "$ENV_FILE"; then
  echo "ERROR: KELVIN_CANARY_ONLY=true not found in ${ENV_FILE} — aborting." >&2
  exit 1
fi
echo "  KELVIN_CANARY_ONLY=true confirmed ✓"

# ---------------------------------------------------------------------------
# STEP C: Verify KELVIN_JWT_SECRET is set and valid
# ---------------------------------------------------------------------------
echo ""
echo "▶ [C] Verifying KELVIN_JWT_SECRET is configured..."
if ! grep -q "KELVIN_JWT_SECRET=" "$ENV_FILE"; then
  echo "ERROR: KELVIN_JWT_SECRET not found in ${ENV_FILE}." >&2
  echo "       Add it before deploying: echo 'KELVIN_JWT_SECRET=<min32chars>' | sudo tee -a ${ENV_FILE}" >&2
  exit 1
fi
JWT_VAL=$(grep "KELVIN_JWT_SECRET=" "$ENV_FILE" | head -n 1 | cut -d'=' -f2- | tr -d '"\r\n ')
JWT_LEN=${#JWT_VAL}
if [ "$JWT_LEN" -lt 32 ]; then
  echo "ERROR: KELVIN_JWT_SECRET length is ${JWT_LEN} (must be at least 32 characters)." >&2
  exit 1
fi
if [[ "$JWT_VAL" == *"placeholder"* || "$JWT_VAL" == "kelvin-insecure-dev-secret-key-32-bytes" ]]; then
  echo "ERROR: KELVIN_JWT_SECRET is using an insecure placeholder value." >&2
  exit 1
fi
echo "  KELVIN_JWT_SECRET present (${JWT_LEN} chars, non-placeholder) ✓"
unset JWT_VAL

# ---------------------------------------------------------------------------
# STEP D: Preserve rollback images
# ---------------------------------------------------------------------------
echo ""
echo "▶ [D] Preserving rollback images..."
docker images kelvin-api --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}"

# Tag current running image as pre-auth backup
if docker inspect kelvin-api:staging &>/dev/null; then
  docker tag kelvin-api:staging "kelvin-api:${BACKUP_TAG}"
  echo "  Tagged kelvin-api:staging → kelvin-api:${BACKUP_TAG} ✓"
else
  echo "  WARNING: kelvin-api:staging image not found — no pre-auth tag created"
fi

# Confirm staging-backup-20261116 still exists
if docker inspect kelvin-api:staging-backup-20261116 &>/dev/null; then
  echo "  kelvin-api:staging-backup-20261116 present ✓"
else
  echo "  WARNING: kelvin-api:staging-backup-20261116 not found"
fi

echo ""
echo "Current images:"
docker images kelvin-api --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

# ---------------------------------------------------------------------------
# STEP E: Check live Supabase migration state
# ---------------------------------------------------------------------------
echo ""
echo "▶ [E] Checking applied DB migrations..."
set -a; source "$ENV_FILE"; set +a
MIGRATION_COUNT=$(psql "$KELVIN_DATABASE_URL" -t -c \
  "SELECT count(*) FROM schema_migrations;" 2>/dev/null | tr -d ' ' || echo "QUERY_FAILED")
echo "  Applied migrations count: ${MIGRATION_COUNT}"

HIGHEST=$(psql "$KELVIN_DATABASE_URL" -t -c \
  "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null | tr -d ' ' || echo "QUERY_FAILED")
echo "  Highest applied version: ${HIGHEST}"

echo ""
echo "  Verifying auth tables exist..."
TABLE_CHECK=$(psql "$KELVIN_DATABASE_URL" -t -c \
  "SELECT table_name FROM information_schema.tables
   WHERE table_schema='public'
     AND table_name IN ('tenants','users','auth_sessions')
   ORDER BY table_name;" 2>/dev/null | tr -d ' ' | sort || echo "QUERY_FAILED")
echo "  Auth tables detected: ${TABLE_CHECK}"
if ! echo "$TABLE_CHECK" | grep -q "auth_sessions"; then
  echo "ERROR: auth_sessions table missing — required migration not applied." >&2
  exit 1
fi
echo "  All required auth tables present ✓"

# ---------------------------------------------------------------------------
# STEP F: Fetch merged main and verify commit
# ---------------------------------------------------------------------------
echo ""
echo "▶ [F] Fetching merged main (expected: ${MERGE_COMMIT})..."
cd "$DEPLOY_DIR"
git config --global --add safe.directory "$DEPLOY_DIR" 2>/dev/null || true
sudo git fetch origin main
sudo git checkout main
sudo git pull origin main

ACTUAL_COMMIT=$(git rev-parse HEAD)
echo "  Local HEAD: ${ACTUAL_COMMIT}"
if [ "$ACTUAL_COMMIT" != "$MERGE_COMMIT" ]; then
  echo "ERROR: HEAD does not match expected merge commit." >&2
  echo "  Expected: ${MERGE_COMMIT}" >&2
  echo "  Got:      ${ACTUAL_COMMIT}" >&2
  exit 1
fi
echo "  Commit verified ✓"

# ---------------------------------------------------------------------------
# STEP G: Build ARM64 API image (GOWORK=off enforced)
# ---------------------------------------------------------------------------
echo ""
echo "▶ [G] Building ARM64 API image..."
sudo docker compose -f "${COMPOSE_FILE}" --env-file "$ENV_FILE" build --no-cache api 2>&1 | tee /tmp/kelvin-build-$(date +%Y%m%d-%H%M).log
echo "  Build complete ✓"

docker tag kelvin-api:staging "kelvin-api:auth-be05a80"
echo "  Tagged new image as kelvin-api:auth-be05a80 ✓"

# ---------------------------------------------------------------------------
# STEP H: Deploy API container (with automated rollback on failure)
# ---------------------------------------------------------------------------
echo ""
echo "▶ [H] Deploying new API container..."
rollback() {
  echo "" >&2
  echo "[-] DEPLOYMENT FAILURE DETECTED — INITIATING AUTOMATIC ROLLBACK..." >&2
  if docker inspect "kelvin-api:${BACKUP_TAG}" &>/dev/null; then
    docker tag "kelvin-api:${BACKUP_TAG}" kelvin-api:staging
    sudo docker compose -f "${COMPOSE_FILE}" --env-file "$ENV_FILE" up -d --no-deps api
    echo "[+] Rollback to ${BACKUP_TAG} completed." >&2
  else
    echo "[-] Cannot rollback: backup tag kelvin-api:${BACKUP_TAG} not found." >&2
  fi
  exit 1
}

sudo docker compose -f "${COMPOSE_FILE}" --env-file "$ENV_FILE" up -d --no-deps api

# Poll startup for up to 30 seconds
echo "  Awaiting container startup (polling loopback port 8080)..."
ATTEMPTS=0
MAX_ATTEMPTS=15
READY=0
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  sleep 2
  ATTEMPTS=$((ATTEMPTS + 1))
  if curl -fsS "${LOOPBACK_HOST}/health/live" >/dev/null 2>&1; then
    echo "  Container is listening on 127.0.0.1:8080 (attempt ${ATTEMPTS}) ✓"
    READY=1
    break
  fi
  echo "    Attempt ${ATTEMPTS}/${MAX_ATTEMPTS}: waiting for API..."
done

if [ $READY -ne 1 ]; then
  echo "[-] ERROR: Container failed to respond on 127.0.0.1:8080 after ${MAX_ATTEMPTS} attempts." >&2
  docker logs kelvin-staging-api --tail 30 2>&1 >&2 || true
  rollback
fi

# Show container status
docker ps --filter name=kelvin --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# ---------------------------------------------------------------------------
# STEP I: Verify API endpoints (both Loopback and Caddy reverse-proxy)
# ---------------------------------------------------------------------------
echo ""
echo "▶ [I] Verifying API endpoints..."

# 1. Health live
LIVE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_HOST}/health/live")
echo "  GET /health/live → HTTP ${LIVE_STATUS}"
[ "$LIVE_STATUS" = "200" ] || { echo "ERROR: /health/live returned ${LIVE_STATUS}"; rollback; }

# 2. Health ready
READY_BODY=$(curl -s "${API_HOST}/health/ready")
READY_STATUS=$(echo "$READY_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; print(d['status'])" 2>/dev/null || echo "PARSE_FAILED")
DB_STATUS=$(echo "$READY_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('database','?'))" 2>/dev/null || echo "?")
echo "  GET /health/ready → status=${READY_STATUS}, database=${DB_STATUS}"
[ "$READY_STATUS" = "READY" ] || { echo "ERROR: /health/ready not READY: ${READY_BODY}"; rollback; }

# 3. Auth login route exists (empty body → 422 or 400, NOT 404)
LOGIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${API_HOST}/api/v1/auth/login")
echo "  POST /api/v1/auth/login (empty body) → HTTP ${LOGIN_STATUS}"
if [ "$LOGIN_STATUS" = "404" ]; then
  echo "ERROR: auth/login returned 404 — auth routes not registered in running container!" >&2
  rollback
fi
[ "$LOGIN_STATUS" = "422" ] || [ "$LOGIN_STATUS" = "400" ] || \
  { echo "ERROR: unexpected auth/login status ${LOGIN_STATUS}"; rollback; }

# 4. Auth me route exists (no token → 401, NOT 404)
ME_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_HOST}/api/v1/auth/me")
echo "  GET /api/v1/auth/me (no token) → HTTP ${ME_STATUS}"
[ "$ME_STATUS" = "401" ] || { echo "ERROR: auth/me returned ${ME_STATUS} (expected 401)"; rollback; }

# 5. Auth refresh route exists (empty → 422 or 400)
REFRESH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${API_HOST}/api/v1/auth/refresh")
echo "  POST /api/v1/auth/refresh (empty body) → HTTP ${REFRESH_STATUS}"
[ "$REFRESH_STATUS" = "422" ] || [ "$REFRESH_STATUS" = "400" ] || \
  { echo "ERROR: auth/refresh returned ${REFRESH_STATUS}"; rollback; }

# 6. Auth logout route exists (no token → 401)
LOGOUT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${API_HOST}/api/v1/auth/logout")
echo "  POST /api/v1/auth/logout (no token) → HTTP ${LOGOUT_STATUS}"
[ "$LOGOUT_STATUS" = "401" ] || [ "$LOGOUT_STATUS" = "400" ] || \
  { echo "ERROR: auth/logout returned ${LOGOUT_STATUS}"; rollback; }

echo ""
echo "================================================================"
echo "  API DEPLOYMENT COMPLETE — All route checks passed ✓"
echo "  Next: Run bootstrap-admin.sh to provision the first administrator"
echo "================================================================"
