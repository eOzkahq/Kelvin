#!/usr/bin/env bash
# =============================================================================
# Kelvin First-Admin Bootstrap Script (Hardened)
# Run AFTER auth-deploy.sh passes all checks.
# Run in: Oracle Cloud Shell (or on Oracle host as opc)
# =============================================================================
set -euo pipefail

API_HOST="https://api.eozka.com"
BOOTSTRAP_EMAIL="owner@eozka.com"
TENANT_SLUG="kelvin-corp"
TENANT_NAME="Kelvin Security Corp"
ADMIN_NAME="Project Owner"
ADMIN_ROLE="PLATFORM_ADMIN"

echo "================================================================"
echo "  Kelvin First-Admin Bootstrap (Hardened)  —  $(date -u)"
echo "================================================================"

# ---------------------------------------------------------------------------
# 0. Resolve environment file dynamically
# ---------------------------------------------------------------------------
ENV_FILE=""
if [ -f "/etc/kelvin/api.env" ]; then
  ENV_FILE="/etc/kelvin/api.env"
elif [ -f "/etc/kelvin/staging.env" ]; then
  ENV_FILE="/etc/kelvin/staging.env"
else
  echo "ERROR: Environment file not found (/etc/kelvin/api.env or staging.env)" >&2
  exit 1
fi
echo "[+] Detected environment file: ${ENV_FILE}"

# Source environment
set -a; source "$ENV_FILE"; set +a

# ---------------------------------------------------------------------------
# 1. Check existing administrator accounts & specifically bootstrap target email
# ---------------------------------------------------------------------------
echo ""
echo "▶ [1] Checking existing administrator accounts and bootstrap target user..."

EXISTING_ADMINS=$(psql "$KELVIN_DATABASE_URL" -t -c \
  "SELECT count(*) FROM users
   WHERE role IN ('PLATFORM_ADMIN','TENANT_ADMIN')
     AND is_active = true
     AND deleted_at IS NULL;" 2>/dev/null | tr -d ' ')
echo "  Existing active admin accounts in DB: ${EXISTING_ADMINS}"

TARGET_EXISTS=$(psql "$KELVIN_DATABASE_URL" -t -c \
  "SELECT count(*) FROM users
   WHERE lower(email) = lower('${BOOTSTRAP_EMAIL}')
     AND deleted_at IS NULL;" 2>/dev/null | tr -d ' ')

if [ "$TARGET_EXISTS" -gt 0 ]; then
  echo ""
  echo "  [!] NOTICE: User '${BOOTSTRAP_EMAIL}' already exists in database:"
  psql "$KELVIN_DATABASE_URL" -c \
    "SELECT u.id, u.email, u.role, u.is_active, u.created_at, u.updated_at, t.name AS tenant
     FROM users u
     JOIN tenants t ON u.tenant_id = t.id
     WHERE lower(u.email) = lower('${BOOTSTRAP_EMAIL}')
       AND u.deleted_at IS NULL;"
  echo ""
  echo "  Running bootstrap will RESET the password for this user."
  read -r -p "  Do you want to reset credentials for ${BOOTSTRAP_EMAIL}? [y/N] " CONFIRM
  if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "  Bootstrap aborted by operator. Proceeding to verification."
    exit 0
  fi
elif [ "$EXISTING_ADMINS" -gt 0 ]; then
  echo ""
  echo "  Existing administrator(s):"
  psql "$KELVIN_DATABASE_URL" -c \
    "SELECT u.email, u.role, u.is_active, u.created_at, t.name AS tenant
     FROM users u
     JOIN tenants t ON u.tenant_id = t.id
     WHERE u.role IN ('PLATFORM_ADMIN','TENANT_ADMIN')
       AND u.is_active = true
       AND u.deleted_at IS NULL;"
  echo ""
  echo "  An administrator already exists. Proceeding will add '${BOOTSTRAP_EMAIL}' as PLATFORM_ADMIN."
  read -r -p "  Continue provisioning ${BOOTSTRAP_EMAIL}? [y/N] " CONFIRM
  if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "  Bootstrap skipped. Proceeding to verification."
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# 2. Ensure bootstrap executable is available (in image or compiled on host)
# ---------------------------------------------------------------------------
echo ""
echo "▶ [2] Checking bootstrap executable..."

USE_DOCKER_BOOTSTRAP=0
if docker run --rm kelvin-api:staging ls /app/bootstrap &>/dev/null; then
  echo "  /app/bootstrap found inside kelvin-api:staging ✓"
  USE_DOCKER_BOOTSTRAP=1
else
  echo "  Notice: /app/bootstrap not packaged in container image."
  echo "  Compiling bootstrap binary for native host execution..."
  mkdir -p /opt/kelvin/bin
  
  if command -v go &>/dev/null; then
    (cd /opt/kelvin/apps/api && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /opt/kelvin/bin/kelvin-bootstrap ./cmd/bootstrap)
  else
    docker run --rm \
      -v /opt/kelvin:/src -w /src/apps/api \
      -e GOWORK=off \
      golang:1.26-alpine \
      go build -trimpath -ldflags="-s -w" -o /opt/kelvin/bin/kelvin-bootstrap ./cmd/bootstrap
  fi
  chmod 0755 /opt/kelvin/bin/kelvin-bootstrap
  echo "  Native host binary compiled: /opt/kelvin/bin/kelvin-bootstrap ✓"
fi

# ---------------------------------------------------------------------------
# 3. Execute first-admin bootstrap (interactive password prompt — no echo)
# ---------------------------------------------------------------------------
echo ""
echo "▶ [3] Running first-admin bootstrap..."
echo "  Parameters:"
echo "    --tenant-name  '${TENANT_NAME}'"
echo "    --tenant-slug  ${TENANT_SLUG}"
echo "    --admin-email  ${BOOTSTRAP_EMAIL}"
echo "    --admin-name   '${ADMIN_NAME}'"
echo "    --admin-role   ${ADMIN_ROLE}"
echo ""
echo "  You will be prompted for the administrator password (not echoed)."
echo "  Password requirements: 8–72 characters."
echo ""

# Build CA volume mount flag if configured
CA_MOUNT_OPTS=()
if [ -n "${SUPABASE_CA_CERT_PATH:-}" ] && [ -f "$SUPABASE_CA_CERT_PATH" ]; then
  CA_MOUNT_OPTS=(-v "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro")
fi

if [ "$USE_DOCKER_BOOTSTRAP" -eq 1 ]; then
  docker run --rm -it \
    --env-file "$ENV_FILE" \
    "${CA_MOUNT_OPTS[@]}" \
    kelvin-api:staging \
    /app/bootstrap \
      --tenant-name "$TENANT_NAME" \
      --tenant-slug "$TENANT_SLUG" \
      --admin-email "$BOOTSTRAP_EMAIL" \
      --admin-name "$ADMIN_NAME" \
      --admin-role "$ADMIN_ROLE"
else
  /opt/kelvin/bin/kelvin-bootstrap \
    --tenant-name "$TENANT_NAME" \
    --tenant-slug "$TENANT_SLUG" \
    --admin-email "$BOOTSTRAP_EMAIL" \
    --admin-name "$ADMIN_NAME" \
    --admin-role "$ADMIN_ROLE"
fi

# ---------------------------------------------------------------------------
# 4. Verify bootstrap result in DB
# ---------------------------------------------------------------------------
echo ""
echo "▶ [4] Verifying bootstrap record in database..."
psql "$KELVIN_DATABASE_URL" -c \
  "SELECT u.id, u.email, u.role, u.is_active, u.created_at, t.name AS tenant, t.slug
   FROM users u
   JOIN tenants t ON u.tenant_id = t.id
   WHERE lower(u.email) = lower('${BOOTSTRAP_EMAIL}')
     AND u.deleted_at IS NULL;"

# ---------------------------------------------------------------------------
# 5. Interactive live API authentication verification
# ---------------------------------------------------------------------------
echo ""
echo "▶ [5] Verifying login against live API..."
echo "  Enter the administrator password to verify authentication:"
read -rs ADMIN_PASS
echo ""

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${BOOTSTRAP_EMAIL}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${API_HOST}/api/v1/auth/login")
ADMIN_PASS=""   # Zero from memory immediately

LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)
LOGIN_STATUS=$(echo "$LOGIN_RESPONSE" | tail -n 1)
echo "  POST /api/v1/auth/login → HTTP ${LOGIN_STATUS}"

if [ "$LOGIN_STATUS" != "200" ]; then
  echo "ERROR: Login failed with HTTP ${LOGIN_STATUS}" >&2
  echo "  Response: ${LOGIN_BODY}" >&2
  exit 1
fi

ACCESS_TOKEN=$(echo "$LOGIN_BODY" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['data']['access_token'])" 2>/dev/null || echo "")
REFRESH_TOKEN=$(echo "$LOGIN_BODY" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['data']['refresh_token'])" 2>/dev/null || echo "")

if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Could not extract access_token from login response" >&2
  exit 1
fi
echo "  Access token issued ✓"

# Verify /auth/me
ME_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${API_HOST}/api/v1/auth/me")
ME_BODY=$(echo "$ME_RESPONSE" | head -n -1)
ME_STATUS=$(echo "$ME_RESPONSE" | tail -n 1)
echo "  GET /api/v1/auth/me → HTTP ${ME_STATUS}"
[ "$ME_STATUS" = "200" ] || { echo "ERROR: /auth/me failed: ${ME_BODY}" >&2; exit 1; }
echo "  Identity confirmed:"
echo "$ME_BODY" | python3 -m json.tool 2>/dev/null || echo "$ME_BODY"

# Verify token rotation
REFRESH_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}" \
  "${API_HOST}/api/v1/auth/refresh")
REFRESH_STATUS=$(echo "$REFRESH_RESPONSE" | tail -n 1)
echo "  POST /api/v1/auth/refresh → HTTP ${REFRESH_STATUS}"
[ "$REFRESH_STATUS" = "200" ] || { echo "ERROR: refresh failed" >&2; exit 1; }

NEW_ACCESS=$(echo "$REFRESH_RESPONSE" | head -n -1 | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['data']['access_token'])" 2>/dev/null || echo "")
echo "  Rotated access token issued ✓"

# Verify logout
LOGOUT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${NEW_ACCESS}" \
  -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}" \
  "${API_HOST}/api/v1/auth/logout")
echo "  POST /api/v1/auth/logout → HTTP ${LOGOUT_STATUS}"
[[ "$LOGOUT_STATUS" =~ ^(200|204)$ ]] || { echo "ERROR: logout failed" >&2; exit 1; }
echo "  Session revoked ✓"

unset ACCESS_TOKEN NEW_ACCESS REFRESH_TOKEN

echo ""
echo "================================================================"
echo "  BOOTSTRAP & AUTH CYCLE VERIFIED SUCCESSFULLY ✓"
echo "  Next step: Deploy frontend to Vercel (Stage 9)"
echo "================================================================"
