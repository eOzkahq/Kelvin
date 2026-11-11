#!/usr/bin/env bash
# ==============================================================================
# KELVIN Staging One-Shot Database Migration Runner (PRE-09)
# Connects to external Supabase PostgreSQL over verified TLS (sslmode=verify-full)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

COMMAND="${1:-up}"
shift || true
EXTRA_ARGS=("$@")

export KELVIN_ENV="${KELVIN_ENV:-staging}"
export KELVIN_DATABASE_URL="${KELVIN_DATABASE_URL:-${DATABASE_URL:-}}"
export KELVIN_MIGRATIONS_PATH="${KELVIN_MIGRATIONS_PATH:-${REPO_ROOT}/apps/api/db/migrations}"

echo "===================================================================="
echo " KELVIN Staging Migration Executor"
echo " Environment: ${KELVIN_ENV}"
echo " Command:     ${COMMAND}"
echo "===================================================================="

# 1. Validate required database connection
if [ -z "${KELVIN_DATABASE_URL}" ]; then
  echo "[-] ERROR: KELVIN_DATABASE_URL (or DATABASE_URL) environment variable is required."
  exit 1
fi

# 2. Enforce verified TLS for staging/production
if [[ "${KELVIN_DATABASE_URL}" != *"sslmode=verify-full"* ]]; then
  echo "[-] ERROR: Staging migration database URL must explicitly specify sslmode=verify-full."
  echo "    Insecure or disabled SSL is prohibited on managed staging infrastructure."
  exit 1
fi

# 3. Check CA certificate if configured
if [ -n "${SUPABASE_CA_CERT_PATH:-}" ]; then
  if [ ! -f "${SUPABASE_CA_CERT_PATH}" ]; then
    echo "[-] ERROR: Configured SUPABASE_CA_CERT_PATH '${SUPABASE_CA_CERT_PATH}' does not exist or is unreadable."
    exit 1
  fi
  export KELVIN_DATABASE_SSL_ROOT_CERT="${SUPABASE_CA_CERT_PATH}"
fi

# 4. Execute one-shot migration CLI
echo "[+] Executing migration CLI with sanitized parameters..."
cd "${REPO_ROOT}/apps/api"

if command -v docker >/dev/null 2>&1 && [ -f "${SCRIPT_DIR}/docker-compose.yml" ] && docker compose version >/dev/null 2>&1; then
  echo "[+] Running migration via docker compose migrate service (kelvin-api:staging)..."
  docker compose -f "${SCRIPT_DIR}/docker-compose.yml" run --rm \
    ${SUPABASE_CA_CERT_PATH:+-v "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro"} \
    -e KELVIN_DATABASE_URL="${KELVIN_DATABASE_URL}" \
    ${SUPABASE_CA_CERT_PATH:+-e KELVIN_DATABASE_SSL_ROOT_CERT="${SUPABASE_CA_CERT_PATH}"} \
    migrate "${COMMAND}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
elif command -v docker >/dev/null 2>&1 && docker image inspect kelvin-api:staging >/dev/null 2>&1; then
  echo "[+] Running migration via verified staging container (kelvin-api:staging)..."
  docker run --rm \
    --network kelvin-staging-net \
    ${SUPABASE_CA_CERT_PATH:+-v "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro"} \
    -e KELVIN_ENV="${KELVIN_ENV}" \
    -e KELVIN_DATABASE_URL="${KELVIN_DATABASE_URL}" \
    -e KELVIN_MIGRATIONS_PATH="/app/db/migrations" \
    ${SUPABASE_CA_CERT_PATH:+-e KELVIN_DATABASE_SSL_ROOT_CERT="${SUPABASE_CA_CERT_PATH}"} \
    kelvin-api:staging /app/kelvin-migrate "${COMMAND}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
elif [ -x "${REPO_ROOT}/apps/api/bin/migrate" ]; then
  echo "[+] Running local static migration binary..."
  "${REPO_ROOT}/apps/api/bin/migrate" "${COMMAND}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
elif command -v go >/dev/null 2>&1; then
  echo "[+] Running migration via local Go toolchain..."
  go run ./cmd/migrate "${COMMAND}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
else
  echo "[-] ERROR: Neither docker compose/image nor Go compiler found to execute migrations."
  exit 1
fi

echo "[+] Staging migration workflow finished successfully."
