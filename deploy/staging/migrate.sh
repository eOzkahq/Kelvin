#!/usr/bin/env bash
# ==============================================================================
# KELVIN Staging One-Shot Database Migration Runner
# Connects to external Supabase PostgreSQL over verified TLS (sslmode=verify-full)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

COMMAND="${1:-version}"
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

# 1. Validate required database connection string
if [ -z "${KELVIN_DATABASE_URL}" ]; then
  echo "[-] ERROR: KELVIN_DATABASE_URL (or DATABASE_URL) environment variable is required."
  exit 1
fi

if [[ ! "${KELVIN_DATABASE_URL}" =~ ^postgres(ql)?:// ]]; then
  echo "[-] ERROR: KELVIN_DATABASE_URL must start with postgres:// or postgresql://"
  exit 1
fi

# 2. Enforce verified TLS for staging/production (exact match for sslmode=verify-full)
if [[ "${KELVIN_ENV}" == "staging" || "${KELVIN_ENV}" == "production" ]]; then
  SSL_VERIFY_REGEX='[?&]sslmode=verify-full(&|$)'
  if [[ ! "${KELVIN_DATABASE_URL}" =~ ${SSL_VERIFY_REGEX} ]]; then
    echo "[-] ERROR: Database URL must explicitly contain query parameter 'sslmode=verify-full' in ${KELVIN_ENV}."
    echo "    Insecure or unverified modes (disable, allow, prefer, require, verify-ca) are strictly prohibited."
    exit 1
  fi
fi

# 3. Detect Docker execution binary / wrapper (supports sudo docker on Oracle Linux)
DOCKER_CMD_ARRAY=()
if [ -n "${DOCKER_CMD:-}" ]; then
  # User specified explicit DOCKER_CMD (e.g. "sudo docker", "docker", or "/usr/bin/docker")
  if [[ "${DOCKER_CMD}" == sudo\ * ]]; then
    DOCKER_CMD_ARRAY=("sudo" "${DOCKER_CMD#sudo }")
  else
    DOCKER_CMD_ARRAY=("${DOCKER_CMD}")
  fi
elif command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD_ARRAY=("docker")
  elif command -v sudo >/dev/null 2>&1; then
    # On Oracle Linux, opc user might not be in docker group; use sudo docker
    DOCKER_CMD_ARRAY=("sudo" "docker")
  else
    DOCKER_CMD_ARRAY=("docker")
  fi
fi

# 4. Resolve and validate custom CA certificate
CA_MOUNT_ARGS=()
CONTAINER_CA_PATH=""

HOST_CA_PATH="${SUPABASE_CA_CERT_PATH:-${KELVIN_DATABASE_SSL_ROOT_CERT:-}}"
URL_CA_PATH=""
ROOTCERT_REGEX='[?&]sslrootcert=([^&]+)'
if [[ "${KELVIN_DATABASE_URL}" =~ ${ROOTCERT_REGEX} ]]; then
  URL_CA_PATH="${BASH_REMATCH[1]}"
fi

if [ -n "${URL_CA_PATH}" ] && [ -n "${HOST_CA_PATH}" ] && [ "${URL_CA_PATH}" != "${HOST_CA_PATH}" ]; then
  echo "[-] ERROR: Conflicting CA certificate paths configured:"
  echo "    URL sslrootcert='${URL_CA_PATH}' vs environment CA='${HOST_CA_PATH}'"
  exit 1
fi

ACTIVE_CA_PATH="${HOST_CA_PATH:-${URL_CA_PATH}}"
if [ -n "${ACTIVE_CA_PATH}" ]; then
  if [ ! -f "${ACTIVE_CA_PATH}" ] || [ ! -r "${ACTIVE_CA_PATH}" ]; then
    echo "[-] ERROR: Configured CA certificate path '${ACTIVE_CA_PATH}' does not exist or is not readable."
    exit 1
  fi
  # Mount the host CA file into container at the identical path so both URL query and environment variable resolve
  CA_MOUNT_ARGS=("-v" "${ACTIVE_CA_PATH}:${ACTIVE_CA_PATH}:ro")
  CONTAINER_CA_PATH="${ACTIVE_CA_PATH}"
fi

# 5. Execute migration command via preferred execution method
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

if [ ${#DOCKER_CMD_ARRAY[@]} -gt 0 ] && [ -f "${COMPOSE_FILE}" ] && "${DOCKER_CMD_ARRAY[@]}" compose version >/dev/null 2>&1; then
  echo "[+] Running migration via docker compose migrate service (kelvin-api:staging)..."
  RUN_ARGS=(
    "${DOCKER_CMD_ARRAY[@]}" compose -f "${COMPOSE_FILE}" run --rm
  )
  if [ ${#CA_MOUNT_ARGS[@]} -gt 0 ]; then
    RUN_ARGS+=("${CA_MOUNT_ARGS[@]}")
  fi
  RUN_ARGS+=(
    -e "KELVIN_ENV=${KELVIN_ENV}"
    -e "KELVIN_DATABASE_URL=${KELVIN_DATABASE_URL}"
  )
  if [ -n "${CONTAINER_CA_PATH}" ]; then
    RUN_ARGS+=(-e "KELVIN_DATABASE_SSL_ROOT_CERT=${CONTAINER_CA_PATH}")
  fi
  RUN_ARGS+=(migrate "${COMMAND}")
  if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    RUN_ARGS+=("${EXTRA_ARGS[@]}")
  fi
  "${RUN_ARGS[@]}"

elif [ ${#DOCKER_CMD_ARRAY[@]} -gt 0 ] && "${DOCKER_CMD_ARRAY[@]}" image inspect kelvin-api:staging >/dev/null 2>&1; then
  echo "[+] Running migration via verified staging container (kelvin-api:staging)..."
  RUN_ARGS=(
    "${DOCKER_CMD_ARRAY[@]}" run --rm
    --network kelvin-staging-net
  )
  if [ ${#CA_MOUNT_ARGS[@]} -gt 0 ]; then
    RUN_ARGS+=("${CA_MOUNT_ARGS[@]}")
  fi
  RUN_ARGS+=(
    -e "KELVIN_ENV=${KELVIN_ENV}"
    -e "KELVIN_DATABASE_URL=${KELVIN_DATABASE_URL}"
    -e "KELVIN_MIGRATIONS_PATH=/app/db/migrations"
  )
  if [ -n "${CONTAINER_CA_PATH}" ]; then
    RUN_ARGS+=(-e "KELVIN_DATABASE_SSL_ROOT_CERT=${CONTAINER_CA_PATH}")
  fi
  RUN_ARGS+=(
    kelvin-api:staging /app/kelvin-migrate "${COMMAND}"
  )
  if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    RUN_ARGS+=("${EXTRA_ARGS[@]}")
  fi
  "${RUN_ARGS[@]}"

elif [ -x "${REPO_ROOT}/apps/api/bin/migrate" ]; then
  echo "[+] Running local static migration binary..."
  LOCAL_ARGS=("${REPO_ROOT}/apps/api/bin/migrate" "${COMMAND}")
  if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    LOCAL_ARGS+=("${EXTRA_ARGS[@]}")
  fi
  if [ -n "${CONTAINER_CA_PATH}" ]; then
    export KELVIN_DATABASE_SSL_ROOT_CERT="${CONTAINER_CA_PATH}"
  fi
  "${LOCAL_ARGS[@]}"

elif command -v go >/dev/null 2>&1; then
  echo "[+] Running migration via local Go toolchain..."
  cd "${REPO_ROOT}/apps/api"
  if [ -n "${CONTAINER_CA_PATH}" ]; then
    export KELVIN_DATABASE_SSL_ROOT_CERT="${CONTAINER_CA_PATH}"
  fi
  GO_ARGS=(go run ./cmd/migrate "${COMMAND}")
  if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    GO_ARGS+=("${EXTRA_ARGS[@]}")
  fi
  "${GO_ARGS[@]}"

else
  echo "[-] ERROR: Neither docker compose/image nor local migration binary found to execute migrations."
  exit 1
fi

echo "[+] Staging migration workflow finished successfully."
