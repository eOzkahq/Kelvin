#!/usr/bin/env bash
# ==============================================================================
# Unit tests for deploy/staging/migrate.sh validation logic
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATE_SCRIPT="${SCRIPT_DIR}/migrate.sh"

echo "=== Running deploy/staging/migrate.sh validation tests ==="
FAILURES=0

assert_fail() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "[-] FAIL: ${desc} (expected failure, but command succeeded)"
    FAILURES=$((FAILURES + 1))
  else
    echo "[+] PASS: ${desc}"
  fi
}

assert_output_contains() {
  local desc="$1"
  local expected="$2"
  shift 2
  local output
  output=$("$@" 2>&1 || true)
  if [[ "${output}" == *"${expected}"* ]]; then
    echo "[+] PASS: ${desc}"
  else
    echo "[-] FAIL: ${desc} (expected output to contain '${expected}', got: '${output}')"
    FAILURES=$((FAILURES + 1))
  fi
}

# 1. Missing KELVIN_DATABASE_URL
assert_output_contains "Fails when KELVIN_DATABASE_URL is unset" \
  "KELVIN_DATABASE_URL (or DATABASE_URL) environment variable is required" \
  env -i PATH="${PATH}" KELVIN_ENV=staging bash "${MIGRATE_SCRIPT}"

# 2. Insecure sslmode in staging rejected
assert_output_contains "Rejects sslmode=disable in staging" \
  "Database URL must explicitly contain query parameter 'sslmode=verify-full'" \
  env -i PATH="${PATH}" KELVIN_ENV=staging KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=disable" bash "${MIGRATE_SCRIPT}"

assert_output_contains "Rejects sslmode=require in staging" \
  "Database URL must explicitly contain query parameter 'sslmode=verify-full'" \
  env -i PATH="${PATH}" KELVIN_ENV=staging KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=require" bash "${MIGRATE_SCRIPT}"

assert_output_contains "Rejects sslmode=verify-ca in staging" \
  "Database URL must explicitly contain query parameter 'sslmode=verify-full'" \
  env -i PATH="${PATH}" KELVIN_ENV=staging KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=verify-ca" bash "${MIGRATE_SCRIPT}"

assert_output_contains "Rejects missing sslmode in staging" \
  "Database URL must explicitly contain query parameter 'sslmode=verify-full'" \
  env -i PATH="${PATH}" KELVIN_ENV=staging KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db" bash "${MIGRATE_SCRIPT}"

# 3. Conflicting CA paths rejected
assert_output_contains "Rejects conflicting URL and environment CA paths" \
  "Conflicting CA certificate paths configured" \
  env -i PATH="${PATH}" KELVIN_ENV=staging \
    KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=verify-full&sslrootcert=/path/a.crt" \
    SUPABASE_CA_CERT_PATH="/path/b.crt" \
    bash "${MIGRATE_SCRIPT}"

# 4. Non-existent CA path rejected
assert_output_contains "Rejects non-existent CA certificate file" \
  "Configured CA certificate path '/nonexistent/supabase-ca.crt' does not exist" \
  env -i PATH="${PATH}" KELVIN_ENV=staging \
    KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=verify-full" \
    SUPABASE_CA_CERT_PATH="/nonexistent/supabase-ca.crt" \
    bash "${MIGRATE_SCRIPT}"

# 5. Non-postgres scheme rejected
assert_output_contains "Rejects non-postgres URL scheme" \
  "KELVIN_DATABASE_URL must start with postgres://" \
  env -i PATH="${PATH}" KELVIN_ENV=staging \
    KELVIN_DATABASE_URL="http://user:pass@db:5432/db?sslmode=verify-full" \
    bash "${MIGRATE_SCRIPT}"

# 6. Mock Docker command receives correct arguments and mounts
MOCK_DOCKER_BIN="${SCRIPT_DIR}/mock_docker.sh"
cat << 'EOF' > "${MOCK_DOCKER_BIN}"
#!/usr/bin/env bash
if [ "$1" = "compose" ] && [ "$2" = "version" ]; then
  echo "Docker Compose version v2.24.0"
  exit 0
fi
if [ "$1" = "compose" ]; then
  # Echo received arguments for verification
  echo "MOCK_COMPOSE_INVOKED: $@"
  exit 0
fi
echo "MOCK_DOCKER_INVOKED: $@"
exit 0
EOF
chmod +x "${MOCK_DOCKER_BIN}"

TEMP_CA="${SCRIPT_DIR}/test_ca.crt"
echo "-----BEGIN CERTIFICATE-----" > "${TEMP_CA}"
echo "MOCK" >> "${TEMP_CA}"
echo "-----END CERTIFICATE-----" >> "${TEMP_CA}"

assert_output_contains "Mocked DOCKER_CMD executes docker compose run with CA mount" \
  "-v ${TEMP_CA}:${TEMP_CA}:ro" \
  env -i PATH="${PATH}" KELVIN_ENV=staging \
    KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=verify-full" \
    SUPABASE_CA_CERT_PATH="${TEMP_CA}" \
    DOCKER_CMD="${MOCK_DOCKER_BIN}" \
    bash "${MIGRATE_SCRIPT}" version

# 7. Sudo Docker execution method
MOCK_BIN_DIR=$(mktemp -d)
cat << 'EOF' > "${MOCK_BIN_DIR}/sudo"
#!/usr/bin/env bash
exec "$@"
EOF
chmod +x "${MOCK_BIN_DIR}/sudo"

assert_output_contains "Supports sudo docker execution method without requiring docker group" \
  "-v ${TEMP_CA}:${TEMP_CA}:ro" \
  env -i PATH="${MOCK_BIN_DIR}:${PATH}" KELVIN_ENV=staging \
    KELVIN_DATABASE_URL="postgresql://user:pass@db:5432/db?sslmode=verify-full" \
    SUPABASE_CA_CERT_PATH="${TEMP_CA}" \
    DOCKER_CMD="sudo ${MOCK_DOCKER_BIN}" \
    bash "${MIGRATE_SCRIPT}" version

rm -rf "${MOCK_BIN_DIR}" "${MOCK_DOCKER_BIN}" "${TEMP_CA}"

if [ "${FAILURES}" -gt 0 ]; then
  echo "[-] Tests completed with ${FAILURES} failures."
  exit 1
fi

echo "[+] All deploy/staging/migrate.sh validation tests passed successfully."
