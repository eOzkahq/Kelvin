#!/usr/bin/env bash
# ==============================================================================
# Kelvin Staging Deployment Script Integration Test Suite
#
# Executes the ACTUAL staging deployment script (scripts/deploy/staging-deploy.sh)
# in an isolated temporary test sandbox with mocked external binaries.
# Never modifies or executes against live host systemd or /opt/kelvin/bin.
#
# Covers all 7 required scenarios:
#   1. Successful deployment
#   2. Build failure before installation
#   3. Installation failure
#   4. Service restart failure with previous binary present (Rollback Success)
#   5. Service restart failure without previous binary (Rollback Unavailable)
#   6. Rollback restart failure
#   7. Temporary directory cleanup verification
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS_COUNT=0
FAIL_COUNT=0

test_pass() {
  echo "  [PASS] $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

test_fail() {
  echo "  [FAIL] $1" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "=============================================================================="
echo "Kelvin Staging Deployment Script Real Integration Tests"
echo "=============================================================================="

# Setup base temporary sandbox for this test run
SANDBOX_DIR="$(mktemp -d /tmp/kelvin-deploy-test-sandbox.XXXXXX)"
MOCK_BIN_DIR="$SANDBOX_DIR/mock_bin"
MOCK_STATE_DIR="$SANDBOX_DIR/mock_state"
TEST_WORKER_DIR="$SANDBOX_DIR/opt_kelvin_bin"
TEST_ENV_FILE="$SANDBOX_DIR/worker.env"
TEST_CA_CERT="$SANDBOX_DIR/supabase-root-ca.crt"

mkdir -p "$MOCK_BIN_DIR" "$MOCK_STATE_DIR" "$TEST_WORKER_DIR"

cleanup_sandbox() {
  rm -rf "$SANDBOX_DIR"
}
trap cleanup_sandbox EXIT

# 1. Create a readable mock CA cert
echo "-----BEGIN CERTIFICATE-----" > "$TEST_CA_CERT"
echo "MOCK_CERTIFICATE_DATA" >> "$TEST_CA_CERT"
echo "-----END CERTIFICATE-----" >> "$TEST_CA_CERT"
chmod 0644 "$TEST_CA_CERT"

# 2. Create valid non-placeholder test worker.env with 0600 permissions
cat << EOF > "$TEST_ENV_FILE"
KELVIN_ENV="staging"
KELVIN_WORKER_ID="worker-test-01"
KELVIN_DATABASE_URL="postgres://worker:realpassword@db.example.internal:5432/kelvin?sslmode=verify-full"
KELVIN_REDIS_URL="rediss://default:realpassword@redis.example.internal:6379"
REDIS_TLS_ENABLED="true"
KELVIN_WORKER_TOKEN_SECRET="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
SUPABASE_URL="https://example.supabase.co"
SUPABASE_SERVICE_ROLE_KEY="eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.real.mock.key"
SUPABASE_CA_CERT_PATH="$TEST_CA_CERT"
KELVIN_DATABASE_SSL_ROOT_CERT="$TEST_CA_CERT"
KELVIN_OCI_RUNTIME="crun"
KELVIN_SCANNER_NETWORK="kelvin-scanner-net"
KELVIN_EGRESS_PROXY_BIND_ADDR="10.89.10.1:8080"
KELVIN_EGRESS_PROXY_ADVERTISED_HOST="10.89.10.1"
EOF
chmod 0600 "$TEST_ENV_FILE"

# 3. Create mock executables in MOCK_BIN_DIR
# Mock uname
cat << 'EOF' > "$MOCK_BIN_DIR/uname"
#!/usr/bin/env bash
if [[ "${1:-}" == "-m" ]]; then
  echo "aarch64"
else
  echo "Linux"
fi
EOF
chmod 0755 "$MOCK_BIN_DIR/uname"

# Mock file
cat << 'EOF' > "$MOCK_BIN_DIR/file"
#!/usr/bin/env bash
echo "$1: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV)"
EOF
chmod 0755 "$MOCK_BIN_DIR/file"

# Mock journalctl
cat << 'EOF' > "$MOCK_BIN_DIR/journalctl"
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 "$MOCK_BIN_DIR/journalctl"

# Mock curl
cat << 'EOF' > "$MOCK_BIN_DIR/curl"
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 "$MOCK_BIN_DIR/curl"

# Mock runuser
cat << 'EOF' > "$MOCK_BIN_DIR/runuser"
#!/usr/bin/env bash
for arg in "$@"; do
  if [[ "$arg" =~ "Rootless" ]]; then
    echo "true"
    exit 0
  fi
  if [[ "$arg" =~ "OCIRuntime" ]]; then
    echo "crun|v2"
    exit 0
  fi
  if [[ "$arg" =~ "kelvin-scanner-net" ]]; then
    echo "OK"
    exit 0
  fi
done
exit 0
EOF
chmod 0755 "$MOCK_BIN_DIR/runuser"

# Mock go
cat << 'EOF' > "$MOCK_BIN_DIR/go"
#!/usr/bin/env bash
if [[ "${MOCK_GO_FAIL:-0}" == "1" ]]; then
  echo "Mock go build error: compilation failed" >&2
  exit 1
fi
out_bin=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    out_bin="$2"
    shift 2
  else
    shift
  fi
done
if [[ -n "$out_bin" ]]; then
  echo "mock_worker_binary_v2_new" > "$out_bin"
  chmod 0755 "$out_bin"
fi
exit 0
EOF
chmod 0755 "$MOCK_BIN_DIR/go"

# Mock install
cat << 'EOF' > "$MOCK_BIN_DIR/install"
#!/usr/bin/env bash
if [[ "${MOCK_INSTALL_FAIL:-0}" == "1" ]]; then
  echo "Mock install error: permission denied" >&2
  exit 1
fi
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|-o|-g)
      shift 2
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done
src="${args[0]}"
dst="${args[1]}"
cp -f "$src" "$dst"
chmod 0755 "$dst" 2>/dev/null || true
exit 0
EOF
chmod 0755 "$MOCK_BIN_DIR/install"

# Mock systemctl
cat << 'EOF' > "$MOCK_BIN_DIR/systemctl"
#!/usr/bin/env bash
cmd="${1:-}"
unit="${2:-}"

if [[ "$cmd" == "show" ]]; then
  echo "99999"
  exit 0
fi

if [[ "$cmd" == "is-active" ]]; then
  exit 0
fi

if [[ "$cmd" == "restart" ]]; then
  state_file="${MOCK_STATE_DIR}/restart_count"
  count=0
  if [[ -f "$state_file" ]]; then
    count="$(cat "$state_file")"
  fi
  count=$((count + 1))
  echo "$count" > "$state_file"

  if [[ "${MOCK_SYSTEMCTL_RESTART_FAIL_ALL:-0}" == "1" ]]; then
    echo "Mock systemctl: service restart failed (ALL)" >&2
    exit 1
  fi

  if [[ "${MOCK_SYSTEMCTL_RESTART_FAIL_FIRST:-0}" == "1" && "$count" -eq 1 ]]; then
    echo "Mock systemctl: service restart failed (FIRST)" >&2
    exit 1
  fi

  if [[ "${MOCK_SYSTEMCTL_RESTART_FAIL:-0}" == "1" ]]; then
    echo "Mock systemctl: service restart failed" >&2
    exit 1
  fi

  exit 0
fi

exit 0
EOF
chmod 0755 "$MOCK_BIN_DIR/systemctl"

# Export MOCK PATH
ORIG_PATH="$PATH"
export PATH="$MOCK_BIN_DIR:$PATH"
export KELVIN_ENV_FILE="$TEST_ENV_FILE"
export KELVIN_BIN_DIR="$TEST_WORKER_DIR"
export KELVIN_SKIP_HOST_VALIDATE=1
export MOCK_STATE_DIR="$MOCK_STATE_DIR"

DEPLOY_SCRIPT="$REPO_ROOT/scripts/deploy/staging-deploy.sh"

reset_test_state() {
  rm -rf "$MOCK_STATE_DIR"/*
  unset MOCK_GO_FAIL || true
  unset MOCK_INSTALL_FAIL || true
  unset MOCK_SYSTEMCTL_RESTART_FAIL || true
  unset MOCK_SYSTEMCTL_RESTART_FAIL_FIRST || true
  unset MOCK_SYSTEMCTL_RESTART_FAIL_ALL || true
}

# ------------------------------------------------------------------------------
# TEST 1: Successful Deployment
# ------------------------------------------------------------------------------
echo "--- Test 1: Successful Deployment ---"
reset_test_state
echo "mock_worker_v1_initial" > "$TEST_WORKER_DIR/kelvin-worker"
chmod 0755 "$TEST_WORKER_DIR/kelvin-worker"
rm -f "$TEST_WORKER_DIR/kelvin-worker.prev"

if out_1="$(bash "$DEPLOY_SCRIPT" 2>&1)"; then
  active_1="$(cat "$TEST_WORKER_DIR/kelvin-worker")"
  prev_1="$(cat "$TEST_WORKER_DIR/kelvin-worker.prev" 2>/dev/null || echo '')"
  if [[ "$active_1" == "mock_worker_binary_v2_new" && "$prev_1" == "mock_worker_v1_initial" ]]; then
    test_pass "Test 1: Deployment succeeded, binary atomically replaced, previous backed up"
  else
    test_fail "Test 1: Active or prev binary mismatch (active: $active_1, prev: $prev_1)"
  fi
else
  test_fail "Test 1: Deployment unexpectedly failed: $out_1"
fi

# ------------------------------------------------------------------------------
# TEST 2: Build failure before installation
# ------------------------------------------------------------------------------
echo "--- Test 2: Build Failure Before Installation ---"
reset_test_state
echo "mock_worker_v1_initial" > "$TEST_WORKER_DIR/kelvin-worker"
rm -f "$TEST_WORKER_DIR/kelvin-worker.prev"
export MOCK_GO_FAIL=1

if out_2="$(bash "$DEPLOY_SCRIPT" 2>&1)"; then
  test_fail "Test 2: Expected build failure, but deployment succeeded"
else
  active_2="$(cat "$TEST_WORKER_DIR/kelvin-worker")"
  if [[ "$active_2" == "mock_worker_v1_initial" ]]; then
    test_pass "Test 2: Build failure aborted cleanly, active binary untouched"
  else
    test_fail "Test 2: Active binary was corrupted on build failure: $active_2"
  fi
fi

# ------------------------------------------------------------------------------
# TEST 3: Installation failure
# ------------------------------------------------------------------------------
echo "--- Test 3: Installation Failure ---"
reset_test_state
echo "mock_worker_v1_initial" > "$TEST_WORKER_DIR/kelvin-worker"
rm -f "$TEST_WORKER_DIR/kelvin-worker.prev"
export MOCK_INSTALL_FAIL=1

if out_3="$(bash "$DEPLOY_SCRIPT" 2>&1)"; then
  test_fail "Test 3: Expected install failure, but deployment succeeded"
else
  active_3="$(cat "$TEST_WORKER_DIR/kelvin-worker")"
  if [[ "$active_3" == "mock_worker_v1_initial" ]]; then
    test_pass "Test 3: Install failure aborted cleanly, active binary preserved"
  else
    test_fail "Test 3: Active binary corrupted: $active_3"
  fi
fi

# ------------------------------------------------------------------------------
# TEST 4: Service restart failure with previous binary present (Rollback Success)
# ------------------------------------------------------------------------------
echo "--- Test 4: Service Restart Failure With Previous Binary Present ---"
reset_test_state
echo "mock_worker_v1_initial" > "$TEST_WORKER_DIR/kelvin-worker"
rm -f "$TEST_WORKER_DIR/kelvin-worker.prev"
export MOCK_SYSTEMCTL_RESTART_FAIL_FIRST=1

if out_4="$(bash "$DEPLOY_SCRIPT" 2>&1)"; then
  test_fail "Test 4: Expected restart failure, but deployment succeeded"
else
  active_4="$(cat "$TEST_WORKER_DIR/kelvin-worker")"
  if echo "$out_4" | grep -q "ROLLBACK SUCCESS" && [[ "$active_4" == "mock_worker_v1_initial" ]]; then
    test_pass "Test 4: Service restart failure restored previous binary and restarted successfully"
  else
    test_fail "Test 4: Rollback failed: active=$active_4, output=$out_4"
  fi
fi

# ------------------------------------------------------------------------------
# TEST 5: Service restart failure without previous binary
# ------------------------------------------------------------------------------
echo "--- Test 5: Service Restart Failure Without Previous Binary ---"
reset_test_state
rm -f "$TEST_WORKER_DIR/kelvin-worker"
rm -f "$TEST_WORKER_DIR/kelvin-worker.prev"
export MOCK_SYSTEMCTL_RESTART_FAIL=1

if out_5="$(bash "$DEPLOY_SCRIPT" 2>&1)"; then
  test_fail "Test 5: Expected restart failure, but deployment succeeded"
else
  if echo "$out_5" | grep -q "ROLLBACK UNAVAILABLE"; then
    test_pass "Test 5: Restart failure without backup correctly reported ROLLBACK UNAVAILABLE"
  else
    test_fail "Test 5: Output missing ROLLBACK UNAVAILABLE: $out_5"
  fi
fi

# ------------------------------------------------------------------------------
# TEST 6: Rollback restart failure
# ------------------------------------------------------------------------------
echo "--- Test 6: Rollback Restart Failure ---"
reset_test_state
echo "mock_worker_v1_initial" > "$TEST_WORKER_DIR/kelvin-worker"
rm -f "$TEST_WORKER_DIR/kelvin-worker.prev"
export MOCK_SYSTEMCTL_RESTART_FAIL_ALL=1

if out_6="$(bash "$DEPLOY_SCRIPT" 2>&1)"; then
  test_fail "Test 6: Expected restart failure, but deployment succeeded"
else
  if echo "$out_6" | grep -q "ROLLBACK FAILED"; then
    test_pass "Test 6: Secondary rollback failure reported ROLLBACK FAILED"
  else
    test_fail "Test 6: Output missing ROLLBACK FAILED: $out_6"
  fi
fi

# ------------------------------------------------------------------------------
# TEST 7: Temporary Directory Cleanup Verification
# ------------------------------------------------------------------------------
echo "--- Test 7: Temporary Directory Cleanup Verification ---"
lingering_tmp="$(find /tmp -maxdepth 1 -name "kelvin-worker-build.*" 2>/dev/null || true)"
if [[ -z "$lingering_tmp" ]]; then
  test_pass "Test 7: No temporary build directories remained in /tmp across all test runs"
else
  test_fail "Test 7: Found lingering build directories in /tmp: $lingering_tmp"
fi

echo "=============================================================================="
echo "Real Deployment Integration Results: $PASS_COUNT PASSED, $FAIL_COUNT FAILED"
echo "=============================================================================="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
echo "ALL DEPLOYMENT INTEGRATION TESTS PASSED!"
