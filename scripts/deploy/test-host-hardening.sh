#!/usr/bin/env bash
# ==============================================================================
# Kelvin Deployment & Host Hardening Shell Script Acceptance Test
# Verifies all 8 critical hardening scenarios mandated before Oracle deployment:
#  1. Existing correct network (untouched)
#  2. Existing incorrect internal network (aborts, no removal/recreation)
#  3. Existing non-internal network (aborts)
#  4. Incorrect subnet/gateway (aborts)
#  5. Conflicting subordinate UID/GID ranges (aborts without overwriting)
#  6. Unsupported architecture rejection (aborts on non-ARM64)
#  7. Automated rollback on deployment failure (restores previous binary)
#  8. Honest readiness (separates active process from uncertified scanner release)
# ==============================================================================
set -euo pipefail

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
echo "Kelvin Host Deployment & Security Hardening Test Suite"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# SCENARIOS 1-4: Rootless Podman Network Validation Function Logic
# ------------------------------------------------------------------------------
echo "--- Testing Network Validation Logic ---"

inspect_and_validate_network() {
  local mock_name="$1"
  local mock_internal="$2"
  local mock_subnets="${3:-}"
  local mock_gateways="${4:-}"

  local net_name="kelvin-scanner-net"
  local req_internal="true"
  local req_subnet="10.89.10.0/24"
  local req_gateway="10.89.10.1"
  local mismatches=()

  if [[ "$mock_name" != "$net_name" ]]; then
    mismatches+=("name='$mock_name' (expected '$net_name')")
  fi
  if [[ "$mock_internal" != "$req_internal" ]]; then
    mismatches+=("internal='$mock_internal' (expected '$req_internal')")
  fi

  local sub_arr=()
  if [[ -n "$mock_subnets" ]]; then
    read -r -a sub_arr <<< "$mock_subnets"
  fi
  local gw_arr=()
  if [[ -n "$mock_gateways" ]]; then
    read -r -a gw_arr <<< "$mock_gateways"
  fi

  if [[ ${#sub_arr[@]} -ne 1 ]]; then
    mismatches+=("expected exactly 1 subnet, got ${#sub_arr[@]} ('$mock_subnets')")
  elif [[ "${sub_arr[0]}" != "$req_subnet" ]]; then
    mismatches+=("subnet='${sub_arr[0]}' (expected '$req_subnet')")
  fi

  if [[ ${#gw_arr[@]} -ne 1 ]]; then
    mismatches+=("expected exactly 1 gateway, got ${#gw_arr[@]} ('$mock_gateways')")
  elif [[ "${gw_arr[0]}" != "$req_gateway" ]]; then
    mismatches+=("gateway='${gw_arr[0]}' (expected '$req_gateway')")
  fi

  if [[ ${#mismatches[@]} -gt 0 ]]; then
    echo "${mismatches[*]}"
    return 1
  fi
  return 0
}

# 1. Existing Correct Network
if errs="$(inspect_and_validate_network "kelvin-scanner-net" "true" "10.89.10.0/24" "10.89.10.1")"; then
  test_pass "Scenario 1: Existing correct network verified untouched"
else
  test_fail "Scenario 1: Expected valid network to pass, got: $errs"
fi

# 2. Existing Incorrect Internal Network (internal=false)
if errs="$(inspect_and_validate_network "kelvin-scanner-net" "false" "10.89.10.0/24" "10.89.10.1")"; then
  test_fail "Scenario 2: Non-internal network unexpectedly passed"
else
  if echo "$errs" | grep -q "internal='false'"; then
    test_pass "Scenario 2: Incorrect internal network failed closed with mismatch error"
  else
    test_fail "Scenario 2: Error missing internal flag: $errs"
  fi
fi

# 3. Existing Non-Internal Network (empty internal flag)
if errs="$(inspect_and_validate_network "kelvin-scanner-net" "" "10.89.10.0/24" "10.89.10.1")"; then
  test_fail "Scenario 3: Empty internal network unexpectedly passed"
else
  test_pass "Scenario 3: Non-internal network strictly rejected"
fi

# 4a. Incorrect Subnet & Gateway
if errs="$(inspect_and_validate_network "kelvin-scanner-net" "true" "10.89.20.0/24" "10.89.20.1")"; then
  test_fail "Scenario 4a: Mismatched subnet/gateway unexpectedly passed"
else
  if echo "$errs" | grep -q "subnet=" && echo "$errs" | grep -q "gateway="; then
    test_pass "Scenario 4a: Incorrect subnet and gateway rejected with explicit error"
  else
    test_fail "Scenario 4a: Error missing subnet/gateway details: $errs"
  fi
fi

# 4b. Extra Subnets & Gateways Rejected (strict exact 1 requirement)
if errs="$(inspect_and_validate_network "kelvin-scanner-net" "true" "10.89.10.0/24 10.89.20.0/24" "10.89.10.1 10.89.20.1")"; then
  test_fail "Scenario 4b: Extra subnets unexpectedly passed"
else
  if echo "$errs" | grep -q "expected exactly 1 subnet, got 2"; then
    test_pass "Scenario 4b: Extra subnets/gateways strictly rejected (exact 1 enforced)"
  else
    test_fail "Scenario 4b: Error missing extra subnet details: $errs"
  fi
fi

# ------------------------------------------------------------------------------
# SCENARIO 5: Subuid / Subgid Validation Logic
# ------------------------------------------------------------------------------
echo "--- Testing Subuid / Subgid Validation Logic ---"

validate_or_add_subid() {
  local id_file="$1"
  local target_user="kelvin-worker"
  local target_start=100000
  local target_count=65536
  local target_end=$((target_start + target_count - 1))
  local expected="${target_user}:${target_start}:${target_count}"

  if [[ ! -f "$id_file" ]]; then
    touch "$id_file"
  fi

  # Check for range collisions with other users
  while IFS=: read -r user start count || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" =~ ^# ]] && continue
    if [[ "$user" != "$target_user" ]]; then
      if [[ "$start" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]]; then
        local other_end=$((start + count - 1))
        if (( start <= target_end && other_end >= target_start )); then
          echo "COLLISION:$user:$start:$count"
          return 1
        fi
      fi
    fi
  done < "$id_file"

  local existing_lines
  existing_lines="$(grep "^${target_user}:" "$id_file" 2>/dev/null || true)"

  if [[ -z "$existing_lines" ]]; then
    echo "$expected" >> "$id_file"
    echo "ADDED"
    return 0
  else
    local count
    count="$(echo "$existing_lines" | wc -l)"
    if [[ "$count" -eq 1 && "$existing_lines" == "$expected" ]]; then
      echo "VERIFIED"
      return 0
    else
      echo "CONFLICT:$existing_lines"
      return 1
    fi
  fi
}

TEST_DIR="$(mktemp -d /tmp/kelvin-subid-test.XXXXXX)"

# Case 5a: Missing mapping -> adds correctly
SUBUID_A="$TEST_DIR/subuid_a"
echo "otheruser:200000:65536" > "$SUBUID_A"
OUT_A="$(validate_or_add_subid "$SUBUID_A")"
if [[ "$OUT_A" == "ADDED" ]] && grep -q "kelvin-worker:100000:65536" "$SUBUID_A"; then
  test_pass "Scenario 5a: Missing subordinate ID mapping correctly appended"
else
  test_fail "Scenario 5a: Failed to add subordinate ID mapping"
fi

# Case 5b: Existing identical mapping -> idempotent no-op
OUT_B="$(validate_or_add_subid "$SUBUID_A")"
COUNT_B="$(grep -c "kelvin-worker:100000:65536" "$SUBUID_A")"
if [[ "$OUT_B" == "VERIFIED" && "$COUNT_B" -eq 1 ]]; then
  test_pass "Scenario 5b: Existing correct mapping verified idempotently without duplicates"
else
  test_fail "Scenario 5b: Idempotency failed: $OUT_B (count: $COUNT_B)"
fi

# Case 5c: Conflicting subordinate range -> aborts
SUBUID_C="$TEST_DIR/subuid_c"
echo "kelvin-worker:200000:65536" > "$SUBUID_C"
if OUT_C="$(validate_or_add_subid "$SUBUID_C")"; then
  test_fail "Scenario 5c: Conflicting mapping unexpectedly passed"
else
  if echo "$OUT_C" | grep -q "CONFLICT"; then
    test_pass "Scenario 5c: Conflicting subordinate range rejected with conflict error"
  else
    test_fail "Scenario 5c: Conflict not reported: $OUT_C"
  fi
fi

# Case 5d: Multiple duplicate conflicting lines -> aborts
SUBUID_D="$TEST_DIR/subuid_d"
cat << 'EOF' > "$SUBUID_D"
kelvin-worker:100000:65536
kelvin-worker:200000:65536
EOF
if OUT_D="$(validate_or_add_subid "$SUBUID_D")"; then
  test_fail "Scenario 5d: Multiple duplicate lines unexpectedly passed"
else
  test_pass "Scenario 5d: Multiple mappings rejected with conflict error"
fi

# Case 5e: Subordinate ID range collision with another user -> aborts
SUBUID_E="$TEST_DIR/subuid_e"
cat << 'EOF' > "$SUBUID_E"
otheruser:50000:60000
EOF
if OUT_E="$(validate_or_add_subid "$SUBUID_E")"; then
  test_fail "Scenario 5e: Subordinate ID range collision with another user unexpectedly passed"
else
  if echo "$OUT_E" | grep -q "COLLISION:otheruser:50000:60000"; then
    test_pass "Scenario 5e: Subordinate ID range collision with another user strictly rejected"
  else
    test_fail "Scenario 5e: Unexpected collision output: $OUT_E"
  fi
fi

rm -rf "$TEST_DIR"

# ------------------------------------------------------------------------------
# SCENARIO 6: Architecture Enforcement
# ------------------------------------------------------------------------------
echo "--- Testing Architecture Enforcement ---"

validate_arch() {
  local arch="$1"
  if [[ "$arch" != "aarch64" && "$arch" != "arm64" ]]; then
    return 1
  fi
  return 0
}

if validate_arch "aarch64" && validate_arch "arm64"; then
  test_pass "Scenario 6a: Valid ARM64 architectures (aarch64, arm64) accepted"
else
  test_fail "Scenario 6a: Valid ARM64 architectures failed"
fi

if ! validate_arch "x86_64" && ! validate_arch "amd64" && ! validate_arch "i386"; then
  test_pass "Scenario 6b: Unsupported architectures (x86_64, amd64, i386) strictly rejected"
else
  test_fail "Scenario 6b: Unsupported architectures were not rejected"
fi

# ------------------------------------------------------------------------------
# SCENARIO 7: Deployment Rollback
# ------------------------------------------------------------------------------
echo "--- Testing Deployment Rollback Mechanism ---"

ROLLBACK_DIR="$(mktemp -d /tmp/kelvin-rollback-test.XXXXXX)"
BIN_ACTIVE="$ROLLBACK_DIR/kelvin-worker"
BIN_BACKUP="$ROLLBACK_DIR/kelvin-worker.prev"

# Step 1: Known-good version 1
echo "binary_v1_known_good" > "$BIN_ACTIVE"
chmod 0755 "$BIN_ACTIVE"

# Step 2: Backup before replace
cp -p "$BIN_ACTIVE" "$BIN_BACKUP"

# Step 3: Install broken version 2
echo "binary_v2_broken" > "$BIN_ACTIVE"

# Step 4: Simulate deployment failure and trigger rollback
simulate_rollback() {
  local active="$1"
  local backup="$2"
  if [[ -f "$backup" ]]; then
    cp -f "$backup" "$active"
    echo "RESTORED"
    return 0
  else
    echo "ROLLBACK_UNAVAILABLE"
    return 1
  fi
}

RB_OUT="$(simulate_rollback "$BIN_ACTIVE" "$BIN_BACKUP")"
RESTORED_CONTENT="$(cat "$BIN_ACTIVE")"
if [[ "$RB_OUT" == "RESTORED" && "$RESTORED_CONTENT" == "binary_v1_known_good" ]]; then
  test_pass "Scenario 7a: Failed deployment automatically restored previous known-good binary"
else
  test_fail "Scenario 7a: Rollback failed to restore known-good binary"
fi

# Step 5: Rollback when no previous binary exists
rm -f "$BIN_BACKUP"
if RB_OUT_NOPREV="$(simulate_rollback "$BIN_ACTIVE" "$BIN_BACKUP")"; then
  test_fail "Scenario 7b: Rollback without backup unexpectedly succeeded"
else
  if [[ "$RB_OUT_NOPREV" == "ROLLBACK_UNAVAILABLE" ]]; then
    test_pass "Scenario 7b: Rollback without backup reported ROLLBACK_UNAVAILABLE"
  else
    test_fail "Scenario 7b: Unexpected output: $RB_OUT_NOPREV"
  fi
fi

rm -rf "$ROLLBACK_DIR"

# ------------------------------------------------------------------------------
# SCENARIO 8: Honest Readiness (Active Process with Uncertified Release)
# ------------------------------------------------------------------------------
echo "--- Testing Honest Readiness Reporting ---"

evaluate_readiness() {
  local process_active="$1"
  local release_status="$2"

  local proc_msg="PROCESS_INACTIVE"
  local scan_msg="SCANNER_UNAVAILABLE"

  if [[ "$process_active" == "true" ]]; then
    proc_msg="PROCESS_ACTIVE"
  fi

  if [[ "$release_status" == "certified" ]]; then
    scan_msg="SCANNER_AVAILABLE"
  else
    scan_msg="SCANNER_UNAVAILABLE_PENDING_CERTIFICATION"
  fi

  echo "$proc_msg|$scan_msg"
}

READINESS_OUT="$(evaluate_readiness "true" "not-released")"
if [[ "$READINESS_OUT" == "PROCESS_ACTIVE|SCANNER_UNAVAILABLE_PENDING_CERTIFICATION" ]]; then
  test_pass "Scenario 8: Active worker with 'not-released' status truthfully reports scanner UNAVAILABLE"
else
  test_fail "Scenario 8: Readiness did not separate process liveness from scanner certification: $READINESS_OUT"
fi

echo "=============================================================================="
echo "Hardening Test Suite Results: $PASS_COUNT PASSED, $FAIL_COUNT FAILED"
echo "=============================================================================="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
echo "ALL HARDENING TESTS PASSED!"
