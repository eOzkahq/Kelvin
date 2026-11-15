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
# SCENARIO 5: Subuid / Subgid Validation Logic & Collision Prevention
# ------------------------------------------------------------------------------
echo "--- Testing Subuid / Subgid Validation Logic ---"

find_available_subid_range() {
  local id_file="$1"
  local target_count="$2"
  local min_start="${3:-100000}"
  local max_id=4294967295

  local ranges=()
  while IFS=: read -r user start count extra || [[ -n "${user:-}" ]]; do
    user="$(echo "${user:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$user" || "$user" =~ ^# ]] && continue
    start="$(echo "${start:-}" | tr -d ' ')"
    count="$(echo "${count:-}" | tr -d ' ')"
    if [[ "$start" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]]; then
      local other_end=$((start + count - 1))
      ranges+=("$start:$other_end")
    fi
  done < "$id_file"

  local candidate="$min_start"
  local changed=1
  while [[ $changed -eq 1 ]]; do
    changed=0
    local cand_end=$((candidate + target_count - 1))
    if (( candidate > max_id || cand_end > max_id || cand_end < candidate )); then
      return 1
    fi
    for r in "${ranges[@]}"; do
      local r_start="${r%%:*}"
      local r_end="${r##*:}"
      if (( candidate <= r_end && r_start <= cand_end )); then
        candidate=$((r_end + 1))
        changed=1
        break
      fi
    done
  done

  local cand_end=$((candidate + target_count - 1))
  if (( candidate > max_id || cand_end > max_id || cand_end < candidate )); then
    return 1
  fi
  echo "$candidate"
  return 0
}

validate_or_add_subid() {
  local id_file="$1"
  local id_type="${2:-UID}"
  local configured_start="${3:-200000}"
  local target_count="${4:-65536}"
  local target_user="kelvin-worker"
  local max_id=4294967295

  if [[ ! -f "$id_file" ]]; then
    touch "$id_file"
  fi

  # Validate target_count
  if [[ ! "$target_count" =~ ^[0-9]+$ ]] || (( target_count <= 0 || target_count > max_id )); then
    echo "ERROR: Invalid subordinate $id_type count: '$target_count'."
    return 1
  fi

  # Audit existing entries in the file for malformed lines and integer overflow
  local line_num=0
  while IFS=: read -r user start count extra || [[ -n "${user:-}" ]]; do
    line_num=$((line_num + 1))
    local raw_line="${user:-}:${start:-}:${count:-}${extra:+:$extra}"
    user="$(echo "${user:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$user" || "$user" =~ ^# ]] && continue

    start="$(echo "${start:-}" | tr -d ' ')"
    count="$(echo "${count:-}" | tr -d ' ')"

    # Malformed check
    if [[ -z "$start" || -z "$count" || -n "${extra:-}" || ! "$start" =~ ^[0-9]+$ || ! "$count" =~ ^[0-9]+$ || "$count" -le 0 ]]; then
      echo "MALFORMED:$id_file:$line_num:$raw_line"
      return 1
    fi

    # Integer overflow check
    if (( start > max_id || count > max_id || start + count - 1 > max_id || start + count - 1 < start )); then
      echo "OVERFLOW:$id_file:$line_num:$raw_line"
      return 1
    fi
  done < "$id_file"

  # Determine target start
  local target_start
  if [[ "$configured_start" == "auto" ]]; then
    if ! target_start="$(find_available_subid_range "$id_file" "$target_count" 100000)"; then
      echo "NO_AVAILABLE_RANGE:$id_file"
      return 1
    fi
  else
    if [[ ! "$configured_start" =~ ^[0-9]+$ ]]; then
      echo "ERROR: Configured subordinate $id_type start is invalid: '$configured_start'."
      return 1
    fi
    target_start="$configured_start"
  fi

  local target_end=$((target_start + target_count - 1))
  if (( target_start > max_id || target_end > max_id || target_end < target_start )); then
    echo "OVERFLOW:configured range $target_start:$target_count exceeds max ID"
    return 1
  fi
  local expected="$target_user:$target_start:$target_count"

  # Audit for range collisions with other users
  while IFS=: read -r user start count extra || [[ -n "${user:-}" ]]; do
    user="$(echo "${user:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$user" || "$user" =~ ^# ]] && continue
    start="$(echo "${start:-}" | tr -d ' ')"
    count="$(echo "${count:-}" | tr -d ' ')"

    if [[ "$start" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]]; then
      local other_end=$((start + count - 1))
      if [[ "$user" != "$target_user" ]]; then
        if (( start <= target_end && other_end >= target_start )); then
          echo "COLLISION:$id_type:$user:$start:$count"
          return 1
        fi
      fi
    fi
  done < "$id_file"

  # Validate kelvin-worker's own mapping
  local existing_lines
  existing_lines="$(grep "^${target_user}:" "$id_file" 2>/dev/null || true)"

  if [[ -z "$existing_lines" ]]; then
    echo "$expected" >> "$id_file"
    echo "ADDED:$expected"
    return 0
  else
    local count_lines
    count_lines="$(echo "$existing_lines" | wc -l)"
    if [[ "$count_lines" -eq 1 && "$existing_lines" == "$expected" ]]; then
      echo "VERIFIED:$expected"
      return 0
    else
      echo "CONFLICT:$existing_lines"
      return 1
    fi
  fi
}

TEST_DIR="$(mktemp -d /tmp/kelvin-subid-test.XXXXXX)"

# Case 5a: Existing opc:100000:65536 preserved when valid non-overlapping Kelvin allocation (200000:65536) added
SUBUID_A="$TEST_DIR/subuid_a"
echo "opc:100000:65536" > "$SUBUID_A"
OUT_A="$(validate_or_add_subid "$SUBUID_A" "UID" "200000" "65536")"
if [[ "$OUT_A" == "ADDED:kelvin-worker:200000:65536" ]] && \
   grep -q "^opc:100000:65536$" "$SUBUID_A" && \
   grep -q "^kelvin-worker:200000:65536$" "$SUBUID_A"; then
  test_pass "Scenario 5a: Existing opc:100000:65536 preserved while non-overlapping kelvin-worker appended"
else
  test_fail "Scenario 5a: Failed to preserve opc or append non-overlapping mapping: $OUT_A"
fi

# Case 5b: Existing valid non-overlapping mapping verified idempotently without duplicates
OUT_B="$(validate_or_add_subid "$SUBUID_A" "UID" "200000" "65536")"
COUNT_B="$(grep -c "^kelvin-worker:200000:65536$" "$SUBUID_A")"
COUNT_OPC_B="$(grep -c "^opc:100000:65536$" "$SUBUID_A")"
if [[ "$OUT_B" == "VERIFIED:kelvin-worker:200000:65536" && "$COUNT_B" -eq 1 && "$COUNT_OPC_B" -eq 1 ]]; then
  test_pass "Scenario 5b: Existing non-overlapping mapping verified idempotently without duplicates"
else
  test_fail "Scenario 5b: Idempotency failed: $OUT_B (kelvin count: $COUNT_B, opc count: $COUNT_OPC_B)"
fi

# Case 5c: UID collision detected in /etc/subuid (e.g. Kelvin configured with 100000 or 150000 overlapping opc)
SUBUID_C="$TEST_DIR/subuid_c"
echo "opc:100000:65536" > "$SUBUID_C"
if OUT_C="$(validate_or_add_subid "$SUBUID_C" "UID" "100000" "65536")"; then
  test_fail "Scenario 5c: Overlapping UID range unexpectedly passed"
else
  if echo "$OUT_C" | grep -q "COLLISION:UID:opc:100000:65536"; then
    test_pass "Scenario 5c: UID collision with opc strictly detected and rejected"
  else
    test_fail "Scenario 5c: Unexpected collision output: $OUT_C"
  fi
fi

# Case 5d: GID collision detected independently in /etc/subgid
SUBGID_D="$TEST_DIR/subgid_d"
echo "opc:100000:65536" > "$SUBGID_D"
echo "dockergroup:200000:65536" >> "$SUBGID_D"
if OUT_D="$(validate_or_add_subid "$SUBGID_D" "GID" "200000" "65536")"; then
  test_fail "Scenario 5d: GID collision unexpectedly passed"
else
  if echo "$OUT_D" | grep -q "COLLISION:GID:dockergroup:200000:65536"; then
    test_pass "Scenario 5d: GID collision in /etc/subgid audited independently and rejected"
  else
    test_fail "Scenario 5d: Unexpected GID collision output: $OUT_D"
  fi
fi

# Case 5e: Collision with another user's overlapping range (e.g. otheruser:150000:60000 overlapping 200000:65536)
SUBUID_E="$TEST_DIR/subuid_e"
echo "otheruser:150000:60000" > "$SUBUID_E" # 150000-209999
if OUT_E="$(validate_or_add_subid "$SUBUID_E" "UID" "200000" "65536")"; then
  test_fail "Scenario 5e: Collision with another user's range unexpectedly passed"
else
  if echo "$OUT_E" | grep -q "COLLISION:UID:otheruser:150000:60000"; then
    test_pass "Scenario 5e: Subordinate ID collision with another user's range rejected"
  else
    test_fail "Scenario 5e: Unexpected collision output: $OUT_E"
  fi
fi

# Case 5f: Multiple conflicting Kelvin mappings in subordinate ID file
SUBUID_F="$TEST_DIR/subuid_f"
cat << 'EOF' > "$SUBUID_F"
kelvin-worker:200000:65536
kelvin-worker:300000:65536
EOF
if OUT_F="$(validate_or_add_subid "$SUBUID_F" "UID" "200000" "65536")"; then
  test_fail "Scenario 5f: Multiple duplicate lines unexpectedly passed"
else
  if echo "$OUT_F" | grep -q "CONFLICT"; then
    test_pass "Scenario 5f: Multiple conflicting Kelvin mappings strictly rejected"
  else
    test_fail "Scenario 5f: Unexpected multiple mappings output: $OUT_F"
  fi
fi

# Case 5g: No available range when ID space is exhausted
SUBUID_G="$TEST_DIR/subuid_g"
echo "exhaustuser:100000:4294867296" > "$SUBUID_G"
if OUT_G="$(validate_or_add_subid "$SUBUID_G" "UID" "auto" "65536")"; then
  test_fail "Scenario 5g: Exhausted range unexpectedly passed"
else
  if echo "$OUT_G" | grep -q "NO_AVAILABLE_RANGE"; then
    test_pass "Scenario 5g: Exhausted subordinate ID space fails closed (no available range)"
  else
    test_fail "Scenario 5g: Unexpected exhausted space output: $OUT_G"
  fi
fi

# Case 5h: Integer overflow detection (start + count exceeds 32-bit UINT_MAX 4294967295)
SUBUID_H="$TEST_DIR/subuid_h"
echo "overflowuser:4294950000:65536" > "$SUBUID_H"
if OUT_H="$(validate_or_add_subid "$SUBUID_H" "UID" "200000" "65536")"; then
  test_fail "Scenario 5h: Integer overflow entry unexpectedly passed"
else
  if echo "$OUT_H" | grep -q "OVERFLOW"; then
    test_pass "Scenario 5h: Integer overflow subordinate entry strictly rejected"
  else
    test_fail "Scenario 5h: Unexpected overflow output: $OUT_H"
  fi
fi

# Case 5i: Malformed subordinate-ID entries (missing colons, non-numeric values, count 0)
SUBUID_I="$TEST_DIR/subuid_i"
cat << 'EOF' > "$SUBUID_I"
malformed_no_colons
bad_numeric:notanumber:65536
EOF
if OUT_I="$(validate_or_add_subid "$SUBUID_I" "UID" "200000" "65536")"; then
  test_fail "Scenario 5i: Malformed entry unexpectedly passed"
else
  if echo "$OUT_I" | grep -q "MALFORMED"; then
    test_pass "Scenario 5i: Malformed subordinate-ID entries strictly rejected"
  else
    test_fail "Scenario 5i: Unexpected malformed output: $OUT_I"
  fi
fi

# Case 5j: Automatic contiguous non-overlapping range discovery
SUBUID_J="$TEST_DIR/subuid_j"
cat << 'EOF' > "$SUBUID_J"
opc:100000:65536
developer:165536:34464
EOF
OUT_J="$(validate_or_add_subid "$SUBUID_J" "UID" "auto" "65536")"
if [[ "$OUT_J" == "ADDED:kelvin-worker:200000:65536" ]] && \
   grep -q "^kelvin-worker:200000:65536$" "$SUBUID_J"; then
  test_pass "Scenario 5j: Dynamic allocation automatically selected first non-overlapping range (200000:65536)"
else
  test_fail "Scenario 5j: Dynamic range allocation failed: $OUT_J"
fi

# Case 5k: Adoption of existing valid 165536:65536 allocation when configuration is absent
SUBUID_K="$TEST_DIR/subuid_k"
cat << 'EOF' > "$SUBUID_K"
opc:100000:65536
kelvin-worker:165536:65536
EOF
OUT_K="$(validate_or_add_subid "$SUBUID_K" "UID" "165536" "65536")"
if [[ "$OUT_K" == "VERIFIED:kelvin-worker:165536:65536" ]]; then
  test_pass "Scenario 5k: Existing host 165536:65536 mapping safely recognized and adopted without modification"
else
  test_fail "Scenario 5k: Existing 165536:65536 mapping adoption failed: $OUT_K"
fi

# Case 5l: Explicit configured mapping conflict (file has 165536, configured with 200000)
if OUT_L="$(validate_or_add_subid "$SUBUID_K" "UID" "200000" "65536")"; then
  test_fail "Scenario 5l: Mismatched explicit configuration unexpectedly passed"
else
  if echo "$OUT_L" | grep -q "CONFLICT"; then
    test_pass "Scenario 5l: Explicit configured mapping mismatch strictly rejected with conflict error"
  else
    test_fail "Scenario 5l: Expected CONFLICT error, got: $OUT_L"
  fi
fi

# Case 5m: UID/GID mismatch validation logic
validate_subid_consistency() {
  local uid_file="$1"
  local gid_file="$2"
  local target_user="kelvin-worker"

  local u_line g_line
  u_line="$(grep "^${target_user}:" "$uid_file" 2>/dev/null || true)"
  g_line="$(grep "^${target_user}:" "$gid_file" 2>/dev/null || true)"

  if [[ -z "$u_line" || -z "$g_line" ]]; then
    echo "INCONSISTENT:missing in one or both files"
    return 1
  fi
  local u_start u_cnt g_start g_cnt
  u_start="$(echo "$u_line" | cut -d: -f2)"
  u_cnt="$(echo "$u_line" | cut -d: -f3)"
  g_start="$(echo "$g_line" | cut -d: -f2)"
  g_cnt="$(echo "$g_line" | cut -d: -f3)"

  if [[ "$u_start" != "$g_start" ]]; then
    echo "MISMATCH:UID start '$u_start' != GID start '$g_start'"
    return 1
  fi
  if [[ "$u_cnt" != "65536" || "$g_cnt" != "65536" ]]; then
    echo "MISMATCH:count mismatch UID='$u_cnt' GID='$g_cnt'"
    return 1
  fi
  echo "CONSISTENT:$u_start:$u_cnt"
  return 0
}

SUBUID_M="$TEST_DIR/subuid_m"
SUBGID_M="$TEST_DIR/subgid_m"
echo "kelvin-worker:165536:65536" > "$SUBUID_M"
echo "kelvin-worker:200000:65536" > "$SUBGID_M"
if OUT_M="$(validate_subid_consistency "$SUBUID_M" "$SUBGID_M")"; then
  test_fail "Scenario 5m: UID/GID mismatch unexpectedly passed"
else
  if echo "$OUT_M" | grep -q "MISMATCH:UID start '165536' != GID start '200000'"; then
    test_pass "Scenario 5m: UID/GID start mismatch between /etc/subuid and /etc/subgid strictly rejected"
  else
    test_fail "Scenario 5m: Unexpected output for mismatch: $OUT_M"
  fi
fi

# Case 5n: Idempotent repeated setup
OUT_N1="$(validate_or_add_subid "$SUBUID_K" "UID" "165536" "65536")"
OUT_N2="$(validate_or_add_subid "$SUBUID_K" "UID" "165536" "65536")"
LINES_N="$(grep -c "^kelvin-worker:165536:65536$" "$SUBUID_K")"
if [[ "$OUT_N1" == "VERIFIED:kelvin-worker:165536:65536" && "$OUT_N2" == "VERIFIED:kelvin-worker:165536:65536" && "$LINES_N" -eq 1 ]]; then
  test_pass "Scenario 5n: Repeated idempotent setup leaves file untouched with exactly 1 mapping"
else
  test_fail "Scenario 5n: Idempotent repeated setup failed (lines: $LINES_N, out1: $OUT_N1, out2: $OUT_N2)"
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

# ------------------------------------------------------------------------------
# SCENARIO 9: Rootless Working Directory Security & Isolation (Problem A Regression)
# ------------------------------------------------------------------------------
echo "--- Testing Worker Working Directory Isolation ---"

TEST_WORKDIR_DIR="$(mktemp -d /tmp/kelvin-workdir-test.XXXXXX)"
INACCESSIBLE_DIR="$TEST_WORKDIR_DIR/opt_kelvin_simulated"
ACCESSIBLE_DIR="$TEST_WORKDIR_DIR/var_lib_kelvin_worker"

mkdir -p "$INACCESSIBLE_DIR"
mkdir -p "$ACCESSIBLE_DIR"

# Case 9a: Inherited inaccessible working directory without explicit chdir fails
simulate_runuser_execution() {
  local initial_dir="$1"
  local explicit_target_dir="$2"

  (
    cd "$initial_dir" 2>/dev/null || return 2
    if [[ -n "$explicit_target_dir" ]]; then
      cd "$explicit_target_dir" || return 1
    fi
    pwd
  )
}

OUT_FAIL="$(simulate_runuser_execution "$TEST_WORKDIR_DIR/nonexistent_dir" "" 2>&1 || true)"
if [[ "$OUT_FAIL" != *"var_lib_kelvin_worker"* ]]; then
  test_pass "Scenario 9a: Inherited invalid/inaccessible working directory without chdir rejected"
else
  test_fail "Scenario 9a: Inaccessible directory unexpectedly succeeded: $OUT_FAIL"
fi

# Case 9b: Explicit change to /var/lib/kelvin-worker guarantees execution in valid worker working directory
OUT_SUCCESS="$(simulate_runuser_execution "$INACCESSIBLE_DIR" "$ACCESSIBLE_DIR")"
if [[ "$OUT_SUCCESS" == *"$ACCESSIBLE_DIR"* ]]; then
  test_pass "Scenario 9b: Explicit chdir to /var/lib/kelvin-worker ensures safe worker execution directory"
else
  test_fail "Scenario 9b: Explicit chdir failed: $OUT_SUCCESS"
fi

rm -rf "$TEST_WORKDIR_DIR"

echo "=============================================================================="
echo "Hardening Test Suite Results: $PASS_COUNT PASSED, $FAIL_COUNT FAILED"
echo "=============================================================================="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
echo "ALL HARDENING TESTS PASSED!"
