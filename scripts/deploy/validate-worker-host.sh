#!/usr/bin/env bash
# ==============================================================================
# Kelvin Host Worker Environment Validation Script
# Targets: Oracle Linux Server 9.8 (ARM64 / aarch64)
# Verifies all prerequisites mandated by ADR-0008 Option A
# ==============================================================================
set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

check_pass() {
  echo "  [PASS] $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

check_fail() {
  echo "  [FAIL] $1" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

check_warn() {
  echo "  [WARN] $1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

echo "=============================================================================="
echo "Kelvin Host Execution Worker Environment Audit (ADR-0008)"
echo "=============================================================================="

# 1. Operating System
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  echo "Operating System: $NAME $VERSION"
  if [[ "$ID" == "ol" || "$ID_LIKE" =~ "rhel" || "$ID_LIKE" =~ "fedora" ]]; then
    check_pass "Operating system is enterprise Linux 9 compatible ($PRETTY_NAME)"
  else
    check_warn "OS is $PRETTY_NAME; staging target is Oracle Linux 9.8"
  fi
else
  check_fail "/etc/os-release not found"
fi

# 2. CPU Architecture
ARCH="$(uname -m)"
echo "Architecture: $ARCH"
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  check_pass "CPU architecture is ARM64 ($ARCH)"
else
  check_fail "CPU architecture is '$ARCH'; staging requires aarch64 or arm64 per ADR-0008"
fi

# 3. Kernel cgroups v2 and Controllers
if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  CONTROLLERS="$(cat /sys/fs/cgroup/cgroup.controllers)"
  echo "Available cgroup controllers: $CONTROLLERS"
  MISSING_CTRL=0
  for ctrl in cpu memory pids; do
    if ! echo "$CONTROLLERS" | grep -qw "$ctrl"; then
      check_fail "cgroups v2 missing mandatory controller: $ctrl"
      MISSING_CTRL=1
    fi
  done
  if [[ $MISSING_CTRL -eq 0 ]]; then
    check_pass "cgroups v2 active with cpu, memory, and pids controllers"
  fi
else
  check_fail "cgroups v2 not active (/sys/fs/cgroup/cgroup.controllers missing)"
fi

# 4. Dedicated Unprivileged Execution Identity
if id -u kelvin-worker >/dev/null 2>&1; then
  WORKER_UID="$(id -u kelvin-worker)"
  WORKER_GID="$(id -g kelvin-worker)"
  if [[ "$WORKER_UID" -eq 10001 && "$WORKER_GID" -eq 10001 ]]; then
    check_pass "User kelvin-worker exists with dedicated UID/GID 10001:10001"
  else
    check_fail "User kelvin-worker exists but UID:GID is $WORKER_UID:$WORKER_GID (expected 10001:10001)"
  fi
else
  check_fail "User kelvin-worker does not exist. Run scripts/deploy/setup-rootless-podman.sh."
fi

# 5. Subuid and Subgid Configuration & Range Collision Audit
# Audits /etc/subuid and /etc/subgid independently, rejects malformed/overflow entries,
# and verifies the exact non-overlapping range allocated for kelvin-worker.
ENV_FILE="${KELVIN_ENV_FILE:-/etc/kelvin/worker.env}"
if [[ -f "$ENV_FILE" ]]; then
  cfg_subuid="$(grep -E '^KELVIN_SUBUID_START=' "$ENV_FILE" 2>/dev/null | head -n 1 | cut -d'=' -f2- || true)"
  cfg_subgid="$(grep -E '^KELVIN_SUBGID_START=' "$ENV_FILE" 2>/dev/null | head -n 1 | cut -d'=' -f2- || true)"
  cfg_subid="$(grep -E '^KELVIN_SUBID_START=' "$ENV_FILE" 2>/dev/null | head -n 1 | cut -d'=' -f2- || true)"
  cfg_count="$(grep -E '^KELVIN_SUBID_COUNT=' "$ENV_FILE" 2>/dev/null | head -n 1 | cut -d'=' -f2- || true)"

  cfg_subuid="${cfg_subuid//\"/}"; cfg_subuid="${cfg_subuid//\'/}"
  cfg_subgid="${cfg_subgid//\"/}"; cfg_subgid="${cfg_subgid//\'/}"
  cfg_subid="${cfg_subid//\"/}"; cfg_subid="${cfg_subid//\'/}"
  cfg_count="${cfg_count//\"/}"; cfg_count="${cfg_count//\'/}"

  [[ -z "${KELVIN_SUBUID_START:-}" && -n "$cfg_subuid" ]] && KELVIN_SUBUID_START="$cfg_subuid"
  [[ -z "${KELVIN_SUBGID_START:-}" && -n "$cfg_subgid" ]] && KELVIN_SUBGID_START="$cfg_subgid"
  [[ -z "${KELVIN_SUBID_START:-}" && -n "$cfg_subid" ]] && KELVIN_SUBID_START="$cfg_subid"
  [[ -z "${KELVIN_SUBID_COUNT:-}" && -n "$cfg_count" ]] && KELVIN_SUBID_COUNT="$cfg_count"
fi

KELVIN_SUBID_COUNT="${KELVIN_SUBID_COUNT:-65536}"
KELVIN_SUBUID_START="${KELVIN_SUBUID_START:-${KELVIN_SUBID_START:-200000}}"
KELVIN_SUBGID_START="${KELVIN_SUBGID_START:-${KELVIN_SUBID_START:-200000}}"

validate_subid_mapping() {
  local id_file="$1"
  local id_type="$2" # UID or GID
  local configured_start="$3"
  local target_count="${4:-65536}"
  local target_user="kelvin-worker"
  local max_id=4294967295

  if [[ ! -f "$id_file" ]]; then
    check_fail "$id_file does not exist"
    return
  fi

  # Audit existing entries in the file for malformed lines and integer overflow
  local line_num=0
  local file_has_errors=0
  while IFS=: read -r user start count extra || [[ -n "${user:-}" ]]; do
    line_num=$((line_num + 1))
    local raw_line="${user:-}:${start:-}:${count:-}${extra:+:$extra}"
    user="$(echo "${user:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$user" || "$user" =~ ^# ]] && continue

    start="$(echo "${start:-}" | tr -d ' ')"
    count="$(echo "${count:-}" | tr -d ' ')"

    # Malformed check: must have user, start, count
    if [[ -z "$start" || -z "$count" || -n "${extra:-}" || ! "$start" =~ ^[0-9]+$ || ! "$count" =~ ^[0-9]+$ || "$count" -le 0 ]]; then
      check_fail "Malformed subordinate $id_type entry in $id_file at line $line_num: '$raw_line'"
      file_has_errors=1
      continue
    fi

    # Integer overflow check
    if (( start > max_id || count > max_id || start + count - 1 > max_id || start + count - 1 < start )); then
      check_fail "Subordinate $id_type entry integer overflow in $id_file at line $line_num: '$raw_line'"
      file_has_errors=1
      continue
    fi
  done < "$id_file"

  if [[ $file_has_errors -eq 1 ]]; then
    return
  fi

  # Check kelvin-worker's mapping
  local existing_lines
  existing_lines="$(grep "^${target_user}:" "$id_file" 2>/dev/null || true)"

  if [[ -z "$existing_lines" ]]; then
    check_fail "$id_file missing configuration for $target_user"
    return
  fi

  local count_lines
  count_lines="$(echo "$existing_lines" | wc -l)"
  if [[ "$count_lines" -ne 1 ]]; then
    check_fail "Multiple conflicting subordinate $id_type mappings in $id_file for $target_user (found: '$existing_lines')"
    return
  fi

  local actual_start actual_count
  actual_start="$(echo "$existing_lines" | cut -d: -f2)"
  actual_count="$(echo "$existing_lines" | cut -d: -f3)"

  if [[ "$configured_start" != "auto" && "$actual_start" != "$configured_start" ]]; then
    check_fail "Conflicting subordinate $id_type mapping in $id_file for $target_user (found: '$existing_lines', expected: '$target_user:$configured_start:$target_count')"
    return
  fi

  if [[ "$actual_count" != "$target_count" ]]; then
    check_fail "Subordinate $id_type range size mismatch in $id_file for $target_user (found count $actual_count, expected $target_count)"
    return
  fi

  local target_start="$actual_start"
  local target_end=$((target_start + target_count - 1))
  if (( target_start > max_id || target_end > max_id || target_end < target_start )); then
    check_fail "Subordinate $id_type range integer overflow for $target_user: $target_start:$target_count exceeds max ID $max_id"
    return
  fi

  # Audit for range collisions with other users
  local collision_found=0
  while IFS=: read -r user start count extra || [[ -n "${user:-}" ]]; do
    user="$(echo "${user:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$user" || "$user" =~ ^# ]] && continue
    start="$(echo "${start:-}" | tr -d ' ')"
    count="$(echo "${count:-}" | tr -d ' ')"

    if [[ "$start" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]]; then
      local other_end=$((start + count - 1))
      if [[ "$user" != "$target_user" ]]; then
        if (( start <= target_end && other_end >= target_start )); then
          check_fail "Subordinate $id_type range collision in $id_file: user '$user' ($start:$count [$start-$other_end]) overlaps with $target_user ($target_start:$target_count [$target_start-$target_end])"
          collision_found=1
        fi
      fi
    fi
  done < "$id_file"

  if [[ $collision_found -eq 0 ]]; then
    check_pass "$id_file configured with verified non-overlapping $id_type mapping ($existing_lines)"
  fi
}

validate_subid_mapping "/etc/subuid" "UID" "$KELVIN_SUBUID_START" "$KELVIN_SUBID_COUNT"
validate_subid_mapping "/etc/subgid" "GID" "$KELVIN_SUBGID_START" "$KELVIN_SUBID_COUNT"

# 6. Systemd User Session Linger
if command -v loginctl >/dev/null 2>&1; then
  LINGER_STATUS="$(loginctl show-user kelvin-worker --property=Linger 2>/dev/null || echo 'Linger=no')"
  if [[ "$LINGER_STATUS" == "Linger=yes" ]]; then
    check_pass "Systemd linger is enabled for kelvin-worker ($LINGER_STATUS)"
  else
    check_fail "Systemd linger not enabled for kelvin-worker ($LINGER_STATUS). Run: loginctl enable-linger kelvin-worker"
  fi
else
  check_warn "loginctl not available to verify user linger"
fi

# 7. Podman Executable & crun Runtime
if command -v podman >/dev/null 2>&1; then
  PODMAN_BIN="$(command -v podman)"
  PODMAN_VER="$(podman --version 2>/dev/null || echo 'unknown')"
  check_pass "Podman available: $PODMAN_BIN ($PODMAN_VER)"
else
  check_fail "Podman binary not found in PATH"
fi

if command -v crun >/dev/null 2>&1; then
  CRUN_BIN="$(command -v crun)"
  CRUN_VER="$(crun --version 2>/dev/null | head -n 1 || echo 'unknown')"
  check_pass "crun runtime available: $CRUN_BIN ($CRUN_VER)"
else
  check_fail "crun binary not found in PATH (mandatory OCI runtime per ADR-0008)"
fi

# 8. Internal Scanner Network (kelvin-scanner-net) Properties
NETWORK_CHECK_CMD='
  export XDG_RUNTIME_DIR="/run/user/10001"
  NET_NAME="kelvin-scanner-net"
  REQ_INTERNAL="true"
  REQ_SUBNET="10.89.10.0/24"
  REQ_GATEWAY="10.89.10.1"

  if ! raw_json="$(podman network inspect "$NET_NAME" 2>&1)"; then
    if echo "$raw_json" | grep -qi "no such network\|not found"; then
      echo "NET_NOT_FOUND"
    else
      echo "NET_INSPECT_ERROR: $raw_json"
    fi
    exit 0
  fi

  if [[ -z "${raw_json//[[:space:]]/}" ]]; then
    echo "NET_MALFORMED: Inspection output is empty"
    exit 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c '\''
import json, sys
try:
    data = json.loads(sys.stdin.read())
    if isinstance(data, list):
        if len(data) != 1:
            print(f"NET_MALFORMED: expected 1 record, got {len(data)}")
            sys.exit(0)
        net = data[0]
    elif isinstance(data, dict):
        net = data
    else:
        print("NET_MALFORMED: invalid root type")
        sys.exit(0)

    name = net.get("name") or net.get("Name")
    internal = net.get("internal")
    if internal is None:
        internal = net.get("Internal")
    subnets = net.get("subnets") or net.get("Subnets")

    mismatches = []
    if name != "kelvin-scanner-net":
        mismatches.append(f"name={name} (expected kelvin-scanner-net)")
    if internal is not True:
        mismatches.append(f"internal={internal} (expected true)")
    if subnets is None or not isinstance(subnets, list):
        mismatches.append("missing subnets list")
    elif len(subnets) != 1:
        mismatches.append(f"expected exactly 1 configured subnet, got {len(subnets)}")
    else:
        s0 = subnets[0]
        sub = s0.get("subnet") or s0.get("Subnet")
        gw = s0.get("gateway") or s0.get("Gateway")
        if sub != "10.89.10.0/24":
            mismatches.append(f"subnet={sub} (expected 10.89.10.0/24)")
        if gw != "10.89.10.1":
            mismatches.append(f"gateway={gw} (expected 10.89.10.1)")

    if mismatches:
        print("NET_MISCONFIGURED: " + "; ".join(mismatches))
    else:
        print("NET_OK")
except Exception as e:
    print(f"NET_MALFORMED: {e}")
'\'' <<< "$raw_json"
  else
    name="$(podman network inspect "$NET_NAME" --format "{{.Name}}" 2>/dev/null || echo "")"
    internal="$(podman network inspect "$NET_NAME" --format "{{.Internal}}" 2>/dev/null || echo "")"
    subnets_len="$(podman network inspect "$NET_NAME" --format "{{len .Subnets}}" 2>/dev/null || echo "0")"

    mismatches=()
    if [[ "$name" != "$NET_NAME" ]]; then
      mismatches+=("name=\x27$name\x27 (expected \x27$NET_NAME\x27)")
    fi
    if [[ "$internal" != "$REQ_INTERNAL" ]]; then
      mismatches+=("internal=\x27$internal\x27 (expected \x27$REQ_INTERNAL\x27)")
    fi
    if [[ "$subnets_len" != "1" ]]; then
      mismatches+=("expected exactly 1 configured subnet, got $subnets_len")
    else
      sub0="$(podman network inspect "$NET_NAME" --format "{{(index .Subnets 0).Subnet}}" 2>/dev/null || echo "")"
      gw0="$(podman network inspect "$NET_NAME" --format "{{(index .Subnets 0).Gateway}}" 2>/dev/null || echo "")"
      if [[ "$sub0" != "$REQ_SUBNET" ]]; then
        mismatches+=("subnet=\x27$sub0\x27 (expected \x27$REQ_SUBNET\x27)")
      fi
      if [[ "$gw0" != "$REQ_GATEWAY" ]]; then
        mismatches+=("gateway=\x27$gw0\x27 (expected \x27$REQ_GATEWAY\x27)")
      fi
    fi

    if [[ ${#mismatches[@]} -eq 0 ]]; then
      echo "NET_OK"
    else
      echo "NET_MISCONFIGURED: ${mismatches[*]}"
    fi
  fi
'

if id -u kelvin-worker >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
  if [[ "$(id -u)" -eq 0 ]]; then
    NET_RESULT="$(runuser -u kelvin-worker -- bash -c "$NETWORK_CHECK_CMD" 2>/dev/null || echo "NET_CHECK_ERROR")"
  elif [[ "$(id -u)" -eq 10001 ]]; then
    NET_RESULT="$(eval "$NETWORK_CHECK_CMD")"
  else
    NET_RESULT="CANNOT_RUN_AS_WORKER"
  fi

  case "$NET_RESULT" in
    "NET_OK")
      check_pass "Internal scanner network kelvin-scanner-net verified (name=kelvin-scanner-net, internal=true, subnet=10.89.10.0/24, gateway=10.89.10.1)"
      ;;
    NET_MISCONFIGURED*)
      check_fail "Network kelvin-scanner-net exists but is misconfigured: ${NET_RESULT#NET_MISCONFIGURED: }"
      ;;
    "NET_NOT_FOUND")
      check_fail "Network kelvin-scanner-net not found. Run scripts/deploy/setup-rootless-podman.sh."
      ;;
    *)
      check_fail "Unable to inspect kelvin-scanner-net ($NET_RESULT). Inability to inspect is a hard failure."
      ;;
  esac
fi

# 9. Worker Environment File Permissions & Placeholder Validation
ENV_FILE="/etc/kelvin/worker.env"
if [[ -f "$ENV_FILE" ]]; then
  PERMS="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || echo 'unknown')"
  OWNER="$(stat -c '%U:%G' "$ENV_FILE" 2>/dev/null || echo 'unknown')"
  if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
    check_pass "Worker configuration $ENV_FILE has strict permissions ($PERMS)"
  else
    check_fail "Worker configuration $ENV_FILE has unsafe permissions ($PERMS; strictly require 0600 or 0400)"
  fi
  if [[ "$OWNER" == "kelvin-worker:kelvin-worker" || "$OWNER" == "10001:10001" ]]; then
    check_pass "Worker configuration $ENV_FILE owned by kelvin-worker"
  else
    check_warn "Worker configuration $ENV_FILE owned by $OWNER (expected kelvin-worker:kelvin-worker)"
  fi

  # Validate against placeholder strings
  if grep -q "TEMPLATE_NOT_CONFIGURED" "$ENV_FILE"; then
    check_fail "$ENV_FILE contains KELVIN_CONFIG_STATUS=TEMPLATE_NOT_CONFIGURED marker. Real credentials required."
  fi
  if grep -q "REPLACE_WITH_" "$ENV_FILE"; then
    check_fail "$ENV_FILE contains REPLACE_WITH_ placeholder values. Real credentials required."
  fi

  # 10. Database CA Certificate Path from Config
  CA_PATH="$(grep -E '^(SUPABASE_CA_CERT_PATH|KELVIN_DATABASE_SSL_ROOT_CERT)=' "$ENV_FILE" | head -n 1 | cut -d'=' -f2- || true)"
  CA_PATH="${CA_PATH//\"/}"
  CA_PATH="${CA_PATH//\'/}"
  if [[ -z "$CA_PATH" ]]; then
    CA_PATH="/etc/kelvin/certs/supabase-root-ca.crt"
  fi
  if [[ -f "$CA_PATH" && -r "$CA_PATH" ]]; then
    check_pass "Database CA certificate verified and readable at $CA_PATH"
  else
    check_fail "Database CA certificate missing or unreadable at configured path: $CA_PATH"
  fi
else
  check_fail "$ENV_FILE does not exist. Populate from deploy/systemd/worker.env.example."
fi

# 11. Systemd Service Unit File
if [[ -f /etc/systemd/system/kelvin-worker.service ]]; then
  check_pass "Systemd service unit installed at /etc/systemd/system/kelvin-worker.service"
else
  check_fail "Systemd service unit not installed at /etc/systemd/system/kelvin-worker.service"
fi

echo "------------------------------------------------------------------------------"
echo "Host Audit Summary: $PASS_COUNT PASSED, $FAIL_COUNT FAILED, $WARN_COUNT WARNINGS"
echo "------------------------------------------------------------------------------"

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo "ERROR: Host audit failed with $FAIL_COUNT errors. Remediate issues before deployment." >&2
  exit 1
fi

echo "Host environment validation successful!"
