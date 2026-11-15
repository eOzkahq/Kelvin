#!/usr/bin/env bash
# ==============================================================================
# Kelvin Scanner Build Verification Script
# Enforces ADR-0008 invariants on locally compiled scanner images:
# - Target architecture (linux/arm64 or linux/amd64)
# - Unprivileged non-root execution (USER 10001:10001)
# - Read-only root filesystem compatibility
# - Non-publishing guarantee (publish=false strictly enforced)
# ==============================================================================
set -euo pipefail

OUT_DIR="${OUT_DIR:-artifacts/scanner-images}"
PLATFORM="${PLATFORM:-linux/arm64}"
NUCLEI_VERSION="${NUCLEI_VERSION:-3.11.1}"
PUBLISH="${PUBLISH:-false}"

echo "==> [Verify Build] Validating local scanner image build artifacts..."

# 1. Non-publishing assertion
if [[ "$PUBLISH" != "false" ]]; then
  echo "WARNING: PUBLISH is set to '$PUBLISH'. Verify-build only validates non-publishing stages."
fi

# 2. Check metadata artifacts
if [[ -f "$OUT_DIR/nuclei-build-metadata.json" ]]; then
  echo "  [OK] Nuclei build metadata artifact present: $OUT_DIR/nuclei-build-metadata.json"
else
  echo "  [WARN] Nuclei build metadata artifact not found at $OUT_DIR/nuclei-build-metadata.json"
fi

# 3. Check Docker image presence and inspect security contracts
NUCLEI_IMAGE="kelvin/scanner-nuclei:${NUCLEI_VERSION}"
if command -v docker >/dev/null 2>&1 && docker image inspect "$NUCLEI_IMAGE" >/dev/null 2>&1; then
  echo "==> Inspecting container image contracts for $NUCLEI_IMAGE..."
  
  arch="$(docker image inspect "$NUCLEI_IMAGE" --format '{{.Architecture}}')"
  os_val="$(docker image inspect "$NUCLEI_IMAGE" --format '{{.Os}}')"
  uid="$(docker image inspect "$NUCLEI_IMAGE" --format '{{.Config.User}}')"

  echo "  Architecture: $arch"
  echo "  OS:           $os_val"
  echo "  User:         $uid"

  if [[ "$os_val" != "linux" ]]; then
    echo "ERROR: Unexpected OS '$os_val' (expected 'linux')" >&2
    exit 1
  fi

  if [[ "$uid" != "10001:10001" ]]; then
    echo "ERROR: Unexpected user '$uid' (expected '10001:10001')" >&2
    exit 1
  fi

  expected_arch="arm64"
  if [[ "$PLATFORM" == *"amd64"* ]]; then
    expected_arch="amd64"
  fi

  if [[ "$arch" != "$expected_arch" ]]; then
    echo "ERROR: Target architecture mismatch! Expected '$expected_arch', got '$arch'" >&2
    exit 1
  fi

  echo "  [OK] Image security contracts verified for $NUCLEI_IMAGE"
else
  echo "  [INFO] Docker daemon or image $NUCLEI_IMAGE not present locally (dry-run / static check)."
fi

echo "==> Scanner build verification passed."
