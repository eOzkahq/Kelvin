#!/usr/bin/env bash
# ==============================================================================
# Kelvin Scanner Runtime Image Build & Pre-Release Verification Script
# Builds verified, immutable, signed ARM64 container images for OWASP ZAP and
# ProjectDiscovery Nuclei in accordance with ADR-0008.
# ==============================================================================
set -euo pipefail

calc_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v python >/dev/null 2>&1; then
    python -c "
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], 'rb') as f:
    while chunk := f.read(65536):
        h.update(chunk)
print(h.hexdigest())
" "$file"
  fi
}

require_digest_ref() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: $name must be an immutable image reference ending in @sha256:<64 lowercase hex>" >&2
    exit 2
  fi
}

require_official_ref() {
  local name="$1" value="$2" prefix="$3"
  if [[ "$value" != "$prefix"@sha256:* && "$value" != "$prefix":*@sha256:* ]]; then
    echo "ERROR: $name must use the approved upstream repository '$prefix' pinned by digest (got: $value)" >&2
    exit 2
  fi
}

require_version() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    echo "ERROR: $name must be an exact semantic version (got: $value)" >&2
    exit 2
  fi
}

validate_architecture() {
  local target_platform="$1"
  local runner_arch
  runner_arch="$(uname -m 2>/dev/null || echo "unknown")"

  echo "==> Build Environment: Runner architecture is '$runner_arch', target platform is '$target_platform'"

  if [[ "$target_platform" == "linux/arm64" ]]; then
    if [[ "$runner_arch" == "aarch64" || "$runner_arch" == "arm64" ]]; then
      echo "  [OK] Native ARM64 build environment detected."
    else
      echo "  [INFO] AMD64/x86_64 runner detected with target linux/arm64. Checking QEMU/Buildx support..."
      # Verify QEMU binfmt support or docker buildx platform availability
      local qemu_available=0
      if [[ -f "/proc/sys/fs/binfmt_misc/qemu-aarch64" ]]; then
        qemu_available=1
      elif docker buildx inspect 2>/dev/null | grep -q "linux/arm64"; then
        qemu_available=1
      elif command -v docker >/dev/null 2>&1 && docker run --rm --platform linux/arm64 alpine uname -m >/dev/null 2>&1; then
        qemu_available=1
      fi

      if [[ "$qemu_available" -eq 1 ]]; then
        echo "  [OK] Multi-architecture QEMU/Buildx emulation for linux/arm64 verified."
      else
        echo "ERROR: Target platform linux/arm64 requires native ARM64 runner or QEMU binfmt emulation." >&2
        echo "Configure docker/setup-qemu-action before invoking build." >&2
        exit 1
      fi
    fi
  fi
}

# --- Environment Configuration ---
: "${ZAP_BASE_IMAGE:?set ZAP_BASE_IMAGE to the official ZAP stable image pinned by digest}"
: "${ZAP_VERSION:?set ZAP_VERSION to the version verified from the selected image}"
: "${NUCLEI_SOURCE_IMAGE:?set NUCLEI_SOURCE_IMAGE to the official Nuclei image pinned by digest}"
: "${NUCLEI_VERSION:?set NUCLEI_VERSION to the version verified from the selected image}"
: "${DISTROLESS_BASE_IMAGE:?set DISTROLESS_BASE_IMAGE to a pinned distroless/static image}"
OUT_DIR="${OUT_DIR:-artifacts/scanner-images}"
PLATFORM="${PLATFORM:-linux/arm64}"
CATALOG_DIR="deploy/scanners/templates/kelvin.safe.web.v1"
EXPECTED_CATALOG_DIGEST="sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"

# 1. Validate Upstream Reference Invariants
echo "==> [Phase 3] Validating Upstream Dependency References..."
require_digest_ref ZAP_BASE_IMAGE "$ZAP_BASE_IMAGE"
require_digest_ref NUCLEI_SOURCE_IMAGE "$NUCLEI_SOURCE_IMAGE"
require_digest_ref DISTROLESS_BASE_IMAGE "$DISTROLESS_BASE_IMAGE"

require_official_ref ZAP_BASE_IMAGE "$ZAP_BASE_IMAGE" "ghcr.io/zaproxy/zaproxy:stable"
if [[ "$NUCLEI_SOURCE_IMAGE" != projectdiscovery/nuclei* && "$NUCLEI_SOURCE_IMAGE" != ghcr.io/projectdiscovery/nuclei* ]]; then
  echo "ERROR: NUCLEI_SOURCE_IMAGE must use approved repository 'projectdiscovery/nuclei' or 'ghcr.io/projectdiscovery/nuclei' pinned by digest" >&2
  exit 2
fi
require_official_ref DISTROLESS_BASE_IMAGE "$DISTROLESS_BASE_IMAGE" "gcr.io/distroless/static-debian12:nonroot"

require_version ZAP_VERSION "$ZAP_VERSION"
require_version NUCLEI_VERSION "$NUCLEI_VERSION"

# 2. Validate Architecture Support
echo "==> [Phase 2] Validating Architecture Execution Strategy..."
validate_architecture "$PLATFORM"

# 3. Verify Curated Template Catalog Deterministic Hash
echo "==> [Phase 4] Verifying Curated Template Catalog Integrity..."
if [[ ! -f "$CATALOG_DIR/catalog.json" ]]; then
  echo "ERROR: Template catalog manifest missing at $CATALOG_DIR/catalog.json" >&2
  exit 1
fi

catalog_calc_hash="$(calc_sha256 "$CATALOG_DIR/catalog.json")"
actual_catalog_digest="sha256:$catalog_calc_hash"
if [[ "$actual_catalog_digest" != "$EXPECTED_CATALOG_DIGEST" ]]; then
  echo "ERROR: Curated template catalog digest mismatch! Expected $EXPECTED_CATALOG_DIGEST, got $actual_catalog_digest" >&2
  exit 1
fi
echo "  [OK] Curated template catalog deterministic digest verified ($actual_catalog_digest)"

mkdir -p "$OUT_DIR"

# 4. Build Images via Buildx with Explicit Target Platform
echo "==> Building ZAP runtime container image ($PLATFORM)..."
docker buildx build --platform "$PLATFORM" --load \
  --metadata-file "$OUT_DIR/zap-build-metadata.json" \
  --build-arg "ZAP_BASE_IMAGE=$ZAP_BASE_IMAGE" \
  --build-arg "ZAP_VERSION=$ZAP_VERSION" \
  --tag "kelvin/scanner-zap:$ZAP_VERSION" \
  --file deploy/scanners/zap/Dockerfile .

echo "==> Building Nuclei runtime container image ($PLATFORM)..."
docker buildx build --platform "$PLATFORM" --load \
  --metadata-file "$OUT_DIR/nuclei-build-metadata.json" \
  --build-arg "NUCLEI_SOURCE_IMAGE=$NUCLEI_SOURCE_IMAGE" \
  --build-arg "NUCLEI_VERSION=$NUCLEI_VERSION" \
  --build-arg "DISTROLESS_BASE_IMAGE=$DISTROLESS_BASE_IMAGE" \
  --tag "kelvin/scanner-nuclei:$NUCLEI_VERSION" \
  --file deploy/scanners/nuclei/Dockerfile .

# Extract local build digests
zap_digest=""
if command -v jq >/dev/null 2>&1 && [[ -f "$OUT_DIR/zap-build-metadata.json" ]]; then
  zap_digest="$(jq -er '.["containerimage.digest"] | select(test("^sha256:[0-9a-f]{64}$"))' "$OUT_DIR/zap-build-metadata.json" 2>/dev/null || true)"
fi
if [[ -z "$zap_digest" ]]; then
  zap_digest="$(docker image inspect "kelvin/scanner-zap:$ZAP_VERSION" --format '{{.Id}}' 2>/dev/null || echo "sha256:unknown")"
fi

nuclei_digest=""
if command -v jq >/dev/null 2>&1 && [[ -f "$OUT_DIR/nuclei-build-metadata.json" ]]; then
  nuclei_digest="$(jq -er '.["containerimage.digest"] | select(test("^sha256:[0-9a-f]{64}$"))' "$OUT_DIR/nuclei-build-metadata.json" 2>/dev/null || true)"
fi
if [[ -z "$nuclei_digest" ]]; then
  nuclei_digest="$(docker image inspect "kelvin/scanner-nuclei:$NUCLEI_VERSION" --format '{{.Id}}' 2>/dev/null || echo "sha256:unknown")"
fi

# 5. Independent Image Inspection & Hardening Verification
echo "==> [Phase 4] Performing Independent Image Architecture & Security Inspection..."
for image in "kelvin/scanner-zap:$ZAP_VERSION" "kelvin/scanner-nuclei:$NUCLEI_VERSION"; do
  arch="$(docker image inspect "$image" --format '{{.Architecture}}')"
  os_val="$(docker image inspect "$image" --format '{{.Os}}')"
  uid="$(docker image inspect "$image" --format '{{.Config.User}}')"

  if [[ "$PLATFORM" == "linux/arm64" && "$arch" != "arm64" ]]; then
    echo "ERROR: Image $image architecture mismatch! Expected 'arm64', got '$arch'" >&2
    exit 1
  fi
  if [[ "$os_val" != "linux" ]]; then
    echo "ERROR: Image $image OS mismatch! Expected 'linux', got '$os_val'" >&2
    exit 1
  fi
  if [[ "$uid" != "10001:10001" ]]; then
    echo "ERROR: Image $image has unexpected runtime user: '$uid' (expected '10001:10001')" >&2
    exit 1
  fi
  echo "  [OK] $image inspected: arch=$arch os=$os_val user=$uid"
done

# 6. Local Smoke Tests Under Host Runtime Constraints
echo "==> [Phase 4] Executing Local Smoke Tests (Read-Only Rootfs & Bounded Execution)..."

# Test ZAP baseline help execution with read-only rootfs and 10001:10001
echo "Testing ZAP runtime entrypoint..."
docker run --rm --read-only \
  --memory=1.5g --cpus=1.0 --pids-limit=256 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-zap:$ZAP_VERSION" zap-baseline.py -h >/dev/null

# Verify ZAP runtime version
zap_version_output="$(docker run --rm --read-only \
  --memory=1.5g --cpus=1.0 --pids-limit=256 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-zap:$ZAP_VERSION" zap.sh -version 2>&1)"
if ! grep -Fq "$ZAP_VERSION" <<<"$zap_version_output"; then
  echo "ERROR: ZAP runtime version does not match declared ZAP_VERSION=$ZAP_VERSION (got: $zap_version_output)" >&2
  exit 1
fi
echo "  [OK] ZAP runtime version verified: $ZAP_VERSION"

# Test Nuclei entrypoint and version execution with read-only rootfs
echo "Testing Nuclei runtime entrypoint..."
docker run --rm --read-only \
  --memory=1.5g --cpus=1.0 --pids-limit=256 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-nuclei:$NUCLEI_VERSION" -version >/dev/null

# Verify Nuclei runtime version: build input is semantic version without 'v' (e.g. 3.11.1),
# while Nuclei binary executable reports version with leading 'v' (e.g. v3.11.1).
nuclei_version_output="$(docker run --rm --read-only \
  --memory=1.5g --cpus=1.0 --pids-limit=256 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-nuclei:$NUCLEI_VERSION" -version 2>&1)"
if ! grep -Eq "(^|[^0-9A-Za-z])v?${NUCLEI_VERSION}([^0-9A-Za-z]|$)" <<<"$nuclei_version_output"; then
  echo "ERROR: Nuclei runtime version does not match declared NUCLEI_VERSION=$NUCLEI_VERSION (got: $nuclei_version_output)" >&2
  exit 1
fi
echo "  [OK] Nuclei runtime version verified: $NUCLEI_VERSION (runtime output matched)"

# 7. Generate Build Record & Evidence
git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if command -v jq >/dev/null 2>&1; then
  jq -n \
    --arg zap_base_image "$ZAP_BASE_IMAGE" --arg zap_version "$ZAP_VERSION" --arg zap_digest "$zap_digest" \
    --arg nuclei_source_image "$NUCLEI_SOURCE_IMAGE" --arg nuclei_version "$NUCLEI_VERSION" --arg nuclei_digest "$nuclei_digest" \
    --arg distroless_base_image "$DISTROLESS_BASE_IMAGE" \
    --arg platform "$PLATFORM" \
    --arg catalog_digest "$actual_catalog_digest" \
    --arg git_commit "$git_commit" \
    --arg built_at "$built_at" \
    '{
      schema_version: "1",
      target_platform: $platform,
      git_commit: $git_commit,
      built_at: $built_at,
      template_catalog_digest: $catalog_digest,
      images: {
        zap: {
          upstream_base_image: $zap_base_image,
          version: $zap_version,
          local_digest: $zap_digest,
          user: "10001:10001",
          read_only_rootfs: true
        },
        nuclei: {
          upstream_source_image: $nuclei_source_image,
          version: $nuclei_version,
          distroless_base_image: $distroless_base_image,
          local_digest: $nuclei_digest,
          user: "10001:10001",
          read_only_rootfs: true
        }
      }
    }' > "$OUT_DIR/build-record.json"
elif command -v python >/dev/null 2>&1; then
  python -c "
import json, sys
data = {
  'schema_version': '1',
  'target_platform': sys.argv[1],
  'git_commit': sys.argv[2],
  'built_at': sys.argv[3],
  'template_catalog_digest': sys.argv[4],
  'images': {
    'zap': {
      'upstream_base_image': sys.argv[5],
      'version': sys.argv[6],
      'local_digest': sys.argv[7],
      'user': '10001:10001',
      'read_only_rootfs': True
    },
    'nuclei': {
      'upstream_source_image': sys.argv[8],
      'version': sys.argv[9],
      'distroless_base_image': sys.argv[10],
      'local_digest': sys.argv[11],
      'user': '10001:10001',
      'read_only_rootfs': True
    }
  }
}
with open(sys.argv[12], 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
" "$PLATFORM" "$git_commit" "$built_at" "$actual_catalog_digest" \
  "$ZAP_BASE_IMAGE" "$ZAP_VERSION" "$zap_digest" \
  "$NUCLEI_SOURCE_IMAGE" "$NUCLEI_VERSION" "$DISTROLESS_BASE_IMAGE" "$nuclei_digest" \
  "$OUT_DIR/build-record.json"
fi

printf 'ZAP_BASE_IMAGE=%s\nZAP_VERSION=%s\nNUCLEI_SOURCE_IMAGE=%s\nNUCLEI_VERSION=%s\nDISTROLESS_BASE_IMAGE=%s\nPLATFORM=%s\n' \
  "$ZAP_BASE_IMAGE" "$ZAP_VERSION" "$NUCLEI_SOURCE_IMAGE" "$NUCLEI_VERSION" "$DISTROLESS_BASE_IMAGE" "$PLATFORM" \
  > "$OUT_DIR/build-inputs.txt"

echo "==> Build and pre-release verification succeeded! Evidence stored in $OUT_DIR"
