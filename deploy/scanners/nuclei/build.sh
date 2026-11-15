#!/usr/bin/env bash
# ==============================================================================
# Kelvin Hermetic Nuclei Source Build Automation Script
# Policy: ADR-0008 (Hermetic Builds, Pinned Toolchain, Zero Runtime Compilers)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SOURCE_ENV="$SCRIPT_DIR/source.env"

if [[ ! -f "$SOURCE_ENV" ]]; then
  echo "ERROR: Source environment specification not found at $SOURCE_ENV" >&2
  exit 1
fi

# Load pinned source and toolchain specifications
# shellcheck disable=SC1090
source "$SOURCE_ENV"

PLATFORM="${PLATFORM:-linux/arm64}"
TAG_NAME="${TAG_NAME:-kelvin/scanner-nuclei:${NUCLEI_VERSION}}"
OUT_METADATA="${OUT_METADATA:-${REPO_ROOT}/artifacts/scanner-images/nuclei-build-metadata.json}"

mkdir -p "$(dirname "$OUT_METADATA")"

echo "=============================================================================="
echo "Kelvin Hermetic Nuclei Source Build"
echo "Target Platform:   $PLATFORM"
echo "Nuclei Version:    $NUCLEI_VERSION (commit: $NUCLEI_SOURCE_COMMIT)"
echo "Go Builder:        $GOLANG_BUILDER_IMAGE"
echo "Distroless Base:   $DISTROLESS_RUNTIME_IMAGE"
echo "Output Tag:        $TAG_NAME"
echo "=============================================================================="

# Build image with buildx using multi-stage source compilation
docker buildx build \
  --platform "$PLATFORM" \
  --load \
  --metadata-file "$OUT_METADATA" \
  --build-arg "GO_BUILDER_IMAGE=${GOLANG_BUILDER_IMAGE}@${GOLANG_BUILDER_DIGEST}" \
  --build-arg "DISTROLESS_BASE_IMAGE=${DISTROLESS_RUNTIME_IMAGE}@${DISTROLESS_RUNTIME_DIGEST}" \
  --build-arg "NUCLEI_VERSION=${NUCLEI_VERSION}" \
  --build-arg "NUCLEI_COMMIT=${NUCLEI_SOURCE_COMMIT}" \
  --tag "$TAG_NAME" \
  --file "$SCRIPT_DIR/Dockerfile" \
  "$REPO_ROOT"

echo "==> Build successful: $TAG_NAME"
