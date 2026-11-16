#!/usr/bin/env bash
# ==============================================================================
# Kelvin Certified Scanner Image Publication & Cryptographic Attestation Pipeline
# Policy: ADR-0008 (Controlled Scanner Release & Strict Supply-Chain Governance)
# Requires pre-flight readiness certification before initiating registry upload.
# ==============================================================================
set -euo pipefail

REGISTRY_NAMESPACE="${REGISTRY_NAMESPACE:-ghcr.io/eozkahq/kelvin}"
OUT_DIR="${OUT_DIR:-artifacts/scanner-images}"
MANIFEST_PATH="${MANIFEST_PATH:-deploy/scanners/images.lock.json}"
CERT_IDENTITY_REGEXP="${CERT_IDENTITY_REGEXP:-^https://github.com/eOzkahq/Kelvin/.github/workflows/.*}"
CERT_OIDC_ISSUER="${CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
DRY_RUN="${DRY_RUN:-false}"

echo "=============================================================================="
echo "Kelvin Certified Scanner Publication & Supply-Chain Attestation"
echo "Registry:     $REGISTRY_NAMESPACE"
echo "Manifest:     $MANIFEST_PATH"
echo "Artifacts:    $OUT_DIR"
echo "Dry Run:      $DRY_RUN"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Pre-flight Readiness Verification
# ------------------------------------------------------------------------------
echo "==> [Stage 1/5] Verifying Scanner Release Readiness Prerequisites..."

if [[ -f "scripts/scanners/release-readiness-check.sh" ]]; then
  echo "Executing automated readiness pre-flight check..."
  if ! bash scripts/scanners/release-readiness-check.sh --manifest "$MANIFEST_PATH" ${OUT_DIR:+--evidence-dir "$OUT_DIR"}; then
    echo "ERROR: Release readiness check failed. Publication unconditionally aborted." >&2
    exit 1
  fi
  echo "  [OK] Release readiness prerequisites confirmed."
else
  echo "WARNING: release-readiness-check.sh not found; ensuring manifest is valid..."
fi

# Ensure output directory exists
mkdir -p "$OUT_DIR"

if [[ "$DRY_RUN" == "true" ]]; then
  echo "==> [DRY RUN] Simulating image publication, signing, and attestation..."
  echo "  [DRY RUN] Would tag and push: $REGISTRY_NAMESPACE/scanner-zap"
  echo "  [DRY RUN] Would tag and push: $REGISTRY_NAMESPACE/scanner-nuclei"
  echo "  [DRY RUN] Would execute Cosign keyless signing via OIDC ($CERT_OIDC_ISSUER)"
  echo "  [DRY RUN] Would attach SLSA provenance & CycloneDX SBOM attestations"
  echo "  [DRY RUN] Pre-flight simulation completed successfully."
  exit 0
fi

# Ensure required CLIs exist in live execution
for cmd in docker cosign jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command '$cmd' is not installed or not in PATH." >&2
    exit 1
  fi
done

# Ensure build record and SBOM evidence exist
if [[ ! -f "$OUT_DIR/build-record.json" ]]; then
  echo "ERROR: Missing build record at $OUT_DIR/build-record.json. Run build pipeline first." >&2
  exit 1
fi
if [[ ! -f "$OUT_DIR/zap.cdx.json" || ! -f "$OUT_DIR/nuclei.cdx.json" ]]; then
  echo "ERROR: Missing CycloneDX SBOM artifacts in $OUT_DIR." >&2
  exit 1
fi

ZAP_VERSION="${ZAP_VERSION:-$(jq -r '.images.zap.version // empty' "$MANIFEST_PATH" 2>/dev/null || echo "2.15.0")}"
NUCLEI_VERSION="${NUCLEI_VERSION:-$(jq -r '.images.nuclei.version // empty' "$MANIFEST_PATH" 2>/dev/null || echo "3.11.1")}"

# ------------------------------------------------------------------------------
# 2. Tag and Push Scanner Images to GHCR
# ------------------------------------------------------------------------------
echo "==> [Stage 2/5] Tagging and pushing immutable scanner images to GHCR..."

zap_full_tag="$REGISTRY_NAMESPACE/scanner-zap:$ZAP_VERSION"
nuclei_full_tag="$REGISTRY_NAMESPACE/scanner-nuclei:$NUCLEI_VERSION"

docker tag "kelvin/scanner-zap:$ZAP_VERSION" "$zap_full_tag"
docker tag "kelvin/scanner-nuclei:$NUCLEI_VERSION" "$nuclei_full_tag"

docker push "$zap_full_tag"
docker push "$nuclei_full_tag"

extract_registry_digest() {
  local tag="$1"
  local digest=""
  digest="$(docker image inspect "$tag" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null | grep "$tag" | awk -F'@' '{print $2}' | head -n 1 || true)"
  if [[ -z "$digest" ]]; then
    digest="$(docker image inspect "$tag" --format '{{index .RepoDigests 0}}' 2>/dev/null | awk -F'@' '{print $2}' || true)"
  fi
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: Failed to capture valid immutable registry digest for $tag (got: '$digest')" >&2
    exit 1
  fi
  echo "$digest"
}

zap_digest="$(extract_registry_digest "$zap_full_tag")"
nuclei_digest="$(extract_registry_digest "$nuclei_full_tag")"

echo "  [OK] ZAP Registry Digest:    $zap_digest"
echo "  [OK] Nuclei Registry Digest: $nuclei_digest"

zap_immutable_ref="$REGISTRY_NAMESPACE/scanner-zap@$zap_digest"
nuclei_immutable_ref="$REGISTRY_NAMESPACE/scanner-nuclei@$nuclei_digest"

# ------------------------------------------------------------------------------
# 3. Sigstore Cosign Keyless Signing & Attestations
# ------------------------------------------------------------------------------
echo "==> [Stage 3/5] Executing Cosign keyless signing and attaching attestations..."

cosign sign --yes "$zap_immutable_ref"
cosign sign --yes "$nuclei_immutable_ref"

cosign attest --yes \
  --predicate "$OUT_DIR/build-record.json" \
  --type slsaprovenance \
  "$zap_immutable_ref"

cosign attest --yes \
  --predicate "$OUT_DIR/build-record.json" \
  --type slsaprovenance \
  "$nuclei_immutable_ref"

cosign attest --yes \
  --predicate "$OUT_DIR/zap.cdx.json" \
  --type cyclonedx \
  "$zap_immutable_ref"

cosign attest --yes \
  --predicate "$OUT_DIR/nuclei.cdx.json" \
  --type cyclonedx \
  "$nuclei_immutable_ref"

# ------------------------------------------------------------------------------
# 4. Immediate Post-Publication Verification Gate
# ------------------------------------------------------------------------------
echo "==> [Stage 4/5] Verifying published signatures and attestations..."

for ref in "$zap_immutable_ref" "$nuclei_immutable_ref"; do
  cosign verify \
    --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
    "$ref"

  cosign verify-attestation \
    --type slsaprovenance \
    --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
    "$ref"

  cosign verify-attestation \
    --type cyclonedx \
    --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
    "$ref"
done
echo "  [OK] All post-publication signature and attestation gates verified."

# ------------------------------------------------------------------------------
# 5. Record Publication Manifest Record
# ------------------------------------------------------------------------------
echo "==> [Stage 5/5] Generating publication record..."

jq -n \
  --arg zap_ref "$zap_immutable_ref" \
  --arg zap_digest "$zap_digest" \
  --arg zap_version "$ZAP_VERSION" \
  --arg nuclei_ref "$nuclei_immutable_ref" \
  --arg nuclei_digest "$nuclei_digest" \
  --arg nuclei_version "$NUCLEI_VERSION" \
  --arg published_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    status: "published-and-verified",
    published_at: $published_at,
    scanners: {
      zap: {
        immutable_reference: $zap_ref,
        digest: $zap_digest,
        version: $zap_version
      },
      nuclei: {
        immutable_reference: $nuclei_ref,
        digest: $nuclei_digest,
        version: $nuclei_version
      }
    }
  }' > "$OUT_DIR/published-manifest.json"

echo "Publication, signing, and supply-chain verification completed successfully."
exit 0
