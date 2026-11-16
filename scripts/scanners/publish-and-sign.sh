#!/usr/bin/env bash
# ==============================================================================
# Kelvin Scanner Image Publication, Cosign Keyless Signing & Provenance Attestation
# Publishes built images to GHCR, verifies registry digests, executes keyless
# Cosign signing, attaches SLSA provenance & SBOM attestations, and verifies them.
# ==============================================================================
set -euo pipefail

: "${ZAP_VERSION:?set ZAP_VERSION to the verified version}"
: "${NUCLEI_VERSION:?set NUCLEI_VERSION to the verified version}"

REGISTRY_NAMESPACE="${REGISTRY_NAMESPACE:-ghcr.io/eozkahq/kelvin}"
OUT_DIR="${OUT_DIR:-artifacts/scanner-images}"
CERT_IDENTITY_REGEXP="${CERT_IDENTITY_REGEXP:-^https://github.com/eOzkahq/Kelvin/.github/workflows/.*}"
CERT_OIDC_ISSUER="${CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

echo "=============================================================================="
echo "Kelvin Scanner Image GHCR Publication, Signing & Supply Chain Attestation"
echo "Registry Namespace: $REGISTRY_NAMESPACE"
echo "Output Directory:   $OUT_DIR"
echo "=============================================================================="

# Pre-flight Evidence Checks
if [[ ! -f "$OUT_DIR/build-record.json" ]]; then
  echo "ERROR: Missing build record at $OUT_DIR/build-record.json. Run build-images.sh first." >&2
  exit 1
fi
if [[ ! -f "$OUT_DIR/zap.cdx.json" || ! -f "$OUT_DIR/nuclei.cdx.json" ]]; then
  echo "ERROR: Missing CycloneDX SBOM artifacts in $OUT_DIR." >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "ERROR: Cosign CLI is required for signing and provenance attestation." >&2
  exit 1
fi

# 1. Tag and Push Scanner Images to GHCR
echo "==> [Phase 6] Tagging and pushing images to GHCR..."

zap_full_tag="$REGISTRY_NAMESPACE/scanner-zap:$ZAP_VERSION"
nuclei_full_tag="$REGISTRY_NAMESPACE/scanner-nuclei:$NUCLEI_VERSION"

docker tag "kelvin/scanner-zap:$ZAP_VERSION" "$zap_full_tag"
docker tag "kelvin/scanner-nuclei:$NUCLEI_VERSION" "$nuclei_full_tag"

docker push "$zap_full_tag"
docker push "$nuclei_full_tag"

# 2. Capture and Verify Immutable Registry Digests
echo "==> [Phase 6] Capturing and verifying registry manifest digests..."

extract_registry_digest() {
  local tag="$1"
  local repo_name="${tag%%:*}"
  local digest=""
  
  # Try docker inspect RepoDigests matching repo name
  digest="$(docker image inspect "$tag" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null | grep -E "(^$repo_name@|$tag)" | awk -F'@' '{print $2}' | head -n 1 || true)"
  
  if [[ -z "$digest" ]]; then
    # Fallback to index 0
    digest="$(docker image inspect "$tag" --format '{{index .RepoDigests 0}}' 2>/dev/null | awk -F'@' '{print $2}' || true)"
  fi

  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: Failed to capture valid immutable registry digest for $tag (got: '$digest')" >&2
    exit 1
  fi
  echo "$digest"
}

zap_reg_digest="$(extract_registry_digest "$zap_full_tag")"
nuclei_reg_digest="$(extract_registry_digest "$nuclei_full_tag")"

echo "  [OK] ZAP Registry Digest:    $zap_reg_digest"
echo "  [OK] Nuclei Registry Digest: $nuclei_reg_digest"

zap_immutable_ref="$REGISTRY_NAMESPACE/scanner-zap@$zap_reg_digest"
nuclei_immutable_ref="$REGISTRY_NAMESPACE/scanner-nuclei@$nuclei_reg_digest"

# 3. Sigstore Cosign Keyless Signing (OIDC)
echo "==> [Phase 7] Cosign Keyless Signing via GitHub Actions OIDC..."

cosign sign --yes "$zap_immutable_ref"
cosign sign --yes "$nuclei_immutable_ref"
echo "  [OK] Cryptographic Cosign signatures generated successfully."

# 4. Attest SLSA Provenance
echo "==> [Phase 7] Attesting SLSA Provenance..."

# Ensure build-record conforms to SLSA v0.2 provenance predicate expected by Cosign
git_commit="$(jq -r '.git_commit // empty' "$OUT_DIR/build-record.json" 2>/dev/null || true)"
if [[ -z "$git_commit" ]]; then
  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "main")"
fi

jq \
  --arg builder_id "https://github.com/eOzkahq/Kelvin/.github/workflows/scanner-images.yml" \
  --arg commit "$git_commit" \
  '. + {
    builder: { id: $builder_id },
    buildType: "https://slsa.dev/provenance/v0.2",
    invocation: {
      configSource: {
        uri: "git+https://github.com/eOzkahq/Kelvin@refs/heads/main",
        digest: { sha1: $commit },
        entryPoint: ".github/workflows/scanner-images.yml"
      },
      parameters: {}
    },
    materials: [
      {
        uri: ("git+https://github.com/eOzkahq/Kelvin@" + $commit),
        digest: { sha1: $commit }
      }
    ]
  }' "$OUT_DIR/build-record.json" > "$OUT_DIR/build-record.json.tmp" && mv "$OUT_DIR/build-record.json.tmp" "$OUT_DIR/build-record.json"

cosign attest --yes \
  --predicate "$OUT_DIR/build-record.json" \
  --type slsaprovenance \
  "$zap_immutable_ref"

cosign attest --yes \
  --predicate "$OUT_DIR/build-record.json" \
  --type slsaprovenance \
  "$nuclei_immutable_ref"
echo "  [OK] SLSA provenance attestations attached."

# 5. Attest CycloneDX SBOM
echo "==> [Phase 7] Attesting CycloneDX Software Bill of Materials (SBOM)..."

cosign attest --yes \
  --predicate "$OUT_DIR/zap.cdx.json" \
  --type cyclonedx \
  "$zap_immutable_ref"

cosign attest --yes \
  --predicate "$OUT_DIR/nuclei.cdx.json" \
  --type cyclonedx \
  "$nuclei_immutable_ref"
echo "  [OK] CycloneDX SBOM attestations attached."

# 6. Post-Publication Strict Verification Gate
echo "==> [Phase 7] Verifying Published Signatures and Attestations..."

echo "Verifying ZAP cryptographic signature..."
cosign verify \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$zap_immutable_ref"

echo "Verifying Nuclei cryptographic signature..."
cosign verify \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$nuclei_immutable_ref"

echo "Verifying ZAP SLSA provenance attestation..."
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$zap_immutable_ref"

echo "Verifying Nuclei SLSA provenance attestation..."
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$nuclei_immutable_ref"

echo "Verifying ZAP CycloneDX SBOM attestation..."
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$zap_immutable_ref"

echo "Verifying Nuclei CycloneDX SBOM attestation..."
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$nuclei_immutable_ref"

echo "  [OK] All post-publication signature and attestation gates PASSED."

# 7. Record Publication Evidence
calc_file_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

zap_sbom_digest="sha256:$(calc_file_sha256 "$OUT_DIR/zap.cdx.json")"
nuclei_sbom_digest="sha256:$(calc_file_sha256 "$OUT_DIR/nuclei.cdx.json")"
zap_clean_digest="${zap_reg_digest#sha256:}"
nuclei_clean_digest="${nuclei_reg_digest#sha256:}"
zap_sig_ref="$REGISTRY_NAMESPACE/scanner-zap:sha256-${zap_clean_digest}.sig"
nuclei_sig_ref="$REGISTRY_NAMESPACE/scanner-nuclei:sha256-${nuclei_clean_digest}.sig"
zap_prov_ref="$REGISTRY_NAMESPACE/scanner-zap:sha256-${zap_clean_digest}.att"
nuclei_prov_ref="$REGISTRY_NAMESPACE/scanner-nuclei:sha256-${nuclei_clean_digest}.att"

jq -n \
  --arg zap_ref "$zap_immutable_ref" \
  --arg zap_digest "$zap_reg_digest" \
  --arg zap_version "$ZAP_VERSION" \
  --arg zap_sbom "$zap_sbom_digest" \
  --arg zap_sig "$zap_sig_ref" \
  --arg zap_prov "$zap_prov_ref" \
  --arg nuclei_ref "$nuclei_immutable_ref" \
  --arg nuclei_digest "$nuclei_reg_digest" \
  --arg nuclei_version "$NUCLEI_VERSION" \
  --arg nuclei_sbom "$nuclei_sbom_digest" \
  --arg nuclei_sig "$nuclei_sig_ref" \
  --arg nuclei_prov "$nuclei_prov_ref" \
  --arg published_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    status: "published-and-verified",
    published_at: $published_at,
    scanners: {
      zap: {
        immutable_reference: $zap_ref,
        digest: $zap_digest,
        version: $zap_version,
        sbom_digest: $zap_sbom,
        signature_ref: $zap_sig,
        provenance_ref: $zap_prov,
        scorecard_status: "ELIGIBLE"
      },
      nuclei: {
        immutable_reference: $nuclei_ref,
        digest: $nuclei_digest,
        version: $nuclei_version,
        sbom_digest: $nuclei_sbom,
        signature_ref: $nuclei_sig,
        provenance_ref: $nuclei_prov,
        scorecard_status: "ELIGIBLE"
      }
    }
  }' > "$OUT_DIR/published-manifest.json"

echo "==> Publication, signing, and supply chain verification COMPLETED SUCCESSFULLY!"
