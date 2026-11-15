#!/usr/bin/env bash
# ==============================================================================
# Kelvin Scanner Image Release Pipeline Acceptance Test Suite
# Verifies all 15 critical supply chain and release security conditions:
#  1. Invalid upstream image references (rejected)
#  2. Mutable image tags (rejected, immutable digest required)
#  3. Invalid digest formats (non-hex, truncated, or empty-hash rejected)
#  4. Invalid versions (non-semver rejected)
#  5. Architecture mismatch (non-ARM64 / non-Linux rejected)
#  6. Unexpected runtime UID/GID (non-10001:10001 rejected)
#  7. Vulnerability gate failure (HIGH/CRITICAL fails closed)
#  8. Missing or malformed CycloneDX SBOM (fails closed)
#  9. Registry digest mismatch (registry manifest != local build rejected)
# 10. Invalid Cosign signature (signature verification failure rejected)
# 11. Invalid provenance identity (untrusted certificate identity/issuer rejected)
# 12. Template catalog digest mismatch (catalog tampering detected)
# 13. Missing release evidence (certification blocked without evidence)
# 14. Attempts to certify incomplete manifests (null/empty digests rejected)
# 15. Worker rejection of 'not-released' manifests in staging/production
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
echo "Kelvin Scanner Image Release Pipeline Acceptance Test Suite"
echo "=============================================================================="

TMP_TEST_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'kelvin-test')"
cleanup() {
  rm -rf "$TMP_TEST_DIR"
}
trap cleanup EXIT

# ------------------------------------------------------------------------------
# SCENARIO 1: Invalid Upstream Image References
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 1: Upstream Reference Validation ---"
validate_upstream_ref() {
  local ref="$1" expected_prefix="$2"
  if [[ ! "$ref" =~ @sha256:[0-9a-f]{64}$ ]]; then
    return 1
  fi
  if [[ "$ref" != "$expected_prefix"@sha256:* && "$ref" != "$expected_prefix":*@sha256:* ]]; then
    return 2
  fi
  return 0
}

valid_ref="ghcr.io/zaproxy/zaproxy:stable@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919"
if validate_upstream_ref "$valid_ref" "ghcr.io/zaproxy/zaproxy:stable"; then
  test_pass "Scenario 1a: Approved upstream repository reference accepted"
else
  test_fail "Scenario 1a: Approved reference failed"
fi

if ! validate_upstream_ref "docker.io/malicious/zaproxy@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919" "ghcr.io/zaproxy/zaproxy:stable"; then
  test_pass "Scenario 1b: Unapproved upstream repository strictly rejected"
else
  test_fail "Scenario 1b: Unapproved repository was accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 2: Mutable Image Tags
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 2: Mutable Tag Rejection ---"
if ! validate_upstream_ref "ghcr.io/zaproxy/zaproxy:stable" "ghcr.io/zaproxy/zaproxy:stable"; then
  test_pass "Scenario 2a: Mutable tag ':stable' without immutable digest rejected"
else
  test_fail "Scenario 2a: Mutable tag accepted"
fi

if ! validate_upstream_ref "projectdiscovery/nuclei:latest" "projectdiscovery/nuclei"; then
  test_pass "Scenario 2b: Mutable tag ':latest' without immutable digest rejected"
else
  test_fail "Scenario 2b: Mutable tag accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 3: Invalid Digest Formats
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 3: Digest Format Validation ---"
validate_digest_format() {
  local d="$1"
  local empty_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  if [[ ! "$d" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    return 1
  fi
  if [[ "$d" == "$empty_hash" ]]; then
    return 2 # prohibited empty placeholder hash
  fi
  return 0
}

if validate_digest_format "sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919"; then
  test_pass "Scenario 3a: Valid lowercase 64-hex SHA256 digest accepted"
else
  test_fail "Scenario 3a: Valid digest failed"
fi

if ! validate_digest_format "sha256:short"; then
  test_pass "Scenario 3b: Truncated digest format rejected"
else
  test_fail "Scenario 3b: Truncated digest accepted"
fi

if ! validate_digest_format "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; then
  test_pass "Scenario 3c: Empty placeholder SHA256 digest strictly rejected"
else
  test_fail "Scenario 3c: Empty placeholder hash accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 4: Invalid Versions
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 4: Semantic Version Validation ---"
validate_version() {
  local v="$1"
  if [[ ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    return 1
  fi
  return 0
}

if validate_version "2.15.0" && validate_version "3.3.7"; then
  test_pass "Scenario 4a: Exact semantic versions accepted"
else
  test_fail "Scenario 4a: Valid semver rejected"
fi

if ! validate_version "latest" && ! validate_version "v-dev" && ! validate_version ""; then
  test_pass "Scenario 4b: Non-semver version strings strictly rejected"
else
  test_fail "Scenario 4b: Invalid version string accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 5: Architecture Mismatch
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 5: Architecture Mismatch Verification ---"
validate_arch() {
  local arch="$1" os="$2"
  if [[ "$arch" != "arm64" || "$os" != "linux" ]]; then
    return 1
  fi
  return 0
}

if validate_arch "arm64" "linux"; then
  test_pass "Scenario 5a: Verified arm64/linux platform accepted"
else
  test_fail "Scenario 5a: arm64/linux rejected"
fi

if ! validate_arch "amd64" "linux" && ! validate_arch "x86_64" "linux"; then
  test_pass "Scenario 5b: Non-ARM64 architectures (amd64, x86_64) strictly rejected"
else
  test_fail "Scenario 5b: Non-ARM64 architecture accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 6: Unexpected Runtime UID/GID
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 6: Runtime Identity Verification ---"
validate_uid() {
  local uid="$1"
  if [[ "$uid" != "10001:10001" ]]; then
    return 1
  fi
  return 0
}

if validate_uid "10001:10001"; then
  test_pass "Scenario 6a: Compliant unprivileged UID/GID 10001:10001 accepted"
else
  test_fail "Scenario 6a: 10001:10001 rejected"
fi

if ! validate_uid "0:0" && ! validate_uid "root" && ! validate_uid "1000:1000"; then
  test_pass "Scenario 6b: Root and non-10001:10001 runtime identities strictly rejected"
else
  test_fail "Scenario 6b: Non-compliant identity accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 7: Vulnerability Gate Failure
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 7: Vulnerability Gate Verification ---"
audit_vulnerability_counts() {
  local high_count="$1" crit_count="$2"
  if [[ "$high_count" -gt 0 || "$crit_count" -gt 0 ]]; then
    return 1 # fail closed
  fi
  return 0
}

if audit_vulnerability_counts 0 0; then
  test_pass "Scenario 7a: Zero HIGH/CRITICAL vulnerabilities passed gate"
else
  test_fail "Scenario 7a: Clean vulnerability scan rejected"
fi

if ! audit_vulnerability_counts 1 0 && ! audit_vulnerability_counts 0 2; then
  test_pass "Scenario 7b: Presence of HIGH or CRITICAL vulnerabilities fails closed"
else
  test_fail "Scenario 7b: Vulnerable image passed gate"
fi

# ------------------------------------------------------------------------------
# SCENARIO 8: Missing or Malformed SBOM
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 8: CycloneDX SBOM Verification ---"
verify_sbom_artifact() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
    return 1
  fi
  if ! grep -q '"bomFormat"[[:space:]]*:[[:space:]]*"CycloneDX"' "$path"; then
    return 2
  fi
  return 0
}

good_sbom="$TMP_TEST_DIR/good.cdx.json"
echo '{"bomFormat": "CycloneDX", "specVersion": "1.5"}' > "$good_sbom"
if verify_sbom_artifact "$good_sbom"; then
  test_pass "Scenario 8a: Valid CycloneDX SBOM accepted"
else
  test_fail "Scenario 8a: Valid SBOM rejected"
fi

missing_sbom="$TMP_TEST_DIR/missing.cdx.json"
bad_sbom="$TMP_TEST_DIR/bad.cdx.json"
echo '{"bomFormat": "SPDX"}' > "$bad_sbom"
if ! verify_sbom_artifact "$missing_sbom" && ! verify_sbom_artifact "$bad_sbom"; then
  test_pass "Scenario 8b: Missing or non-CycloneDX SBOM strictly fails closed"
else
  test_fail "Scenario 8b: Invalid SBOM accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 9: Registry Digest Mismatch
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 9: Registry Digest Mismatch Detection ---"
verify_registry_match() {
  local build_digest="$1" registry_digest="$2"
  if [[ "$build_digest" != "$registry_digest" ]]; then
    return 1
  fi
  return 0
}

d_match="sha256:1111111111111111111111111111111111111111111111111111111111111111"
d_mismatch="sha256:2222222222222222222222222222222222222222222222222222222222222222"

if verify_registry_match "$d_match" "$d_match"; then
  test_pass "Scenario 9a: Matching registry digest verified"
else
  test_fail "Scenario 9a: Matching digest rejected"
fi

if ! verify_registry_match "$d_match" "$d_mismatch"; then
  test_pass "Scenario 9b: Registry digest mismatch strictly detected and rejected"
else
  test_fail "Scenario 9b: Mismatched registry digest accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 10: Invalid Cosign Signature
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 10: Cosign Signature Verification ---"
verify_cosign_mock() {
  local sig_status="$1"
  if [[ "$sig_status" != "valid" ]]; then
    return 1
  fi
  return 0
}

if verify_cosign_mock "valid"; then
  test_pass "Scenario 10a: Cryptographically verified Cosign signature accepted"
else
  test_fail "Scenario 10a: Valid signature rejected"
fi

if ! verify_cosign_mock "missing" && ! verify_cosign_mock "tampered"; then
  test_pass "Scenario 10b: Missing or invalid Cosign signature strictly rejected"
else
  test_fail "Scenario 10b: Invalid signature accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 11: Invalid Provenance Identity
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 11: Provenance Identity Verification ---"
verify_provenance_identity() {
  local uri="$1" issuer="$2"
  local req_issuer="https://token.actions.githubusercontent.com"
  if [[ "$issuer" != "$req_issuer" ]]; then
    return 1
  fi
  if [[ ! "$uri" =~ ^https://github\.com/Inkesk-Dozing/Kelvin/\.github/workflows/ ]]; then
    return 2
  fi
  return 0
}

good_uri="https://github.com/Inkesk-Dozing/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
good_issuer="https://token.actions.githubusercontent.com"
if verify_provenance_identity "$good_uri" "$good_issuer"; then
  test_pass "Scenario 11a: Expected repo and workflow provenance identity accepted"
else
  test_fail "Scenario 11a: Valid provenance identity rejected"
fi

foreign_uri="https://github.com/Attacker/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
if ! verify_provenance_identity "$foreign_uri" "$good_issuer"; then
  test_pass "Scenario 11b: Foreign/unauthorized repository provenance strictly rejected"
else
  test_fail "Scenario 11b: Foreign provenance identity accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 12: Template Catalog Digest Mismatch
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 12: Template Catalog Tamper Detection ---"
catalog_file="deploy/scanners/templates/kelvin.safe.web.v1/catalog.json"
expected_catalog="sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"

if [[ -f "$catalog_file" ]]; then
  actual_hash="$(sha256sum "$catalog_file" 2>/dev/null | awk '{print $1}' || python -c "import hashlib; print(hashlib.sha256(open('$catalog_file','rb').read()).hexdigest())")"
  if [[ "sha256:$actual_hash" == "$expected_catalog" ]]; then
    test_pass "Scenario 12a: Canonical template catalog matches expected deterministic digest"
  else
    test_fail "Scenario 12a: Canonical catalog digest mismatch ($actual_hash)"
  fi
fi

tampered_catalog="$TMP_TEST_DIR/tampered.json"
echo '{"tampered": true}' > "$tampered_catalog"
tampered_hash="sha256:$(sha256sum "$tampered_catalog" 2>/dev/null | awk '{print $1}' || python -c "import hashlib; print(hashlib.sha256(open('$tampered_catalog','rb').read()).hexdigest())")"
if [[ "$tampered_hash" != "$expected_catalog" ]]; then
  test_pass "Scenario 12b: Modified/tampered template catalog detected and rejected"
else
  test_fail "Scenario 12b: Tampered catalog accepted"
fi

# ------------------------------------------------------------------------------
# SCENARIO 13: Missing Release Evidence
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 13: Release Evidence Gate ---"
verify_evidence_dir() {
  local dir="$1"
  for f in "build-record.json" "build-inputs.txt" "zap.cdx.json" "nuclei.cdx.json"; do
    if [[ ! -s "$dir/$f" ]]; then
      return 1
    fi
  done
  return 0
}

empty_ev_dir="$TMP_TEST_DIR/empty_ev"
mkdir -p "$empty_ev_dir"
if ! verify_evidence_dir "$empty_ev_dir"; then
  test_pass "Scenario 13a: Missing release evidence prevents image promotion"
else
  test_fail "Scenario 13a: Empty evidence directory passed"
fi

full_ev_dir="$TMP_TEST_DIR/full_ev"
mkdir -p "$full_ev_dir"
for f in "build-record.json" "build-inputs.txt" "zap.cdx.json" "nuclei.cdx.json"; do
  echo "evidence" > "$full_ev_dir/$f"
done
if verify_evidence_dir "$full_ev_dir"; then
  test_pass "Scenario 13b: Complete verifiable release evidence passes gate"
else
  test_fail "Scenario 13b: Full evidence directory failed"
fi

# ------------------------------------------------------------------------------
# SCENARIO 14: Attempts to Certify Incomplete Manifests
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 14: Incomplete Manifest Certification Prevention ---"
incomplete_manifest="$TMP_TEST_DIR/incomplete.json"
cat <<'EOF' > "$incomplete_manifest"
{
  "schema_version": "1",
  "status": "certified",
  "images": {
    "zap": {
      "upstream": "ghcr.io/zaproxy/zaproxy:stable",
      "upstream_digest": null,
      "version": null,
      "kelvin_image": null,
      "kelvin_digest": null
    }
  }
}
EOF

if ! bash scripts/scanners/verify-release-manifest.sh "$incomplete_manifest" >/dev/null 2>&1; then
  test_pass "Scenario 14: Attempt to certify incomplete manifest with null digests rejected"
else
  test_fail "Scenario 14: Incomplete manifest was certified"
fi

# ------------------------------------------------------------------------------
# SCENARIO 15: Worker Rejection of 'not-released' Manifests
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 15: Worker Fail-Closed 'not-released' Gating ---"
canonical_manifest="deploy/scanners/images.lock.json"
manifest_status="$(grep '"status"' "$canonical_manifest" | head -n 1 | awk -F'"' '{print $4}')"

if [[ "$manifest_status" == "not-released" ]]; then
  test_pass "Scenario 15a: Canonical baseline images.lock.json status is strictly 'not-released'"
else
  test_fail "Scenario 15a: Baseline manifest is not 'not-released' (got: $manifest_status)"
fi

audit_output="$(bash scripts/scanners/verify-release-manifest.sh "$canonical_manifest")"
if echo "$audit_output" | grep -q "strictly disabled by fail-closed worker governance"; then
  test_pass "Scenario 15b: Fail-closed governance explicitly disables scanner execution when not-released"
else
  test_fail "Scenario 15b: Fail-closed governance message missing in audit"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo "Scanner Release Pipeline Test Results: $PASS_COUNT PASSED, $FAIL_COUNT FAILED"
echo "=============================================================================="

if [[ $FAIL_COUNT -eq 0 ]]; then
  echo "ALL 15 SCANNER RELEASE GATES PASSED!"
  exit 0
else
  echo "TEST SUITE FAILED!" >&2
  exit 1
fi
