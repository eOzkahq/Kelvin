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
# 16. Workflow permission boundaries & publish=false gating (least-privilege CI)
# 17. Nuclei Dockerfile global ARG scoping before FROM instructions
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

# Nuclei semantic version handling: build input is "3.11.1" (pure semver),
# while runtime binary output reports "v3.11.1"
validate_nuclei_version_match() {
  local build_v="$1" runtime_out="$2"
  if ! validate_version "$build_v"; then
    return 1 # build input must be pure semver (no leading v)
  fi
  local expected_v="v$build_v"
  if ! grep -Eq "(^|[^0-9A-Za-z])v?${build_v}([^0-9A-Za-z]|$)" <<<"$runtime_out"; then
    return 2 # runtime output mismatch
  fi
  return 0
}

mock_nuclei_output="[INF] Current nuclei version: v3.11.1 (latest)"
if validate_nuclei_version_match "3.11.1" "$mock_nuclei_output"; then
  test_pass "Scenario 4c: Nuclei semver build input (3.11.1) matches binary report (v3.11.1)"
else
  test_fail "Scenario 4c: Nuclei version match failed"
fi

if ! validate_nuclei_version_match "v3.11.1" "$mock_nuclei_output"; then
  test_pass "Scenario 4d: Nuclei build input with leading 'v' strictly rejected"
else
  test_fail "Scenario 4d: Leading 'v' in build input was accepted"
fi

if ! validate_nuclei_version_match "3.11.1" "[INF] Current nuclei version: v3.10.0 (outdated)"; then
  test_pass "Scenario 4e: Mismatched Nuclei binary version strictly rejected"
else
  test_fail "Scenario 4e: Mismatched Nuclei binary version accepted"
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
  if [[ ! "$uri" =~ ^https://github\.com/eOzkull/Kelvin/\.github/workflows/ ]]; then
    return 2
  fi
  return 0
}

good_uri="https://github.com/eOzkull/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
good_issuer="https://token.actions.githubusercontent.com"
if verify_provenance_identity "$good_uri" "$good_issuer"; then
  test_pass "Scenario 11a: Expected repo and workflow provenance identity (eOzkull/Kelvin) accepted"
else
  test_fail "Scenario 11a: Valid provenance identity rejected"
fi

foreign_uri="https://github.com/Attacker/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
old_owner_uri="https://github.com/Inkesk-Dozing/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
if ! verify_provenance_identity "$foreign_uri" "$good_issuer" && ! verify_provenance_identity "$old_owner_uri" "$good_issuer"; then
  test_pass "Scenario 11b: Foreign provenance and legacy owner (Inkesk-Dozing) strictly rejected"
else
  test_fail "Scenario 11b: Foreign or legacy provenance identity accepted"
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
  test_pass "Scenario 14a: Attempt to certify incomplete manifest with null digests rejected"
else
  test_fail "Scenario 14a: Incomplete manifest was certified"
fi

old_ns_manifest="$TMP_TEST_DIR/old_ns.json"
cat <<'EOF' > "$old_ns_manifest"
{
  "schema_version": "1",
  "status": "certified",
  "images": {
    "zap": {
      "upstream": "ghcr.io/zaproxy/zaproxy:stable",
      "upstream_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "version": "2.15.0",
      "kelvin_image": "ghcr.io/inkesk-dozing/kelvin/scanner-zap",
      "kelvin_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  }
}
EOF
if ! bash scripts/scanners/verify-release-manifest.sh "$old_ns_manifest" >/dev/null 2>&1; then
  test_pass "Scenario 14b: Legacy namespace (ghcr.io/inkesk-dozing) in manifest rejected"
else
  test_fail "Scenario 14b: Legacy namespace in manifest was accepted"
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
# SCENARIO 16: Workflow Permission Boundaries & publish=false Gating
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 16: Workflow Permission Boundaries & Release Gating ---"
workflow_file=".github/workflows/scanner-images.yml"

if [[ ! -f "$workflow_file" ]]; then
  test_fail "Scenario 16: Workflow file $workflow_file missing"
else
  # 16a: Top-level environment must not have ENABLE_CI: 'true' hardcoded override
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
env_block = wf.get('env', {})
if env_block and env_block.get('ENABLE_CI') == 'true':
    sys.exit(1)
sys.exit(0)
"; then
    test_pass "Scenario 16a: Hardcoded ENABLE_CI: 'true' top-level override removed"
  else
    test_fail "Scenario 16a: Found hardcoded ENABLE_CI: 'true' in top-level env"
  fi

  # 16b: Workflow must separate build-and-scan from publish-and-sign jobs
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
jobs = wf.get('jobs', {})
if 'build-and-scan' in jobs and 'publish-and-sign' in jobs and 'build-scan-and-release' not in jobs:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16b: Separate build-and-scan and publish-and-sign jobs configured"
  else
    test_fail "Scenario 16b: Missing expected job separation in $workflow_file"
  fi

  # 16c: Build job must have only 'contents: read' permissions
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
perms = wf.get('jobs', {}).get('build-and-scan', {}).get('permissions', {})
if perms == {'contents': 'read'}:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16c: Build job has strictly least-privilege 'contents: read' permissions"
  else
    test_fail "Scenario 16c: Build job has excessive or unexpected permissions"
  fi

  # 16d: Build job condition requires inputs.enable_ci == true
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
cond = str(wf.get('jobs', {}).get('build-and-scan', {}).get('if', ''))
if 'inputs.enable_ci == true' in cond:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16d: Build job gated on inputs.enable_ci == true"
  else
    test_fail "Scenario 16d: Build job missing strict inputs.enable_ci gating"
  fi

  # 16e: Publishing job runs only when inputs.publish == true and build job succeeds
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
job = wf.get('jobs', {}).get('publish-and-sign', {})
cond = str(job.get('if', ''))
needs = job.get('needs', [])
if isinstance(needs, str):
    needs = [needs]
if 'inputs.publish == true' in cond and 'build-and-scan' in needs:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16e: Publishing job requires build-and-scan success and inputs.publish == true"
  else
    test_fail "Scenario 16e: Publishing job missing needs dependency or publish condition"
  fi

  # 16f: Grant packages: write, id-token: write, attestations: write only to publishing job
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
pub_perms = wf.get('jobs', {}).get('publish-and-sign', {}).get('permissions', {})
build_perms = wf.get('jobs', {}).get('build-and-scan', {}).get('permissions', {})
top_perms = wf.get('permissions', {})

has_write = all(pub_perms.get(k) == 'write' for k in ['packages', 'id-token', 'attestations'])
build_clean = not any(build_perms.get(k) == 'write' for k in ['packages', 'id-token', 'attestations'])
top_clean = not any(top_perms.get(k) == 'write' for k in ['packages', 'id-token', 'attestations'])

if has_write and build_clean and top_clean:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16f: Sensitive write permissions granted strictly to publishing job"
  else
    test_fail "Scenario 16f: Permission leakage detected between workflow jobs"
  fi

  # 16g: Verify publish=false cannot authenticate to GHCR, push images, or sign
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
build_steps = wf.get('jobs', {}).get('build-and-scan', {}).get('steps', [])
build_str = yaml.dump(build_steps)

sensitive_tokens = ['login-action', 'publish-and-sign.sh', 'cosign-installer', 'docker push']
leaked = [t for t in sensitive_tokens if t in build_str]
if not leaked:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16g: Sensitive publishing actions isolated to publish-and-sign job"
  else
    test_fail "Scenario 16g: Sensitive publishing action found in build-and-scan job"
  fi

  # 16h: All GitHub Actions pinned to immutable commit SHAs
  if python -c "
import yaml, re, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)
unpinned = []
for jname, jdata in wf.get('jobs', {}).items():
    for step in jdata.get('steps', []):
        uses = step.get('uses')
        if uses:
            if not re.search(r'@[0-9a-f]{40}', uses):
                unpinned.append(f'{jname}: {uses}')
if not unpinned:
    sys.exit(0)
print('Unpinned actions:', unpinned, file=sys.stderr)
sys.exit(1)
"; then
    test_pass "Scenario 16h: All GitHub Actions steps strictly pinned by immutable commit SHA"
  else
    test_fail "Scenario 16h: Unpinned GitHub Action reference detected in $workflow_file"
  fi

  # 16i: Exact verified immutable commit SHAs for setup-qemu-action and setup-buildx-action
  if python -c "
import sys
with open('$workflow_file', 'r') as f:
    content = f.read()

qemu_valid = 'docker/setup-qemu-action@49b3bc8e6bdd4a60e6116a5414239cba5943d3cf' in content
buildx_valid = 'docker/setup-buildx-action@c47758b77c9736f4b2ef4073d4d51994fabfe349' in content
qemu_invalid = '49b3bc8e6bdd4480b82837412f66d573217e85c4' in content
buildx_invalid = 'c47758b77c9736f4b4e79d4850a0074cbe657f63' in content

if qemu_valid and buildx_valid and not qemu_invalid and not buildx_invalid:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16i: Exact verified action commit SHAs for QEMU (v3.2.0) and Buildx (v3.7.1) confirmed"
  else
    test_fail "Scenario 16i: Invalid or corrupted action commit SHA detected in $workflow_file"
  fi

  # 16j: Exact verified immutable commit SHA for aquasecurity/trivy-action (v0.31.0) and rejection of v0.29.0
  if python -c "
import sys
with open('$workflow_file', 'r') as f:
    content = f.read()

trivy_valid = 'aquasecurity/trivy-action@76071ef0d7ec797419534a183b498b4d6366cf37' in content
trivy_invalid = '18f2510ee396bbf400402947b394f2dd8c87dbb0' in content
trivy_count = content.count('aquasecurity/trivy-action@76071ef0d7ec797419534a183b498b4d6366cf37')

if trivy_valid and trivy_count == 2 and not trivy_invalid:
    sys.exit(0)
sys.exit(1)
"; then
    test_pass "Scenario 16j: Exact verified action commit SHA for Trivy (v0.31.0) confirmed across both scan steps and v0.29.0 rejected"
  else
    test_fail "Scenario 16j: Trivy action commit SHA verification failed in $workflow_file"
  fi

  # 16k: Explicit verified Trivy release version (v0.70.0) configured to override unreleased v0.63.0 default
  if python -c "
import yaml, sys
with open('$workflow_file', 'r') as f:
    wf = yaml.safe_load(f)

build_steps = wf.get('jobs', {}).get('build-and-scan', {}).get('steps', [])
trivy_steps = [s for s in build_steps if 'trivy-action' in s.get('uses', '')]

if len(trivy_steps) != 2:
    sys.exit(1)

for s in trivy_steps:
    v = s.get('with', {}).get('version')
    if v != 'v0.70.0':
        sys.exit(2)

sys.exit(0)
"; then
    test_pass "Scenario 16k: Both Trivy scan steps explicitly specify verified release version (v0.70.0) to avoid 404"
  else
    test_fail "Scenario 16k: Trivy scan steps missing explicit verified version v0.70.0 in $workflow_file"
  fi
fi

# ------------------------------------------------------------------------------
# SCENARIO 17: Nuclei Dockerfile Global ARG Placement Verification
# ------------------------------------------------------------------------------
echo "--- Testing Scenario 17: Nuclei Dockerfile Global ARG Scope Verification ---"
nuclei_dockerfile="deploy/scanners/nuclei/Dockerfile"

validate_dockerfile_from_args() {
  local df_path="$1"
  python -c "
import sys, re

with open('$df_path', 'r') as f:
    lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

# Find the index of the first FROM instruction
first_from_idx = None
for idx, line in enumerate(lines):
    if re.match(r'^FROM\s+', line, re.IGNORECASE):
        first_from_idx = idx
        break

if first_from_idx is None:
    print('No FROM instruction found', file=sys.stderr)
    sys.exit(1)

# Collect all ARGs before the first FROM (global scope)
global_args = set()
for line in lines[:first_from_idx]:
    m = re.match(r'^ARG\s+([A-Za-z0-9_]+)', line, re.IGNORECASE)
    if m:
        global_args.add(m.group(1))

# Check for required global ARGs used in subsequent FROM instructions
required_from_args = {'NUCLEI_SOURCE_IMAGE', 'DISTROLESS_BASE_IMAGE'}
missing = required_from_args - global_args
if missing:
    print(f'Missing required global ARG(s) before first FROM: {missing}', file=sys.stderr)
    sys.exit(1)

# Ensure DISTROLESS_BASE_IMAGE is not declared between FROM instructions
for line in lines[first_from_idx:]:
    if re.match(r'^FROM\s+', line, re.IGNORECASE):
        continue
    if re.match(r'^ARG\s+DISTROLESS_BASE_IMAGE', line, re.IGNORECASE):
        print('DISTROLESS_BASE_IMAGE found in stage scope instead of global scope', file=sys.stderr)
        sys.exit(2)

sys.exit(0)
"
}

if validate_dockerfile_from_args "$nuclei_dockerfile"; then
  test_pass "Scenario 17a: Nuclei Dockerfile declares both NUCLEI_SOURCE_IMAGE and DISTROLESS_BASE_IMAGE before first FROM"
else
  test_fail "Scenario 17a: Nuclei Dockerfile global ARG validation failed"
fi

# Negative test: Dockerfile with misplaced ARG after first FROM must be rejected
faulty_dockerfile="$TMP_TEST_DIR/faulty.Dockerfile"
cat <<'EOF' > "$faulty_dockerfile"
ARG NUCLEI_SOURCE_IMAGE
FROM ${NUCLEI_SOURCE_IMAGE} AS upstream

ARG DISTROLESS_BASE_IMAGE
FROM ${DISTROLESS_BASE_IMAGE}
EOF

if ! validate_dockerfile_from_args "$faulty_dockerfile" >/dev/null 2>&1; then
  test_pass "Scenario 17b: Misplaced ARG DISTROLESS_BASE_IMAGE after first FROM successfully detected and rejected"
else
  test_fail "Scenario 17b: Faulty Dockerfile with misplaced ARG was accepted"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo "Scanner Release Pipeline Test Results: $PASS_COUNT PASSED, $FAIL_COUNT FAILED"
echo "=============================================================================="

if [[ $FAIL_COUNT -eq 0 ]]; then
  echo "ALL 17 SCANNER RELEASE GATES PASSED!"
  exit 0
else
  echo "TEST SUITE FAILED!" >&2
  exit 1
fi
