#!/usr/bin/env bash
# ==============================================================================
# Kelvin Scanner Release Manifest Verification & Integrity Audit Script
# Validates deploy/scanners/images.lock.json against fail-closed release policy.
# Ensures 'certified' status cannot be achieved through manual status-only edits.
# ==============================================================================
set -euo pipefail

MANIFEST_PATH="${1:-deploy/scanners/images.lock.json}"
EMPTY_SHA256="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EXPECTED_CATALOG_ID="kelvin.safe.web.v1"
EXPECTED_CATALOG_DIGEST="sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"
CATALOG_PATH="deploy/scanners/templates/kelvin.safe.web.v1/catalog.json"

json_get() {
  local file="$1" path="$2"
  if command -v jq >/dev/null 2>&1; then
    jq -r "$path // empty" "$file" 2>/dev/null || echo ""
  elif command -v python >/dev/null 2>&1; then
    python -c "
import json, sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)
    expr = sys.argv[2].strip('.').split('.')
    val = data
    for p in expr:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            val = None
            break
    if val is not None:
        print(val)
except Exception:
    pass
" "$file" "$path" 2>/dev/null || echo ""
  else
    echo "ERROR: Neither jq nor python available to parse JSON." >&2
    exit 1
  fi
}

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

echo "==> Auditing Kelvin Scanner Release Manifest: $MANIFEST_PATH"

if [[ ! -f "$MANIFEST_PATH" ]]; then
  echo "ERROR: Release manifest not found at $MANIFEST_PATH" >&2
  exit 1
fi

status="$(json_get "$MANIFEST_PATH" ".status")"
schema_version="$(json_get "$MANIFEST_PATH" ".schema_version")"

if [[ "$schema_version" != "1" && "$schema_version" != "1.0" ]]; then
  echo "ERROR: Unsupported manifest schema version '$schema_version'" >&2
  exit 1
fi

if [[ "$status" == "not-released" ]]; then
  echo "  [AUDIT NOTE] Manifest status is 'not-released'."
  echo "  --> Live container scanner execution remains strictly disabled by fail-closed worker governance."
  echo "  --> Host worker will run in task-handling mode while rejecting live scanner execution."
  exit 0
fi

if [[ "$status" != "certified" ]]; then
  echo "ERROR: Invalid manifest status '$status'. Allowed statuses: 'not-released', 'certified'" >&2
  exit 1
fi

# Strict Verification for Status 'certified'
echo "==> Performing Strict Release Governance Verification for 'certified' Status..."

# Check ZAP Fields
zap_upstream="$(json_get "$MANIFEST_PATH" ".images.zap.upstream")"
zap_up_digest="$(json_get "$MANIFEST_PATH" ".images.zap.upstream_digest")"
zap_version="$(json_get "$MANIFEST_PATH" ".images.zap.version")"
zap_image="$(json_get "$MANIFEST_PATH" ".images.zap.kelvin_image")"
zap_digest="$(json_get "$MANIFEST_PATH" ".images.zap.kelvin_digest")"

if [[ "$zap_upstream" != "ghcr.io/zaproxy/zaproxy:stable" ]]; then
  echo "ERROR: ZAP upstream must be 'ghcr.io/zaproxy/zaproxy:stable' (got: '$zap_upstream')" >&2
  exit 1
fi
if [[ ! "$zap_up_digest" =~ ^sha256:[0-9a-f]{64}$ || "$zap_up_digest" == "$EMPTY_SHA256" ]]; then
  echo "ERROR: ZAP upstream digest must be valid non-empty sha256 (got: '$zap_up_digest')" >&2
  exit 1
fi
if [[ ! "$zap_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "ERROR: ZAP version must be valid semver (got: '$zap_version')" >&2
  exit 1
fi
if [[ "$zap_image" != "ghcr.io/eozkull/kelvin/scanner-zap"* ]]; then
  echo "ERROR: ZAP kelvin_image must be in official namespace 'ghcr.io/eozkull/kelvin/scanner-zap' (got: '$zap_image')" >&2
  exit 1
fi
if [[ ! "$zap_digest" =~ ^sha256:[0-9a-f]{64}$ || "$zap_digest" == "$EMPTY_SHA256" ]]; then
  echo "ERROR: ZAP release digest must be valid non-empty sha256 (got: '$zap_digest')" >&2
  exit 1
fi

# Check Nuclei Fields
nuclei_upstream="$(json_get "$MANIFEST_PATH" ".images.nuclei.upstream")"
nuclei_up_digest="$(json_get "$MANIFEST_PATH" ".images.nuclei.upstream_digest")"
nuclei_version="$(json_get "$MANIFEST_PATH" ".images.nuclei.version")"
distroless_base="$(json_get "$MANIFEST_PATH" ".images.nuclei.distroless_base")"
distroless_digest="$(json_get "$MANIFEST_PATH" ".images.nuclei.distroless_digest")"
nuclei_image="$(json_get "$MANIFEST_PATH" ".images.nuclei.kelvin_image")"
nuclei_digest="$(json_get "$MANIFEST_PATH" ".images.nuclei.kelvin_digest")"
catalog_id="$(json_get "$MANIFEST_PATH" ".images.nuclei.template_catalog_id")"
catalog_digest="$(json_get "$MANIFEST_PATH" ".images.nuclei.template_catalog_digest")"

if [[ "$nuclei_upstream" != "projectdiscovery/nuclei" && "$nuclei_upstream" != "ghcr.io/projectdiscovery/nuclei" ]]; then
  echo "ERROR: Nuclei upstream must be approved ProjectDiscovery repository (got: '$nuclei_upstream')" >&2
  exit 1
fi
if [[ ! "$nuclei_up_digest" =~ ^sha256:[0-9a-f]{64}$ || "$nuclei_up_digest" == "$EMPTY_SHA256" ]]; then
  echo "ERROR: Nuclei upstream digest must be valid non-empty sha256 (got: '$nuclei_up_digest')" >&2
  exit 1
fi
if [[ ! "$nuclei_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "ERROR: Nuclei version must be valid semver (got: '$nuclei_version')" >&2
  exit 1
fi
if [[ "$distroless_base" != "gcr.io/distroless/static-debian12:nonroot" ]]; then
  echo "ERROR: Nuclei distroless base must be 'gcr.io/distroless/static-debian12:nonroot' (got: '$distroless_base')" >&2
  exit 1
fi
if [[ ! "$distroless_digest" =~ ^sha256:[0-9a-f]{64}$ || "$distroless_digest" == "$EMPTY_SHA256" ]]; then
  echo "ERROR: Nuclei distroless digest must be valid non-empty sha256 (got: '$distroless_digest')" >&2
  exit 1
fi
if [[ "$nuclei_image" != "ghcr.io/eozkull/kelvin/scanner-nuclei"* ]]; then
  echo "ERROR: Nuclei kelvin_image must be in official namespace 'ghcr.io/eozkull/kelvin/scanner-nuclei' (got: '$nuclei_image')" >&2
  exit 1
fi
if [[ ! "$nuclei_digest" =~ ^sha256:[0-9a-f]{64}$ || "$nuclei_digest" == "$EMPTY_SHA256" ]]; then
  echo "ERROR: Nuclei release digest must be valid non-empty sha256 (got: '$nuclei_digest')" >&2
  exit 1
fi
if [[ "$catalog_id" != "$EXPECTED_CATALOG_ID" ]]; then
  echo "ERROR: Nuclei template catalog ID must be '$EXPECTED_CATALOG_ID' (got: '$catalog_id')" >&2
  exit 1
fi
if [[ "$catalog_digest" != "$EXPECTED_CATALOG_DIGEST" ]]; then
  echo "ERROR: Nuclei template catalog digest mismatch! Expected $EXPECTED_CATALOG_DIGEST, got $catalog_digest" >&2
  exit 1
fi

# Verify Catalog Files On Disk
if [[ -f "$CATALOG_PATH" ]]; then
  actual_cat_hash="$(calc_sha256 "$CATALOG_PATH")"
  if [[ "sha256:$actual_cat_hash" != "$EXPECTED_CATALOG_DIGEST" ]]; then
    echo "ERROR: Catalog file on disk $CATALOG_PATH does not match declared digest $EXPECTED_CATALOG_DIGEST (got sha256:$actual_cat_hash)" >&2
    exit 1
  fi
fi

echo "==> [AUDIT PASSED] Release manifest structural integrity, schema, and catalog digest constraints verified."
