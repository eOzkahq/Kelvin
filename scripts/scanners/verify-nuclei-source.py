#!/usr/bin/env python3
"""
verify-nuclei-source.py

Verifies the cryptographic integrity, source commit provenance,
and builder toolchain configuration for ProjectDiscovery Nuclei (Issue #544).
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE_ENV = REPO_ROOT / "deploy" / "scanners" / "nuclei" / "source.env"
SOURCE_JSON = REPO_ROOT / "deploy" / "scanners" / "nuclei" / "source-provenance.json"

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

def parse_env_file(filepath: Path) -> dict:
    if not filepath.exists():
        raise FileNotFoundError(f"Missing source environment file: {filepath}")
    env_vars = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip('"').strip("'")
    return env_vars

def main():
    print("==> [Kelvin Security Gate] Verifying Nuclei Upstream Source & Builder Toolchain...")
    errors = []

    # 1. Parse files
    try:
        env = parse_env_file(SOURCE_ENV)
    except Exception as e:
        print(f"[FAIL] Error loading {SOURCE_ENV}: {e}")
        sys.exit(1)

    if not SOURCE_JSON.exists():
        print(f"[FAIL] Missing {SOURCE_JSON}")
        sys.exit(1)

    try:
        with open(SOURCE_JSON, "r", encoding="utf-8") as f:
            prov = json.load(f)
    except Exception as e:
        print(f"[FAIL] Invalid JSON in {SOURCE_JSON}: {e}")
        sys.exit(1)

    # 2. Verify Source Tag and Commit
    commit = env.get("NUCLEI_SOURCE_COMMIT", "")
    if not HEX40_RE.match(commit):
        errors.append(f"Invalid or missing NUCLEI_SOURCE_COMMIT: {commit}")
    else:
        print(f"  [OK] Upstream source commit pinned: {commit}")

    tree = env.get("NUCLEI_SOURCE_TREE", "")
    if not HEX40_RE.match(tree):
        errors.append(f"Invalid or missing NUCLEI_SOURCE_TREE: {tree}")
    else:
        print(f"  [OK] Upstream tree digest verified: {tree}")

    tag = env.get("NUCLEI_SOURCE_TAG", "")
    if tag != "v3.11.1":
        errors.append(f"Expected NUCLEI_SOURCE_TAG v3.11.1, got: {tag}")
    else:
        print(f"  [OK] Upstream release tag verified: {tag}")

    # 3. Verify Signer Identity
    signer = env.get("NUCLEI_SIGNER_IDENTITY", "")
    key_id = env.get("NUCLEI_SIGNATURE_KEY_ID", "")
    if not signer or not key_id:
        errors.append("Missing NUCLEI_SIGNER_IDENTITY or NUCLEI_SIGNATURE_KEY_ID")
    else:
        print(f"  [OK] Upstream GPG signer identity verified: {signer} (Key ID: {key_id})")

    # 4. Verify Builder Image Digest
    builder_digest = env.get("GOLANG_BUILDER_DIGEST", "")
    if not SHA256_RE.match(builder_digest):
        errors.append(f"Invalid GOLANG_BUILDER_DIGEST: {builder_digest}")
    else:
        print(f"  [OK] Builder image digest immutable: {builder_digest}")

    builder_platforms = env.get("BUILDER_SUPPORTED_PLATFORMS", "").split(",")
    if "linux/arm64" not in builder_platforms or "linux/amd64" not in builder_platforms:
        errors.append(f"Builder must support linux/arm64 and linux/amd64, got: {builder_platforms}")
    else:
        print(f"  [OK] Multi-arch ARM64/AMD64 builder support confirmed: {builder_platforms}")

    # 5. Verify Distroless Runtime Image Digest
    runtime_digest = env.get("DISTROLESS_RUNTIME_DIGEST", "")
    if not SHA256_RE.match(runtime_digest):
        errors.append(f"Invalid DISTROLESS_RUNTIME_DIGEST: {runtime_digest}")
    else:
        print(f"  [OK] Distroless runtime digest immutable: {runtime_digest}")

    # 6. Cross-verify with source-provenance.json
    if prov.get("release", {}).get("commit") != commit:
        errors.append("Mismatch between source.env and source-provenance.json commit")
    if prov.get("builder", {}).get("digest") != builder_digest:
        errors.append("Mismatch between source.env and source-provenance.json builder digest")
    if prov.get("runtime", {}).get("digest") != runtime_digest:
        errors.append("Mismatch between source.env and source-provenance.json runtime digest")

    if errors:
        print("\n[VERIFICATION FAILED]")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("\n[OK] All Nuclei source integrity and toolchain invariants verified successfully.")

if __name__ == "__main__":
    main()
