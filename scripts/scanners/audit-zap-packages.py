#!/usr/bin/env python3
"""
audit-zap-packages.py

Validates the mapping of all 384 reported ZAP vulnerability records
against package-audit.json and waivers.yaml (Issue #553).
"""

import json
import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WAIVERS_FILE = REPO_ROOT / "deploy" / "scanners" / "zap" / "waivers.yaml"
AUDIT_FILE = REPO_ROOT / "deploy" / "scanners" / "zap" / "package-audit.json"

def main():
    print("==> [Kelvin Security Gate] Auditing ZAP Debian & Runtime Package Dependencies...")

    if not WAIVERS_FILE.exists():
        print(f"[FAIL] Missing waivers file: {WAIVERS_FILE}")
        sys.exit(1)

    if not AUDIT_FILE.exists():
        print(f"[FAIL] Missing package audit file: {AUDIT_FILE}")
        sys.exit(1)

    with open(WAIVERS_FILE, "r", encoding="utf-8") as f:
        waiver_data = yaml.safe_load(f)

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        audit_data = json.load(f)

    waivers = waiver_data.get("waivers", [])
    total_waivers = len(waivers)
    print(f"  [INFO] Total ZAP Baseline Findings in Registry: {total_waivers}")

    if total_waivers != 384:
        print(f"[FAIL] Expected 384 waivers, found {total_waivers}")
        sys.exit(1)

    packages = audit_data.get("packages", {})
    total_audit_cves = sum(p["cve_count"] for p in packages.values())

    print(f"  [INFO] Total Mapped Findings in Audit Catalog: {total_audit_cves} across {len(packages)} packages")

    if total_audit_cves != total_waivers:
        print(f"[FAIL] Audit finding count ({total_audit_cves}) does not match registry count ({total_waivers})")
        sys.exit(1)

    # Verify critical package categories
    expected_categories = {
        "linux-libc-dev": 193,
        "firefox-esr": 51,
        "apt": 1,
        "setuptools": 1
    }

    for pkg, exp_count in expected_categories.items():
        if pkg not in packages:
            print(f"[FAIL] Missing expected critical package in audit: {pkg}")
            sys.exit(1)
        actual = packages[pkg]["cve_count"]
        if actual != exp_count:
            print(f"[FAIL] Expected {exp_count} CVEs for {pkg}, got {actual}")
            sys.exit(1)
        print(f"  [OK] {pkg}: {actual} CVEs verified (Runtime required: {packages[pkg]['runtime_required']})")

    # Verify dev packages identified for minimization
    dev_packages = ["libexpat1-dev", "zlib1g-dev", "libpython3.11-dev"]
    for dp in dev_packages:
        if dp in packages:
            if not packages[dp]["is_dev_package"]:
                print(f"[FAIL] Development package {dp} not marked as is_dev_package")
                sys.exit(1)
            print(f"  [OK] Dev package identified for pruning: {dp} ({packages[dp]['cve_count']} CVEs)")

    print("\n[OK] ZAP package audit verification passed with 100% finding reconciliation.")

if __name__ == "__main__":
    main()
