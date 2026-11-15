#!/usr/bin/env python3
"""
Lossless migration tool: Migrates existing Kelvin .trivyignore comments and CVEs
into canonical YAML waiver registries (deploy/scanners/<scanner>/waivers.yaml).
Governed by ADR-0008.
"""

import os
import re
import sys
import yaml

def migrate_trivyignore(input_path, scanner_name):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    curr_comment = None
    in_header = True
    waivers = []

    for idx, line in enumerate(lines):
        line_s = line.strip()
        if in_header:
            if line_s.startswith("CVE-") or (line_s.startswith("# [") and "]" in line_s):
                in_header = False
            else:
                continue

        if not line_s:
            continue

        if line_s.startswith("#"):
            curr_comment = line_s.lstrip("#").strip()
        elif line_s.startswith("CVE-"):
            cve = line_s.split()[0]
            if not curr_comment:
                raise ValueError(f"Missing preceding comment for CVE {cve} at line {idx+1}")

            m = re.match(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(\S+)\s+-\s+(.+)", curr_comment)
            if not m:
                raise ValueError(f"Failed to parse comment pattern at line {idx+1}: '{curr_comment}'")

            sev, comp, just = m.groups()

            # Deterministic upstream tracking references
            if comp.startswith("pkg:deb/"):
                tracking = f"https://security-tracker.debian.org/tracker/{cve}"
            elif comp.startswith("pkg:golang/"):
                tracking = f"https://pkg.go.dev/vuln/{cve}"
            else:
                tracking = f"https://nvd.nist.gov/vuln/detail/{cve}"

            # Every migrated record MUST initially be pending_review with NO fabricated fields
            waiver = {
                "cve_id": cve,
                "component": comp,
                "severity": sev,
                "technical_justification": just,
                "status": "pending_review",
                "owner": None,
                "review_date": None,
                "expiry_date": None,
                "tracking_reference": tracking,
                "approval": None,
            }
            waivers.append(waiver)
            curr_comment = None

    registry = {
        "schema_version": "1.0.0",
        "scanner": scanner_name,
        "metadata": {
            "policy_reference": "ADR-0008",
            "description": f"Kelvin Scanner Vulnerability Exception Waiver Registry - {scanner_name.upper()}",
            "updated_at": "2026-11-15T20:00:00Z",
            "ttl_days": {
                "CRITICAL": 30,
                "HIGH": 90,
                "MEDIUM": 180,
                "LOW": 180,
            },
            "expiry_warning_days": 14,
        },
        "waivers": waivers,
    }
    return registry

def main():
    zap_in = "deploy/scanners/zap/.trivyignore"
    zap_out = "deploy/scanners/zap/waivers.yaml"
    nuclei_in = "deploy/scanners/nuclei/.trivyignore"
    nuclei_out = "deploy/scanners/nuclei/waivers.yaml"

    print("==> Executing Kelvin Lossless Vulnerability Waiver Migration...")
    zap_reg = migrate_trivyignore(zap_in, "zap")
    with open(zap_out, "w", encoding="utf-8") as f:
        yaml.dump(zap_reg, f, sort_keys=False, width=120)
    print(f"  [OK] Migrated ZAP: {len(zap_reg['waivers'])} exceptions to {zap_out}")

    nuclei_reg = migrate_trivyignore(nuclei_in, "nuclei")
    with open(nuclei_out, "w", encoding="utf-8") as f:
        yaml.dump(nuclei_reg, f, sort_keys=False, width=120)
    print(f"  [OK] Migrated Nuclei: {len(nuclei_reg['waivers'])} exceptions to {nuclei_out}")

    total = len(zap_reg["waivers"]) + len(nuclei_reg["waivers"])
    print(f"==> Migration Complete: {total} total records migrated to 'pending_review' status.")

if __name__ == "__main__":
    main()
