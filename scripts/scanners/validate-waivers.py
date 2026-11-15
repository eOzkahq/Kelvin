#!/usr/bin/env python3
"""
Kelvin Scanner Vulnerability Exception Waiver Registry Validator & Generator
Enforces fail-closed governance, auditable maintainer approvals, severity TTL limits,
expiration dates, duplicate detection, and synchronization with .trivyignore.
Governed by ADR-0008.
"""

import argparse
import datetime
import json
import os
import re
import sys
import yaml

DEFAULT_MAINTAINERS = ["@eOzkull", "eOzkull"]
SEVERITY_TTL_DAYS = {
    "CRITICAL": 30,
    "HIGH": 90,
    "MEDIUM": 180,
    "LOW": 180,
}
EXPIRY_WARNING_DAYS = 14
CVE_REGEX = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
PLACEHOLDER_REGEX = re.compile(r"(<.*>|UNASSIGNED|PENDING|PLACEHOLDER|TBD|TODO)", re.IGNORECASE)
COMPONENT_PURL_REGEX = re.compile(r"^pkg:[a-z0-9_-]+/[^@\s]+@[^@\s]+$")

APPROVED_ADVISORY_PREFIXES = [
    "https://nvd.nist.gov/vuln/detail/",
    "https://github.com/advisories/",
    "https://security-tracker.debian.org/tracker/",
    "https://pkg.go.dev/vuln/",
    "https://ubuntu.com/security/",
    "https://osv.dev/",
    "https://cve.org/",
    "https://www.cve.org/",
]

DATE_FORMAT = "%Y-%m-%d"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

class ValidationError(Exception):
    pass

def parse_iso_date(date_str, field_name, cve_id):
    if not isinstance(date_str, str):
        raise ValidationError(f"[{cve_id}] {field_name} must be a string formatted as YYYY-MM-DD, got {type(date_str).__name__}")
    try:
        return datetime.datetime.strptime(date_str, DATE_FORMAT).date()
    except ValueError:
        raise ValidationError(f"[{cve_id}] {field_name} '{date_str}' is not a valid date formatted as YYYY-MM-DD")

def parse_iso_datetime(dt_str, field_name, cve_id):
    if not isinstance(dt_str, str):
        raise ValidationError(f"[{cve_id}] {field_name} must be a string formatted as ISO 8601, got {type(dt_str).__name__}")
    # Support YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DD
    for fmt in [DATETIME_FORMAT, DATE_FORMAT, "%Y-%m-%dT%H:%M:%S"]:
        try:
            return datetime.datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    raise ValidationError(f"[{cve_id}] {field_name} '{dt_str}' is not a valid ISO datetime")

def validate_waiver(waiver, current_date, authorized_maintainers, ttl_config, allow_pending=True):
    """
    Validates a single waiver entry according to Kelvin ADR-0008 governance rules.
    Returns: (is_active_approved, warning_message_or_None)
    """
    required_keys = [
        "cve_id", "component", "severity", "technical_justification",
        "status", "owner", "review_date", "expiry_date",
        "tracking_reference", "approval"
    ]
    for key in required_keys:
        if key not in waiver:
            raise ValidationError(f"Missing required field '{key}' in waiver: {waiver}")

    cve_id = waiver["cve_id"]
    if not isinstance(cve_id, str) or not CVE_REGEX.match(cve_id):
        raise ValidationError(f"Invalid CVE identifier '{cve_id}'. Must match regex {CVE_REGEX.pattern}")

    component = waiver["component"]
    if not isinstance(component, str) or not component.strip():
        raise ValidationError(f"[{cve_id}] 'component' must be a non-empty string")
    if not COMPONENT_PURL_REGEX.match(component):
        raise ValidationError(f"[{cve_id}] 'component' must follow canonical Package URL (purl) format 'pkg:<type>/<name>@<version>', got '{component}'")

    severity = waiver["severity"]
    if severity not in SEVERITY_TTL_DAYS:
        raise ValidationError(f"[{cve_id}] Invalid severity '{severity}'. Must be one of {list(SEVERITY_TTL_DAYS.keys())}")

    justification = waiver["technical_justification"]
    if not isinstance(justification, str) or len(justification.strip()) < 10:
        raise ValidationError(f"[{cve_id}] 'technical_justification' must be an informative explanation with at least 10 characters")
    if PLACEHOLDER_REGEX.search(justification):
        raise ValidationError(f"[{cve_id}] 'technical_justification' contains forbidden placeholder text: '{justification}'")

    tracking = waiver["tracking_reference"]
    if not isinstance(tracking, str) or not tracking.strip():
        raise ValidationError(f"[{cve_id}] 'tracking_reference' must be a non-empty URI string")
    if not (tracking.startswith("https://") or tracking.startswith("http://")):
        raise ValidationError(f"[{cve_id}] 'tracking_reference' must be an HTTP/HTTPS advisory URI: '{tracking}'")
    if not any(tracking.startswith(prefix) for prefix in APPROVED_ADVISORY_PREFIXES):
        raise ValidationError(
            f"[{cve_id}] 'tracking_reference' '{tracking}' does not match an approved security advisory source. "
            f"Approved sources include NVD, GHSA, Debian Security Tracker, Go Vuln DB, OSV, and CVE.org."
        )

    status = waiver["status"]
    valid_statuses = ["pending_review", "approved", "rejected", "expired"]
    if status not in valid_statuses:
        raise ValidationError(f"[{cve_id}] Invalid status '{status}'. Must be one of {valid_statuses}")

    warning = None

    if status == "pending_review":
        if not allow_pending:
            raise ValidationError(f"[{cve_id}] Pending review waivers are not permitted in this context")
        # In pending_review, owner, review_date, expiry_date, approval may be None or placeholders
        return False, None

    if status in ["rejected", "expired"]:
        # Inactive statuses
        return False, None

    # status == "approved"
    owner = waiver.get("owner")
    if not owner or not isinstance(owner, str) or PLACEHOLDER_REGEX.search(owner):
        raise ValidationError(f"[{cve_id}] Approved waiver has invalid or placeholder owner: '{owner}'")

    review_date_str = waiver.get("review_date")
    if not review_date_str or PLACEHOLDER_REGEX.search(str(review_date_str)):
        raise ValidationError(f"[{cve_id}] Approved waiver has invalid or placeholder review_date: '{review_date_str}'")
    review_date = parse_iso_date(review_date_str, "review_date", cve_id)
    if review_date > current_date:
        raise ValidationError(f"[{cve_id}] review_date '{review_date}' cannot be in the future (current_date: {current_date})")

    expiry_date_str = waiver.get("expiry_date")
    if not expiry_date_str or PLACEHOLDER_REGEX.search(str(expiry_date_str)):
        raise ValidationError(f"[{cve_id}] Approved waiver has invalid or placeholder expiry_date: '{expiry_date_str}'")
    expiry_date = parse_iso_date(expiry_date_str, "expiry_date", cve_id)
    if expiry_date <= review_date:
        raise ValidationError(f"[{cve_id}] expiry_date '{expiry_date}' must be strictly after review_date '{review_date}'")

    # Enforce Severity TTL
    max_ttl = ttl_config.get(severity, SEVERITY_TTL_DAYS[severity])
    actual_ttl = (expiry_date - review_date).days
    if actual_ttl > max_ttl:
        raise ValidationError(
            f"[{cve_id}] Expiry TTL of {actual_ttl} days exceeds maximum allowed TTL of {max_ttl} days for {severity} severity"
        )

    # Check for expiration against current date
    if expiry_date < current_date:
        raise ValidationError(
            f"[{cve_id}] Approved waiver expired on {expiry_date} (current_date: {current_date}). Must be updated or status changed to 'expired'."
        )

    # Expiry warning
    days_left = (expiry_date - current_date).days
    if days_left <= EXPIRY_WARNING_DAYS:
        warning = f"[{cve_id}] WARNING: Approved waiver will expire in {days_left} day(s) on {expiry_date}"

    # Approval Audit Verification
    approval = waiver.get("approval")
    if not isinstance(approval, dict):
        raise ValidationError(
            f"[{cve_id}] Status is 'approved' but approval audit object is missing or invalid: {approval}"
        )

    approved_by = approval.get("approved_by")
    if not approved_by or not isinstance(approved_by, str) or PLACEHOLDER_REGEX.search(approved_by):
        raise ValidationError(f"[{cve_id}] Approval missing or has placeholder 'approved_by': '{approved_by}'")

    if authorized_maintainers and approved_by not in authorized_maintainers:
        raise ValidationError(
            f"[{cve_id}] Approval by '{approved_by}' is unauthorized. Authorized maintainers: {authorized_maintainers}"
        )

    approval_ref = approval.get("approval_reference")
    if not approval_ref or not isinstance(approval_ref, str) or PLACEHOLDER_REGEX.search(approval_ref):
        raise ValidationError(f"[{cve_id}] Approval missing or has placeholder 'approval_reference': '{approval_ref}'")

    approved_at = approval.get("approved_at")
    if not approved_at or PLACEHOLDER_REGEX.search(str(approved_at)):
        raise ValidationError(f"[{cve_id}] Approval missing or has placeholder 'approved_at': '{approved_at}'")
    parse_iso_datetime(approved_at, "approved_at", cve_id)

    return True, warning

def validate_registry_file(file_path, current_date=None, authorized_maintainers=None):
    if current_date is None:
        current_date = datetime.date.today()
    if authorized_maintainers is None:
        authorized_maintainers = DEFAULT_MAINTAINERS

    if not os.path.exists(file_path):
        raise ValidationError(f"Registry file not found at: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            raise ValidationError(f"YAML parse error in {file_path}: {e}")

    if not isinstance(data, dict):
        raise ValidationError(f"Root of {file_path} must be a dictionary")

    if data.get("schema_version") not in ["1.0.0", "1", 1]:
        raise ValidationError(f"Unsupported schema_version in {file_path}: {data.get('schema_version')}")

    scanner = data.get("scanner")
    if scanner not in ["zap", "nuclei"]:
        raise ValidationError(f"Invalid scanner type in {file_path}: {scanner}")

    ttl_config = data.get("metadata", {}).get("ttl_days", SEVERITY_TTL_DAYS)

    waivers = data.get("waivers", [])
    if not isinstance(waivers, list):
        raise ValidationError(f"'waivers' in {file_path} must be a list")

    seen_pairs = set()
    active_approved_count = 0
    pending_count = 0
    rejected_count = 0
    expired_count = 0
    warnings = []
    active_waivers = []

    for idx, w in enumerate(waivers):
        if not isinstance(w, dict):
            raise ValidationError(f"Waiver index {idx} in {file_path} is not a dictionary: {w}")

        cve_id = w.get("cve_id", f"INDEX_{idx}")
        component = w.get("component", "UNKNOWN")
        pair = (cve_id, component)
        if pair in seen_pairs:
            raise ValidationError(f"Duplicate waiver entry detected for CVE '{cve_id}' on component '{component}'")
        seen_pairs.add(pair)

        is_active, warn = validate_waiver(w, current_date, authorized_maintainers, ttl_config)
        if warn:
            warnings.append(warn)

        st = w.get("status")
        if st == "pending_review":
            pending_count += 1
        elif st == "approved":
            if is_active:
                active_approved_count += 1
                active_waivers.append(w)
        elif st == "rejected":
            rejected_count += 1
        elif st == "expired":
            expired_count += 1

    stats = {
        "file_path": file_path,
        "scanner": scanner,
        "total_count": len(waivers),
        "active_approved_count": active_approved_count,
        "pending_count": pending_count,
        "rejected_count": rejected_count,
        "expired_count": expired_count,
        "warnings": warnings,
        "active_waivers": active_waivers,
    }
    return stats

def generate_trivyignore_content(registry_data, stats):
    scanner = registry_data.get("scanner", "scanner")
    scanner_title = "OWASP ZAP Baseline" if scanner == "zap" else "ProjectDiscovery Nuclei"
    active_waivers = stats.get("active_waivers", [])

    lines = [
        "# ==============================================================================",
        f"# Kelvin Security Policy: {scanner_title} Active Vulnerability Waivers",
        f"# Governed by ADR-0008. Machine-generated from deploy/scanners/{scanner}/waivers.yaml.",
        f"# Total Registered Exceptions: {stats['total_count']} CVE- records",
        f"# Active Approved Waivers:     {stats['active_approved_count']}",
        f"# Pending Maintainer Review:   {stats['pending_count']} CVE- records (inactive, non-suppressing)",
        "# DO NOT EDIT THIS FILE DIRECTLY. Run:",
        "#   python scripts/scanners/validate-waivers.py --generate-ignore",
        "# =============================================================================="
    ]

    if not active_waivers:
        lines.append("# (No active approved waivers. All findings remain active and unsuppressed.)")
        lines.append("")
        return "\n".join(lines)

    lines.append("")
    for w in active_waivers:
        cve = w["cve_id"]
        sev = w["severity"]
        comp = w["component"]
        just = w["technical_justification"]
        exp = w["expiry_date"]
        lines.append(f"# [{sev}] {comp} - {just}")
        lines.append(f"{cve} exp:{exp}")
        lines.append("")

    return "\n".join(lines)

def verify_sync(registry_file, ignore_file, current_date=None, authorized_maintainers=None):
    stats = validate_registry_file(registry_file, current_date, authorized_maintainers)
    with open(registry_file, "r", encoding="utf-8") as f:
        reg_data = yaml.safe_load(f)

    expected_content = generate_trivyignore_content(reg_data, stats)
    if not os.path.exists(ignore_file):
        raise ValidationError(f"Target ignore file does not exist: {ignore_file}")

    with open(ignore_file, "r", encoding="utf-8") as f:
        actual_content = f.read()

    # Normalize line endings
    if expected_content.replace("\r\n", "\n").strip() != actual_content.replace("\r\n", "\n").strip():
        raise ValidationError(
            f"Synchronization drift detected between {registry_file} and {ignore_file}.\n"
            f"Run 'python scripts/scanners/validate-waivers.py --generate-ignore' to synchronize."
        )
    return True

def reconcile_raw_findings(zap_raw_sbom, nuclei_raw_sbom, zap_registry, nuclei_registry, output_report, current_date=None):
    if current_date is None:
        current_date = datetime.date.today()

    def load_sbom_vulns(path):
        if not path or not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("vulnerabilities", [])
        except Exception as e:
            print(f"WARNING: Error reading SBOM at {path}: {e}", file=sys.stderr)
            return []

    zap_raw_vulns = load_sbom_vulns(zap_raw_sbom)
    nuclei_raw_vulns = load_sbom_vulns(nuclei_raw_sbom)

    zap_stats = validate_registry_file(zap_registry, current_date)
    nuclei_stats = validate_registry_file(nuclei_registry, current_date)

    with open(zap_registry, "r", encoding="utf-8") as f:
        zap_data = yaml.safe_load(f)
    with open(nuclei_registry, "r", encoding="utf-8") as f:
        nuclei_data = yaml.safe_load(f)

    def reconcile_scanner(scanner_name, raw_vulns, registry_data, stats):
        waivers_by_cve = {}
        for w in registry_data.get("waivers", []):
            waivers_by_cve.setdefault(w["cve_id"], []).append(w)

        approved_matched = []
        pending_matched = []
        unhandled = []

        for v in raw_vulns:
            vid = v.get("id", "UNKNOWN")
            ratings = v.get("ratings", [])
            sev = ratings[0].get("severity", "UNKNOWN").upper() if ratings else "UNKNOWN"
            affects = v.get("affects", [])
            ref = affects[0].get("ref", "UNKNOWN") if affects else "UNKNOWN"

            matching_waivers = waivers_by_cve.get(vid, [])
            active_approved = [w for w in matching_waivers if w.get("status") == "approved" and w.get("expiry_date", "") >= current_date.strftime(DATE_FORMAT)]
            pending = [w for w in matching_waivers if w.get("status") == "pending_review"]

            if active_approved:
                approved_matched.append({"id": vid, "sev": sev, "ref": ref, "waiver": active_approved[0]})
            elif pending:
                pending_matched.append({"id": vid, "sev": sev, "ref": ref, "waiver": pending[0]})
                unhandled.append({"id": vid, "sev": sev, "ref": ref, "reason": "Pending maintainer review (inactive)"})
            else:
                unhandled.append({"id": vid, "sev": sev, "ref": ref, "reason": "No registered waiver"})

        return {
            "scanner": scanner_name,
            "total_raw": len(raw_vulns),
            "approved_matched": len(approved_matched),
            "pending_matched": len(pending_matched),
            "unhandled_count": len(unhandled),
            "unhandled_list": unhandled,
        }

    zap_recon = reconcile_scanner("OWASP ZAP", zap_raw_vulns, zap_data, zap_stats)
    nuclei_recon = reconcile_scanner("ProjectDiscovery Nuclei", nuclei_raw_vulns, nuclei_data, nuclei_stats)

    report_lines = [
        "==============================================================================",
        "Kelvin Scanner Vulnerability & Waiver Reconciliation Audit Report",
        f"Generated At (Audit Date): {current_date.strftime(DATE_FORMAT)}",
        "Policy Reference: ADR-0008 (Fail-Closed Scanner Security Gating)",
        "==============================================================================",
        "",
        f"--- OWASP ZAP Reconciliation Summary ---",
        f"  Total Raw HIGH/CRITICAL Findings Detected: {zap_recon['total_raw']}",
        f"  Registered Waivers in Registry:           {zap_stats['total_count']}",
        f"  Active Approved Waivers (Suppressing):    {zap_recon['approved_matched']}",
        f"  Pending Review Waivers (Non-Suppressing): {zap_recon['pending_matched']}",
        f"  Net Unhandled Findings:                   {zap_recon['unhandled_count']}",
        "",
        f"--- ProjectDiscovery Nuclei Reconciliation Summary ---",
        f"  Total Raw HIGH/CRITICAL Findings Detected: {nuclei_recon['total_raw']}",
        f"  Registered Waivers in Registry:           {nuclei_stats['total_count']}",
        f"  Active Approved Waivers (Suppressing):    {nuclei_recon['approved_matched']}",
        f"  Pending Review Waivers (Non-Suppressing): {nuclei_recon['pending_matched']}",
        f"  Net Unhandled Findings:                   {nuclei_recon['unhandled_count']}",
        "",
        "==============================================================================",
        "GOVERNANCE AUDIT VERDICT:",
    ]

    total_unhandled = zap_recon["unhandled_count"] + nuclei_recon["unhandled_count"]
    if total_unhandled == 0 and (zap_recon["total_raw"] > 0 or nuclei_recon["total_raw"] > 0):
        report_lines.append("  [PASS] All detected vulnerabilities are covered by active approved waivers.")
    else:
        report_lines.append(f"  [GATED] {total_unhandled} unhandled/unreviewed vulnerabilities detected across scanners.")
        report_lines.append("  Scanner release security gate requires 0 unhandled vulnerabilities.")
    report_lines.append("==============================================================================")

    report_text = "\n".join(report_lines)
    if output_report:
        os.makedirs(os.path.dirname(os.path.abspath(output_report)), exist_ok=True)
        with open(output_report, "w", encoding="utf-8") as f:
            f.write(report_text + "\n")

    print(report_text)
    return total_unhandled

def main():
    parser = argparse.ArgumentParser(description="Kelvin Scanner Vulnerability Exception Waiver Validator")
    parser.add_argument("--check", action="store_true", help="Validate waiver registries for syntax, schema, and policy compliance")
    parser.add_argument("--generate-ignore", action="store_true", help="Generate .trivyignore files from active approved waivers")
    parser.add_argument("--verify-sync", action="store_true", help="Verify .trivyignore files are synchronized with waiver registries")
    parser.add_argument("--reconcile", action="store_true", help="Reconcile raw vulnerability SBOMs against waiver registries")
    parser.add_argument("--zap-registry", default="deploy/scanners/zap/waivers.yaml", help="Path to ZAP waivers.yaml")
    parser.add_argument("--nuclei-registry", default="deploy/scanners/nuclei/waivers.yaml", help="Path to Nuclei waivers.yaml")
    parser.add_argument("--zap-ignore", default="deploy/scanners/zap/.trivyignore", help="Path to ZAP .trivyignore")
    parser.add_argument("--nuclei-ignore", default="deploy/scanners/nuclei/.trivyignore", help="Path to Nuclei .trivyignore")
    parser.add_argument("--zap-raw", help="Path to ZAP raw CycloneDX SBOM")
    parser.add_argument("--nuclei-raw", help="Path to Nuclei raw CycloneDX SBOM")
    parser.add_argument("--output", help="Path to output report file")
    parser.add_argument("--current-date", help="Override current date (YYYY-MM-DD) for deterministic testing")

    args = parser.parse_args()

    current_date = datetime.date.today()
    if args.current_date:
        try:
            current_date = datetime.datetime.strptime(args.current_date, DATE_FORMAT).date()
        except ValueError:
            print(f"ERROR: Invalid --current-date '{args.current_date}', expected YYYY-MM-DD", file=sys.stderr)
            sys.exit(1)

    try:
        if args.check:
            print(f"==> Validating Kelvin Scanner Waiver Registries (Audit Date: {current_date})...")
            z_stats = validate_registry_file(args.zap_registry, current_date)
            print(f"  [OK] ZAP Registry:    {z_stats['total_count']} total ({z_stats['active_approved_count']} active, {z_stats['pending_count']} pending review)")
            for w in z_stats["warnings"]:
                print(f"    {w}")

            n_stats = validate_registry_file(args.nuclei_registry, current_date)
            print(f"  [OK] Nuclei Registry: {n_stats['total_count']} total ({n_stats['active_approved_count']} active, {n_stats['pending_count']} pending review)")
            for w in n_stats["warnings"]:
                print(f"    {w}")

        if args.generate_ignore:
            print(f"==> Generating .trivyignore files from active approved waivers...")
            z_stats = validate_registry_file(args.zap_registry, current_date)
            with open(args.zap_registry, "r", encoding="utf-8") as f:
                z_data = yaml.safe_load(f)
            z_content = generate_trivyignore_content(z_data, z_stats)
            with open(args.zap_ignore, "w", encoding="utf-8") as f:
                f.write(z_content)
            print(f"  [OK] Generated {args.zap_ignore} ({z_stats['active_approved_count']} active waivers rendered)")

            n_stats = validate_registry_file(args.nuclei_registry, current_date)
            with open(args.nuclei_registry, "r", encoding="utf-8") as f:
                n_data = yaml.safe_load(f)
            n_content = generate_trivyignore_content(n_data, n_stats)
            with open(args.nuclei_ignore, "w", encoding="utf-8") as f:
                f.write(n_content)
            print(f"  [OK] Generated {args.nuclei_ignore} ({n_stats['active_approved_count']} active waivers rendered)")

        if args.verify-sync if hasattr(args, "verify-sync") else getattr(args, "verify_sync"):
            print(f"==> Verifying synchronization between registries and .trivyignore files...")
            verify_sync(args.zap_registry, args.zap_ignore, current_date)
            print(f"  [OK] {args.zap_ignore} matches {args.zap_registry}")
            verify_sync(args.nuclei_registry, args.nuclei_ignore, current_date)
            print(f"  [OK] {args.nuclei_ignore} matches {args.nuclei_registry}")

        if args.reconcile:
            print(f"==> Reconciling Raw Vulnerability Findings against Registries...")
            reconcile_raw_findings(
                args.zap_raw, args.nuclei_raw,
                args.zap_registry, args.nuclei_registry,
                args.output, current_date
            )

    except ValidationError as ve:
        print(f"\nGOVERNANCE VALIDATION ERROR: {ve}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUNEXPECTED ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
