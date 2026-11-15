#!/usr/bin/env python3
"""
Unit and regression test suite for Kelvin Scanner Vulnerability Exception Governance.
Validates schemas, approval requirements, severity TTL boundaries, date constraints,
drift detection, and raw finding reconciliation using deterministic test dates.
Governed by ADR-0008.
"""

import copy
import datetime
import json
import os
import sys
import unittest
import yaml

import importlib.util

# Import validator module
validator_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "validate-waivers.py")
spec = importlib.util.spec_from_file_location("validate_waivers", validator_path)
vw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vw)

TEST_DATE = datetime.date(2026, 11, 15)
AUTHORIZED_MAINTAINERS = ["@eOzkull", "eOzkull"]

class TestWaiverGovernance(unittest.TestCase):

    def setUp(self):
        self.base_valid_approved_waiver = {
            "cve_id": "CVE-2026-12345",
            "component": "pkg:deb/debian/libtest@1.0.0",
            "severity": "HIGH",
            "technical_justification": "Upstream vendor fix deferred; unexploitable in sandbox environment.",
            "status": "approved",
            "owner": "@eOzkull",
            "review_date": "2026-11-01",
            "expiry_date": "2027-01-30", # 90 days
            "tracking_reference": "https://security-tracker.debian.org/tracker/CVE-2026-12345",
            "approval": {
                "approved_by": "@eOzkull",
                "approval_reference": "https://github.com/eOzkull/Kelvin/pull/542",
                "approved_at": "2026-11-01T12:00:00Z"
            }
        }
        self.ttl_config = vw.SEVERITY_TTL_DAYS

    def test_migrated_registries_pass_validation(self):
        """Verify that the official migrated ZAP and Nuclei registries pass validation in pending_review status."""
        z_stats = vw.validate_registry_file("deploy/scanners/zap/waivers.yaml", TEST_DATE, AUTHORIZED_MAINTAINERS)
        self.assertEqual(z_stats["total_count"], 384)
        self.assertEqual(z_stats["pending_count"], 384)
        self.assertEqual(z_stats["active_approved_count"], 0)

        n_stats = vw.validate_registry_file("deploy/scanners/nuclei/waivers.yaml", TEST_DATE, AUTHORIZED_MAINTAINERS)
        self.assertEqual(n_stats["total_count"], 26)
        self.assertEqual(n_stats["pending_count"], 26)
        self.assertEqual(n_stats["active_approved_count"], 0)

    def test_valid_approved_waiver_passes(self):
        """A properly formatted approved waiver with valid maintainer approval passes validation."""
        is_active, warn = vw.validate_waiver(
            self.base_valid_approved_waiver, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config
        )
        self.assertTrue(is_active)
        self.assertIsNone(warn)

    def test_missing_required_fields_fails(self):
        """Omitting any required field must raise ValidationError (fail closed)."""
        required_keys = [
            "cve_id", "component", "severity", "technical_justification",
            "status", "owner", "review_date", "expiry_date",
            "tracking_reference", "approval"
        ]
        for key in required_keys:
            w = copy.deepcopy(self.base_valid_approved_waiver)
            del w[key]
            with self.assertRaises(vw.ValidationError) as ctx:
                vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
            self.assertIn(f"Missing required field '{key}'", str(ctx.exception))

    def test_placeholder_values_in_approved_waiver_fails(self):
        """Approved waivers containing placeholders (<...>, UNASSIGNED, PLACEHOLDER, TODO) must fail closed."""
        placeholder_targets = [
            ("owner", "<MAINTAINER_OWNER>"),
            ("owner", "UNASSIGNED"),
            ("review_date", "<REVIEW_DATE>"),
            ("expiry_date", "<EXPIRY_DATE>"),
            ("tracking_reference", ""),
        ]
        for field, bad_val in placeholder_targets:
            w = copy.deepcopy(self.base_valid_approved_waiver)
            w[field] = bad_val
            with self.assertRaises(vw.ValidationError):
                vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)

    def test_approval_object_placeholders_fail(self):
        """Approval audit records containing placeholders or unassigned values must fail closed."""
        approval_targets = [
            ("approved_by", "<MAINTAINER>"),
            ("approved_by", "UNASSIGNED"),
            ("approval_reference", "<PR_NUMBER>"),
            ("approved_at", "<TIMESTAMP>"),
        ]
        for field, bad_val in approval_targets:
            w = copy.deepcopy(self.base_valid_approved_waiver)
            w["approval"][field] = bad_val
            with self.assertRaises(vw.ValidationError):
                vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)

    def test_unauthorized_approver_fails(self):
        """Approval by an unauthorized or unknown entity must fail closed."""
        w = copy.deepcopy(self.base_valid_approved_waiver)
        w["approval"]["approved_by"] = "@malicious_actor"
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("unauthorized", str(ctx.exception).lower())

    def test_invalid_cve_identifiers(self):
        """Malformed CVE identifiers must fail validation."""
        invalid_cves = ["CVE-123", "CVE-2026", "CVE-ABCD-1234", "GHSA-1234", "VULN-001", ""]
        for bad_cve in invalid_cves:
            w = copy.deepcopy(self.base_valid_approved_waiver)
            w["cve_id"] = bad_cve
            with self.assertRaises(vw.ValidationError):
                vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)

    def test_duplicate_entries_rejected(self):
        """Registries with duplicate (cve_id, component) pairs must be rejected."""
        registry_data = {
            "schema_version": "1.0.0",
            "scanner": "zap",
            "metadata": {"ttl_days": self.ttl_config},
            "waivers": [
                self.base_valid_approved_waiver,
                copy.deepcopy(self.base_valid_approved_waiver) # Duplicate!
            ]
        }
        test_file = "test_duplicate_waivers.yaml"
        with open(test_file, "w", encoding="utf-8") as f:
            yaml.dump(registry_data, f)
        try:
            with self.assertRaises(vw.ValidationError) as ctx:
                vw.validate_registry_file(test_file, TEST_DATE, AUTHORIZED_MAINTAINERS)
            self.assertIn("Duplicate waiver entry detected", str(ctx.exception))
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    def test_date_constraints(self):
        """Review dates cannot be in the future, and expiry must be strictly after review date."""
        # Future review date
        w_future = copy.deepcopy(self.base_valid_approved_waiver)
        w_future["review_date"] = "2026-12-01" # TEST_DATE is 2026-11-15
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w_future, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("cannot be in the future", str(ctx.exception))

        # Expiry before review date
        w_backwards = copy.deepcopy(self.base_valid_approved_waiver)
        w_backwards["review_date"] = "2026-11-01"
        w_backwards["expiry_date"] = "2026-10-31"
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w_backwards, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("must be strictly after review_date", str(ctx.exception))

    def test_severity_ttl_limits(self):
        """Severity TTL maximums must be strictly enforced: CRITICAL (30d), HIGH (90d), MEDIUM (180d), LOW (180d)."""
        test_cases = [
            ("CRITICAL", 31, False), # Fails: > 30 days
            ("CRITICAL", 30, True),  # Passes: == 30 days
            ("HIGH", 91, False),     # Fails: > 90 days
            ("HIGH", 90, True),      # Passes: == 90 days
            ("MEDIUM", 181, False),  # Fails: > 180 days
            ("MEDIUM", 180, True),   # Passes: == 180 days
            ("LOW", 181, False),     # Fails: > 180 days
            ("LOW", 180, True),      # Passes: == 180 days
        ]
        for sev, days, should_pass in test_cases:
            w = copy.deepcopy(self.base_valid_approved_waiver)
            w["severity"] = sev
            w["review_date"] = "2026-11-01"
            exp = datetime.date(2026, 11, 1) + datetime.timedelta(days=days)
            w["expiry_date"] = exp.strftime(vw.DATE_FORMAT)

            if should_pass:
                is_active, _ = vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
                self.assertTrue(is_active)
            else:
                with self.assertRaises(vw.ValidationError) as ctx:
                    vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
                self.assertIn("exceeds maximum allowed TTL", str(ctx.exception))

    def test_expired_waiver_fails_validation(self):
        """Approved waiver whose expiry_date is in the past must fail closed."""
        w_expired = copy.deepcopy(self.base_valid_approved_waiver)
        w_expired["review_date"] = "2026-10-01"
        w_expired["expiry_date"] = "2026-11-10" # Past relative to TEST_DATE (2026-11-15)
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w_expired, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("expired on", str(ctx.exception).lower())

    def test_expiry_warning_window(self):
        """Approved waiver expiring within 14 days must trigger an advance warning."""
        w_expiring_soon = copy.deepcopy(self.base_valid_approved_waiver)
        w_expiring_soon["review_date"] = "2026-11-01"
        # 7 days from TEST_DATE (2026-11-15 + 7 = 2026-11-22)
        w_expiring_soon["expiry_date"] = "2026-11-22"
        is_active, warn = vw.validate_waiver(w_expiring_soon, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertTrue(is_active)
        self.assertIsNotNone(warn)
        self.assertIn("will expire in 7 day(s)", warn)

    def test_pending_records_never_rendered_to_ignore(self):
        """Pending review records must NEVER be rendered to .trivyignore or suppress findings."""
        registry_data = {
            "schema_version": "1.0.0",
            "scanner": "zap",
            "metadata": {"ttl_days": self.ttl_config},
            "waivers": [
                {
                    "cve_id": "CVE-2026-99999",
                    "component": "pkg:deb/debian/libpending@1.0",
                    "severity": "HIGH",
                    "technical_justification": "Pending maintainer triage",
                    "status": "pending_review",
                    "owner": None,
                    "review_date": None,
                    "expiry_date": None,
                    "tracking_reference": "https://security-tracker.debian.org/tracker/CVE-2026-99999",
                    "approval": None
                }
            ]
        }
        stats = {
            "total_count": 1,
            "active_approved_count": 0,
            "pending_count": 1,
            "active_waivers": []
        }
        content = vw.generate_trivyignore_content(registry_data, stats)
        self.assertNotIn("CVE-2026-99999 exp:", content)
        self.assertIn("Active Approved Waivers:     0", content)
        self.assertIn("No active approved waivers", content)

    def test_generated_file_drift_detection(self):
        """Manual tampering with .trivyignore must be detected and fail closed."""
        test_reg = "test_drift_reg.yaml"
        test_ignore = "test_drift.trivyignore"

        reg_data = {
            "schema_version": "1.0.0",
            "scanner": "zap",
            "metadata": {"ttl_days": self.ttl_config},
            "waivers": [self.base_valid_approved_waiver]
        }
        with open(test_reg, "w", encoding="utf-8") as f:
            yaml.dump(reg_data, f)

        # Write matching ignore file first
        stats = vw.validate_registry_file(test_reg, TEST_DATE, AUTHORIZED_MAINTAINERS)
        expected_content = vw.generate_trivyignore_content(reg_data, stats)
        with open(test_ignore, "w", encoding="utf-8") as f:
            f.write(expected_content)

        try:
            # Clean sync passes
            self.assertTrue(vw.verify_sync(test_reg, test_ignore, TEST_DATE, AUTHORIZED_MAINTAINERS))

            # Tamper with ignore file
            with open(test_ignore, "a", encoding="utf-8") as f:
                f.write("\nCVE-2026-UNAUTHORIZED\n")

            # Must raise ValidationError on drift
            with self.assertRaises(vw.ValidationError) as ctx:
                vw.verify_sync(test_reg, test_ignore, TEST_DATE, AUTHORIZED_MAINTAINERS)
            self.assertIn("Synchronization drift detected", str(ctx.exception))
        finally:
            if os.path.exists(test_reg):
                os.remove(test_reg)
            if os.path.exists(test_ignore):
                os.remove(test_ignore)

    def test_reconciliation_logic(self):
        """Reconciliation accurately separates approved waivers, pending waivers, and unhandled findings."""
        zap_raw = [
            {"id": "CVE-2026-12345", "ratings": [{"severity": "HIGH"}], "affects": [{"ref": "pkg:deb/debian/libtest@1.0.0"}]},
            {"id": "CVE-2026-88888", "ratings": [{"severity": "HIGH"}], "affects": [{"ref": "pkg:deb/debian/libpending@1.0.0"}]},
            {"id": "CVE-2026-77777", "ratings": [{"severity": "HIGH"}], "affects": [{"ref": "pkg:deb/debian/libunhandled@1.0.0"}]},
        ]
        raw_sbom_path = "test_raw_sbom.json"
        with open(raw_sbom_path, "w", encoding="utf-8") as f:
            json.dump({"vulnerabilities": zap_raw}, f)

        reg_data = {
            "schema_version": "1.0.0",
            "scanner": "zap",
            "metadata": {"ttl_days": self.ttl_config},
            "waivers": [
                self.base_valid_approved_waiver, # Matches CVE-2026-12345 (Approved)
                {
                    "cve_id": "CVE-2026-88888",  # Matches CVE-2026-88888 (Pending)
                    "component": "pkg:deb/debian/libpending@1.0.0",
                    "severity": "HIGH",
                    "technical_justification": "Under maintainer evaluation",
                    "status": "pending_review",
                    "owner": None,
                    "review_date": None,
                    "expiry_date": None,
                    "tracking_reference": "https://security-tracker.debian.org/tracker/CVE-2026-88888",
                    "approval": None
                }
                # CVE-2026-77777 has NO entry (Unhandled)
            ]
        }
        reg_path = "test_recon_reg.yaml"
        with open(reg_path, "w", encoding="utf-8") as f:
            yaml.dump(reg_data, f)

        report_path = "test_recon_report.txt"
        try:
            unhandled = vw.reconcile_raw_findings(
                raw_sbom_path, None,
                reg_path, "deploy/scanners/nuclei/waivers.yaml",
                report_path, TEST_DATE
            )
            # CVE-2026-88888 (pending) + CVE-2026-77777 (no waiver) = 2 unhandled
            self.assertEqual(unhandled, 2)
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Active Approved Waivers (Suppressing):    1", content)
            self.assertIn("Pending Review Waivers (Non-Suppressing): 1", content)
            self.assertIn("Net Unhandled Findings:                   2", content)
            self.assertIn("[GATED] 2 unhandled/unreviewed vulnerabilities detected", content)
        finally:
            for p in [raw_sbom_path, reg_path, report_path]:
                if os.path.exists(p):
                    os.remove(p)

    def test_invalid_component_purl_rejected(self):
        """Component string not adhering to pkg:<type>/<name>@<version> must fail closed."""
        w = copy.deepcopy(self.base_valid_approved_waiver)
        w["component"] = "libtest" # missing purl scheme and version
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("canonical Package URL", str(ctx.exception))

    def test_unapproved_advisory_tracking_rejected(self):
        """Tracking reference not from approved advisory databases must fail closed."""
        w = copy.deepcopy(self.base_valid_approved_waiver)
        w["tracking_reference"] = "https://untrusted-blog.com/exploit"
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("does not match an approved security advisory source", str(ctx.exception))

    def test_short_or_placeholder_justification_rejected(self):
        """Short justifications or placeholder text must fail validation."""
        w = copy.deepcopy(self.base_valid_approved_waiver)
        w["technical_justification"] = "short"
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("informative explanation", str(ctx.exception))

        w["technical_justification"] = "TODO: add explanation later"
        with self.assertRaises(vw.ValidationError) as ctx:
            vw.validate_waiver(w, TEST_DATE, AUTHORIZED_MAINTAINERS, self.ttl_config)
        self.assertIn("forbidden placeholder", str(ctx.exception))

if __name__ == "__main__":
    unittest.main(verbosity=2)
