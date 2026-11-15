package main

import (
	"testing"
	"time"
)

func TestReconcileEngine_Classification(t *testing.T) {
	auditDate := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	engine := NewEngine(auditDate)

	validExpiry := "2026-12-31"
	pastExpiry := "2026-10-01"

	reg := &WaiverRegistry{
		SchemaVersion: "1.0.0",
		Scanner:       "test-scanner",
		Waivers: []WaiverEntry{
			{
				CVEID:                  "CVE-2026-0001",
				Component:              "pkg:deb/debian/libtest@1.0",
				Severity:               "HIGH",
				TechnicalJustification: "Approved active waiver with valid expiry",
				Status:                 "approved",
				ExpiryDate:             &validExpiry,
			},
			{
				CVEID:                  "CVE-2026-0002",
				Component:              "pkg:deb/debian/libtest@1.0",
				Severity:               "HIGH",
				TechnicalJustification: "Approved waiver but expired in the past",
				Status:                 "approved",
				ExpiryDate:             &pastExpiry,
			},
			{
				CVEID:                  "CVE-2026-0003",
				Component:              "pkg:deb/debian/libtest@1.0",
				Severity:               "CRITICAL",
				TechnicalJustification: "Pending review waiver",
				Status:                 "pending_review",
			},
			{
				CVEID:                  "CVE-2026-0004",
				Component:              "pkg:deb/debian/libtest@1.0",
				Severity:               "MEDIUM",
				TechnicalJustification: "Waiver registered but finding is fixed in source",
				Status:                 "approved",
				ExpiryDate:             &validExpiry,
			},
		},
	}

	sbom := &CycloneDXSBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Vulnerabilities: []SBOMVulnRecord{
			{
				ID: "CVE-2026-0001",
				Ratings: []SBOMRating{
					{Severity: "high"},
				},
				Affects: []SBOMAffectsPackage{
					{Ref: "pkg:deb/debian/libtest@1.0"},
				},
			},
			{
				ID: "CVE-2026-0002",
				Ratings: []SBOMRating{
					{Severity: "high"},
				},
				Affects: []SBOMAffectsPackage{
					{Ref: "pkg:deb/debian/libtest@1.0"},
				},
			},
			{
				ID: "CVE-2026-0003",
				Ratings: []SBOMRating{
					{Severity: "critical"},
				},
				Affects: []SBOMAffectsPackage{
					{Ref: "pkg:deb/debian/libtest@1.0"},
				},
			},
			{
				ID: "CVE-2026-9999", // Brand new unhandled finding
				Ratings: []SBOMRating{
					{Severity: "critical"},
				},
				Affects: []SBOMAffectsPackage{
					{Ref: "pkg:deb/debian/libunhandled@2.0"},
				},
			},
		},
	}

	report, err := engine.Reconcile("test-scanner", sbom, reg)
	if err != nil {
		t.Fatalf("unexpected reconciliation error: %v", err)
	}

	// Assert counts:
	// Raw findings: 4
	// Total waivers: 4
	// CVE-2026-0001 -> Approved (1)
	// CVE-2026-0002 -> Expired (1)
	// CVE-2026-0003 -> Pending (1)
	// CVE-2026-9999 -> Unhandled (1)
	// CVE-2026-0004 -> Fixed (1)
	if report.TotalRawFindings != 4 {
		t.Errorf("expected 4 raw findings, got %d", report.TotalRawFindings)
	}
	if report.TotalRegisteredWaivers != 4 {
		t.Errorf("expected 4 registered waivers, got %d", report.TotalRegisteredWaivers)
	}
	if report.Summary.Approved != 1 {
		t.Errorf("expected 1 approved, got %d", report.Summary.Approved)
	}
	if report.Summary.Expired != 1 {
		t.Errorf("expected 1 expired, got %d", report.Summary.Expired)
	}
	if report.Summary.Pending != 1 {
		t.Errorf("expected 1 pending, got %d", report.Summary.Pending)
	}
	if report.Summary.Unhandled != 1 {
		t.Errorf("expected 1 unhandled, got %d", report.Summary.Unhandled)
	}
	if report.Summary.Fixed != 1 {
		t.Errorf("expected 1 fixed, got %d", report.Summary.Fixed)
	}

	// Gated verdict check
	if report.Verdict != VerdictGated {
		t.Errorf("expected GATED verdict due to pending, expired, and unhandled findings, got %s", report.Verdict)
	}

	// Total findings in report must equal raw findings (4) + fixed findings (1) = 5
	if len(report.Findings) != 5 {
		t.Errorf("expected 5 reconciled findings in report, got %d", len(report.Findings))
	}
}

func TestReconcileEngine_CleanPass(t *testing.T) {
	auditDate := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	engine := NewEngine(auditDate)

	validExpiry := "2026-12-31"

	reg := &WaiverRegistry{
		Waivers: []WaiverEntry{
			{
				CVEID:                  "CVE-2026-0001",
				Component:              "pkg:golang/test@1.0",
				Severity:               "HIGH",
				TechnicalJustification: "Approved active waiver with valid expiry",
				Status:                 "approved",
				ExpiryDate:             &validExpiry,
			},
		},
	}

	sbom := &CycloneDXSBOM{
		Vulnerabilities: []SBOMVulnRecord{
			{
				ID: "CVE-2026-0001",
				Ratings: []SBOMRating{
					{Severity: "high"},
				},
				Affects: []SBOMAffectsPackage{
					{Ref: "pkg:golang/test@1.0"},
				},
			},
		},
	}

	report, err := engine.Reconcile("nuclei", sbom, reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Verdict != VerdictPass {
		t.Errorf("expected PASS verdict when all findings are approved, got %s", report.Verdict)
	}
	if report.Summary.Approved != 1 || report.Summary.Unhandled != 0 {
		t.Errorf("unexpected summary state: %+v", report.Summary)
	}
}
