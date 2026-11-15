package main

import (
	"strings"
	"testing"
)

func TestScorecard_EligibleEvaluation(t *testing.T) {
	input := ScorecardInput{
		ScannerName:  "nuclei",
		ImageRef:     "kelvin/scanner-nuclei:3.11.1",
		ImageDigest:  "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
		Architecture: "linux/arm64",
		RuntimeUser:  "10001:10001",
		PackageCount: 15,
		SBOMPresent:  true,
		SBOMFormat:   "CycloneDX v1.5",
		VulnCounts: VulnerabilityCount{
			Critical: 0,
			High:     0,
		},
		WaiverCounts: WaiverCount{
			Approved:  2,
			Pending:   0,
			Expired:   0,
			Unhandled: 0,
		},
		SourceCommit:   "a8c88feb4a1c8e961b7902534ce3af97e9d524a4",
		BuilderDigest:  "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696",
		BuildTimestamp: "2026-11-15T20:00:00Z",
	}

	sc := Evaluate(input)
	if sc.ReleaseEligibility != "ELIGIBLE" {
		t.Fatalf("expected ELIGIBLE release verdict, got: %s (reasons: %v)", sc.ReleaseEligibility, sc.BlockingReasons)
	}

	if len(sc.BlockingReasons) != 0 {
		t.Errorf("expected 0 blocking reasons, got: %v", sc.BlockingReasons)
	}

	md := sc.ToMarkdown()
	if !strings.Contains(md, "Release Eligibility:** `ELIGIBLE`") {
		t.Errorf("expected Markdown to contain ELIGIBLE status")
	}
}

func TestScorecard_IneligibleOnSecurityViolations(t *testing.T) {
	// Violations: Root user, unhandled CVE, missing SBOM, invalid digest
	input := ScorecardInput{
		ScannerName:  "zap",
		ImageDigest:  "latest", // invalid digest
		Architecture: "linux/mips", // unsupported arch
		RuntimeUser:  "0:0", // root user violation
		SBOMPresent:  false, // missing SBOM
		WaiverCounts: WaiverCount{
			Unhandled: 1, // 1 unhandled CVE
			Expired:   1, // 1 expired waiver
		},
	}

	sc := Evaluate(input)
	if sc.ReleaseEligibility != "INELIGIBLE" {
		t.Fatalf("expected INELIGIBLE for violating image, got: %s", sc.ReleaseEligibility)
	}

	if len(sc.BlockingReasons) < 4 {
		t.Errorf("expected multiple blocking reasons, got: %v", sc.BlockingReasons)
	}

	md := sc.ToMarkdown()
	if !strings.Contains(md, "Release Eligibility:** `INELIGIBLE`") {
		t.Errorf("expected Markdown to report INELIGIBLE")
	}
}
