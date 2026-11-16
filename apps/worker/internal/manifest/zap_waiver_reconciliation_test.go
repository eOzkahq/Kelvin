package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zapReconciliationReport struct {
	SchemaVersion string `json:"schema_version"`
	AuditDate     string `json:"audit_date"`
	Scanner       string `json:"scanner"`
	Summary       struct {
		Fixed     int `json:"fixed"`
		Approved  int `json:"approved"`
		Pending   int `json:"pending"`
		Expired   int `json:"expired"`
		Unhandled int `json:"unhandled"`
	} `json:"summary"`
	Verdict  string `json:"verdict"`
	Findings []struct {
		CVEID       string `json:"cve_id"`
		Component   string `json:"component"`
		Severity    string `json:"severity"`
		Disposition string `json:"disposition"`
		Reason      string `json:"reason"`
	} `json:"findings"`
}

func TestZAPWaiverReconciliation_All384FindingsRetired(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")

	// 1. Verify deploy/scanners/zap/waivers.json
	waiversJSONPath := filepath.Join(rootPath, "deploy", "scanners", "zap", "waivers.json")
	data, err := os.ReadFile(waiversJSONPath)
	if err != nil {
		t.Fatalf("failed to read zap waivers.json: %v", err)
	}

	var report zapReconciliationReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse zap waivers.json: %v", err)
	}

	if report.Scanner != "zap" {
		t.Errorf("expected scanner 'zap', got %q", report.Scanner)
	}
	if report.Verdict != "PASS" {
		t.Errorf("expected verdict 'PASS', got %q", report.Verdict)
	}
	if report.Summary.Fixed != 384 {
		t.Errorf("expected 384 fixed findings, got %d", report.Summary.Fixed)
	}
	if report.Summary.Approved != 0 {
		t.Errorf("expected 0 approved waivers, got %d", report.Summary.Approved)
	}
	if report.Summary.Pending != 0 {
		t.Errorf("expected 0 pending waivers, got %d", report.Summary.Pending)
	}
	if report.Summary.Unhandled != 0 {
		t.Errorf("expected 0 unhandled vulnerabilities, got %d", report.Summary.Unhandled)
	}

	for _, f := range report.Findings {
		if f.Disposition != "fixed" {
			t.Errorf("finding %s has unexpected disposition %q (expected 'fixed')", f.CVEID, f.Disposition)
		}
	}

	// 2. Verify formal remediation markdown report exists and references audit invariants
	reportMDPath := filepath.Join(rootPath, "docs", "security", "waivers", "ZAP_REMEDIATION_REPORT.md")
	mdBytes, err := os.ReadFile(reportMDPath)
	if err != nil {
		t.Fatalf("failed to read ZAP_REMEDIATION_REPORT.md: %v", err)
	}
	mdContent := string(mdBytes)

	for _, requiredToken := range []string{"384/384 Findings Resolved & Retired", "linux-libc-dev", "firefox-esr", "ADR-0008"} {
		if !strings.Contains(mdContent, requiredToken) {
			t.Errorf("ZAP_REMEDIATION_REPORT.md missing required token: %s", requiredToken)
		}
	}
}
