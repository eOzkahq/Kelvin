package normalization

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestResultValidatorAcceptsValidAndDeduplicates(t *testing.T) {
	validator := NewResultValidator()

	f1 := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "SQL Injection in Search Form",
		"severity": "HIGH",
		"confidence": 0.9,
		"target": {
			"asset": "target.example.com",
			"endpoint": "https://target.example.com/search"
		},
		"vulnerability": {
			"cwe_id": "CWE-89",
			"template_id": "sqli-search"
		},
		"description": "SQL injection discovered",
		"remediation": {
			"summary": "Use prepared statements"
		},
		"evidence": [
			{
				"type": "LOG",
				"content_type": "text/plain",
				"content_redacted": "SELECT * FROM users WHERE id='1'",
				"redacted_fields": []
			}
		],
		"scanner": {
			"name": "nuclei",
			"adapter_version": "1.0.0"
		},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	// Exact duplicate of f1
	f2 := f1

	report := validator.ValidateBatch([]json.RawMessage{f1, f2}, "target.example.com")
	if report.TotalProcessed != 2 {
		t.Errorf("expected 2 processed, got %d", report.TotalProcessed)
	}
	if report.AcceptedCount != 1 {
		t.Errorf("expected 1 accepted, got %d", report.AcceptedCount)
	}
	if report.DuplicateCount != 1 {
		t.Errorf("expected 1 duplicate, got %d", report.DuplicateCount)
	}
	if report.RejectedCount != 0 {
		t.Errorf("expected 0 rejected, got %d: %+v", report.RejectedCount, report.Quarantined)
	}
}

func TestResultValidatorQuarantinesInvalidRecords(t *testing.T) {
	validator := NewResultValidator()

	// 1. Evidence exceeding 64KB cap
	hugeEvidence := strings.Repeat("A", MaxEvidenceBytesPerFinding+100)
	hugeEvidenceFinding := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Oversized Evidence Finding",
		"severity": "LOW",
		"confidence": 0.5,
		"target": {"asset": "target.example.com"},
		"vulnerability": {"template_id": "huge-ev"},
		"description": "Test",
		"remediation": {"summary": "Fix"},
		"evidence": [
			{
				"type": "LOG",
				"content_redacted": "` + hugeEvidence + `",
				"redacted_fields": []
			}
		],
		"scanner": {"name": "test", "adapter_version": "1.0.0"},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	// 2. Out of scope asset
	outOfScopeFinding := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Out of Scope Target",
		"severity": "LOW",
		"confidence": 0.5,
		"target": {"asset": "evil.attacker.com"},
		"vulnerability": {"template_id": "out-of-scope"},
		"description": "Test",
		"remediation": {"summary": "Fix"},
		"scanner": {"name": "test", "adapter_version": "1.0.0"},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	// 3. Query string left in target endpoint
	queryInEndpointFinding := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Endpoint with Query String",
		"severity": "LOW",
		"confidence": 0.5,
		"target": {"asset": "target.example.com", "endpoint": "https://target.example.com/item?id=123"},
		"vulnerability": {"template_id": "query-endpoint"},
		"description": "Test",
		"remediation": {"summary": "Fix"},
		"scanner": {"name": "test", "adapter_version": "1.0.0"},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	report := validator.ValidateBatch([]json.RawMessage{hugeEvidenceFinding, outOfScopeFinding, queryInEndpointFinding}, "target.example.com")
	if report.AcceptedCount != 0 {
		t.Errorf("expected 0 accepted, got %d", report.AcceptedCount)
	}
	if report.RejectedCount != 3 {
		t.Errorf("expected 3 quarantined, got %d", report.RejectedCount)
	}
	if len(report.Quarantined) != 3 {
		t.Fatalf("expected 3 quarantine records, got %d", len(report.Quarantined))
	}

	// Verify reasons and violation messages
	if !strings.Contains(report.Quarantined[0].Violations[0], "exceeds 64KiB cap") {
		t.Errorf("expected 64KiB cap violation, got: %v", report.Quarantined[0].Violations)
	}
	if !strings.Contains(report.Quarantined[1].Violations[0], "does not match expected assessment asset") {
		t.Errorf("expected scope mismatch violation, got: %v", report.Quarantined[1].Violations)
	}
	if !strings.Contains(report.Quarantined[2].Violations[0], "query parameters") {
		t.Errorf("expected query parameters violation, got: %v", report.Quarantined[2].Violations)
	}
}

func TestResultValidatorDetectsFingerprintTampering(t *testing.T) {
	validator := NewResultValidator()

	// Finding claiming forged fingerprint
	f := CanonicalFinding{
		SchemaVersion: "1.0",
		Title:         "Sample Finding",
		Severity:      "MEDIUM",
		Confidence:    0.7,
		Target: Target{
			Asset: "target.example.com",
		},
		Vulnerability: Vulnerability{
			TemplateID: "sample-rule",
		},
		Scanner: ScannerInfo{
			Name:           "nuclei",
			AdapterVersion: "1.0.0",
		},
		Fingerprint:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // forged
		DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
	}

	violations := validator.ValidateSingle(f, "target.example.com")
	if len(violations) == 0 {
		t.Fatal("expected fingerprint tampering to be flagged")
	}

	foundTampering := false
	for _, v := range violations {
		if strings.Contains(v, "fingerprint mismatch") {
			foundTampering = true
			break
		}
	}
	if !foundTampering {
		t.Errorf("expected fingerprint mismatch error, got: %v", violations)
	}
}
