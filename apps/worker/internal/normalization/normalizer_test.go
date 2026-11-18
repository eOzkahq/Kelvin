package normalization

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizerProcessesMVPAdapterFindings(t *testing.T) {
	normalizer := NewNormalizer()
	ctx := Context{
		AssessmentID:  "11111111-1111-1111-1111-111111111111",
		RunID:         "22222222-2222-2222-2222-222222222222",
		CorrelationID: "corr-123",
	}

	// 1. ZAP finding
	zapFinding := []byte(`{
		"schema_version": "1.0",
		"title": "Cross Site Scripting (Reflected)",
		"severity": "HIGH",
		"confidence": 0.9,
		"target": {
			"asset": "target.example.com",
			"endpoint": "https://target.example.com/search?q=test"
		},
		"vulnerability": {
			"cwe_id": "CWE-79",
			"template_id": "40012"
		},
		"description": "XSS vulnerability in query parameter",
		"remediation": {
			"summary": "Sanitize and escape all input"
		},
		"evidence": [
			{
				"type": "LOG",
				"content_type": "text/plain",
				"content_redacted": "q=<script>",
				"redacted_fields": ["session_id"]
			}
		],
		"scanner": {
			"name": "zap-baseline",
			"adapter_version": "1.0.0"
		},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	resZAP, err := normalizer.Normalize(zapFinding, ctx)
	if err != nil {
		t.Fatalf("Normalize ZAP finding failed: %v", err)
	}
	if resZAP.Severity != "HIGH" {
		t.Errorf("expected HIGH, got %s", resZAP.Severity)
	}
	if resZAP.Fingerprint == "" || len(resZAP.Fingerprint) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %s", resZAP.Fingerprint)
	}
	if resZAP.Scanner.RunID != ctx.RunID {
		t.Errorf("expected run_id %s, got %s", ctx.RunID, resZAP.Scanner.RunID)
	}
	if resZAP.ScannerMeta["kelvin.assessment_id"] != ctx.AssessmentID {
		t.Errorf("expected assessment_id stamped in scanner_meta")
	}
	if strings.Contains(resZAP.Target.Endpoint, "?q=test") {
		t.Errorf("query string was not stripped from endpoint: %s", resZAP.Target.Endpoint)
	}

	// 2. Nuclei finding
	nucleiFinding := []byte(`{
		"schema_version": "1.0",
		"title": "Log4j RCE",
		"severity": "CRITICAL",
		"confidence": 0.95,
		"target": {
			"asset": "target.example.com"
		},
		"vulnerability": {
			"template_id": "cve-2021-44228",
			"cve_ids": ["CVE-2021-44228"]
		},
		"description": "Log4Shell RCE vulnerability",
		"remediation": {
			"summary": "Update log4j"
		},
		"scanner": {
			"name": "nuclei",
			"adapter_version": "1.0.0"
		},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	resNuclei, err := normalizer.Normalize(nucleiFinding, ctx)
	if err != nil {
		t.Fatalf("Normalize Nuclei finding failed: %v", err)
	}
	if resNuclei.Severity != "CRITICAL" || resNuclei.Fingerprint == "" {
		t.Errorf("unexpected normalized nuclei finding: %+v", resNuclei)
	}

	// 4. Containerized Nmap finding
	nmapFinding := []byte(`{
		"schema_version": "1.0",
		"title": "Plaintext Service (Telnet)",
		"severity": "HIGH",
		"confidence": 0.95,
		"target": {
			"asset": "target.example.com",
			"endpoint": "https://target.example.com:23"
		},
		"vulnerability": {
			"cwe_id": "319",
			"cve_ids": ["cve-2020-1234", "CVE-2020-1234", " cve-2020-0001 "]
		},
		"description": "Telnet service transmitting data in cleartext",
		"scanner": {
			"name": "nmap",
			"adapter_version": "1.0.0"
		},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	resNmap, err := normalizer.Normalize(nmapFinding, ctx)
	if err != nil {
		t.Fatalf("Normalize Nmap finding failed: %v", err)
	}
	if resNmap.Severity != "HIGH" {
		t.Errorf("expected HIGH severity for Telnet, got: %s", resNmap.Severity)
	}
	if resNmap.Vulnerability.CWEID != "CWE-319" {
		t.Errorf("expected CWE-319, got: %s", resNmap.Vulnerability.CWEID)
	}
	if len(resNmap.Vulnerability.CVEIDs) != 2 || resNmap.Vulnerability.CVEIDs[0] != "CVE-2020-0001" {
		t.Errorf("expected deduplicated sorted CVEs, got: %+v", resNmap.Vulnerability.CVEIDs)
	}
	if len(resNmap.Fingerprint) != 64 {
		t.Errorf("expected 64-character hex fingerprint, got: %s", resNmap.Fingerprint)
	}
}

func TestNormalizerCWEAndCVENormalizationConsistency(t *testing.T) {
	normalizer := NewNormalizer()
	ctx := Context{AssessmentID: "11111111-1111-1111-1111-111111111111"}

	// Finding A: ZAP reporting numeric CWE and tagged fingerprint
	findingA := []byte(`{
		"schema_version": "1.0",
		"title": "SQL Injection",
		"severity": "CRITICAL",
		"confidence": 0.95,
		"target": {"asset": "example.com", "endpoint": "https://example.com/api/user"},
		"vulnerability": {"cwe_id": "89"},
		"scanner": {"name": "zap", "adapter_version": "1.0.0"}
	}`)

	// Finding B: Nuclei reporting uppercase CWE-89
	findingB := []byte(`{
		"schema_version": "1.0",
		"title": "SQL Injection",
		"severity": "CRITICAL",
		"confidence": 0.95,
		"target": {"asset": "example.com", "endpoint": "https://example.com/api/user"},
		"vulnerability": {"cwe_id": "CWE-89"},
		"scanner": {"name": "nuclei", "adapter_version": "1.0.0"}
	}`)

	resA, errA := normalizer.Normalize(findingA, ctx)
	if errA != nil {
		t.Fatalf("Normalize A failed: %v", errA)
	}
	resB, errB := normalizer.Normalize(findingB, ctx)
	if errB != nil {
		t.Fatalf("Normalize B failed: %v", errB)
	}

	if resA.Vulnerability.CWEID != "CWE-89" || resB.Vulnerability.CWEID != "CWE-89" {
		t.Fatalf("expected both CWEs normalized to CWE-89, got %s and %s", resA.Vulnerability.CWEID, resB.Vulnerability.CWEID)
	}

	if resA.Fingerprint != resB.Fingerprint {
		t.Fatalf("expected identical fingerprints for matching findings across scanners, got %s vs %s", resA.Fingerprint, resB.Fingerprint)
	}
}

func TestNormalizerBatchRejectsMalformedAndCollectsErrors(t *testing.T) {
	normalizer := NewNormalizer()
	ctx := Context{
		AssessmentID: "11111111-1111-1111-1111-111111111111",
		RunID:        "22222222-2222-2222-2222-222222222222",
	}

	valid := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Valid Finding",
		"severity": "LOW",
		"confidence": 0.5,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "test-template"},
		"description": "Sample",
		"remediation": {"summary": "Fix it"},
		"scanner": {"name": "test-scanner", "adapter_version": "1.0.0"},
		"discovered_at": "` + time.Now().UTC().Format(time.RFC3339) + `"
	}`)

	invalidSev := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Bad Severity",
		"severity": "UNKNOWN_SEVERITY",
		"confidence": 0.5,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "test"},
		"scanner": {"name": "test-scanner", "adapter_version": "1.0.0"},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	missingAsset := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Missing Asset",
		"severity": "LOW",
		"confidence": 0.5,
		"target": {"asset": ""},
		"vulnerability": {"template_id": "test"},
		"scanner": {"name": "test-scanner", "adapter_version": "1.0.0"},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	accepted, errs := normalizer.NormalizeBatch([]json.RawMessage{valid, invalidSev, missingAsset}, ctx)
	if len(accepted) != 1 {
		t.Errorf("expected 1 accepted finding, got %d", len(accepted))
	}
	if len(errs) != 2 {
		t.Errorf("expected 2 quarantined finding errors, got %d", len(errs))
	}
}
