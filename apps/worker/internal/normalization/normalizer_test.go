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

	// 3. Built-in TLS finding
	tlsFinding := []byte(`{
		"schema_version": "1.0",
		"title": "Deprecated TLS Protocol",
		"severity": "MEDIUM",
		"confidence": 1.0,
		"target": {
			"asset": "target.example.com",
			"endpoint": "https://target.example.com:443"
		},
		"vulnerability": {
			"template_id": "kelvin.tls.protocol.deprecated"
		},
		"description": "Server accepts TLS 1.0",
		"remediation": {
			"summary": "Disable TLS 1.0"
		},
		"scanner": {
			"name": "tls-assessor",
			"adapter_version": "1.0.0"
		},
		"discovered_at": "2026-11-01T20:00:00Z"
	}`)

	resTLS, err := normalizer.Normalize(tlsFinding, ctx)
	if err != nil {
		t.Fatalf("Normalize TLS finding failed: %v", err)
	}
	if resTLS.Severity != "MEDIUM" || resTLS.Fingerprint == "" {
		t.Errorf("unexpected normalized TLS finding: %+v", resTLS)
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
