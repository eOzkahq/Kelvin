package adapters

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBuiltinPreflightResult(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerHTTPPreflight,
		Target:       "https://preflight.example.com",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}

	started := time.Now().UTC()
	completed := started.Add(50 * time.Millisecond)

	// Case 1: Healthy HTTP response
	obsResponded := preflightObservation{
		Outcome:    "HTTP_RESPONDED",
		Target:     "https://preflight.example.com",
		StatusCode: 200,
		Protocol:   "HTTP/1.1",
		LatencyMS:  45,
	}
	res, err := NormalizeBuiltinPreflightResult(task, obsResponded, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinPreflightResult failed: %v", err)
	}
	if res.Status != StatusCompleted || len(res.Findings) != 0 {
		t.Errorf("expected COMPLETED with 0 findings, got status=%s findings=%d", res.Status, len(res.Findings))
	}

	// Case 2: Inconclusive unreachable target
	obsUnreachable := preflightObservation{
		Outcome: "UNREACHABLE",
		Target:  "https://preflight.example.com",
		Error:   "connection_refused",
	}
	resUnreachable, err := NormalizeBuiltinPreflightResult(task, obsUnreachable, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinPreflightResult unreachable failed: %v", err)
	}
	if resUnreachable.Status != StatusCompletedWithWarnings || len(resUnreachable.Diagnostics) != 1 {
		t.Errorf("expected COMPLETED_WITH_WARNINGS with 1 diagnostic, got status=%s diagnostics=%d", resUnreachable.Status, len(resUnreachable.Diagnostics))
	}

	// Case 3: Timeout
	obsTimeout := preflightObservation{
		Outcome: "UNREACHABLE",
		Target:  "https://preflight.example.com",
		Error:   "timeout",
	}
	resTimeout, err := NormalizeBuiltinPreflightResult(task, obsTimeout, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinPreflightResult timeout failed: %v", err)
	}
	if resTimeout.Status != StatusTimedOut || len(resTimeout.Diagnostics) != 1 || resTimeout.Diagnostics[0].Code != "DEADLINE_EXCEEDED" {
		t.Errorf("expected TIMED_OUT with DEADLINE_EXCEEDED diagnostic, got status=%s diag=%+v", resTimeout.Status, resTimeout.Diagnostics)
	}
}

func TestNormalizeBuiltinHeadersResult(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerHTTPHeaders,
		Target:       "https://headers.example.com",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}

	started := time.Now().UTC()
	completed := started.Add(100 * time.Millisecond)

	finding, err := BuildBuiltinFinding(
		ScannerHTTPHeaders,
		"headers.example.com",
		"https://headers.example.com/",
		"kelvin.http_headers.hsts_missing",
		"HSTS header missing",
		"MEDIUM",
		"Strict-Transport-Security header was not observed",
		"Configure HSTS header",
		0.9,
		[]BuiltinEvidence{
			{
				Type:            "HEADER_DUMP",
				ContentType:     "text/plain",
				ContentRedacted: "Strict-Transport-Security: <missing>",
				RedactedFields:  []string{},
			},
		},
		[]string{"http", "security-headers"},
		started,
	)
	if err != nil {
		t.Fatalf("BuildBuiltinFinding failed: %v", err)
	}

	// Case 1: Confirmed finding on HTTP_RESPONDED
	obs := httpHeadersObservation{
		Outcome:        "HTTP_RESPONDED",
		Target:         "https://headers.example.com",
		StatusCode:     200,
		Protocol:       "HTTP/2.0",
		RuleSetVersion: HTTPHeaderRuleSetVersion,
	}
	res, err := NormalizeBuiltinHeadersResult(task, obs, []json.RawMessage{finding}, nil, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinHeadersResult failed: %v", err)
	}
	if res.Status != StatusCompleted || len(res.Findings) != 1 {
		t.Errorf("expected COMPLETED with 1 finding, got status=%s findings=%d", res.Status, len(res.Findings))
	}

	// Case 2: Inconclusive check drops findings
	obsFailed := httpHeadersObservation{
		Outcome: "CONNECTION_FAILED",
		Target:  "https://headers.example.com",
		Error:   "dial tcp: connection refused",
	}
	resFailed, err := NormalizeBuiltinHeadersResult(task, obsFailed, []json.RawMessage{finding}, nil, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinHeadersResult failed on inconclusive: %v", err)
	}
	if len(resFailed.Findings) != 0 {
		t.Errorf("inconclusive check must drop speculative findings, got %d findings", len(resFailed.Findings))
	}
	if resFailed.Status != StatusCompletedWithWarnings {
		t.Errorf("expected COMPLETED_WITH_WARNINGS for inconclusive check, got %s", resFailed.Status)
	}
}

func TestNormalizeBuiltinTLSResult(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerTLSAssessor,
		Target:       "https://tls.example.com:443",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}

	started := time.Now().UTC()
	completed := started.Add(200 * time.Millisecond)

	finding, err := BuildBuiltinFinding(
		ScannerTLSAssessor,
		"tls.example.com",
		"https://tls.example.com:443",
		"kelvin.tls.protocol.deprecated",
		"Deprecated TLS 1.0 protocol enabled",
		"HIGH",
		"The server negotiates TLS 1.0 which is deprecated",
		"Disable TLS 1.0 and enable TLS 1.2+",
		1.0,
		[]BuiltinEvidence{
			{
				Type:            "CERTIFICATE_DUMP",
				ContentType:     "text/plain",
				ContentRedacted: "Protocol: TLS 1.0 (0x0301)",
				RedactedFields:  []string{},
			},
		},
		[]string{"tls", "configuration"},
		started,
	)
	if err != nil {
		t.Fatalf("BuildBuiltinFinding failed: %v", err)
	}

	// Case 1: Confirmed TLS finding
	obs := tlsObservation{
		Outcome:            "TLS_NEGOTIATED",
		Target:             "https://tls.example.com:443",
		ProtocolVersion:    "TLS 1.0",
		SupportedProtocols: []string{"TLS 1.0", "TLS 1.2"},
		ChainTrusted:       true,
		RuleSetVersion:     TLSRuleSetVersion,
	}
	res, err := NormalizeBuiltinTLSResult(task, obs, []json.RawMessage{finding}, nil, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinTLSResult failed: %v", err)
	}
	if res.Status != StatusCompleted || len(res.Findings) != 1 {
		t.Errorf("expected COMPLETED with 1 finding, got status=%s findings=%d", res.Status, len(res.Findings))
	}

	// Case 2: Inconclusive handshake drop findings
	obsFailed := tlsObservation{
		Outcome: "TLS_FAILED",
		Target:  "https://tls.example.com:443",
		Error:   "tls: handshake failure",
	}
	resFailed, err := NormalizeBuiltinTLSResult(task, obsFailed, []json.RawMessage{finding}, nil, started, completed)
	if err != nil {
		t.Fatalf("NormalizeBuiltinTLSResult failed on TLS_FAILED: %v", err)
	}
	if len(resFailed.Findings) != 0 {
		t.Errorf("inconclusive check must drop speculative findings, got %d findings", len(resFailed.Findings))
	}
	if resFailed.Status != StatusCompletedWithWarnings {
		t.Errorf("expected COMPLETED_WITH_WARNINGS for inconclusive TLS check, got %s", resFailed.Status)
	}
}

func TestBuildBuiltinFindingValidation(t *testing.T) {
	now := time.Now().UTC()

	// Invalid prefix should fail
	_, err := BuildBuiltinFinding(
		ScannerHTTPHeaders,
		"example.com",
		"https://example.com",
		"custom.rule.without.prefix",
		"Title",
		"LOW",
		"Desc",
		"Rem",
		0.5,
		nil,
		nil,
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "kelvin.") {
		t.Errorf("expected error for invalid rule prefix, got: %v", err)
	}

	// Empty host should fail
	_, err = BuildBuiltinFinding(
		ScannerHTTPHeaders,
		"",
		"https://example.com",
		"kelvin.test.rule",
		"Title",
		"LOW",
		"Desc",
		"Rem",
		0.5,
		nil,
		nil,
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error for empty host, got: %v", err)
	}
}
