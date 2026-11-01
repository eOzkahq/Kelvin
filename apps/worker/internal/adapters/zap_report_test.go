package adapters

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNormalizeZAPReportCreatesCanonicalEnvelopeWithoutTrustingInstanceURLs(t *testing.T) {
	task := Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", CorrelationID: "corr-zap", Scanner: ScannerZAPBaseline, Target: "https://approved.example", ProfileID: "kelvin.profile.standard.v1", HardDeadline: time.Minute}
	report := []byte(`{"@version":"2.16.1","site":[{"alerts":[{"pluginid":"10020","alert":"X-Frame-Options Header Not Set","riskcode":"2","confidence":"High","desc":"<p>Missing frame protection</p>","solution":"Set a frame policy","cweid":"693","instances":[{"uri":"https://evil.example/private?token=secret"}]}]}]}`)
	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	result, err := NormalizeZAPReport(task, report, "2.16.1", now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCompleted || len(result.Findings) != 1 || result.Metadata.CorrelationID != task.CorrelationID {
		t.Fatalf("unexpected normalized output: %+v", result)
	}
	if string(result.ScannerMetadata["zap.safety_profile"]) != `"`+ZAPSafetyProfileVersion+`"` {
		t.Fatalf("safety profile version not stamped in output: %s", result.ScannerMetadata["zap.safety_profile"])
	}
	finding := string(result.Findings[0])
	if !strings.Contains(finding, `"asset":"approved.example"`) || strings.Contains(finding, "evil.example") || strings.Contains(finding, "secret") {
		t.Fatalf("scanner controlled URLs or evidence escaped normalization: %s", finding)
	}
	if err := ValidateFindings(result.Findings[0]); err != nil {
		t.Fatalf("normalized finding rejected: %v", err)
	}
}

func TestNormalizeZAPReportTaxonomyAndNumericConfidence(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerZAPBaseline,
		Target:       "https://approved.example",
		ProfileID:    "kelvin.profile.standard.v1",
		HardDeadline: time.Minute,
	}

	report := []byte(`{
		"@version": "2.16.1",
		"site": [{
			"alerts": [
				{
					"pluginid": "40012",
					"alert": "Cross Site Scripting (Reflected)",
					"riskcode": "3",
					"confidence": "3",
					"desc": "Cross site scripting vulnerability detected",
					"solution": "Sanitize and encode all user supplied input",
					"cweid": "79",
					"wascid": "8",
					"sourceid": "1",
					"count": "2"
				},
				{
					"pluginid": "10038",
					"alert": "Content Security Policy (CSP) Header Not Set",
					"riskcode": "1",
					"confidence": "2",
					"desc": "Content Security Policy (CSP) is an added layer of security",
					"solution": "Ensure CSP is properly configured",
					"cweid": "16",
					"wascid": "15"
				}
			]
		}]
	}`)

	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	result, err := NormalizeZAPReport(task, report, "2.16.1", now, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("NormalizeZAPReport failed: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	var finding1 map[string]any
	if err := json.Unmarshal(result.Findings[0], &finding1); err != nil {
		t.Fatalf("failed to unmarshal finding 1: %v", err)
	}

	if finding1["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", finding1["severity"])
	}
	if finding1["confidence"] != 0.9 {
		t.Errorf("expected confidence 0.9 for numeric confidence '3', got %v", finding1["confidence"])
	}

	vuln1, ok := finding1["vulnerability"].(map[string]any)
	if !ok {
		t.Fatalf("expected vulnerability map in finding 1")
	}
	if vuln1["cwe_id"] != "CWE-79" {
		t.Errorf("expected CWE-79, got %v", vuln1["cwe_id"])
	}
	if vuln1["wasc_id"] != "WASC-8" {
		t.Errorf("expected WASC-8, got %v", vuln1["wasc_id"])
	}

	meta1, ok := finding1["scanner_meta"].(map[string]any)
	if !ok {
		t.Fatalf("expected scanner_meta map in finding 1")
	}
	if meta1["zap.plugin_id"] != "40012" {
		t.Errorf("expected zap.plugin_id 40012, got %v", meta1["zap.plugin_id"])
	}
	if meta1["zap.source_id"] != "1" {
		t.Errorf("expected zap.source_id 1, got %v", meta1["zap.source_id"])
	}
	if meta1["zap.alert_count"] != "2" {
		t.Errorf("expected zap.alert_count 2, got %v", meta1["zap.alert_count"])
	}

	for i, f := range result.Findings {
		if err := ValidateFindings(f); err != nil {
			t.Errorf("finding %d failed validation: %v", i, err)
		}
	}
}

func TestNormalizeZAPReportRejectsMalformedAndUnboundedReports(t *testing.T) {
	task := Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: ScannerZAPBaseline, Target: "https://approved.example", ProfileID: "standard", HardDeadline: time.Minute}
	for _, raw := range [][]byte{[]byte(`{`), []byte(`{"site":[]} {}`), make([]byte, maxZAPReportBytes+1)} {
		if _, err := NormalizeZAPReport(task, raw, "2.16.1", time.Now(), time.Now()); err == nil {
			t.Fatal("accepted malformed/unbounded report")
		}
	}
}

func TestZAPContractAdapterCanRunFixtureReportOffline(t *testing.T) {
	// This verifies the parsing contract independently of an OCI runtime; the
	// live container is not needed in CI and no target traffic is generated.
	task := Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: ScannerZAPBaseline, Target: "https://approved.example", ProfileID: "standard", HardDeadline: time.Minute}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	adapter := NewVerifiedZAPBaselineAdapter(func(context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{ScannerVersion: "2.16.1", AdapterVersion: "1.0.0", ImageReference: "registry.example/kelvin-zap@" + digest, ImageDigest: digest}, nil
	}, func(_ context.Context, _ Task) ([]byte, error) {
		return []byte(`{"@version":"2.16.1","site":[{"alerts":[]}]}`), nil
	})
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCompleted || len(result.Findings) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	encoded, err := EncodeOutputEnvelope(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded["schema_version"] != OutputEnvelopeVersion {
		t.Fatalf("output envelope did not serialize: %v", err)
	}
}
