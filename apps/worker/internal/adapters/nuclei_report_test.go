package adapters

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNormalizeNucleiReportCreatesCanonicalEnvelopeWithoutTrustingHost(t *testing.T) {
	task := Task{
		JobID:         "11111111-1111-1111-1111-111111111111",
		AssessmentID:  "22222222-2222-2222-2222-222222222222",
		TenantID:      "33333333-3333-3333-3333-333333333333",
		CorrelationID: "corr-nuclei",
		Scanner:       ScannerNuclei,
		Target:        "https://approved.example",
		ProfileID:     "kelvin.profile.standard.v1",
		HardDeadline:  time.Minute,
	}

	report := []byte(`{"template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Remote code execution","classification":{"cvss-score":10.0,"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"]}},"type":"http","host":"http://evil.example:8080","matched-at":"http://evil.example:8080/vulnerable/info?token=secret"}
{"template-id":"git-config","info":{"name":".git/config exposure","severity":"medium","description":"Git repository exposed"},"type":"http","host":"http://evil.example:8080","matched-at":"http://evil.example:8080/.git/config"}
`)

	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	result, err := NormalizeNucleiReport(task, report, "3.3.0", "kelvin.safe.web.v1", digest, now, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	if (result.Status != StatusCompleted && result.Status != StatusCompletedWithWarnings) || len(result.Findings) != 2 || result.Metadata.CorrelationID != task.CorrelationID {
		t.Fatalf("unexpected normalized output: %+v", result)
	}
	if string(result.ScannerMetadata["nuclei.template_catalog_version"]) != `"kelvin.safe.web.v1"` {
		t.Fatalf("catalog version not stamped: %s", result.ScannerMetadata["nuclei.template_catalog_version"])
	}

	for _, fRaw := range result.Findings {
		finding := string(fRaw)
		if !strings.Contains(finding, `"asset":"approved.example"`) || strings.Contains(finding, "evil.example") || strings.Contains(finding, "secret") {
			t.Fatalf("untrusted target or secret leaked: %s", finding)
		}
		if err := ValidateFindings(fRaw); err != nil {
			t.Fatalf("normalized finding rejected: %v", err)
		}
	}
}

func TestNormalizeNucleiReportRejectsMalformedAndUnboundedReports(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerNuclei,
		Target:       "https://approved.example",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for _, raw := range [][]byte{[]byte(`{bad json`), []byte(`{"template-id":"x","info":{"name":"foo","severity":"invalid_sev"}}`), make([]byte, maxNucleiReportBytes+1)} {
		if _, err := NormalizeNucleiReport(task, raw, "3.3.0", "kelvin.safe.web.v1", digest, time.Now(), time.Now()); err == nil {
			t.Fatal("accepted malformed/unbounded report")
		}
	}
}

func TestNucleiContractAdapterCanRunFixtureReportOffline(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerNuclei,
		Target:       "https://approved.example",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	adapter := NewVerifiedNucleiAdapter(func(context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion:         "3.3.0",
			AdapterVersion:         "1.0.0",
			ImageReference:         "registry.example/kelvin-nuclei@" + digest,
			ImageDigest:            digest,
			TemplateCatalogVersion: "kelvin.safe.web.v1",
			TemplateCatalogDigest:  digest,
		}, nil
	}, func(_ context.Context, _ Task) ([]byte, error) {
		return []byte(`{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"type":"http"}` + "\n"), nil
	})

	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	result, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCompleted || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}

	encoded, err := EncodeOutputEnvelope(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOutputEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Metadata.ScannerID != ScannerNuclei {
		t.Fatalf("scanner ID mismatch: %s", decoded.Metadata.ScannerID)
	}
}

func TestNucleiAdapterRejectsUnapprovedConfig(t *testing.T) {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	adapter := NewVerifiedNucleiAdapter(func(context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion:         "3.3.0",
			AdapterVersion:         "1.0.0",
			ImageReference:         "registry.example/kelvin-nuclei@" + digest,
			ImageDigest:            digest,
			TemplateCatalogVersion: "kelvin.safe.web.v1",
			TemplateCatalogDigest:  digest,
		}, nil
	}, func(_ context.Context, _ Task) ([]byte, error) {
		return []byte{}, nil
	})

	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	badConfigs := [][]byte{
		[]byte(`{"schema_version":"1.0","scanner_id":"nuclei","nuclei":{"template_set_id":"custom-set","severity_allowlist":["low"]}}`),
		[]byte(`{"schema_version":"1.0","scanner_id":"nuclei","requests_per_second":10}`),
		[]byte(`{"schema_version":"1.0","scanner_id":"zap"}`),
	}

	for _, cfg := range badConfigs {
		if err := adapter.ValidateConfig(cfg); err == nil {
			t.Fatalf("accepted invalid config: %s", cfg)
		}
	}
}

func TestNormalizeNucleiReportPartialFieldsAndScopeDiagnostics(t *testing.T) {
	task := Task{
		JobID:         "11111111-1111-1111-1111-111111111111",
		AssessmentID:  "22222222-2222-2222-2222-222222222222",
		TenantID:      "33333333-3333-3333-3333-333333333333",
		CorrelationID: "corr-scope",
		Scanner:       ScannerNuclei,
		Target:        "https://app.example.com",
		ProfileID:     "kelvin.profile.standard.v1",
		HardDeadline:  time.Minute,
	}

	// Line 1: Missing info.name -> falls back to template-id; reports metadata IP in matched-at -> generates diagnostic
	// Line 2: Empty description; valid severity; extracted results and curl command
	report := []byte(`{"template-id":"aws-metadata-exposure","info":{"severity":"high"},"type":"http","matched-at":"http://169.254.169.254/latest/meta-data/"}
{"template-id":"info-disclosure","info":{"name":"Information Disclosure","severity":"low","description":"Minor info leak"},"type":"http","matched-at":"https://app.example.com/status","extracted-results":["debug_flag=true"],"curl-command":"curl -X GET https://app.example.com/status?secret=12345"}
`)

	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	result, err := NormalizeNucleiReport(task, report, "3.3.0", "kelvin.safe.web.v1", digest, now, now.Add(time.Second))
	if err != nil {
		t.Fatalf("NormalizeNucleiReport failed: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	// Verify diagnostic recorded for line 1 metadata target
	if len(result.Diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic for out-of-scope metadata target, got %d", len(result.Diagnostics))
	}
	if result.Diagnostics[0].Code != "NUCLEI_OUT_OF_SCOPE_TARGET" {
		t.Errorf("expected diagnostic code NUCLEI_OUT_OF_SCOPE_TARGET, got %s", result.Diagnostics[0].Code)
	}

	// Verify fallback title for line 1
	var f1 map[string]any
	if err := json.Unmarshal(result.Findings[0], &f1); err != nil {
		t.Fatal(err)
	}
	if f1["title"] != "aws-metadata-exposure" {
		t.Errorf("expected title to fall back to template-id, got %v", f1["title"])
	}

	// Verify evidence and sanitized curl command for line 2
	var f2 map[string]any
	if err := json.Unmarshal(result.Findings[1], &f2); err != nil {
		t.Fatal(err)
	}
	meta2 := f2["scanner_meta"].(map[string]any)
	extracted, ok := meta2["nuclei.extracted_results"].([]any)
	if !ok || len(extracted) != 1 || extracted[0] != "debug_flag=true" {
		t.Errorf("extracted results not preserved in scanner_meta: %v", meta2["nuclei.extracted_results"])
	}

	evidenceList := f2["evidence"].([]any)
	if len(evidenceList) < 2 {
		t.Fatalf("expected at least 2 evidence entries (title + curl), got %d", len(evidenceList))
	}
	curlEvidence := evidenceList[1].(map[string]any)
	if strings.Contains(curlEvidence["content_redacted"].(string), "12345") {
		t.Errorf("sensitive query parameter escaped curl redaction: %v", curlEvidence["content_redacted"])
	}
}

func TestNormalizeNucleiReportSingleStringClassification(t *testing.T) {
	task := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Scanner:      ScannerNuclei,
		Target:       "https://target.example",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}

	// Single string for cve-id and cwe-id instead of array
	report := []byte(`{"template-id":"cve-2020-0001","info":{"name":"Sample CVE","severity":"medium","classification":{"cve-id":"CVE-2020-0001","cwe-id":"79"}}}` + "\n")
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	result, err := NormalizeNucleiReport(task, report, "3.3.0", "kelvin.safe.web.v1", digest, time.Now(), time.Now())
	if err != nil {
		t.Fatalf("failed with single string classification: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	var f map[string]any
	if err := json.Unmarshal(result.Findings[0], &f); err != nil {
		t.Fatal(err)
	}
	vuln := f["vulnerability"].(map[string]any)
	if vuln["cwe_id"] != "CWE-79" {
		t.Errorf("expected CWE-79, got %v", vuln["cwe_id"])
	}
	cves := vuln["cve_ids"].([]any)
	if len(cves) != 1 || cves[0] != "CVE-2020-0001" {
		t.Errorf("expected [CVE-2020-0001], got %v", cves)
	}
}
