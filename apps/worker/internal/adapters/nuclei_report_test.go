package adapters

import (
	"context"
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

	if result.Status != StatusCompleted || len(result.Findings) != 2 || result.Metadata.CorrelationID != task.CorrelationID {
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
