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
