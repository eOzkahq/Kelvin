package adapters

import (
	"encoding/json"
	"testing"
	"time"
)

func validOutputEnvelope() ScannerOutputEnvelope {
	exit := 0
	return ScannerOutputEnvelope{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID: "22222222-2222-2222-2222-222222222222", ScannerID: "zap",
			ScannerVersion: "2.16.1", AdapterVersion: "1.0.0",
			RunID:         "11111111-1111-1111-1111-111111111111",
			StartedAt:     time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
			CompletedAt:   time.Date(2026, 11, 1, 0, 0, 2, 0, time.UTC),
			CorrelationID: "corr-123",
		},
		Status: StatusCompleted, ExitCode: &exit, DurationMS: 2000,
		Findings:    []json.RawMessage{json.RawMessage(`{"schema_version":"1.0","title":"TLS finding","severity":"LOW","confidence":0.9,"target":{"asset":"asset-1"},"vulnerability":{},"scanner":{"name":"zap","adapter_version":"1.0.0"},"discovered_at":"2026-11-01T00:00:00Z"}`)},
		Diagnostics: []ExecutionDiagnostic{}, RawArtifacts: RawArtifactReferences{},
	}
}

func TestOutputEnvelopeRoundTrip(t *testing.T) {
	envelope := validOutputEnvelope()
	envelope.RawArtifacts.StdoutRef = "artifact://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/stdout"
	envelope.RawPayload = &RawPayload{Format: "text", Content: "raw scanner output; not normalized findings"}
	encoded, err := EncodeOutputEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOutputEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status != StatusCompleted || len(decoded.Findings) != 1 || decoded.RawPayload == nil || decoded.RawPayload.Content == string(decoded.Findings[0]) {
		t.Fatalf("round-trip did not preserve distinct result channels: %+v", decoded)
	}
}

func TestOutputEnvelopeRejectsUnknownAndMalformedWireData(t *testing.T) {
	encoded, err := EncodeOutputEnvelope(validOutputEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := DecodeOutputEnvelope(unknown); err == nil {
		t.Fatal("DecodeOutputEnvelope accepted an unknown field")
	}
	if _, err := DecodeOutputEnvelope(append(encoded, []byte(` {}`)...)); err == nil {
		t.Fatal("DecodeOutputEnvelope accepted trailing JSON")
	}
}

func TestOutputEnvelopeStatusSemantics(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ScannerOutputEnvelope)
	}{
		{"warning status without warning", func(e *ScannerOutputEnvelope) { e.Status = StatusCompletedWithWarnings }},
		{"completed with warning", func(e *ScannerOutputEnvelope) {
			e.Diagnostics = []ExecutionDiagnostic{{Level: "warning", Code: "RULE_SKIPPED", Message: "One check was skipped"}}
		}},
		{"partial without flag", func(e *ScannerOutputEnvelope) { e.Status = StatusPartial }},
		{"partial with findings", func(e *ScannerOutputEnvelope) { e.Status = StatusPartial; e.Partial = true }},
		{"failed without diagnostic", func(e *ScannerOutputEnvelope) { e.Status = StatusFailed }},
		{"timed out without diagnostic", func(e *ScannerOutputEnvelope) { e.Status = StatusTimedOut }},
		{"cancelled without diagnostic", func(e *ScannerOutputEnvelope) { e.Status = StatusCancelled }},
		{"completed with malformed finding", func(e *ScannerOutputEnvelope) {
			e.Findings = []json.RawMessage{json.RawMessage(`{"title":"raw scanner output"}`)}
		}},
		{"artifact URL rejected", func(e *ScannerOutputEnvelope) { e.RawArtifacts.StderrRef = "https://example.com/raw" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validOutputEnvelope()
			tc.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatal("Validate accepted inconsistent envelope")
			}
		})
	}
	withWarning := validOutputEnvelope()
	withWarning.Status = StatusCompletedWithWarnings
	withWarning.Diagnostics = []ExecutionDiagnostic{{Level: "warning", Code: "RULE_SKIPPED", Message: "One check was skipped"}}
	if err := withWarning.Validate(); err != nil {
		t.Fatalf("valid warning result rejected: %v", err)
	}
	partial := validOutputEnvelope()
	partial.Status, partial.Partial = StatusPartial, true
	partial.Diagnostics = []ExecutionDiagnostic{{Level: "warning", Code: "DEADLINE_NEAR", Message: "Some checks did not run"}}
	if err := partial.Validate(); err != nil {
		t.Fatalf("valid partial result rejected: %v", err)
	}
	failed := validOutputEnvelope()
	failed.Status = StatusFailed
	failed.Diagnostics = []ExecutionDiagnostic{{Level: "error", Code: "SCANNER_CRASH", Message: "Scanner exited unsuccessfully"}}
	if err := failed.Validate(); err != nil {
		t.Fatalf("valid failure result rejected: %v", err)
	}
	for _, status := range []ExecutionStatus{StatusTimedOut, StatusCancelled} {
		e := validOutputEnvelope()
		e.Status = status
		code := "DEADLINE_EXCEEDED"
		if status == StatusCancelled {
			code = "CANCELLED"
		}
		e.Diagnostics = []ExecutionDiagnostic{{Level: "error", Code: code, Message: "Execution stopped"}}
		if err := e.Validate(); err != nil {
			t.Errorf("valid %s result rejected: %v", status, err)
		}
	}
}
