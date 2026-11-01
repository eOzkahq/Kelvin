package adapter

import (
	"errors"
	"testing"
	"time"
)

func validOutputEnvelope() OutputEnvelope {
	start := time.Now().Add(-5 * time.Second)
	end := time.Now()
	return OutputEnvelope{
		SchemaVersion: OutputEnvelopeVersion,
		AssessmentID:  "11111111-1111-1111-1111-111111111111",
		TaskID:        "22222222-2222-2222-2222-222222222222",
		TenantID:      "33333333-3333-3333-3333-333333333333",
		CorrelationID: "corr-output-1",
		Status:        StatusSuccess,
		StartedAt:     start,
		CompletedAt:   end,
		Duration:      end.Sub(start),
		IsPartial:     false,
		RawOutput:     []byte("[*] Scan output line 1\n[*] Scan output line 2"),
		Findings:      []byte(`[{"title":"Missing Security Headers"}]`),
		Diagnostics: ExecutionDiagnostics{
			ExitCode:             0,
			StdoutSize:           40,
			StderrSize:           0,
			NetworkRequestsCount: 12,
		},
		Scanner: ScannerMetadata{
			ScannerID:      "zap",
			AdapterVersion: "1.0.0",
			EngineVersion:  "2.14.0",
			ExecutionMode:  "passive",
		},
	}
}

func TestOutputEnvelopeSerializationRoundTrip(t *testing.T) {
	env := validOutputEnvelope()
	data, err := env.Serialize()
	if err != nil {
		t.Fatalf("expected serialization to succeed: %v", err)
	}

	decoded, err := DeserializeOutputEnvelope(data)
	if err != nil {
		t.Fatalf("expected deserialization to succeed: %v", err)
	}

	if decoded.AssessmentID != env.AssessmentID {
		t.Fatalf("expected AssessmentID %s, got %s", env.AssessmentID, decoded.AssessmentID)
	}
	if decoded.Status != StatusSuccess {
		t.Fatalf("expected Status SUCCESS, got %s", decoded.Status)
	}
	if string(decoded.RawOutput) != string(env.RawOutput) {
		t.Fatalf("raw output mismatch")
	}
}

func TestOutputEnvelopeSchemaVersionValidation(t *testing.T) {
	env := validOutputEnvelope()
	env.SchemaVersion = "9.9"
	if err := ValidateOutputEnvelope(env); !errors.Is(err, ErrInvalidOutputSchema) {
		t.Fatalf("expected ErrInvalidOutputSchema, got %v", err)
	}
}

func TestOutputEnvelopePartialStatusRequiresReason(t *testing.T) {
	env := validOutputEnvelope()
	env.Status = StatusPartial
	env.IsPartial = true
	env.PartialReason = ""
	if err := ValidateOutputEnvelope(env); !errors.Is(err, ErrMissingPartialCause) {
		t.Fatalf("expected ErrMissingPartialCause when partial_reason is empty, got %v", err)
	}

	env.PartialReason = PartialReasonDeadlineExceeded
	if err := ValidateOutputEnvelope(env); err != nil {
		t.Fatalf("expected validation to pass with valid partial_reason: %v", err)
	}
}

func TestOutputEnvelopeInvalidTimeline(t *testing.T) {
	env := validOutputEnvelope()
	env.CompletedAt = env.StartedAt.Add(-1 * time.Minute)
	if err := ValidateOutputEnvelope(env); !errors.Is(err, ErrInvalidTimeline) {
		t.Fatalf("expected ErrInvalidTimeline, got %v", err)
	}
}

func TestOutputEnvelopeRejectsMalformedUUID(t *testing.T) {
	env := validOutputEnvelope()
	env.TaskID = "not-a-uuid"
	if err := ValidateOutputEnvelope(env); !errors.Is(err, ErrInvalidUUID) {
		t.Fatalf("expected ErrInvalidUUID, got %v", err)
	}
}
