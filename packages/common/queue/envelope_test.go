package queue

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJobEnvelope_Validation(t *testing.T) {
	validJob := JobEnvelope{
		SchemaVersion:       2,
		JobID:               uuid.New().String(),
		AssessmentID:        uuid.New().String(),
		TenantID:            uuid.New().String(),
		ActorID:             uuid.New().String(),
		TargetID:            uuid.New().String(),
		TargetAddress:       "https://staging.target.internal",
		ScanProfile:         "standard-web",
		RequestedScanners:   []string{"nuclei", "zap"},
		HardDeadlineSeconds: 600,
		CreatedAt:           time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(30 * time.Minute),
		CorrelationID:       uuid.New().String(),
	}

	t.Run("valid envelope passes", func(t *testing.T) {
		if err := validJob.Validate(); err != nil {
			t.Fatalf("expected valid envelope to pass, got: %v", err)
		}
	})

	t.Run("nil envelope fails", func(t *testing.T) {
		var nilEnv *JobEnvelope
		if err := nilEnv.Validate(); err == nil || !errors.Is(err, ErrInvalidJobEnvelope) {
			t.Fatalf("expected ErrInvalidJobEnvelope, got: %v", err)
		}
	})

	t.Run("unsupported schema version fails", func(t *testing.T) {
		env := validJob
		env.SchemaVersion = 99
		if err := env.Validate(); err == nil || !errors.Is(err, ErrInvalidJobEnvelope) {
			t.Fatalf("expected ErrInvalidJobEnvelope for invalid schema version, got: %v", err)
		}
	})

	t.Run("invalid UUID fails", func(t *testing.T) {
		env := validJob
		env.JobID = "not-a-uuid"
		if err := env.Validate(); err == nil || !errors.Is(err, ErrInvalidJobEnvelope) {
			t.Fatalf("expected ErrInvalidJobEnvelope for non-UUID job ID, got: %v", err)
		}
	})

	t.Run("missing target address fails", func(t *testing.T) {
		env := validJob
		env.TargetAddress = ""
		if err := env.Validate(); err == nil || !errors.Is(err, ErrInvalidJobEnvelope) {
			t.Fatalf("expected ErrInvalidJobEnvelope for empty target address, got: %v", err)
		}
	})

	t.Run("expired envelope fails", func(t *testing.T) {
		env := validJob
		env.ExpiresAt = time.Now().UTC().Add(-10 * time.Minute)
		if err := env.Validate(); err == nil || !errors.Is(err, ErrJobExpired) {
			t.Fatalf("expected ErrJobExpired for past expiration time, got: %v", err)
		}
	})
}

func TestUnpackJobEnvelope(t *testing.T) {
	jobID := uuid.New().String()
	asmtID := uuid.New().String()
	tenantID := uuid.New().String()
	corrID := uuid.New().String()

	t.Run("unpack version 2 message", func(t *testing.T) {
		v2Env := JobEnvelope{
			SchemaVersion:       2,
			JobID:               jobID,
			AssessmentID:        asmtID,
			TenantID:            tenantID,
			TargetAddress:       "https://app.kelvin.internal",
			ScanProfile:         "api-audit",
			RequestedScanners:   []string{"nmap"},
			HardDeadlineSeconds: 300,
			CreatedAt:           time.Now().UTC(),
			ExpiresAt:           time.Now().UTC().Add(15 * time.Minute),
			CorrelationID:       corrID,
		}
		raw, _ := json.Marshal(v2Env)
		msg := Message{
			Version:       2,
			ID:            jobID,
			AssessmentID:  asmtID,
			TenantID:      tenantID,
			CorrelationID: corrID,
			Type:          "NMAP",
			Payload:       raw,
			MaxAttempts:   3,
		}

		if err := msg.Validate(); err != nil {
			t.Fatalf("msg.Validate() failed: %v", err)
		}

		unpacked, err := UnpackJobEnvelope(msg)
		if err != nil {
			t.Fatalf("UnpackJobEnvelope() failed: %v", err)
		}
		if unpacked.TargetAddress != "https://app.kelvin.internal" {
			t.Errorf("expected target address https://app.kelvin.internal, got %s", unpacked.TargetAddress)
		}
		if unpacked.SchemaVersion != 2 {
			t.Errorf("expected SchemaVersion 2, got %d", unpacked.SchemaVersion)
		}
	})

	t.Run("unpack version 1 message backward compatibility", func(t *testing.T) {
		v1Payload := map[string]any{
			"target":                "https://legacy.target.internal",
			"profile_id":            "legacy-profile",
			"hard_deadline_seconds": 450,
			"scanners":              []string{"nuclei"},
		}
		raw, _ := json.Marshal(v1Payload)
		msg := Message{
			Version:       1,
			ID:            jobID,
			AssessmentID:  asmtID,
			TenantID:      tenantID,
			CorrelationID: corrID,
			Type:          "NUCLEI",
			Payload:       raw,
			MaxAttempts:   3,
		}

		if err := msg.Validate(); err != nil {
			t.Fatalf("msg.Validate() failed: %v", err)
		}

		unpacked, err := UnpackJobEnvelope(msg)
		if err != nil {
			t.Fatalf("UnpackJobEnvelope() failed: %v", err)
		}
		if unpacked.TargetAddress != "https://legacy.target.internal" {
			t.Errorf("expected target address https://legacy.target.internal, got %s", unpacked.TargetAddress)
		}
		if unpacked.ScanProfile != "legacy-profile" {
			t.Errorf("expected scan profile legacy-profile, got %s", unpacked.ScanProfile)
		}
		if unpacked.HardDeadlineSeconds != 450 {
			t.Errorf("expected deadline 450, got %d", unpacked.HardDeadlineSeconds)
		}
	})
}
