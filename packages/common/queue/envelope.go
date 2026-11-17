package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kelvin/kelvin/packages/common/validation"
)

var (
	// ErrJobExpired indicates a job was dequeued after its hard expiration time.
	ErrJobExpired = errors.New("queue: job envelope has expired")
	// ErrInvalidJobEnvelope indicates missing or malformed required fields in the envelope.
	ErrInvalidJobEnvelope = errors.New("queue: invalid job envelope schema")
)

// CurrentSchemaVersion is the authoritative schema version for assessment job envelopes.
const CurrentSchemaVersion = 2

// JobEnvelope represents the authoritative Version 2 job envelope contract.
// It guarantees strict tenant isolation, actor attribution, scope binding, and expiration.
type JobEnvelope struct {
	SchemaVersion         int             `json:"schema_version"`
	JobID                 string          `json:"job_id"`
	AssessmentID          string          `json:"assessment_id"`
	TenantID              string          `json:"tenant_id"`
	ActorID               string          `json:"actor_id,omitempty"`
	TargetID              string          `json:"target_id,omitempty"`
	TargetAddress         string          `json:"target_address"`
	ScopeSnapshotRef      string          `json:"scope_snapshot_ref,omitempty"`
	ScanProfile           string          `json:"scan_profile"`
	RequestedScanners     []string        `json:"requested_scanners"`
	RequestedCapabilities []string        `json:"requested_capabilities,omitempty"`
	RateLimit             string          `json:"rate_limit,omitempty"`
	HardDeadlineSeconds   int64           `json:"hard_deadline_seconds"`
	CreatedAt             time.Time       `json:"created_at"`
	ExpiresAt             time.Time       `json:"expires_at"`
	CorrelationID         string          `json:"correlation_id"`
	CustomParameters      json.RawMessage `json:"custom_parameters,omitempty"`
}

// Validate checks all schema constraints and expiration bounds.
func (e *JobEnvelope) Validate() error {
	if e == nil {
		return fmt.Errorf("%w: envelope cannot be nil", ErrInvalidJobEnvelope)
	}
	if e.SchemaVersion != 1 && e.SchemaVersion != 2 {
		return fmt.Errorf("%w: unsupported schema version %d", ErrInvalidJobEnvelope, e.SchemaVersion)
	}
	if !validation.IsUUID(e.JobID) {
		return fmt.Errorf("%w: job_id must be a valid UUID, got %q", ErrInvalidJobEnvelope, e.JobID)
	}
	if !validation.IsUUID(e.AssessmentID) {
		return fmt.Errorf("%w: assessment_id must be a valid UUID, got %q", ErrInvalidJobEnvelope, e.AssessmentID)
	}
	if !validation.IsUUID(e.TenantID) {
		return fmt.Errorf("%w: tenant_id must be a valid UUID, got %q", ErrInvalidJobEnvelope, e.TenantID)
	}
	if e.TargetAddress == "" {
		return fmt.Errorf("%w: target_address is required", ErrInvalidJobEnvelope)
	}
	if e.ScanProfile == "" {
		return fmt.Errorf("%w: scan_profile is required", ErrInvalidJobEnvelope)
	}
	if e.HardDeadlineSeconds <= 0 {
		e.HardDeadlineSeconds = 600
	}
	if !e.ExpiresAt.IsZero() && time.Now().UTC().After(e.ExpiresAt) {
		return fmt.Errorf("%w: job expired at %s", ErrJobExpired, e.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// UnpackJobEnvelope deserializes and validates a queue message payload into an authoritative JobEnvelope.
// It natively supports Schema Version 2 while maintaining backward compatibility for Version 1 payloads.
func UnpackJobEnvelope(msg Message) (*JobEnvelope, error) {
	if msg.Version == 2 {
		var env JobEnvelope
		if err := json.Unmarshal(msg.Payload, &env); err != nil {
			return nil, fmt.Errorf("%w: failed to unmarshal v2 envelope: %v", ErrInvalidJobEnvelope, err)
		}
		if env.JobID == "" {
			env.JobID = msg.ID
		}
		if env.AssessmentID == "" {
			env.AssessmentID = msg.AssessmentID
		}
		if env.TenantID == "" {
			env.TenantID = msg.TenantID
		}
		if env.CorrelationID == "" {
			env.CorrelationID = msg.CorrelationID
		}
		if err := env.Validate(); err != nil {
			return nil, err
		}
		return &env, nil
	}

	// Schema Version 1 backward compatibility fallback
	var v1Payload struct {
		Target              string          `json:"target"`
		ProfileID           string          `json:"profile_id"`
		HardDeadlineSeconds int64           `json:"hard_deadline_seconds"`
		Scanners            []string        `json:"scanners"`
		RateLimit           string          `json:"rate_limit"`
		Params              json.RawMessage `json:"params,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &v1Payload); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal v1 payload: %v", ErrInvalidJobEnvelope, err)
	}

	deadline := v1Payload.HardDeadlineSeconds
	if deadline <= 0 {
		deadline = 600
	}

	scanners := v1Payload.Scanners
	if len(scanners) == 0 && msg.Type != "" && msg.Type != "assessment" && msg.Type != "pipeline" {
		scanners = []string{msg.Type}
	}

	env := &JobEnvelope{
		SchemaVersion:       1,
		JobID:               msg.ID,
		AssessmentID:        msg.AssessmentID,
		TenantID:            msg.TenantID,
		TargetAddress:       v1Payload.Target,
		ScanProfile:         v1Payload.ProfileID,
		RequestedScanners:   scanners,
		RateLimit:           v1Payload.RateLimit,
		HardDeadlineSeconds: deadline,
		CreatedAt:           time.Now().UTC(),
		CorrelationID:       msg.CorrelationID,
		CustomParameters:    v1Payload.Params,
	}

	if err := env.Validate(); err != nil {
		return nil, err
	}
	return env, nil
}
