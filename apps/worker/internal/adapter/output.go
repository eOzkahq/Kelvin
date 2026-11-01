// Package adapter defines the canonical scanner output envelope.
//
// The output envelope encapsulates execution telemetry, raw untrusted scanner outputs,
// execution diagnostics, and partial completion status in a versioned contract.
package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OutputEnvelopeVersion is the version of the scanner output envelope schema.
const OutputEnvelopeVersion = "1.0"

// Sentinel errors for output envelope validation.
var (
	ErrInvalidOutputSchema = errors.New("output: unsupported envelope schema version")
	ErrInvalidOutputStatus = errors.New("output: invalid or missing execution status")
	ErrInvalidTimeline     = errors.New("output: completion timestamp cannot precede start timestamp")
	ErrMissingPartialCause = errors.New("output: partial status requires explicit partial_reason")
)

// Standard partial execution reasons.
const (
	PartialReasonDeadlineExceeded    = "DEADLINE_EXCEEDED"
	PartialReasonRequestBudgetExhaust = "REQUEST_BUDGET_EXHAUSTED"
	PartialReasonOOMKilled           = "OOM_KILLED"
	PartialReasonUserCanceled        = "USER_CANCELED"
	PartialReasonSubprocessCrash     = "SUBPROCESS_CRASH"
)

// ExecutionDiagnostics contains process-level telemetry and captured streams.
type ExecutionDiagnostics struct {
	ExitCode             int    `json:"exit_code"`
	StdoutSize           int    `json:"stdout_size"`
	StderrSize           int    `json:"stderr_size"`
	TruncatedStdout      string `json:"truncated_stdout,omitempty"`
	TruncatedStderr      string `json:"truncated_stderr,omitempty"`
	OOMKilled            bool   `json:"oom_killed"`
	DeadlineExceeded     bool   `json:"deadline_exceeded"`
	PeakMemoryBytes      int64  `json:"peak_memory_bytes,omitempty"`
	CPUTimeUserMs        int64  `json:"cpu_time_user_ms,omitempty"`
	CPUTimeSysMs         int64  `json:"cpu_time_sys_ms,omitempty"`
	NetworkRequestsCount int    `json:"network_requests_count,omitempty"`
	ErrorMessage         string `json:"error_message,omitempty"`
}

// ScannerMetadata contains engine provenance and versioning details.
type ScannerMetadata struct {
	ScannerID           string `json:"scanner_id"`
	AdapterVersion      string `json:"adapter_version"`
	EngineVersion       string `json:"engine_version"`
	TemplateSetRevision string `json:"template_set_revision,omitempty"`
	ExecutionMode       string `json:"execution_mode"`
}

// OutputEnvelope defines the standard envelope returned by all scanner adapters to the worker.
type OutputEnvelope struct {
	SchemaVersion    string               `json:"schema_version"`
	AssessmentID     string               `json:"assessment_id"`
	TaskID           string               `json:"task_id"`
	TenantID         string               `json:"tenant_id"`
	CorrelationID    string               `json:"correlation_id"`
	Status           ExecutionStatus      `json:"status"`
	StartedAt        time.Time            `json:"started_at"`
	CompletedAt      time.Time            `json:"completed_at"`
	Duration         time.Duration        `json:"duration"`
	IsPartial        bool                 `json:"is_partial"`
	PartialReason    string               `json:"partial_reason,omitempty"`
	// RawOutput is the unmodified raw output stream (untrusted, strictly separated from findings).
	RawOutput        []byte               `json:"raw_output,omitempty"`
	// Findings is the untrusted JSON payload destined for canonical normalization.
	Findings         json.RawMessage      `json:"findings,omitempty"`
	Diagnostics      ExecutionDiagnostics `json:"diagnostics"`
	Scanner          ScannerMetadata      `json:"scanner"`
	CustomAttributes map[string]any       `json:"custom_attributes,omitempty"`
}

// ValidateOutputEnvelope verifies envelope invariants and structural validity.
func ValidateOutputEnvelope(env OutputEnvelope) error {
	if env.SchemaVersion != OutputEnvelopeVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrInvalidOutputSchema, env.SchemaVersion, OutputEnvelopeVersion)
	}

	for name, id := range map[string]string{
		"assessment_id": env.AssessmentID,
		"task_id":       env.TaskID,
		"tenant_id":     env.TenantID,
	} {
		if id == "" {
			return fmt.Errorf("%w: %s is required", ErrMissingRequiredField, name)
		}
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("%w: %s (%q)", ErrInvalidUUID, name, id)
		}
	}

	switch env.Status {
	case StatusSuccess, StatusCompletedWithWarnings, StatusPartial, StatusFailed, StatusCanceled, StatusTimedOut:
		// Valid execution statuses
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOutputStatus, env.Status)
	}

	if env.CompletedAt.Before(env.StartedAt) {
		return ErrInvalidTimeline
	}

	if env.IsPartial || env.Status == StatusPartial {
		if env.PartialReason == "" {
			return ErrMissingPartialCause
		}
	}

	if env.Scanner.ScannerID == "" {
		return fmt.Errorf("%w: scanner.scanner_id is required", ErrMissingRequiredField)
	}

	return nil
}

// Serialize converts the OutputEnvelope into a clean JSON byte slice.
func (env OutputEnvelope) Serialize() ([]byte, error) {
	if err := ValidateOutputEnvelope(env); err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// DeserializeOutputEnvelope parses JSON into an OutputEnvelope and validates it.
func DeserializeOutputEnvelope(data []byte) (OutputEnvelope, error) {
	var env OutputEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return OutputEnvelope{}, fmt.Errorf("output: failed to unmarshal json: %w", err)
	}
	if err := ValidateOutputEnvelope(env); err != nil {
		return OutputEnvelope{}, err
	}
	return env, nil
}
