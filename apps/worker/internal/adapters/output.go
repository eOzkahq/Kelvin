package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const OutputEnvelopeVersion = "1.0"

var artifactReferencePattern = regexp.MustCompile(`^artifact://[0-9a-fA-F-]{36}(/[A-Za-z0-9._-]+)?$`)

type ExecutionStatus string

const (
	StatusCompleted             ExecutionStatus = "COMPLETED"
	StatusCompletedWithWarnings ExecutionStatus = "COMPLETED_WITH_WARNINGS"
	StatusPartial               ExecutionStatus = "PARTIAL"
	StatusFailed                ExecutionStatus = "FAILED"
	StatusTimedOut              ExecutionStatus = "TIMED_OUT"
	StatusCancelled             ExecutionStatus = "CANCELLED"
)

type OutputMetadata struct {
	AssessmentID   string    `json:"assessment_id"`
	ScannerID      string    `json:"scanner_id"`
	ScannerVersion string    `json:"scanner_version"`
	AdapterVersion string    `json:"adapter_version"`
	RunID          string    `json:"run_id"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	CorrelationID  string    `json:"correlation_id,omitempty"`
}

type RawArtifactReferences struct {
	StdoutRef string `json:"stdout_ref,omitempty"`
	StderrRef string `json:"stderr_ref,omitempty"`
}

// RawPayload remains explicitly untrusted and separate from normalized
// findings. Content is bounded by the worker output cap before construction.
type RawPayload struct {
	Format  string `json:"format"` // "json" or "text"
	Content string `json:"content"`
}

type ExecutionDiagnostic struct {
	Level   string `json:"level"` // info, warning, error
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScannerOutputEnvelope is the versioned adapter result. Findings contain
// normalized finding.v1 objects; raw payload and stream artifacts are kept in
// separate, explicitly untrusted fields.
type ScannerOutputEnvelope struct {
	SchemaVersion   string                     `json:"schema_version"`
	Metadata        OutputMetadata             `json:"metadata"`
	Status          ExecutionStatus            `json:"status"`
	ExitCode        *int                       `json:"exit_code,omitempty"`
	DurationMS      int64                      `json:"duration_ms"`
	Findings        []json.RawMessage          `json:"findings"`
	Diagnostics     []ExecutionDiagnostic      `json:"diagnostics"`
	ScannerMetadata map[string]json.RawMessage `json:"scanner_metadata,omitempty"`
	Partial         bool                       `json:"partial"`
	RawArtifacts    RawArtifactReferences      `json:"raw_artifacts"`
	RawPayload      *RawPayload                `json:"raw_payload,omitempty"`
}

// Result is the common scanner adapter result envelope.
type Result = ScannerOutputEnvelope

// Validate checks envelope invariants and validates every normalized finding.
func (e ScannerOutputEnvelope) Validate() error {
	if e.SchemaVersion != OutputEnvelopeVersion {
		return fmt.Errorf("adapters: unsupported output envelope version %q", e.SchemaVersion)
	}
	if _, err := uuid.Parse(e.Metadata.AssessmentID); err != nil {
		return fmt.Errorf("adapters: output assessment_id must be a UUID")
	}
	if e.Metadata.ScannerID == "" || e.Metadata.ScannerVersion == "" || e.Metadata.AdapterVersion == "" {
		return fmt.Errorf("adapters: output scanner id and versions are required")
	}
	if _, err := uuid.Parse(e.Metadata.RunID); err != nil {
		return fmt.Errorf("adapters: output run_id must be a UUID")
	}
	if e.Metadata.StartedAt.IsZero() || e.Metadata.CompletedAt.IsZero() || e.Metadata.CompletedAt.Before(e.Metadata.StartedAt) {
		return fmt.Errorf("adapters: output timestamps are missing or inconsistent")
	}
	if e.DurationMS < 0 {
		return fmt.Errorf("adapters: duration_ms must not be negative")
	}
	if e.Findings == nil || e.Diagnostics == nil {
		return fmt.Errorf("adapters: findings and diagnostics must be arrays, including when empty")
	}
	switch e.Status {
	case StatusCompleted:
		if e.ExitCode == nil || *e.ExitCode != 0 || e.Partial || hasDiagnostic(e.Diagnostics, "warning") || hasDiagnostic(e.Diagnostics, "error") {
			return fmt.Errorf("adapters: COMPLETED cannot be partial or contain warnings/errors")
		}
	case StatusCompletedWithWarnings:
		if e.ExitCode == nil || *e.ExitCode != 0 || e.Partial || !hasDiagnostic(e.Diagnostics, "warning") || hasDiagnostic(e.Diagnostics, "error") {
			return fmt.Errorf("adapters: COMPLETED_WITH_WARNINGS requires a warning and cannot be partial")
		}
	case StatusPartial:
		if !e.Partial || len(e.Findings) == 0 || !hasDiagnostic(e.Diagnostics, "warning") {
			return fmt.Errorf("adapters: PARTIAL requires partial=true, a finding, and a warning diagnostic")
		}
	case StatusFailed:
		if e.Partial {
			return fmt.Errorf("adapters: FAILED cannot set partial")
		}
		if !hasDiagnostic(e.Diagnostics, "error") {
			return fmt.Errorf("adapters: FAILED requires an error diagnostic")
		}
	case StatusTimedOut:
		if !hasDiagnosticCode(e.Diagnostics, "DEADLINE_EXCEEDED") {
			return fmt.Errorf("adapters: TIMED_OUT requires DEADLINE_EXCEEDED diagnostic")
		}
	case StatusCancelled:
		if !hasDiagnosticCode(e.Diagnostics, "CANCELLED") {
			return fmt.Errorf("adapters: CANCELLED requires CANCELLED diagnostic")
		}
	default:
		return fmt.Errorf("adapters: unknown execution status %q", e.Status)
	}
	for i, finding := range e.Findings {
		if err := ValidateFindings(finding); err != nil {
			return fmt.Errorf("adapters: normalized finding %d is invalid: %w", i, err)
		}
	}
	for _, d := range e.Diagnostics {
		if (d.Level != "info" && d.Level != "warning" && d.Level != "error") || d.Code == "" || d.Message == "" || len(d.Message) > 4096 {
			return fmt.Errorf("adapters: malformed execution diagnostic")
		}
	}
	if err := validateArtifactRef(e.RawArtifacts.StdoutRef); err != nil {
		return err
	}
	if err := validateArtifactRef(e.RawArtifacts.StderrRef); err != nil {
		return err
	}
	if e.RawPayload != nil {
		if e.RawPayload.Format != "json" && e.RawPayload.Format != "text" {
			return fmt.Errorf("adapters: raw payload format must be json or text")
		}
		if len(e.RawPayload.Content) > 1<<20 {
			return fmt.Errorf("adapters: raw payload exceeds 1 MiB envelope limit")
		}
		if e.RawPayload.Format == "json" && !json.Valid([]byte(e.RawPayload.Content)) {
			return fmt.Errorf("adapters: raw JSON payload is malformed")
		}
	}
	for key, value := range e.ScannerMetadata {
		if !strings.Contains(key, ".") || !json.Valid(value) {
			return fmt.Errorf("adapters: scanner metadata must contain named JSON values")
		}
	}
	if metadata, err := json.Marshal(e.ScannerMetadata); err != nil || len(metadata) > 64<<10 {
		return fmt.Errorf("adapters: scanner metadata exceeds 64 KiB or is invalid")
	}
	return nil
}

func hasDiagnostic(diagnostics []ExecutionDiagnostic, level string) bool {
	for _, d := range diagnostics {
		if d.Level == level {
			return true
		}
	}
	return false
}

func hasDiagnosticCode(diagnostics []ExecutionDiagnostic, code string) bool {
	for _, d := range diagnostics {
		if d.Code == code {
			return true
		}
	}
	return false
}

func validateArtifactRef(ref string) error {
	if ref == "" {
		return nil
	}
	if !artifactReferencePattern.MatchString(ref) {
		return fmt.Errorf("adapters: raw artifact reference must be an opaque artifact:// reference")
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "artifact" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Path, "..") {
		return fmt.Errorf("adapters: raw artifact reference must be an opaque artifact:// reference")
	}
	if _, err := uuid.Parse(u.Host); err != nil {
		return fmt.Errorf("adapters: raw artifact reference must contain a UUID")
	}
	return nil
}

// EncodeOutputEnvelope validates before serialization to ensure malformed
// findings or ambiguous completion states never cross the worker boundary.
func EncodeOutputEnvelope(envelope ScannerOutputEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// DecodeOutputEnvelope rejects unknown/trailing data and validates the result.
func DecodeOutputEnvelope(raw []byte) (ScannerOutputEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope ScannerOutputEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return ScannerOutputEnvelope{}, fmt.Errorf("adapters: decode output envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ScannerOutputEnvelope{}, fmt.Errorf("adapters: output envelope contains trailing JSON")
		}
		return ScannerOutputEnvelope{}, fmt.Errorf("adapters: invalid trailing output envelope data: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return ScannerOutputEnvelope{}, err
	}
	return envelope, nil
}
