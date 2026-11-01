// Package adapter defines the canonical Go interface, lifecycle contract,
// and capability model for all KELVIN scanner integrations (Phase 2).
//
// Every built-in engine (HTTP preflight, TLS assessor, headers/cookies) and
// external sandboxed engine (OWASP ZAP Baseline, Nuclei) implements
// ScannerAdapter to ensure uniform initialization, execution, resource bounding,
// health inspection, and lifecycle governance under ADR-0005.
package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Standard sentinel errors returned across adapter lifecycle operations.
var (
	ErrNotInitialized    = errors.New("adapter: scanner adapter is not initialized")
	ErrAlreadyInitialized = errors.New("adapter: scanner adapter is already initialized")
	ErrInvalidConfig     = errors.New("adapter: invalid scanner configuration")
	ErrExecutionFailed   = errors.New("adapter: execution failed")
	ErrExecutionCanceled = errors.New("adapter: execution canceled")
	ErrUnavailable       = errors.New("adapter: scanner engine unavailable")
)

// HealthState classifies the readiness of an adapter and its underlying runtime.
type HealthState string

const (
	HealthStateHealthy     HealthState = "HEALTHY"
	HealthStateDegraded    HealthState = "DEGRADED"
	HealthStateUnavailable HealthState = "UNAVAILABLE"
)

// HealthStatus reports runtime diagnostic health and connectivity.
type HealthStatus struct {
	State     HealthState   `json:"state"`
	Message   string        `json:"message,omitempty"`
	CheckedAt time.Time     `json:"checked_at"`
	Latency   time.Duration `json:"latency"`
	Details   map[string]any `json:"details,omitempty"`
}

// Capabilities describes the operational and protocol envelope of a scanner engine.
type Capabilities struct {
	PassiveOnly          bool     `json:"passive_only"`
	ActiveScanning       bool     `json:"active_scanning"`
	SupportedProtocols   []string `json:"supported_protocols"`
	SupportedTargetTypes []string `json:"supported_target_types"`
	MaxConcurrency       int      `json:"max_concurrency"`
	SupportsCancellation bool     `json:"supports_cancellation"`
	RequiresSandbox      bool     `json:"requires_sandbox"`
}

// Config represents generic scanner-level runtime settings.
type Config struct {
	MaxTimeout    time.Duration   `json:"max_timeout"`
	MaxRateLimit  int             `json:"max_rate_limit"`
	CustomOptions map[string]any  `json:"custom_options,omitempty"`
	RawPayload    json.RawMessage `json:"raw_payload,omitempty"`
}

// ExecutionInput represents the contextual task input passed to Execute.
type ExecutionInput struct {
	TaskID        string          `json:"task_id"`
	AssessmentID  string          `json:"assessment_id"`
	TenantID      string          `json:"tenant_id"`
	CorrelationID string          `json:"correlation_id"`
	Target        string          `json:"target"`
	ProfileID     string          `json:"profile_id"`
	Deadline      time.Duration   `json:"deadline"`
	Config        Config          `json:"config"`
	Params        json.RawMessage `json:"params,omitempty"`
}

// ExecutionStatus enumerates the outcome status of an adapter execution run.
type ExecutionStatus string

const (
	StatusSuccess               ExecutionStatus = "SUCCESS"
	StatusCompletedWithWarnings ExecutionStatus = "COMPLETED_WITH_WARNINGS"
	StatusPartial               ExecutionStatus = "PARTIAL"
	StatusFailed                ExecutionStatus = "FAILED"
	StatusCanceled              ExecutionStatus = "CANCELED"
	StatusTimedOut              ExecutionStatus = "TIMED_OUT"
)

// ExecutionResult captures the output, diagnostics, and findings of an adapter run.
type ExecutionResult struct {
	Status           ExecutionStatus `json:"status"`
	ExitCode         int             `json:"exit_code"`
	Duration         time.Duration   `json:"duration"`
	Stdout           string          `json:"stdout,omitempty"`
	Stderr           string          `json:"stderr,omitempty"`
	Findings         []byte          `json:"findings,omitempty"`
	OOMKilled        bool            `json:"oom_killed"`
	DeadlineExceeded bool            `json:"deadline_exceeded"`
	Partial          bool            `json:"partial"`
	PartialReason    string          `json:"partial_reason,omitempty"`
	Diagnostics      map[string]any  `json:"diagnostics,omitempty"`
}

// ScannerAdapter defines the core contract for all KELVIN security assessment engines.
// All implementations must adhere strictly to ADR-0005 sandboxing and ADR-0002 finding schemas.
type ScannerAdapter interface {
	// Name returns the unique, canonical identifier of the scanner (e.g., "preflight", "tls", "zap", "nuclei").
	Name() string

	// Version returns the engine or adapter version string.
	Version() string

	// Initialize prepares the adapter for execution, binding logging and verifying dependencies.
	Initialize(ctx context.Context, logger *zap.Logger) error

	// ValidateConfig inspects the configuration before execution to prevent out-of-spec parameters.
	ValidateConfig(cfg Config) error

	// Capabilities returns the functional boundaries and supported features of the scanner.
	Capabilities() Capabilities

	// Health reports the operational availability and diagnostic state of the scanner runtime.
	Health(ctx context.Context) HealthStatus

	// Execute runs the assessment within sandboxed isolation, returning structured untrusted findings.
	Execute(ctx context.Context, input ExecutionInput) (ExecutionResult, error)

	// Cancel aborts any running execution cleanly, releasing associated processes or network resources.
	Cancel() error
}

// BaseAdapter provides default scaffolding for adapters to inherit lifecycle state.
type BaseAdapter struct {
	name        string
	version     string
	logger      *zap.Logger
	initialized bool
}

// NewBaseAdapter constructs a BaseAdapter with a name and version.
func NewBaseAdapter(name, version string) BaseAdapter {
	return BaseAdapter{
		name:    name,
		version: version,
	}
}

// Name returns the adapter name.
func (b *BaseAdapter) Name() string {
	return b.name
}

// Version returns the adapter version.
func (b *BaseAdapter) Version() string {
	return b.version
}

// IsInitialized returns true if Initialize has succeeded.
func (b *BaseAdapter) IsInitialized() bool {
	return b.initialized
}

// Logger returns the bound logger or a no-op logger if uninitialized.
func (b *BaseAdapter) Logger() *zap.Logger {
	if b.logger == nil {
		return zap.NewNop()
	}
	return b.logger
}

// MarkInitialized sets the initialized state and binds the logger.
func (b *BaseAdapter) MarkInitialized(logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	b.logger = logger.With(zap.String("adapter", b.name), zap.String("version", b.version))
	b.initialized = true
}

// MarkTerminated resets the initialized state.
func (b *BaseAdapter) MarkTerminated() {
	b.initialized = false
}

// ValidateExecutionInput performs structural and security invariant validation on incoming inputs.
func ValidateExecutionInput(input ExecutionInput) error {
	if input.TaskID == "" {
		return fmt.Errorf("adapter: task_id must not be empty")
	}
	if input.AssessmentID == "" {
		return fmt.Errorf("adapter: assessment_id must not be empty")
	}
	if input.TenantID == "" {
		return fmt.Errorf("adapter: tenant_id must not be empty")
	}
	if input.Target == "" {
		return fmt.Errorf("adapter: target must not be empty")
	}
	if input.ProfileID == "" {
		return fmt.Errorf("adapter: profile_id must not be empty")
	}
	if input.Deadline <= 0 {
		return fmt.Errorf("adapter: execution deadline must be positive")
	}
	return nil
}
