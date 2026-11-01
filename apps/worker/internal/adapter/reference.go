package adapter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ReferenceAdapter serves as the canonical reference implementation of ScannerAdapter,
// demonstrating expected lifecycle handling, health reporting, configuration validation,
// and graceful cancellation.
type ReferenceAdapter struct {
	BaseAdapter
	mu       sync.Mutex
	canceled bool
}

// NewReferenceAdapter creates an uninitialized ReferenceAdapter instance.
func NewReferenceAdapter() *ReferenceAdapter {
	return &ReferenceAdapter{
		BaseAdapter: NewBaseAdapter("reference", "1.0.0"),
	}
}

// Initialize binds the logger and verifies readiness.
func (r *ReferenceAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.IsInitialized() {
		return ErrAlreadyInitialized
	}
	r.MarkInitialized(logger)
	r.canceled = false
	r.Logger().Info("reference adapter initialized")
	return nil
}

// ValidateConfig verifies that limits and custom options fall within acceptable bounds.
func (r *ReferenceAdapter) ValidateConfig(cfg Config) error {
	if cfg.MaxTimeout < 0 {
		return fmt.Errorf("%w: max_timeout cannot be negative", ErrInvalidConfig)
	}
	if cfg.MaxRateLimit < 0 {
		return fmt.Errorf("%w: max_rate_limit cannot be negative", ErrInvalidConfig)
	}
	return nil
}

// Capabilities declares the feature set and constraints of the reference adapter.
func (r *ReferenceAdapter) Capabilities() Capabilities {
	return Capabilities{
		PassiveOnly:          true,
		ActiveScanning:       false,
		SupportedProtocols:   []string{"http", "https"},
		SupportedTargetTypes: []string{"hostname", "ipv4", "url"},
		MaxConcurrency:       5,
		SupportsCancellation: true,
		RequiresSandbox:      false,
	}
}

// Health checks the runtime status of the reference adapter.
func (r *ReferenceAdapter) Health(ctx context.Context) HealthStatus {
	start := time.Now()
	if !r.IsInitialized() {
		return HealthStatus{
			State:     HealthStateUnavailable,
			Message:   "adapter not initialized",
			CheckedAt: time.Now(),
			Latency:   time.Since(start),
		}
	}

	return HealthStatus{
		State:     HealthStateHealthy,
		Message:   "ready",
		CheckedAt: time.Now(),
		Latency:   time.Since(start),
	}
}

// Execute performs mock scanning operations while honoring cancellation and timeouts.
func (r *ReferenceAdapter) Execute(ctx context.Context, input ExecutionInput) (ExecutionResult, error) {
	if !r.IsInitialized() {
		return ExecutionResult{Status: StatusFailed}, ErrNotInitialized
	}

	if err := ValidateExecutionInput(input); err != nil {
		return ExecutionResult{Status: StatusFailed}, err
	}

	if err := r.ValidateConfig(input.Config); err != nil {
		return ExecutionResult{Status: StatusFailed}, err
	}

	start := time.Now()
	r.Logger().Info("starting execution",
		zap.String("task_id", input.TaskID),
		zap.String("target", input.Target),
	)

	select {
	case <-ctx.Done():
		r.mu.Lock()
		r.canceled = true
		r.mu.Unlock()
		return ExecutionResult{
			Status:           StatusCanceled,
			Duration:         time.Since(start),
			DeadlineExceeded: errors.Is(ctx.Err(), context.DeadlineExceeded),
		}, ctx.Err()
	default:
	}

	r.mu.Lock()
	if r.canceled {
		r.mu.Unlock()
		return ExecutionResult{
			Status:   StatusCanceled,
			Duration: time.Since(start),
		}, ErrExecutionCanceled
	}
	r.mu.Unlock()

	return ExecutionResult{
		Status:   StatusSuccess,
		ExitCode: 0,
		Duration: time.Since(start),
		Stdout:   "reference scan executed successfully",
		Findings: []byte(`{"findings":[]}`),
	}, nil
}

// Cancel signals execution termination.
func (r *ReferenceAdapter) Cancel() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canceled = true
	if r.IsInitialized() {
		r.Logger().Info("execution cancellation requested")
	}
	return nil
}

// Ensure ReferenceAdapter conforms to the ScannerAdapter interface.
var _ ScannerAdapter = (*ReferenceAdapter)(nil)
