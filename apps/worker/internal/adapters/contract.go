package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// Capabilities declares the checks and operational bounds an adapter supports.
// These declarations are descriptive; the worker and sandbox remain the
// enforcement boundary for scope, request pacing, resources, and deadlines.
type Capabilities struct {
	CheckCategories []string
	RequiresNetwork bool
	SupportsCancel  bool
	MaxRequestRate  int
	MaxRequests     int
}

// ScannerAdapter is the lifecycle contract for scanner implementations.
// Initialize is called once before registration/use. ValidateConfig must fail
// closed on unknown or unsupported options. Execute runs one validated task;
// callers must pass the worker's deadline-bearing context. Cancel is an
// immediate best-effort cancellation signal for the active execution.
// Result returns the last completed execution result, or ErrNoResult.
// Implementations must not access persistence directly.
type ScannerAdapter interface {
	Adapter
	Initialize(context.Context, *zap.Logger) error
	ValidateConfig(json.RawMessage) error
	Capabilities() Capabilities
	Execute(context.Context, Task) (Result, error)
	Cancel() error
	Health(context.Context) error
	Result() (Result, error)
}

var ErrNoResult = errors.New("adapters: no execution result available")

// Runner is the narrow execution dependency used by ReferenceAdapter. A
// production runner should delegate external binaries to sandbox.Executor.
type Runner func(context.Context, Task) (Result, error)

// ReferenceAdapter demonstrates the lifecycle contract and serializes access
// to its current execution. It contains no database or unrestricted network
// client; the runner receives only the validated Task and bounded context.
type ReferenceAdapter struct {
	AdapterName string
	Caps        Capabilities
	Run         Runner

	mu        sync.Mutex
	cancel    context.CancelFunc
	result    Result
	hasResult bool
	ready     bool
}

func (a *ReferenceAdapter) Name() string { return a.AdapterName }

func (a *ReferenceAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a == nil || a.AdapterName == "" || a.Run == nil {
		return fmt.Errorf("adapters: reference adapter requires a name and runner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if logger == nil {
		return fmt.Errorf("adapters: logger must not be nil")
	}
	a.mu.Lock()
	a.ready = true
	a.mu.Unlock()
	return nil
}

func (a *ReferenceAdapter) ValidateConfig(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		_, err := DefaultScannerConfig(a.AdapterName)
		if err == nil {
			return nil
		}
		return nil // non-MVP reference adapters may define their own config contract
	}
	if _, err := DefaultScannerConfig(a.AdapterName); err == nil {
		config, err := DecodeScannerConfig(raw)
		if err != nil {
			return err
		}
		if config.ScannerID != a.AdapterName {
			return fmt.Errorf("adapters: scanner config id does not match adapter name")
		}
		return nil
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("adapters: config must be a JSON object: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("adapters: config must be a JSON object")
	}
	return nil
}

func (a *ReferenceAdapter) Capabilities() Capabilities {
	caps := a.Caps
	caps.CheckCategories = append([]string(nil), caps.CheckCategories...)
	return caps
}

func (a *ReferenceAdapter) Execute(ctx context.Context, task Task) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	a.mu.Lock()
	if !a.ready {
		a.mu.Unlock()
		return Result{}, fmt.Errorf("adapters: adapter %q is not initialized", a.AdapterName)
	}
	if a.cancel != nil {
		a.mu.Unlock()
		return Result{}, fmt.Errorf("adapters: adapter %q is already executing", a.AdapterName)
	}
	execCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.mu.Unlock()

	result, err := a.Run(execCtx, task)
	cancel()
	if err == nil {
		err = result.Validate()
	}
	a.mu.Lock()
	a.cancel = nil
	if err == nil {
		a.result = result
		a.hasResult = true
	}
	a.mu.Unlock()
	return result, err
}

func (a *ReferenceAdapter) Cancel() error {
	a.mu.Lock()
	cancel := a.cancel
	a.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	return nil
}

func (a *ReferenceAdapter) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.ready {
		return fmt.Errorf("adapters: adapter %q is not initialized", a.AdapterName)
	}
	return nil
}

func (a *ReferenceAdapter) Result() (Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.hasResult {
		return Result{}, ErrNoResult
	}
	result := a.result
	result.Findings = cloneRawMessages(result.Findings)
	result.Diagnostics = append([]ExecutionDiagnostic(nil), result.Diagnostics...)
	if result.ExitCode != nil {
		code := *result.ExitCode
		result.ExitCode = &code
	}
	if result.RawPayload != nil {
		payload := *result.RawPayload
		result.RawPayload = &payload
	}
	if result.ScannerMetadata != nil {
		metadata := make(map[string]json.RawMessage, len(result.ScannerMetadata))
		for key, value := range result.ScannerMetadata {
			metadata[key] = append(json.RawMessage(nil), value...)
		}
		result.ScannerMetadata = metadata
	}
	return result, nil
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	cloned := make([]json.RawMessage, len(values))
	for i, value := range values {
		cloned[i] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

var _ ScannerAdapter = (*ReferenceAdapter)(nil)
