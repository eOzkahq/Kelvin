package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

func validExecutionInput() ExecutionInput {
	return ExecutionInput{
		TaskID:        "task-123",
		AssessmentID:  "assess-456",
		TenantID:      "tenant-789",
		CorrelationID: "corr-abc",
		Target:        "https://example.com",
		ProfileID:     "standard",
		Deadline:      5 * time.Second,
		Config: Config{
			MaxTimeout:   10 * time.Second,
			MaxRateLimit: 50,
		},
	}
}

func TestReferenceAdapterInterfaceCompliance(t *testing.T) {
	var a ScannerAdapter = NewReferenceAdapter()
	if a.Name() != "reference" {
		t.Fatalf("expected name 'reference', got %q", a.Name())
	}
	if a.Version() != "1.0.0" {
		t.Fatalf("expected version '1.0.0', got %q", a.Version())
	}
}

func TestReferenceAdapterLifecycle(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	a := NewReferenceAdapter()

	// Initial health should report unavailable before initialization
	h := a.Health(ctx)
	if h.State != HealthStateUnavailable {
		t.Fatalf("expected UNAVAILABLE prior to init, got %s", h.State)
	}

	// Execution prior to init must fail closed
	_, err := a.Execute(ctx, validExecutionInput())
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got %v", err)
	}

	// Initialize adapter
	if err := a.Initialize(ctx, logger); err != nil {
		t.Fatalf("failed to initialize adapter: %v", err)
	}

	// Repeated initialization must error
	if err := a.Initialize(ctx, logger); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}

	// Health should now be healthy
	h = a.Health(ctx)
	if h.State != HealthStateHealthy {
		t.Fatalf("expected HEALTHY post-init, got %s", h.State)
	}

	// Capabilities inspection
	caps := a.Capabilities()
	if !caps.PassiveOnly {
		t.Fatalf("expected passive_only=true")
	}
	if caps.ActiveScanning {
		t.Fatalf("expected active_scanning=false")
	}
	if caps.MaxConcurrency <= 0 {
		t.Fatalf("expected positive concurrency, got %d", caps.MaxConcurrency)
	}

	// Execute valid input
	res, err := a.Execute(ctx, validExecutionInput())
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if res.Status != StatusSuccess {
		t.Fatalf("expected status SUCCESS, got %s", res.Status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
}

func TestReferenceAdapterExecutionInputValidation(t *testing.T) {
	ctx := context.Background()
	a := NewReferenceAdapter()
	_ = a.Initialize(ctx, zap.NewNop())

	cases := []struct {
		name      string
		mutate    func(*ExecutionInput)
		shouldErr bool
	}{
		{
			name:      "valid input",
			mutate:    func(i *ExecutionInput) {},
			shouldErr: false,
		},
		{
			name:      "missing task_id",
			mutate:    func(i *ExecutionInput) { i.TaskID = "" },
			shouldErr: true,
		},
		{
			name:      "missing assessment_id",
			mutate:    func(i *ExecutionInput) { i.AssessmentID = "" },
			shouldErr: true,
		},
		{
			name:      "missing tenant_id",
			mutate:    func(i *ExecutionInput) { i.TenantID = "" },
			shouldErr: true,
		},
		{
			name:      "missing target",
			mutate:    func(i *ExecutionInput) { i.Target = "" },
			shouldErr: true,
		},
		{
			name:      "missing profile_id",
			mutate:    func(i *ExecutionInput) { i.ProfileID = "" },
			shouldErr: true,
		},
		{
			name:      "non-positive deadline",
			mutate:    func(i *ExecutionInput) { i.Deadline = 0 },
			shouldErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validExecutionInput()
			tc.mutate(&input)
			_, err := a.Execute(ctx, input)
			if (err != nil) != tc.shouldErr {
				t.Fatalf("case %s: got error %v, shouldErr=%v", tc.name, err, tc.shouldErr)
			}
		})
	}
}

func TestReferenceAdapterCancellation(t *testing.T) {
	ctx := context.Background()
	a := NewReferenceAdapter()
	_ = a.Initialize(ctx, zap.NewNop())

	// Cancel adapter
	if err := a.Cancel(); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}

	res, err := a.Execute(ctx, validExecutionInput())
	if !errors.Is(err, ErrExecutionCanceled) {
		t.Fatalf("expected ErrExecutionCanceled, got %v", err)
	}
	if res.Status != StatusCanceled {
		t.Fatalf("expected status CANCELED, got %s", res.Status)
	}
}

func TestReferenceAdapterDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled upfront

	a := NewReferenceAdapter()
	_ = a.Initialize(ctx, zap.NewNop())

	res, err := a.Execute(ctx, validExecutionInput())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if res.Status != StatusCanceled {
		t.Fatalf("expected status CANCELED, got %s", res.Status)
	}
}
