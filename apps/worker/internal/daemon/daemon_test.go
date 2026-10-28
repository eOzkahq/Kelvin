package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	schemas "github.com/kelvin/kelvin/packages/schemas"
	"go.uber.org/zap"
)

type recordingQueue struct {
	inner     *queue.MemoryQueue
	mu        sync.Mutex
	failed    []queue.Job
	completed []queue.Job
}

func (r *recordingQueue) Dequeue(ctx context.Context) (queue.Job, error) {
	return r.inner.Dequeue(ctx)
}

func (r *recordingQueue) Complete(ctx context.Context, job queue.Job) error {
	r.mu.Lock()
	r.completed = append(r.completed, job)
	r.mu.Unlock()
	return r.inner.Complete(ctx, job)
}

func (r *recordingQueue) Fail(ctx context.Context, job queue.Job, reason string) error {
	r.mu.Lock()
	r.failed = append(r.failed, job)
	r.mu.Unlock()
	return r.inner.Fail(ctx, job, reason)
}

func TestRunFailsJobWithoutRegisteredAdapter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: sandbox.NewFake()}, q, registry)
	}()

	q.inner.Push(queue.Job{ID: "11111111-1111-1111-1111-111111111111", TenantID: "123e4567-e89b-12d3-a456-426614174000", Type: "nuclei", CorrelationID: "corr-1"})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("expected job-1 to fail without adapter, got %+v", q.failed)
	}
	if len(q.completed) != 0 {
		t.Fatalf("job without adapter must not complete, got %d", len(q.completed))
	}
}

func TestRunProcessesJobWithRegisteredAdapter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "w-test",
			PollInterval: 10 * time.Millisecond,
			Executor:     sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 0, Findings: validFindingPayload(), Duration: time.Second}),
			Limits:       limits.DefaultLimits(),
		}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "22222222-2222-2222-2222-222222222222",
		AssessmentID: "33333333-3333-3333-3333-333333333333",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         "stub",
		Payload:      []byte(`{"target":"example.com","profile_id":"kelvin.profile.standard.v1","hard_deadline_seconds":600}`),
	})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || q.completed[0].ID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("expected job-2 completed, got %+v", q.completed)
	}
}

type resultAdapter struct {
	name   string
	result adapters.Result
	err    error
}

func (s resultAdapter) Name() string { return s.name }

func (s resultAdapter) Execute(ctx context.Context, t adapters.Task) (adapters.Result, error) {
	return s.result, s.err
}

func validFindingPayload() []byte {
	return []byte(`{
		"schema_version": "1.0",
		"title": "example finding",
		"severity": "INFORMATIONAL",
		"confidence": 0.5,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "example-template"},
		"scanner": {"name": "stub", "adapter_version": "1.0.0"},
		"discovered_at": "2026-10-28T00:00:00Z"
	}`)
}

func TestRunCompletesJobWithValidFindings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
	if err := registry.Register(resultAdapter{name: "stub", result: adapters.Result{
		ExitCode: 0,
		Findings: validFindingPayload(),
		Duration: time.Second,
	}}); err != nil {

    t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "w-test",
			PollInterval: 10 * time.Millisecond,
			Executor:     sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 0, Findings: validFindingPayload(), Duration: time.Second}),
			Limits:       limits.DefaultLimits(),
		}, q, registry)
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: nil}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "33333333-3333-3333-3333-333333333333",
		AssessmentID: "44444444-4444-4444-4444-444444444444",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         "stub",
		Payload:      []byte(`{"target":"example.com","profile_id":"kelvin.profile.standard.v1","hard_deadline_seconds":600}`),
	})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || q.completed[0].ID != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("expected job-3 completed, got %+v", q.completed)
	}
	if len(q.failed) != 0 {
		t.Fatalf("job with valid findings must not fail, got %+v", q.failed)
	}
}

func TestRunFailsJobOnDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
	if err := registry.Register(resultAdapter{name: "stub", result: adapters.Result{
		ExitCode:         -1,
		DeadlineExceeded: true,
		Duration:         30 * time.Second,
	}}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "w-test",
			PollInterval: 10 * time.Millisecond,
			Executor:     sandbox.NewFake().WithResult(sandbox.Result{ExitCode: -1, DeadlineExceeded: true, Duration: 30 * time.Second}),
			Limits:       limits.DefaultLimits(),
		}, q, registry)

    done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: nil}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "44444444-4444-4444-4444-444444444444",
		AssessmentID: "55555555-5555-5555-5555-555555555555",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         "stub",
		Payload:      []byte(`{"target":"example.com","profile_id":"kelvin.profile.standard.v1","hard_deadline_seconds":60}`),
	})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "44444444-4444-4444-4444-444444444444" {
		t.Fatalf("expected job-4 to fail on deadline, got failed=%+v completed=%+v", q.failed, q.completed)
	}
}

func TestRunFailsJobOnOOM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()

  
  if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
	if err := registry.Register(resultAdapter{name: "stub", result: adapters.Result{
		ExitCode:  137,
		OOMKilled: true,
		Duration:  10 * time.Second,
	}}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "w-test",
			PollInterval: 10 * time.Millisecond,
			Executor:     sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 137, OOMKilled: true, Duration: 10 * time.Second}),
			Limits:       limits.DefaultLimits(),
		}, q, registry)
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: nil}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "55555555-5555-5555-5555-555555555555",
		AssessmentID: "66666666-6666-6666-6666-666666666666",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         "stub",
		Payload:      []byte(`{"target":"example.com","profile_id":"kelvin.profile.standard.v1","hard_deadline_seconds":600}`),
	})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "55555555-5555-5555-5555-555555555555" {
		t.Fatalf("expected job-5 to fail on OOM, got failed=%+v", q.failed)
	}
}

func TestRunFailsJobOnInvalidFindings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
	if err := registry.Register(resultAdapter{name: "stub", result: adapters.Result{
		ExitCode: 0,
		Findings: []byte(`{"unknown_field": true}`),
		Duration: time.Second,
	}}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "w-test",
			PollInterval: 10 * time.Millisecond,
			Executor:     sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 0, Findings: []byte(`{"unknown_field": true}`), Duration: time.Second}),
			Limits:       limits.DefaultLimits(),
		}, q, registry)
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: nil}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "66666666-6666-6666-6666-666666666666",
		AssessmentID: "77777777-7777-7777-7777-777777777777",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         "stub",
		Payload:      []byte(`{"target":"example.com","profile_id":"kelvin.profile.standard.v1","hard_deadline_seconds":600}`),
	})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "66666666-6666-6666-6666-666666666666" {
		t.Fatalf("expected job-6 to fail on invalid findings, got failed=%+v", q.failed)
	}
}

func TestRunFailsJobOnScannerCrash(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
	if err := registry.Register(resultAdapter{name: "stub", result: adapters.Result{
		ExitCode: 1,
		Stderr:   "scanner panic",
		Duration: 5 * time.Second,
	}}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "w-test",
			PollInterval: 10 * time.Millisecond,
			Executor:     sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 1, Stderr: "scanner panic", Duration: 5 * time.Second}),
			Limits:       limits.DefaultLimits(),
		}, q, registry)
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: nil}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "77777777-7777-7777-7777-777777777777",
		AssessmentID: "88888888-8888-8888-8888-888888888888",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         "stub",
		Payload:      []byte(`{"target":"example.com","profile_id":"kelvin.profile.standard.v1","hard_deadline_seconds":600}`),
	})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "77777777-7777-7777-7777-777777777777" {
		t.Fatalf("expected job-7 to fail on scanner crash, got failed=%+v", q.failed)
	}
}

func TestRunRejectsJobWithoutTenantContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := &recordingQueue{inner: queue.NewMemoryQueue()}
	registry := adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond, Executor: sandbox.NewFake()}, q, registry)
	}()
	q.inner.Push(queue.Job{ID: "unscoped-job", Type: "stub"})
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "unscoped-job" {
		t.Fatalf("unscoped job wasn't rejected: %+v", q.failed)
	}
	if len(q.completed) != 0 {
		t.Fatalf("unscoped job completed: %+v", q.completed)
	}
}

// fakeExecutor adapts sandbox.FakeExecutor to the sandbox.Executor interface
// used by the daemon.
type fakeExecutor struct {
	inner *sandbox.FakeExecutor
}

func (f *fakeExecutor) Execute(ctx context.Context, spec sandbox.Spec) (*sandbox.Result, error) {
	return f.inner.Execute(ctx, spec)
}

// validFindingPayload returns a finding.v1.json-conformant payload.
func validFindingPayload() []byte {
	return []byte(`{
		"schema_version": "1.0",
		"title": "example finding",
		"severity": "INFORMATIONAL",
		"confidence": 0.5,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "example-template"},
		"scanner": {"name": "stub", "adapter_version": "1.0.0"},
		"discovered_at": "2026-10-28T00:00:00Z"
	}`)
}

type stubAdapter struct{ name string }

func (s stubAdapter) Name() string { return s.name }

func (s stubAdapter) Execute(ctx context.Context, t adapters.Task) (adapters.Result, error) {
	return adapters.Result{
		ExitCode: 0,
		Findings: validFindingPayload(),
		Duration: time.Second,
	}, nil
}

func TestWorkerImportsSharedFindingContract(t *testing.T) {
	raw := schemas.MustRead("finding.v1.json")
	if len(raw) == 0 {
		t.Fatal("finding.v1.json must be importable from the worker module")
	}
}
