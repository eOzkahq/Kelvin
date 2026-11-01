package daemon

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/schemas"
	"go.uber.org/zap"
)

type recordingQueue struct {
	inner     *queue.MemoryQueue
	mu        sync.Mutex
	failed    []queue.Job
	completed []queue.Job
	event     chan struct{}
}

func newRecordingQueue() *recordingQueue {
	return &recordingQueue{inner: queue.NewMemoryQueue(), event: make(chan struct{}, 8)}
}
func (r *recordingQueue) Dequeue(ctx context.Context) (queue.Job, error) { return r.inner.Dequeue(ctx) }
func (r *recordingQueue) Complete(ctx context.Context, j queue.Job) error {
	r.mu.Lock()
	r.completed = append(r.completed, j)
	r.mu.Unlock()
	r.event <- struct{}{}
	return r.inner.Complete(ctx, j)
}
func (r *recordingQueue) Fail(ctx context.Context, j queue.Job, _ string) error {
	r.mu.Lock()
	r.failed = append(r.failed, j)
	r.mu.Unlock()
	r.event <- struct{}{}
	return r.inner.Fail(ctx, j, "failed")
}

type stubAdapter struct{ name string }

func (s stubAdapter) Name() string                                  { return s.name }
func (s stubAdapter) Version() string                               { return "1.0.0" }
func (s stubAdapter) Initialize(context.Context, *zap.Logger) error { return nil }
func (s stubAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (s stubAdapter) Capabilities() adapters.Capabilities {
	return adapters.Capabilities{SupportedTargetTypes: []string{"url"}, CheckCategories: []string{"passive"}}
}
func (s stubAdapter) Execute(context.Context, adapters.Task) (adapters.Result, error) {
	return adapters.Result{}, nil
}
func (s stubAdapter) Cancel() error                { return nil }
func (s stubAdapter) Health(context.Context) error { return nil }
func (s stubAdapter) Result() (adapters.Result, error) {
	return adapters.Result{}, adapters.ErrNoResult
}

func runWorker(t *testing.T, q *recordingQueue, registry *adapters.Registry, executor sandbox.Executor) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "test-worker", PollInterval: time.Millisecond, Executor: executor}, q, registry)
	}()
	return cancel, done
}

func waitEvent(t *testing.T, q *recordingQueue) {
	t.Helper()
	select {
	case <-q.event:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not complete job")
	}
}

func TestRunProcessesRegisteredJob(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
		t.Fatal(err)
	}
	executor := sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 0, Findings: schemas.MustRead("fixtures/positive/nmap.tls-cbc.json"), Duration: time.Second})
	cancel, done := runWorker(t, q, registry, executor)
	q.inner.Push(queue.Job{ID: "22222222-2222-2222-2222-222222222222", AssessmentID: "33333333-3333-3333-3333-333333333333", TenantID: "123e4567-e89b-12d3-a456-426614174000", Type: "stub", Payload: []byte(`{"target":"example.com","profile_id":"standard","hard_deadline_seconds":10}`)})
	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || len(q.failed) != 0 {
		t.Fatalf("completed=%d failed=%d", len(q.completed), len(q.failed))
	}
}

func TestRunRejectsUnknownAdapter(t *testing.T) {
	q := newRecordingQueue()
	cancel, done := runWorker(t, q, adapters.NewRegistry(), sandbox.NewFake())
	q.inner.Push(queue.Job{ID: "11111111-1111-1111-1111-111111111111", TenantID: "123e4567-e89b-12d3-a456-426614174000", Type: "unknown"})
	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 {
		t.Fatalf("expected one failure, got %d", len(q.failed))
	}
}

func TestRunRejectsInvalidTenant(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registry.Register(stubAdapter{name: "stub"}); err != nil {
		t.Fatal(err)
	}
	cancel, done := runWorker(t, q, registry, sandbox.NewFake())
	q.inner.Push(queue.Job{ID: "bad-tenant", Type: "stub"})
	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 {
		t.Fatalf("expected one failure, got %d", len(q.failed))
	}
}
