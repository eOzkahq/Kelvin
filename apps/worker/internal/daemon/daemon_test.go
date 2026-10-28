package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
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
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond}, q, registry)
	}()

	q.inner.Push(queue.Job{ID: "job-1", TenantID: "123e4567-e89b-12d3-a456-426614174000", Type: "nuclei", CorrelationID: "corr-1"})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || q.failed[0].ID != "job-1" {
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
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond}, q, registry)
	}()

	q.inner.Push(queue.Job{ID: "job-2", TenantID: "123e4567-e89b-12d3-a456-426614174000", Type: "stub"})
	time.Sleep(150 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || q.completed[0].ID != "job-2" {
		t.Fatalf("expected job-2 completed, got %+v", q.completed)
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
		done <- Run(ctx, zap.NewNop(), Config{WorkerID: "w-test", PollInterval: 10 * time.Millisecond}, q, registry)
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

type stubAdapter struct{ name string }

func (s stubAdapter) Name() string { return s.name }

func TestWorkerImportsSharedFindingContract(t *testing.T) {
	raw := schemas.MustRead("finding.v1.json")
	if len(raw) == 0 {
		t.Fatal("finding.v1.json must be importable from the worker module")
	}
}
