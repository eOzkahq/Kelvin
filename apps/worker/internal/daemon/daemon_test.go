package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/schemas"
	"go.uber.org/zap"
)

type recordingQueue struct {
	inner         *queue.MemoryQueue
	mu            sync.Mutex
	failed        []queue.Job
	failedReasons []string
	completed     []queue.Job
	event         chan struct{}
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
func (r *recordingQueue) Fail(ctx context.Context, j queue.Job, reason string) error {
	r.mu.Lock()
	r.failed = append(r.failed, j)
	r.failedReasons = append(r.failedReasons, reason)
	r.mu.Unlock()
	r.event <- struct{}{}
	return r.inner.Fail(ctx, j, reason)
}
func (r *recordingQueue) Cancel(ctx context.Context, id string) error {
	return r.inner.Cancel(ctx, id)
}
func (r *recordingQueue) GetStatus(ctx context.Context, id string) (commonqueue.Status, error) {
	return r.inner.GetStatus(ctx, id)
}

type stubAdapter struct{ name string }

func (s stubAdapter) Name() string    { return s.name }
func (s stubAdapter) Version() string { return "1.0.0" }
func (s stubAdapter) VerifyRuntimeVersion(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
	if err := ctx.Err(); err != nil {
		return adapters.RuntimeVersionInfo{}, err
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	return adapters.RuntimeVersionInfo{ScannerVersion: s.Version(), AdapterVersion: s.Version(), ImageReference: "test/scanner@" + digest, ImageDigest: digest, TemplateCatalogVersion: "kelvin.safe.web.v1", TemplateCatalogDigest: digest}, nil
}
func (s stubAdapter) Initialize(context.Context, *zap.Logger) error { return nil }
func (s stubAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (s stubAdapter) Capabilities() adapters.Capabilities {
	return adapters.Capabilities{SupportedTargetTypes: []string{"url"}, CheckCategories: []string{"passive"}, RequiresSandbox: true}
}

func registerStub(registry *adapters.Registry) error {
	adapter := stubAdapter{name: adapters.ScannerNuclei}
	caps := adapter.Capabilities()
	digest := "sha256:" + strings.Repeat("a", 64)
	return registry.RegisterAdapter(adapters.Metadata{
		ID: adapters.ScannerNuclei, DisplayName: "Stub", Version: "1.0.0",
		SupportedTargets: []string{"url"}, Capabilities: caps, ConfigVersion: adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{ScannerVersion: "1.0.0", ImageReference: "test/scanner@" + digest, ImageDigest: digest, TemplateCatalogVersion: "kelvin.safe.web.v1", TemplateCatalogDigest: digest},
	}, func() adapters.ScannerAdapter { return adapter })
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
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}
	executor := sandbox.NewFake().WithResult(sandbox.Result{ExitCode: 0, Findings: schemas.MustRead("fixtures/positive/nmap.tls-cbc.json"), Duration: time.Second})
	cancel, done := runWorker(t, q, registry, executor)
	q.inner.Push(queue.Job{ID: "22222222-2222-2222-2222-222222222222", AssessmentID: "33333333-3333-3333-3333-333333333333", TenantID: "123e4567-e89b-12d3-a456-426614174000", Type: adapters.ScannerNuclei, Payload: []byte(`{"target":"https://example.com","profile_id":"standard","hard_deadline_seconds":10}`)})
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
	if err := registerStub(registry); err != nil {
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

func TestDaemonPreflightReadinessCheckFailure(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	checker := readiness.NewChecker(zap.NewNop())
	checker.RegisterSystemProbe(readiness.FunctionProbe{
		ProbeName:   "broken_system",
		ProbeTarget: "system",
		CheckFn: func(ctx context.Context) readiness.ProbeResult {
			return readiness.ProbeResult{
				Name:   "broken_system",
				Target: "system",
				Status: readiness.StatusUnavailable,
				Error:  "critical dependency missing",
			}
		},
	})

	err := Run(context.Background(), zap.NewNop(), Config{
		WorkerID:         "test-worker",
		PollInterval:     time.Millisecond,
		Executor:         sandbox.NewFake(),
		ReadinessChecker: checker,
	}, q, registry)

	if err == nil {
		t.Fatal("expected Run to fail with pre-flight readiness error, got nil")
	}
}

func TestDaemonRejectsJobWhenScannerNotReady(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	checker := readiness.NewChecker(zap.NewNop())
	// Register scanner as unavailable
	checker.RegisterScannerProbe(adapters.ScannerNuclei, readiness.FunctionProbe{
		ProbeName:   "nuclei_unready",
		ProbeTarget: adapters.ScannerNuclei,
		CheckFn: func(ctx context.Context) readiness.ProbeResult {
			return readiness.ProbeResult{
				Name:   "nuclei_unready",
				Target: adapters.ScannerNuclei,
				Status: readiness.StatusUnavailable,
				Error:  "container image not pulled",
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:         "test-worker",
			PollInterval:     time.Millisecond,
			Executor:         sandbox.NewFake(),
			ReadinessChecker: checker,
		}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "55555555-5555-5555-5555-555555555555",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.com"}`),
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || len(q.completed) != 0 {
		t.Fatalf("expected job to fail due to unready scanner: completed=%d failed=%d", len(q.completed), len(q.failed))
	}
}

func TestDaemonCancelsRunningJobViaQueueStatus(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	fake := sandbox.NewFake()
	fake.Delay = 100 * time.Millisecond // simulate active work

	cancel, done := runWorker(t, q, registry, fake)

	jobID := "66666666-6666-6666-6666-666666666666"
	q.inner.Push(queue.Job{
		ID:           jobID,
		AssessmentID: "77777777-7777-7777-7777-777777777777",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.com","profile_id":"standard","hard_deadline_seconds":10}`),
	})

	// Cancel job via queue status while worker is executing
	time.Sleep(20 * time.Millisecond)
	if err := q.Cancel(context.Background(), jobID); err != nil {
		t.Fatalf("failed to cancel job: %v", err)
	}

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || len(q.completed) != 0 {
		t.Fatalf("expected job to fail with cancellation: completed=%d failed=%d", len(q.completed), len(q.failed))
	}
	if len(q.failedReasons) == 0 || !strings.Contains(q.failedReasons[0], "execution cancelled") {
		t.Fatalf("expected reason 'execution cancelled', got %v", q.failedReasons)
	}
}
