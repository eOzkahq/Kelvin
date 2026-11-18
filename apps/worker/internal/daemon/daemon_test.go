package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/concurrency"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/scope"
	"github.com/kelvin/kelvin/packages/schemas"
	"go.uber.org/zap"
)

type testMockResolver struct {
	fallback scope.Resolver
}

func (r testMockResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	switch host {
	case "approved.example.com", "scanner-mock.kelvin.internal", "example.test", "scan.example.com":
		return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
	}
	if strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".example.com") {
		return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
	}
	return r.fallback.LookupNetIP(ctx, network, host)
}

func init() {
	scope.DefaultResolver = testMockResolver{fallback: net.DefaultResolver}
}

type recordingQueue struct {
	inner          *queue.MemoryQueue
	mu             sync.Mutex
	failed         []queue.Job
	failedReasons  []string
	completed      []queue.Job
	leasesAcquired int
	event          chan struct{}
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
func (r *recordingQueue) AcquireLease(ctx context.Context, jobID string, ttl time.Duration) (bool, error) {
	r.mu.Lock()
	r.leasesAcquired++
	r.mu.Unlock()
	return r.inner.AcquireLease(ctx, jobID, ttl)
}
func (r *recordingQueue) RenewLease(ctx context.Context, jobID string, ttl time.Duration) error {
	return r.inner.RenewLease(ctx, jobID, ttl)
}
func (r *recordingQueue) ReleaseLease(ctx context.Context, jobID string) error {
	return r.inner.ReleaseLease(ctx, jobID)
}
func (r *recordingQueue) IsLeaseActive(ctx context.Context, jobID string) (bool, string, error) {
	return r.inner.IsLeaseActive(ctx, jobID)
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

func TestDaemonRejectsJobWhenConcurrencySaturated(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	policy := concurrency.Policy{
		GlobalLimit:     1,
		PerTenantLimit:  1,
		DefaultLeaseTTL: time.Minute,
		WaitTimeout:     50 * time.Millisecond,
	}
	ctrl, err := concurrency.NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	// Saturate global slot
	_, err = ctrl.TryAcquire(context.Background(), concurrency.Request{
		JobID:    "existing-job",
		TenantID: "existing-tenant",
		Scanner:  "nuclei",
	})
	if err != nil {
		t.Fatal(err)
	}

	metricsReg := metrics.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:              "test-worker",
			PollInterval:          time.Millisecond,
			Executor:              sandbox.NewFake(),
			Metrics:               metricsReg,
			ConcurrencyController: ctrl,
		}, q, registry)
	}()

	q.inner.Push(queue.Job{
		ID:           "88888888-8888-8888-8888-888888888888",
		AssessmentID: "99999999-9999-9999-9999-999999999999",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.com","profile_id":"standard","hard_deadline_seconds":10}`),
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || len(q.completed) != 0 {
		t.Fatalf("expected job to fail due to concurrency saturation: completed=%d failed=%d", len(q.completed), len(q.failed))
	}
	if len(q.failedReasons) == 0 || !strings.Contains(q.failedReasons[0], "concurrency capacity unavailable") {
		t.Fatalf("expected failure reason 'concurrency capacity unavailable', got %v", q.failedReasons)
	}

	snap := metricsReg.Snapshot()
	if snap.ResourceViolations[metrics.ViolationConcurrency] != 1 {
		t.Fatalf("expected 1 ViolationConcurrency metric, got %d", snap.ResourceViolations[metrics.ViolationConcurrency])
	}
}

func TestDaemonAcquiresAndReleasesSlotOnSuccess(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	policy := concurrency.Policy{
		GlobalLimit:     1,
		PerTenantLimit:  1,
		DefaultLeaseTTL: time.Minute,
		WaitTimeout:     100 * time.Millisecond,
	}
	ctrl, err := concurrency.NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:              "test-worker",
			PollInterval:          time.Millisecond,
			Executor:              sandbox.NewFake(),
			ConcurrencyController: ctrl,
		}, q, registry)
	}()

	jobID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	q.inner.Push(queue.Job{
		ID:           jobID,
		AssessmentID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.com","profile_id":"standard","hard_deadline_seconds":10}`),
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 {
		t.Fatalf("expected 1 completed job, got %d", len(q.completed))
	}

	// Verify that the concurrency lease was released
	snap, _ := ctrl.Snapshot(context.Background())
	if snap.Global.Active != 0 {
		t.Fatalf("expected 0 active slots after job completed, got %d", snap.Global.Active)
	}
}

func TestDaemonCanaryOnlyPolicy(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{
			WorkerID:     "canary-worker",
			PollInterval: time.Millisecond,
			Executor:     sandbox.NewFake(),
			CanaryOnly:   true,
			CanaryAllowedTargets: []string{
				"scanner-mock.kelvin.internal",
				"mock-target.kelvin.internal",
			},
		}, q, registry)
	}()

	// 1. Enqueue job with unauthorized external target
	unauthorizedJob := queue.Job{
		ID:           "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://production-target.com","profile_id":"standard","hard_deadline_seconds":10}`),
	}
	q.inner.Push(unauthorizedJob)
	waitEvent(t, q)

	q.mu.Lock()
	if len(q.failed) != 1 {
		t.Fatalf("expected 1 failed job for unauthorized canary target, got %d", len(q.failed))
	}
	if !strings.Contains(q.failedReasons[0], "rejected by canary-only execution policy") {
		t.Errorf("unexpected failure reason: %s", q.failedReasons[0])
	}
	q.mu.Unlock()

	// 2. Enqueue job with allowed canary target
	authorizedJob := queue.Job{
		ID:           "33333333-3333-3333-3333-333333333333",
		AssessmentID: "44444444-4444-4444-4444-444444444444",
		TenantID:     "123e4567-e89b-12d3-a456-426614174000",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://scanner-mock.kelvin.internal/vulnerable","profile_id":"standard","hard_deadline_seconds":10}`),
	}
	q.inner.Push(authorizedJob)
	waitEvent(t, q)

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 {
		t.Fatalf("expected 1 completed canary job, got %d", len(q.completed))
	}
	if q.completed[0].ID != authorizedJob.ID {
		t.Errorf("expected completed job ID %s, got %s", authorizedJob.ID, q.completed[0].ID)
	}
}

func TestDaemon_DistributedLeasePreventsDuplicateExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := adapters.NewRegistry()
	if err := registerStub(reg); err != nil {
		t.Fatalf("failed to register stub: %v", err)
	}

	q := newRecordingQueue()
	jobID := "job-duplicate-lease-test"
	activeJob := queue.Job{
		ID:           jobID,
		AssessmentID: "123e4567-e89b-12d3-a456-426614174001",
		TenantID:     "123e4567-e89b-12d3-a456-426614174002",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.test","profile_id":"standard","hard_deadline_seconds":5}`),
	}

	// 1. Another worker already acquired the lease
	acquired, err := q.AcquireLease(ctx, jobID, 10*time.Second)
	if err != nil || !acquired {
		t.Fatalf("setup: failed to pre-acquire lease: %v", err)
	}

	// 2. Run process() directly with a competing worker context
	cfg := Config{
		WorkerID:       "competing-worker-2",
		HeartbeatEvery: 5 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		process(ctx, zap.NewNop(), q, reg, activeJob, cfg)
		close(done)
	}()

	select {
	case <-done:
		// Succeeded in skipping without executing
	case <-time.After(2 * time.Second):
		t.Fatal("process did not exit promptly when lease was held by another worker")
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) > 0 {
		t.Fatalf("expected 0 completed jobs due to lease collision, got %d", len(q.completed))
	}
	if len(q.failed) > 0 {
		t.Fatalf("expected 0 failed jobs (silent skip on duplicate), got %d: %v", len(q.failed), q.failedReasons)
	}
}

func TestDaemon_RejectsExpiredJobEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := adapters.NewRegistry()
	if err := registerStub(reg); err != nil {
		t.Fatalf("failed to register stub: %v", err)
	}

	q := newRecordingQueue()
	jobID := "123e4567-e89b-12d3-a456-426614174099"
	expiredEnv := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        "123e4567-e89b-12d3-a456-426614174001",
		TenantID:            "123e4567-e89b-12d3-a456-426614174002",
		TargetAddress:       "https://example.test",
		ScanProfile:         "standard",
		RequestedScanners:   []string{adapters.ScannerNuclei},
		HardDeadlineSeconds: 10,
		CreatedAt:           time.Now().UTC().Add(-1 * time.Hour),
		ExpiresAt:           time.Now().UTC().Add(-10 * time.Minute), // expired
		CorrelationID:       "corr-expired-test",
	}
	payloadBytes, _ := json.Marshal(expiredEnv)

	job := queue.Job{
		Version:       2,
		ID:            jobID,
		AssessmentID:  expiredEnv.AssessmentID,
		TenantID:      expiredEnv.TenantID,
		CorrelationID: expiredEnv.CorrelationID,
		Type:          adapters.ScannerNuclei,
		Payload:       payloadBytes,
	}

	cfg := Config{
		WorkerID:       "worker-expired-test",
		HeartbeatEvery: 5 * time.Second,
	}

	process(ctx, zap.NewNop(), q, reg, job, cfg)

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) > 0 {
		t.Fatalf("expected 0 completed jobs for expired envelope, got %d", len(q.completed))
	}
	if len(q.failed) != 1 {
		t.Fatalf("expected 1 failed job for expired envelope, got %d", len(q.failed))
	}
	if !strings.Contains(q.failedReasons[0], "expired") {
		t.Errorf("expected failure reason to contain 'expired', got %q", q.failedReasons[0])
	}
}

func TestDaemon_ResourceViolationMetrics_OOM_PIDs_Deadline(t *testing.T) {
	ctx := context.Background()

	jobID := "123e4567-e89b-12d3-a456-426614174091"
	job := queue.Job{
		Version:      2,
		ID:           jobID,
		AssessmentID: "123e4567-e89b-12d3-a456-426614174001",
		TenantID:     "123e4567-e89b-12d3-a456-426614174002",
		Type:         adapters.ScannerNuclei,
	}
	task := adapters.Task{
		JobID:        job.ID,
		TenantID:     job.TenantID,
		AssessmentID: job.AssessmentID,
		Target:       "https://example.test",
	}

	// Case 1: OOM violation
	{
		q := newRecordingQueue()
		metricsReg := metrics.NewRegistry()
		cfg := Config{WorkerID: "worker-oom-test", Metrics: metricsReg}
		result := &sandbox.Result{ExitCode: 137, OOMKilled: true}
		execErr := errors.New("container out of memory")

		processResult(zap.NewNop(), q, job, task, result, execErr, ctx, cfg)

		snap := metricsReg.Snapshot()
		if snap.ResourceViolations[metrics.ViolationOOM] != 1 {
			t.Errorf("expected 1 ViolationOOM, got %d", snap.ResourceViolations[metrics.ViolationOOM])
		}
		if snap.Terminations[metrics.CauseOOM] != 1 {
			t.Errorf("expected 1 CauseOOM, got %d", snap.Terminations[metrics.CauseOOM])
		}
		if len(q.failed) != 1 || !strings.Contains(q.failedReasons[0], "out of memory") {
			t.Errorf("expected failure reason 'out of memory', got %v", q.failedReasons)
		}
	}

	// Case 2: PIDs exhaustion violation
	{
		q := newRecordingQueue()
		metricsReg := metrics.NewRegistry()
		cfg := Config{WorkerID: "worker-pid-test", Metrics: metricsReg}
		result := &sandbox.Result{ExitCode: 1, PIDLimitExceeded: true}
		execErr := errors.New("fork failed: resource temporarily unavailable")

		processResult(zap.NewNop(), q, job, task, result, execErr, ctx, cfg)

		snap := metricsReg.Snapshot()
		if snap.ResourceViolations[metrics.ViolationPIDs] != 1 {
			t.Errorf("expected 1 ViolationPIDs, got %d", snap.ResourceViolations[metrics.ViolationPIDs])
		}
		if len(q.failed) != 1 || !strings.Contains(q.failedReasons[0], "pids exhausted") {
			t.Errorf("expected failure reason containing 'pids exhausted', got %v", q.failedReasons)
		}
	}

	// Case 3: Execution deadline violation
	{
		q := newRecordingQueue()
		metricsReg := metrics.NewRegistry()
		cfg := Config{WorkerID: "worker-deadline-test", Metrics: metricsReg}
		result := &sandbox.Result{ExitCode: -1, DeadlineExceeded: true}

		processResult(zap.NewNop(), q, job, task, result, sandbox.ErrDeadlineExceeded, ctx, cfg)

		snap := metricsReg.Snapshot()
		if snap.ResourceViolations[metrics.ViolationDeadline] != 1 {
			t.Errorf("expected 1 ViolationDeadline, got %d", snap.ResourceViolations[metrics.ViolationDeadline])
		}
		if snap.Terminations[metrics.CauseDeadline] != 1 {
			t.Errorf("expected 1 CauseDeadline, got %d", snap.Terminations[metrics.CauseDeadline])
		}
		if len(q.failed) != 1 || !strings.Contains(q.failedReasons[0], "deadline exceeded") {
			t.Errorf("expected failure reason containing 'deadline exceeded', got %v", q.failedReasons)
		}
	}
}

func TestDaemon_PreExecutionScopeAndSSRFGuard(t *testing.T) {
	ctx := context.Background()
	reg := adapters.NewRegistry()
	if err := registerStub(reg); err != nil {
		t.Fatalf("failed to register stub: %v", err)
	}
	if err := reg.Initialize(ctx, zap.NewNop()); err != nil {
		t.Fatalf("failed to initialize registry: %v", err)
	}

	// Case 1: Prohibited loopback target fails closed before execution
	{
		q := newRecordingQueue()
		metricsReg := metrics.NewRegistry()
		cfg := Config{
			WorkerID: "worker-ssrf-test",
			Metrics:  metricsReg,
		}

		jobID := "123e4567-e89b-12d3-a456-426614174095"
		env := commonqueue.JobEnvelope{
			SchemaVersion:       2,
			JobID:               jobID,
			AssessmentID:        "123e4567-e89b-12d3-a456-426614174001",
			TenantID:            "123e4567-e89b-12d3-a456-426614174002",
			TargetAddress:       "http://127.0.0.1:8080/internal",
			ScanProfile:         "standard",
			RequestedScanners:   []string{adapters.ScannerNuclei},
			HardDeadlineSeconds: 30,
			CreatedAt:           time.Now().UTC(),
			ExpiresAt:           time.Now().UTC().Add(time.Hour),
		}
		payload, _ := json.Marshal(env)
		job := queue.Job{
			Version:       2,
			ID:            jobID,
			AssessmentID:  env.AssessmentID,
			TenantID:      env.TenantID,
			Type:          adapters.ScannerNuclei,
			Payload:       payload,
		}

		process(ctx, zap.NewNop(), q, reg, job, cfg)

		q.mu.Lock()
		failedCount := len(q.failed)
		var failedReason string
		if failedCount > 0 {
			failedReason = q.failedReasons[0]
		}
		q.mu.Unlock()

		if failedCount != 1 {
			t.Fatalf("expected 1 failed job on prohibited target, got %d", failedCount)
		}
		if !strings.Contains(failedReason, "scope validation failed") && !strings.Contains(failedReason, "prohibited") {
			t.Errorf("expected failure reason mentioning scope/prohibited, got %q", failedReason)
		}

		snap := metricsReg.Snapshot()
		if snap.ResourceViolations[metrics.ViolationNetwork] != 1 {
			t.Errorf("expected 1 ViolationNetwork metric, got %d", snap.ResourceViolations[metrics.ViolationNetwork])
		}
		if snap.Terminations[metrics.CauseNetwork] != 1 {
			t.Errorf("expected 1 CauseNetwork termination metric, got %d", snap.Terminations[metrics.CauseNetwork])
		}
	}

	// Case 2: Out of scope domain rejected by ScopePolicyProvider
	{
		q := newRecordingQueue()
		metricsReg := metrics.NewRegistry()
		scopedPolicy, _ := scope.NewPolicy([]string{"authorized.example.com"}, nil, nil)
		cfg := Config{
			WorkerID: "worker-scope-test",
			Metrics:  metricsReg,
			ScopePolicyProvider: func(context.Context, adapters.Task) (scope.Policy, error) {
				return scopedPolicy, nil
			},
		}

		jobID := "123e4567-e89b-12d3-a456-426614174096"
		env := commonqueue.JobEnvelope{
			SchemaVersion:       2,
			JobID:               jobID,
			AssessmentID:        "123e4567-e89b-12d3-a456-426614174001",
			TenantID:            "123e4567-e89b-12d3-a456-426614174002",
			TargetAddress:       "https://unauthorized.target.com",
			ScanProfile:         "standard",
			RequestedScanners:   []string{adapters.ScannerNuclei},
			HardDeadlineSeconds: 30,
			CreatedAt:           time.Now().UTC(),
			ExpiresAt:           time.Now().UTC().Add(time.Hour),
		}
		payload, _ := json.Marshal(env)
		job := queue.Job{
			Version:       2,
			ID:            jobID,
			AssessmentID:  env.AssessmentID,
			TenantID:      env.TenantID,
			Type:          adapters.ScannerNuclei,
			Payload:       payload,
		}

		process(ctx, zap.NewNop(), q, reg, job, cfg)

		q.mu.Lock()
		failedCount := len(q.failed)
		var failedReason string
		if failedCount > 0 {
			failedReason = q.failedReasons[0]
		}
		q.mu.Unlock()

		if failedCount != 1 {
			t.Fatalf("expected 1 failed job on out-of-scope target, got %d", failedCount)
		}
		if !strings.Contains(failedReason, "outside approved scope") && !strings.Contains(failedReason, "scope validation failed") {
			t.Errorf("expected failure reason mentioning outside approved scope, got %q", failedReason)
		}

		snap := metricsReg.Snapshot()
		if snap.ResourceViolations[metrics.ViolationNetwork] != 1 {
			t.Errorf("expected 1 ViolationNetwork metric, got %d", snap.ResourceViolations[metrics.ViolationNetwork])
		}
		if snap.Terminations[metrics.CauseNetwork] != 1 {
			t.Errorf("expected 1 CauseNetwork termination metric, got %d", snap.Terminations[metrics.CauseNetwork])
		}
	}
}

func TestDaemon_RefusesLeaseForUnavailableScanner(t *testing.T) {
	ctx := context.Background()

	reg := adapters.NewRegistry()
	if err := registerStub(reg); err != nil {
		t.Fatalf("failed to register stub: %v", err)
	}

	checker := readiness.NewChecker(zap.NewNop())
	// Register probe that fails (e.g. scanner container image not present on host)
	checker.RegisterScannerProbe(adapters.ScannerNuclei, readiness.FunctionProbe{
		ProbeName:   "nuclei_image",
		ProbeTarget: adapters.ScannerNuclei,
		CheckFn: func(ctx context.Context) readiness.ProbeResult {
			return readiness.ProbeResult{
				Name:    "nuclei_image",
				Target:  adapters.ScannerNuclei,
				Status:  readiness.StatusUnavailable,
				Message: "container image is not present on host",
				Error:   "image not found",
			}
		},
	})

	q := newRecordingQueue()
	jobID := "123e4567-e89b-12d3-a456-426614174088"
	job := queue.Job{
		ID:           jobID,
		AssessmentID: "123e4567-e89b-12d3-a456-426614174001",
		TenantID:     "123e4567-e89b-12d3-a456-426614174002",
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.test","profile_id":"standard","hard_deadline_seconds":10}`),
	}

	cfg := Config{
		WorkerID:         "worker-readiness-lease-guard-test",
		HeartbeatEvery:   5 * time.Second,
		ReadinessChecker: checker,
	}

	process(ctx, zap.NewNop(), q, reg, job, cfg)

	q.mu.Lock()
	defer q.mu.Unlock()

	// Verify distributed lease was NEVER acquired
	if q.leasesAcquired != 0 {
		t.Fatalf("expected 0 lease acquisitions for unavailable scanner, got %d", q.leasesAcquired)
	}

	// Verify job failed closed with actionable diagnostic message
	if len(q.failed) != 1 {
		t.Fatalf("expected 1 failed job fail-closed, got %d", len(q.failed))
	}
	if !strings.Contains(q.failedReasons[0], "runtime readiness check failed") {
		t.Fatalf("expected failure reason mentioning readiness check failed, got %q", q.failedReasons[0])
	}
}
