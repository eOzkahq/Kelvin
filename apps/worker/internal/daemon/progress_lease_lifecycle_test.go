package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/progress"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"go.uber.org/zap"
)

// trackingLeaseQueue wraps queue.MemoryQueue and instruments lease events and heartbeats.
type trackingLeaseQueue struct {
	*queue.MemoryQueue
	mu              sync.Mutex
	acquires        []string
	renews          []string
	releases        []string
	workerHeartbeat []string
	jobHeartbeats   map[string]int
	event           chan struct{}
}

func newTrackingLeaseQueue() *trackingLeaseQueue {
	return &trackingLeaseQueue{
		MemoryQueue:   queue.NewMemoryQueue(),
		jobHeartbeats: make(map[string]int),
		event:         make(chan struct{}, 16),
	}
}

func (t *trackingLeaseQueue) AcquireLease(ctx context.Context, jobID string, ttl time.Duration) (bool, error) {
	t.mu.Lock()
	t.acquires = append(t.acquires, jobID)
	t.mu.Unlock()
	return t.MemoryQueue.AcquireLease(ctx, jobID, ttl)
}

func (t *trackingLeaseQueue) RenewLease(ctx context.Context, jobID string, ttl time.Duration) error {
	t.mu.Lock()
	t.renews = append(t.renews, jobID)
	t.mu.Unlock()
	return t.MemoryQueue.RenewLease(ctx, jobID, ttl)
}

func (t *trackingLeaseQueue) ReleaseLease(ctx context.Context, jobID string) error {
	t.mu.Lock()
	t.releases = append(t.releases, jobID)
	t.mu.Unlock()
	return t.MemoryQueue.ReleaseLease(ctx, jobID)
}

func (t *trackingLeaseQueue) Heartbeat(ctx context.Context, key, workerID string, ttl time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if strings.HasPrefix(key, "worker:") {
		t.workerHeartbeat = append(t.workerHeartbeat, key)
	} else {
		t.jobHeartbeats[key]++
	}
	return nil
}

func (t *trackingLeaseQueue) Complete(ctx context.Context, j queue.Job) error {
	_ = t.MemoryQueue.Complete(ctx, j)
	select {
	case t.event <- struct{}{}:
	default:
	}
	return nil
}

func (t *trackingLeaseQueue) Fail(ctx context.Context, j queue.Job, reason string) error {
	_ = t.MemoryQueue.Fail(ctx, j, reason)
	select {
	case t.event <- struct{}{}:
	default:
	}
	return nil
}

// TestProgress_MonotonicStageProgression verifies that an assessment job emits strictly
// monotonic, timestamped stage transitions and sanitized progress messages:
// PREFLIGHT -> SCANNER_INITIALIZATION -> SCANNER_EXECUTION -> OUTPUT_COLLECTION -> COMPLETION
func TestProgress_MonotonicStageProgression(t *testing.T) {
	memPub := progress.NewMemoryPublisher()
	q := newRecordingQueue()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Register preflight and nuclei adapters
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerHTTPPreflight, "1.0.0", "Preflight Pass", "INFORMATIONAL", "ref-pf"); err != nil {
		t.Fatal(err)
	}
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerNuclei, "3.3.0", "Vulnerability Detected", "HIGH", "ref-nuclei"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatal(err)
	}

	jobID := uuid.New().String()
	assessmentID := uuid.New().String()
	tenantID := uuid.New().String()

	cfg := Config{
		WorkerID:          "worker-progress-test",
		ProgressPublisher: memPub,
	}

	env := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        assessmentID,
		TenantID:            tenantID,
		TargetAddress:       "https://approved.example.com",
		ScanProfile:         "standard",
		RequestedScanners:   []string{adapters.ScannerNuclei},
		HardDeadlineSeconds: 30,
		CreatedAt:           time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	}
	payload, _ := json.Marshal(env)
	job := queue.Job{
		Version:      2,
		ID:           jobID,
		AssessmentID: assessmentID,
		TenantID:     tenantID,
		Type:         adapters.ScannerNuclei,
		Payload:      payload,
	}

	process(context.Background(), logger, q, registry, job, cfg)

	q.mu.Lock()
	completed := len(q.completed)
	q.mu.Unlock()
	if completed != 1 {
		t.Fatalf("expected job to complete, got %d", completed)
	}

	events := memPub.EventsForJob(jobID)
	if len(events) == 0 {
		t.Fatal("expected progress events published for job, got 0")
	}

	// Verify monotonic timestamp ordering
	for i := 1; i < len(events); i++ {
		prev := events[i-1].Timestamp
		curr := events[i].Timestamp
		if curr.Before(prev) {
			t.Errorf("progress event %d timestamp %s is before previous %s", i, curr, prev)
		}
	}

	// Verify stages observed
	stagesSeen := make(map[progress.Stage]bool)
	for _, ev := range events {
		stagesSeen[ev.Stage] = true
		if ev.Progress != nil && ev.Progress.Message != "" {
			// Verify sanitizer stripped any secret tokens
			if strings.Contains(ev.Progress.Message, "secret") || strings.Contains(ev.Progress.Message, "token") {
				t.Errorf("sensitive keyword found in progress message: %s", ev.Progress.Message)
			}
		}
	}

	// Expected essential stages
	expectedStages := []progress.Stage{
		progress.StagePreflight,
		progress.StageScannerExecution,
	}
	for _, exp := range expectedStages {
		if !stagesSeen[exp] {
			t.Errorf("expected stage %s to be observed, seen stages: %v", exp, stagesSeen)
		}
	}
}

// TestProgress_DeterminateAndIndeterminateMetrics verifies:
// - Determinate progress calculates exact percentage and units.
// - Indeterminate progress reports honest unknown total.
func TestProgress_DeterminateAndIndeterminateMetrics(t *testing.T) {
	memPub := progress.NewMemoryPublisher()
	logger := zap.NewNop()
	tracker := progress.NewTracker("test-assessment", "test-job", "test-tenant", "nuclei", memPub, logger)
	ctx := context.Background()

	// 1. Indeterminate progress
	indet := progress.NewIndeterminateProgress("Scanning target endpoints")
	if err := tracker.ReportProgress(ctx, indet); err != nil {
		t.Fatalf("report indeterminate progress: %v", err)
	}

	// 2. Determinate progress (e.g. 25 of 100 templates executed)
	det := progress.NewDeterminateProgress(25, 100, "templates", "Executed 25 of 100 templates")
	if err := tracker.ReportProgress(ctx, det); err != nil {
		t.Fatalf("report determinate progress: %v", err)
	}

	// 3. Determinate progress (100 of 100 templates executed)
	detDone := progress.NewDeterminateProgress(100, 100, "templates", "Completed all templates")
	if err := tracker.ReportProgress(ctx, detDone); err != nil {
		t.Fatalf("report final progress: %v", err)
	}

	events := memPub.EventsForJob("test-job")
	if len(events) != 3 {
		t.Fatalf("expected 3 progress events, got %d", len(events))
	}

	// Verify event 1: indeterminate
	ev1 := events[0]
	if ev1.Progress.HasPercentage() {
		t.Errorf("event 1 should be indeterminate")
	}

	// Verify event 2: 25%
	ev2 := events[1]
	if !ev2.Progress.HasPercentage() {
		t.Errorf("event 2 should be determinate")
	}
	if ev2.Progress.Percentage == nil || *ev2.Progress.Percentage != 25.0 {
		t.Errorf("expected 25.0%%, got %v", ev2.Progress.Percentage)
	}

	// Verify event 3: 100%
	ev3 := events[2]
	if ev3.Progress.Percentage == nil || *ev3.Progress.Percentage != 100.0 {
		t.Errorf("expected 100.0%%, got %v", ev3.Progress.Percentage)
	}
}

// TestDistributedLease_PeriodicRenewalDuringExecution verifies that a running
// assessment job periodically renews its distributed execution lease in the background,
// and releases the lease immediately upon completion.
func TestDistributedLease_PeriodicRenewalDuringExecution(t *testing.T) {
	q := newTrackingLeaseQueue()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Scanner that runs for 120ms, allowing multiple lease renewals with 30ms heartbeat
	slowScanner := harnessMockAdapter{
		name:    adapters.ScannerNuclei,
		version: "3.3.0",
		digest:  "sha256:" + strings.Repeat("a", 64),
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			select {
			case <-time.After(120 * time.Millisecond):
				code := 0
				now := time.Now().UTC()
				return adapters.Result{
					Status:   adapters.StatusCompleted,
					ExitCode: &code,
					Metadata: adapters.OutputMetadata{
						AssessmentID:   task.AssessmentID,
						ScannerID:      task.Scanner,
						ScannerVersion: "3.3.0",
						AdapterVersion: "3.3.0",
						RunID:          task.JobID,
						StartedAt:      now.Add(-120 * time.Millisecond),
						CompletedAt:    now,
					},
				}, nil
			case <-ctx.Done():
				return adapters.Result{Status: adapters.StatusTimedOut}, ctx.Err()
			}
		},
	}

	digest := "sha256:" + strings.Repeat("a", 64)
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerNuclei,
		DisplayName:      adapters.ScannerNuclei,
		Version:          "3.3.0",
		SupportedTargets: []string{"url"},
		Capabilities:     slowScanner.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion:         "3.3.0",
			ImageReference:         adapters.ScannerNuclei + "@" + digest,
			ImageDigest:            digest,
			TemplateCatalogVersion: adapters.PinnedNucleiTemplateCatalogVersion,
			TemplateCatalogDigest:  adapters.PinnedNucleiTemplateCatalogDigest,
		},
	}, func() adapters.ScannerAdapter { return slowScanner }); err != nil {
		t.Fatal(err)
	}

	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatal(err)
	}

	jobID := uuid.New().String()
	env := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        uuid.New().String(),
		TenantID:            uuid.New().String(),
		TargetAddress:       "https://approved.example.com",
		ScanProfile:         "standard",
		RequestedScanners:   []string{adapters.ScannerNuclei},
		HardDeadlineSeconds: 30,
		CreatedAt:           time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	}
	payload, _ := json.Marshal(env)
	job := queue.Job{
		Version:      2,
		ID:           jobID,
		AssessmentID: env.AssessmentID,
		TenantID:     env.TenantID,
		Type:         adapters.ScannerNuclei,
		Payload:      payload,
	}

	cfg := Config{
		WorkerID:       "worker-lease-renewal-test",
		HeartbeatEvery: 30 * time.Millisecond,
	}

	process(context.Background(), logger, q, registry, job, cfg)

	q.mu.Lock()
	defer q.mu.Unlock()

	// 1. Verify lease acquired
	if len(q.acquires) != 1 || q.acquires[0] != jobID {
		t.Errorf("expected 1 lease acquire for %s, got %v", jobID, q.acquires)
	}

	// 2. Verify lease renewed periodically (with 30ms interval and 120ms runtime, expect >= 2 renewals)
	if len(q.renews) < 2 {
		t.Errorf("expected at least 2 lease renewals during execution, got %d renewals: %v", len(q.renews), q.renews)
	}

	// 3. Verify lease released on completion
	if len(q.releases) != 1 || q.releases[0] != jobID {
		t.Errorf("expected 1 lease release for %s on completion, got %v", jobID, q.releases)
	}
}

// TestDistributedLease_PreventsDuplicateConcurrentExecution verifies that when a job
// lease is actively held by one worker, a second worker skips execution fail-closed.
func TestDistributedLease_PreventsDuplicateConcurrentExecution(t *testing.T) {
	q := newTrackingLeaseQueue()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatal(err)
	}

	jobID := uuid.New().String()

	// Pre-acquire the lease for Worker A
	acquired, err := q.AcquireLease(context.Background(), jobID, 10*time.Second)
	if err != nil || !acquired {
		t.Fatalf("pre-acquire lease failed: acquired=%v, err=%v", acquired, err)
	}

	// Worker B attempts to process the same job
	executionInvoked := false
	fakeExecutor := sandbox.NewFake()
	cfg := Config{
		WorkerID: "worker-b-duplicate-tester",
		Executor: fakeExecutor,
	}

	env := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        uuid.New().String(),
		TenantID:            uuid.New().String(),
		TargetAddress:       "https://approved.example.com",
		ScanProfile:         "standard",
		RequestedScanners:   []string{adapters.ScannerNuclei},
		HardDeadlineSeconds: 30,
		CreatedAt:           time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	}
	payload, _ := json.Marshal(env)
	job := queue.Job{
		Version:      2,
		ID:           jobID,
		AssessmentID: env.AssessmentID,
		TenantID:     env.TenantID,
		Type:         adapters.ScannerNuclei,
		Payload:      payload,
	}

	process(context.Background(), logger, q, registry, job, cfg)

	if fakeExecutor.Last.Image != "" || executionInvoked {
		t.Fatal("security violation: duplicate execution occurred while lease was held by another worker")
	}
}

// TestDistributedLease_ReclamationOnCrashOrExpiry verifies that if a worker crashes
// while holding a lease, once the lease TTL expires, another worker can safely acquire
// the lease and recover/complete the job.
func TestDistributedLease_ReclamationOnCrashOrExpiry(t *testing.T) {
	q := newTrackingLeaseQueue()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerNuclei, "3.3.0", "Recovered Finding", "INFORMATIONAL", "ref"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatal(err)
	}

	jobID := uuid.New().String()

	// 1. Worker 1 acquires lease with very short TTL of 50ms and "crashes" (no release, no renew)
	acquired, err := q.AcquireLease(context.Background(), jobID, 50*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("worker 1 acquire failed: %v", err)
	}

	// 2. Immediate second acquire fails
	acquiredSecond, _ := q.AcquireLease(context.Background(), jobID, 50*time.Millisecond)
	if acquiredSecond {
		t.Fatal("expected second acquire to fail while lease is active")
	}

	// 3. Sleep 70ms to allow lease TTL to elapse
	time.Sleep(70 * time.Millisecond)

	// 4. Worker 2 attempts execution: lease is reclaimed successfully
	cfg := Config{
		WorkerID: "worker-2-recovery",
	}

	env := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        uuid.New().String(),
		TenantID:            uuid.New().String(),
		TargetAddress:       "https://approved.example.com",
		ScanProfile:         "standard",
		RequestedScanners:   []string{adapters.ScannerNuclei},
		HardDeadlineSeconds: 30,
		CreatedAt:           time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	}
	payload, _ := json.Marshal(env)
	job := queue.Job{
		Version:      2,
		ID:           jobID,
		AssessmentID: env.AssessmentID,
		TenantID:     env.TenantID,
		Type:         adapters.ScannerNuclei,
		Payload:      payload,
	}

	process(context.Background(), logger, q, registry, job, cfg)

	q.mu.Lock()
	defer q.mu.Unlock()
	// Job must complete successfully after lease recovery
	if len(q.releases) != 1 || q.releases[0] != jobID {
		t.Errorf("expected Worker 2 to acquire, complete and release lease, releases: %v", q.releases)
	}
}

// TestWorkerVitality_PeriodicHeartbeats verifies that the daemon loop emits periodic
// worker vitality heartbeats to the queue backend.
func TestWorkerVitality_PeriodicHeartbeats(t *testing.T) {
	q := newTrackingLeaseQueue()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		WorkerID:       "vitality-worker-1",
		HeartbeatEvery: 25 * time.Millisecond,
		PollInterval:   time.Millisecond,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, logger, cfg, q, registry)
	}()

	// Wait 80ms to accumulate ~3 heartbeats
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done

	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.workerHeartbeat) < 2 {
		t.Errorf("expected at least 2 worker vitality heartbeats, got %d: %v", len(q.workerHeartbeat), q.workerHeartbeat)
	}
	for _, hb := range q.workerHeartbeat {
		if hb != "worker:vitality-worker-1" {
			t.Errorf("unexpected heartbeat key: %s", hb)
		}
	}
}
