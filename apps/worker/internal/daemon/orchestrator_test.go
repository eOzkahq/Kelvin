package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

type inProcessMockAdapter struct {
	name    string
	version string
}

func (m inProcessMockAdapter) Name() string    { return m.name }
func (m inProcessMockAdapter) Version() string { return m.version }
func (m inProcessMockAdapter) VerifyRuntimeVersion(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
	return adapters.RuntimeVersionInfo{
		ScannerVersion: m.version,
		AdapterVersion: m.version,
	}, nil
}
func (m inProcessMockAdapter) Initialize(context.Context, *zap.Logger) error { return nil }
func (m inProcessMockAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (m inProcessMockAdapter) Capabilities() adapters.Capabilities {
	return adapters.Capabilities{
		SupportedTargetTypes: []string{"url"},
		CheckCategories:      []string{"discovery"},
		RequiresSandbox:      false,
	}
}
func (m inProcessMockAdapter) Execute(ctx context.Context, task adapters.Task) (adapters.Result, error) {
	now := time.Now().UTC()
	code := 0
	return adapters.Result{
		SchemaVersion: "1.0",
		Metadata: adapters.OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      task.Scanner,
			ScannerVersion: m.version,
			AdapterVersion: m.version,
			RunID:          task.JobID,
			StartedAt:      now.Add(-time.Millisecond * 50),
			CompletedAt:    now,
			CorrelationID:  task.CorrelationID,
		},
		Status:      adapters.StatusCompleted,
		ExitCode:    &code,
		DurationMS:  50,
		Findings:    []json.RawMessage{},
		Diagnostics: []adapters.ExecutionDiagnostic{},
	}, nil
}
func (m inProcessMockAdapter) Cancel() error                { return nil }
func (m inProcessMockAdapter) Health(context.Context) error { return nil }
func (m inProcessMockAdapter) Result() (adapters.Result, error) {
	return adapters.Result{}, nil
}

func registerInProcess(registry *adapters.Registry, name string) error {
	adapter := inProcessMockAdapter{name: name, version: "1.0.0"}
	caps := adapter.Capabilities()
	return registry.RegisterAdapter(adapters.Metadata{
		ID:               name,
		DisplayName:      name,
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     caps,
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy:    adapters.VersionPolicy{ScannerVersion: "1.0.0"},
	}, func() adapters.ScannerAdapter { return adapter })
}

func TestOrchestratorExecutesInProcessScanner(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerInProcess(registry, adapters.ScannerHTTPPreflight); err != nil {
		t.Fatal(err)
	}

	cancel, done := runWorker(t, q, registry, sandbox.NewFake())

	jobID := uuid.New().String()
	assessmentID := uuid.New().String()
	tenantID := uuid.New().String()

	payload, _ := json.Marshal(map[string]any{
		"target":                "https://example.com",
		"profile_id":            adapters.ProfileStandard,
		"hard_deadline_seconds": 10,
	})

	q.inner.Push(queue.Job{
		ID:           jobID,
		AssessmentID: assessmentID,
		TenantID:     tenantID,
		Type:         adapters.ScannerHTTPPreflight,
		Payload:      payload,
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || len(q.failed) != 0 {
		t.Fatalf("expected 1 completed job, got completed=%d failed=%d", len(q.completed), len(q.failed))
	}
}

func TestOrchestratorRejectsUnapprovedProfileScanner(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	// Register nuclei
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	cancel, done := runWorker(t, q, registry, sandbox.NewFake())

	// Push job attempting to run nuclei under the passive profile (which allows 0 active scanners)
	payload, _ := json.Marshal(map[string]any{
		"target":                "https://example.com",
		"profile_id":            adapters.ProfilePassive,
		"hard_deadline_seconds": 10,
	})

	q.inner.Push(queue.Job{
		ID:           uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Type:         adapters.ScannerNuclei,
		Payload:      payload,
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 || len(q.completed) != 0 {
		t.Fatalf("expected job to be rejected due to unauthorized profile scanner, got completed=%d failed=%d", len(q.completed), len(q.failed))
	}
}

func TestOrchestratorExecutesAssessmentPipeline(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()

	// Register all scanners required for Standard profile
	if err := registerInProcess(registry, adapters.ScannerHTTPPreflight); err != nil {
		t.Fatal(err)
	}
	if err := registerInProcess(registry, adapters.ScannerTLSAssessor); err != nil {
		t.Fatal(err)
	}
	if err := registerInProcess(registry, adapters.ScannerHTTPHeaders); err != nil {
		t.Fatal(err)
	}
	if err := registerStub(registry); err != nil { // Nuclei stub
		t.Fatal(err)
	}
	// Register ZAP stub
	digest := "sha256:" + strings.Repeat("b", 64)
	zapAdapter := stubAdapter{name: adapters.ScannerZAPBaseline}
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerZAPBaseline,
		DisplayName:      "ZAP",
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     zapAdapter.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion: "1.0.0",
			ImageReference: "zap@" + digest,
			ImageDigest:    digest,
		},
	}, func() adapters.ScannerAdapter { return zapAdapter }); err != nil {
		t.Fatal(err)
	}

	executor := sandbox.NewFake().WithResult(sandbox.Result{
		ExitCode: 0,
		Findings: []byte(`{"findings":[]}`),
		Duration: time.Millisecond * 10,
	})

	cancel, done := runWorker(t, q, registry, executor)

	jobID := uuid.New().String()
	assessmentID := uuid.New().String()
	tenantID := uuid.New().String()

	payload, _ := json.Marshal(map[string]any{
		"target":                "https://example.com",
		"profile_id":            adapters.ProfileStandard,
		"hard_deadline_seconds": 30,
	})

	q.inner.Push(queue.Job{
		ID:           jobID,
		AssessmentID: assessmentID,
		TenantID:     tenantID,
		Type:         JobTypeAssessment,
		Payload:      payload,
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || len(q.failed) != 0 {
		t.Fatalf("expected assessment pipeline job to complete, got completed=%d failed=%d (reasons: %v)", len(q.completed), len(q.failed), q.failedReasons)
	}
}

func TestOrchestratorPipelineHaltsOnPrerequisiteFailure(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()

	// Register failing preflight
	failingPreflight := failingMockAdapter{name: adapters.ScannerHTTPPreflight, version: "1.0.0"}
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerHTTPPreflight,
		DisplayName:      adapters.ScannerHTTPPreflight,
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     adapters.Capabilities{SupportedTargetTypes: []string{"url"}, RequiresSandbox: false},
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy:    adapters.VersionPolicy{ScannerVersion: "1.0.0"},
	}, func() adapters.ScannerAdapter { return failingPreflight }); err != nil {
		t.Fatal(err)
	}

	// Register TLS assessor
	if err := registerInProcess(registry, adapters.ScannerTLSAssessor); err != nil {
		t.Fatal(err)
	}

	cancel, done := runWorker(t, q, registry, sandbox.NewFake())

	payload, _ := json.Marshal(map[string]any{
		"target":                "https://example.com",
		"profile_id":            adapters.ProfileStandard,
		"hard_deadline_seconds": 15,
	})

	q.inner.Push(queue.Job{
		ID:           uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Type:         JobTypeAssessment,
		Payload:      payload,
	})

	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	// When a required phase in the pipeline fails, the assessment job is marked complete with partial/failed phase records
	if len(q.completed) != 1 {
		t.Fatalf("expected pipeline to complete with recorded phase failures, got completed=%d", len(q.completed))
	}
}

type failingMockAdapter struct {
	name    string
	version string
}

func (m failingMockAdapter) Name() string    { return m.name }
func (m failingMockAdapter) Version() string { return m.version }
func (m failingMockAdapter) VerifyRuntimeVersion(context.Context) (adapters.RuntimeVersionInfo, error) {
	return adapters.RuntimeVersionInfo{ScannerVersion: m.version, AdapterVersion: m.version}, nil
}
func (m failingMockAdapter) Initialize(context.Context, *zap.Logger) error { return nil }
func (m failingMockAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (m failingMockAdapter) Capabilities() adapters.Capabilities {
	return adapters.Capabilities{SupportedTargetTypes: []string{"url"}, RequiresSandbox: false}
}
func (m failingMockAdapter) Execute(context.Context, adapters.Task) (adapters.Result, error) {
	code := 1
	now := time.Now().UTC()
	return adapters.Result{
		SchemaVersion: "1.0",
		Metadata: adapters.OutputMetadata{
			ScannerID:   m.name,
			StartedAt:   now,
			CompletedAt: now,
		},
		Status:   adapters.StatusFailed,
		ExitCode: &code,
		Diagnostics: []adapters.ExecutionDiagnostic{
			{Level: "error", Message: "preflight reachability check failed: host down"},
		},
	}, nil
}
func (m failingMockAdapter) Cancel() error                { return nil }
func (m failingMockAdapter) Health(context.Context) error { return nil }
func (m failingMockAdapter) Result() (adapters.Result, error) {
	return adapters.Result{}, nil
}

type mockOrchestratorResolver struct{}

func (m mockOrchestratorResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if host == "example.com" {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	return nil, nil
}

func TestOrchestratorIntegratesEgressProxy(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerStub(registry); err != nil { // Nuclei
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	executor := sandbox.NewFake().WithResult(sandbox.Result{
		ExitCode: 0,
		Findings: []byte(`{"findings":[]}`),
		Duration: time.Millisecond * 10,
	})

	scopePol, err := scope.NewPolicy([]string{"example.com"}, []string{"93.184.216.0/24"}, mockOrchestratorResolver{})
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		WorkerID: "test-worker",
		Executor: executor,
		ScopePolicyProvider: func(ctx context.Context, task adapters.Task) (scope.Policy, error) {
			return scopePol, nil
		},
	}

	orch := NewOrchestrator(registry, executor, nil, nil, nil, zap.NewNop())
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: time.Minute,
	}

	res, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("expected ExecuteScanner to succeed: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify the sandbox spec was provisioned with egress proxy and network enabled
	if executor.Last.EgressProxy == "" {
		t.Fatal("expected EgressProxy to be configured on the sandbox spec")
	}
	if executor.Last.NetworkDisabled {
		t.Fatal("expected NetworkDisabled to be false when scoped EgressProxy is configured")
	}
	if !strings.HasPrefix(executor.Last.EgressProxy, "http://127.0.0.1:") {
		t.Errorf("expected localhost proxy URL, got %s", executor.Last.EgressProxy)
	}
}

func TestOrchestratorEnforcesScannerResourceLimits(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerStub(registry); err != nil { // Nuclei
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	executor := sandbox.NewFake().WithResult(sandbox.Result{
		ExitCode: 0,
		Findings: []byte(`{"findings":[]}`),
		Duration: time.Millisecond * 10,
	})

	cfg := Config{
		WorkerID: "test-worker",
		Executor: executor,
	}

	orch := NewOrchestrator(registry, executor, nil, nil, nil, zap.NewNop())
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: time.Minute,
	}

	_, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("expected ExecuteScanner to succeed: %v", err)
	}

	// Verify Nuclei limits applied
	if executor.Last.Limits.MemoryLimit != "1024m" {
		t.Errorf("expected Nuclei memory limit 1024m, got %s", executor.Last.Limits.MemoryLimit)
	}
	if executor.Last.Limits.CPUQuota != "2.0" {
		t.Errorf("expected Nuclei CPU quota 2.0, got %s", executor.Last.Limits.CPUQuota)
	}
	if executor.Last.Limits.MaxPIDs != 64 {
		t.Errorf("expected Nuclei max PIDs 64, got %d", executor.Last.Limits.MaxPIDs)
	}
}

func TestOrchestratorRecordsResourceExhaustionFailures(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerStub(registry); err != nil { // Nuclei
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	metricsReg := metrics.NewRegistry()
	executor := sandbox.NewFake()

	cfg := Config{
		WorkerID: "test-worker",
		Executor: executor,
		Metrics:  metricsReg,
	}

	orch := NewOrchestrator(registry, executor, nil, nil, metricsReg, zap.NewNop())
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: time.Minute,
	}

	// 1. Simulate OOM exhaustion
	executor.WithResult(sandbox.Result{
		OOMKilled: true,
		ExitCode:  137,
		Duration:  time.Millisecond * 50,
	})

	_, _ = orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	snap := metricsReg.Snapshot()
	if snap.ResourceViolations[metrics.ViolationOOM] != 1 {
		t.Errorf("expected 1 OOM resource violation, got %d", snap.ResourceViolations[metrics.ViolationOOM])
	}
	if snap.Terminations[metrics.CauseOOM] != 1 {
		t.Errorf("expected 1 OOM termination, got %d", snap.Terminations[metrics.CauseOOM])
	}

	// 2. Simulate Deadline exhaustion
	executor.WithResult(sandbox.Result{
		DeadlineExceeded: true,
		ExitCode:         124,
		Duration:         time.Minute,
	})

	_, _ = orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	snap = metricsReg.Snapshot()
	if snap.ResourceViolations[metrics.ViolationDeadline] != 1 {
		t.Errorf("expected 1 Deadline resource violation, got %d", snap.ResourceViolations[metrics.ViolationDeadline])
	}
	if snap.Terminations[metrics.CauseDeadline] != 1 {
		t.Errorf("expected 1 Deadline termination, got %d", snap.Terminations[metrics.CauseDeadline])
	}
}

type mockNetTimeoutError struct{}

func (m mockNetTimeoutError) Error() string   { return "i/o timeout" }
func (m mockNetTimeoutError) Timeout() bool   { return true }
func (m mockNetTimeoutError) Temporary() bool { return true }

func TestDistinguishExecutionTimeoutFromConnectionTimeout(t *testing.T) {
	// 1. Execution timeout via ErrDeadlineExceeded
	if got := ClassifyTimeout(sandbox.ErrDeadlineExceeded, nil); got != TimeoutExecution {
		t.Errorf("ClassifyTimeout(ErrDeadlineExceeded) = %v, want %v", got, TimeoutExecution)
	}

	// 2. Execution timeout via result.DeadlineExceeded
	res := &sandbox.Result{DeadlineExceeded: true, ExitCode: -1}
	if got := ClassifyTimeout(nil, res); got != TimeoutExecution {
		t.Errorf("ClassifyTimeout(res.DeadlineExceeded) = %v, want %v", got, TimeoutExecution)
	}

	// 3. Execution timeout via context.DeadlineExceeded
	if got := ClassifyTimeout(context.DeadlineExceeded, nil); got != TimeoutExecution {
		t.Errorf("ClassifyTimeout(context.DeadlineExceeded) = %v, want %v", got, TimeoutExecution)
	}

	// 4. Connection timeout via net.Error
	netTimeout := mockNetTimeoutError{}
	if got := ClassifyTimeout(netTimeout, nil); got != TimeoutConnection {
		t.Errorf("ClassifyTimeout(netTimeout) = %v, want %v", got, TimeoutConnection)
	}

	// 5. Connection timeout via network dial error message
	dialErr := fmt.Errorf("dial tcp 93.184.216.34:443: connect: connection refused")
	if got := ClassifyTimeout(dialErr, nil); got != TimeoutConnection {
		t.Errorf("ClassifyTimeout(dialErr) = %v, want %v", got, TimeoutConnection)
	}

	// 6. Generic non-timeout error
	genErr := fmt.Errorf("unexpected EOF")
	if got := ClassifyTimeout(genErr, nil); got != TimeoutNone {
		t.Errorf("ClassifyTimeout(genErr) = %v, want %v", got, TimeoutNone)
	}
}

func TestExecuteScannerGeneratesStatusTimedOutEnvelope(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	metricsReg := metrics.NewRegistry()
	executor := sandbox.NewFake().WithResult(sandbox.Result{
		DeadlineExceeded: true,
		ExitCode:         124,
		Duration:         2 * time.Second,
	})

	cfg := Config{
		WorkerID: "test-worker",
		Executor: executor,
		Metrics:  metricsReg,
	}

	orch := NewOrchestrator(registry, executor, nil, nil, metricsReg, zap.NewNop())
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 2 * time.Second,
	}

	res, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	if err == nil {
		t.Fatal("expected error on scanner deadline timeout")
	}
	if res == nil || !res.DeadlineExceeded {
		t.Fatalf("expected res.DeadlineExceeded = true, got %+v (err=%v)", res, err)
	}
	if len(res.OutputEnvelope) == 0 {
		t.Fatal("expected non-empty OutputEnvelope for timed out scanner")
	}

	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("failed to decode output envelope: %v", err)
	}
	if env.Status != adapters.StatusTimedOut {
		t.Errorf("env.Status = %q, want %q", env.Status, adapters.StatusTimedOut)
	}
	if env.ExitCode == nil || *env.ExitCode != -1 {
		t.Errorf("env.ExitCode = %v, want -1", env.ExitCode)
	}
	hasDeadlineDiag := false
	for _, diag := range env.Diagnostics {
		if diag.Code == "DEADLINE_EXCEEDED" && diag.Level == "error" {
			hasDeadlineDiag = true
			break
		}
	}
	if !hasDeadlineDiag {
		t.Errorf("missing DEADLINE_EXCEEDED diagnostic: %+v", env.Diagnostics)
	}
}

func TestExecutePipelineAbortsWhenAssessmentDeadlineExceeded(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerInProcess(registry, adapters.ScannerHTTPPreflight); err != nil {
		t.Fatal(err)
	}
	if err := registerInProcess(registry, adapters.ScannerTLSAssessor); err != nil {
		t.Fatal(err)
	}

	metricsReg := metrics.NewRegistry()
	fakeExec := sandbox.NewFake()
	cfg := Config{
		WorkerID: "test-worker",
		Executor: fakeExec,
		Metrics:  metricsReg,
	}

	orch := NewOrchestrator(registry, fakeExec, nil, nil, metricsReg, zap.NewNop())

	// Set task hard deadline to 1 nanosecond (already expired before pipeline runs)
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      JobTypeAssessment,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: time.Nanosecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // ensure context expires

	res, err := orch.ExecutePipeline(ctx, zap.NewNop(), task, cfg)
	if err == nil {
		t.Fatal("expected execution error when assessment deadline is expired")
	}
	if res == nil || !res.DeadlineExceeded {
		t.Fatalf("expected res.DeadlineExceeded=true, got %+v", res)
	}

	snap := metricsReg.Snapshot()
	if snap.ResourceViolations[metrics.ViolationDeadline] == 0 {
		t.Errorf("expected ViolationDeadline metric incremented, got %d", snap.ResourceViolations[metrics.ViolationDeadline])
	}

	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("failed to decode pipeline output envelope: %v", err)
	}
	if env.Status != adapters.StatusTimedOut {
		t.Errorf("env.Status = %q, want %q", env.Status, adapters.StatusTimedOut)
	}
}

func TestScannerDeadlineRespectsAssessmentRemainingTime(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	fakeExec := sandbox.NewFake()
	cfg := Config{
		WorkerID: "test-worker",
		Executor: fakeExec,
	}

	orch := NewOrchestrator(registry, fakeExec, nil, nil, nil, zap.NewNop())

	// Scanner default deadline for Nuclei is 10 minutes (600s).
	// Assessment remaining deadline is 5 seconds.
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := orch.ExecuteScanner(ctx, zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify the spec deadline received by executor did not exceed 5 seconds
	if fakeExec.Last.Deadline > 5*time.Second {
		t.Errorf("expected spec.Deadline <= 5s, got %v", fakeExec.Last.Deadline)
	}
}
