package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/progress"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

type inProcessMockAdapter struct {
	name             string
	version          string
	supportsProgress bool
	supportsCancel   bool
	run              func(ctx context.Context, task adapters.Task) (adapters.Result, error)
}

func (m inProcessMockAdapter) Name() string    { return m.name }
func (m inProcessMockAdapter) Version() string { return m.version }
func (m inProcessMockAdapter) VerifyRuntimeVersion(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
	info := adapters.RuntimeVersionInfo{
		ScannerVersion: m.version,
		AdapterVersion: m.version,
	}
	if m.name == adapters.ScannerNuclei {
		info.TemplateCatalogVersion = "kelvin.safe.web.v1"
		info.TemplateCatalogDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	}
	return info, nil
}
func (m inProcessMockAdapter) Initialize(context.Context, *zap.Logger) error { return nil }
func (m inProcessMockAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (m inProcessMockAdapter) Capabilities() adapters.Capabilities {
	return adapters.Capabilities{
		SupportedTargetTypes: []string{"url"},
		CheckCategories:      []string{"discovery"},
		RequiresSandbox:      false,
		SupportsProgress:     m.supportsProgress,
		SupportsCancel:       m.supportsCancel,
	}
}
func (m inProcessMockAdapter) Execute(ctx context.Context, task adapters.Task) (adapters.Result, error) {
	if m.run != nil {
		return m.run(ctx, task)
	}
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
	return registerMock(registry, adapter)
}

func registerMock(registry *adapters.Registry, adapter inProcessMockAdapter) error {
	caps := adapter.Capabilities()
	vp := adapters.VersionPolicy{ScannerVersion: "1.0.0"}
	if adapter.name == adapters.ScannerNuclei {
		vp.TemplateCatalogVersion = "kelvin.safe.web.v1"
		vp.TemplateCatalogDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	}
	return registry.RegisterAdapter(adapters.Metadata{
		ID:               adapter.name,
		DisplayName:      adapter.name,
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     caps,
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy:    vp,
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
	if !strings.Contains(executor.Last.EgressProxy, "127.0.0.1:") {
		t.Errorf("expected localhost proxy URL, got %s", executor.Last.EgressProxy)
	}
	if !strings.Contains(executor.Last.EgressProxy, "kelvin-egress-") {
		t.Errorf("expected authenticated proxy URL with execution token, got %s", executor.Last.EgressProxy)
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

func TestExecuteScannerHandlesCancellation(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	metricsReg := metrics.NewRegistry()
	fakeExec := sandbox.NewFake()
	fakeExec.Delay = 50 * time.Millisecond

	cfg := Config{
		WorkerID: "test-worker",
		Executor: fakeExec,
		Metrics:  metricsReg,
	}

	orch := NewOrchestrator(registry, fakeExec, nil, nil, metricsReg, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after 10ms (while fake execution is delayed 50ms)
	time.AfterFunc(10*time.Millisecond, cancel)

	res, err := orch.ExecuteScanner(ctx, zap.NewNop(), task, cfg)
	if err == nil {
		t.Fatal("expected execution error on cancellation")
	}
	if !errors.Is(err, sandbox.ErrCancelled) {
		t.Fatalf("expected sandbox.ErrCancelled, got %v", err)
	}
	if res == nil || !res.Cancelled {
		t.Fatalf("expected res.Cancelled = true, got %+v", res)
	}

	snap := metricsReg.Snapshot()
	if snap.Terminations[metrics.CauseCancelled] != 1 {
		t.Errorf("expected 1 CauseCancelled termination, got %d", snap.Terminations[metrics.CauseCancelled])
	}

	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("failed to decode cancelled envelope: %v", err)
	}
	if env.Status != adapters.StatusCancelled {
		t.Errorf("env.Status = %q, want %q", env.Status, adapters.StatusCancelled)
	}
	hasCancelDiag := false
	for _, diag := range env.Diagnostics {
		if diag.Code == "CANCELLED" {
			hasCancelDiag = true
			break
		}
	}
	if !hasCancelDiag {
		t.Errorf("missing CANCELLED diagnostic in envelope: %+v", env.Diagnostics)
	}
}

func TestExecutePipelineHaltsImmediatelyOnCancellation(t *testing.T) {
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

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      JobTypeAssessment,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before start

	res, err := orch.ExecutePipeline(ctx, zap.NewNop(), task, cfg)
	if err == nil {
		t.Fatal("expected error on cancelled pipeline")
	}
	if !errors.Is(err, sandbox.ErrCancelled) {
		t.Fatalf("expected sandbox.ErrCancelled, got %v", err)
	}
	if res == nil || !res.Cancelled {
		t.Fatalf("expected res.Cancelled = true, got %+v", res)
	}

	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("failed to decode pipeline output envelope: %v", err)
	}
	if env.Status != adapters.StatusCancelled {
		t.Errorf("env.Status = %q, want %q", env.Status, adapters.StatusCancelled)
	}
}

func TestRepeatedCancellationIsIdempotent(t *testing.T) {
	adapter := &adapters.ReferenceAdapter{
		AdapterName: "test-ref",
		Caps: adapters.Capabilities{
			SupportsCancel: true,
		},
		Run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			return adapters.Result{}, nil
		},
	}
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	// Repeated Cancel calls must not panic or error
	for i := 0; i < 5; i++ {
		if err := adapter.Cancel(); err != nil {
			t.Errorf("call %d: Cancel() error = %v", i, err)
		}
	}
}

func TestExecuteScannerProgressStageTransitions(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerInProcess(registry, adapters.ScannerHTTPHeaders); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	memPub := progress.NewMemoryPublisher()

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())
	orch.SetProgressPublisher(memPub)

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerHTTPHeaders,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	res, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, Config{})
	if err != nil {
		t.Fatalf("ExecuteScanner failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("res.ExitCode = %d, want 0", res.ExitCode)
	}

	events := memPub.EventsForJob(task.JobID)
	if len(events) == 0 {
		t.Fatal("expected published progress events, got 0")
	}

	// Verify sequential stage transitions
	var observedStages []progress.Stage
	for _, ev := range events {
		if len(observedStages) == 0 || observedStages[len(observedStages)-1] != ev.Stage {
			observedStages = append(observedStages, ev.Stage)
		}
	}

	expectedOrder := []progress.Stage{
		progress.StagePreflight,
		progress.StageScannerInitialization,
		progress.StageScannerExecution,
		progress.StageOutputCollection,
		progress.StageResultNormalization,
		progress.StageCompletion,
	}

	if len(observedStages) != len(expectedOrder) {
		t.Fatalf("observed %d stages (%v), want %d (%v)", len(observedStages), observedStages, len(expectedOrder), expectedOrder)
	}
	for i, exp := range expectedOrder {
		if observedStages[i] != exp {
			t.Errorf("stage %d: got %s, want %s", i, observedStages[i], exp)
		}
	}
}

func TestExecuteScannerHonestIndeterminateProgress(t *testing.T) {
	registry := adapters.NewRegistry()
	if err := registerInProcess(registry, adapters.ScannerHTTPPreflight); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	memPub := progress.NewMemoryPublisher()

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerHTTPPreflight,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	cfg := Config{ProgressPublisher: memPub}
	_, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("ExecuteScanner failed: %v", err)
	}

	events := memPub.EventsForJob(task.JobID)
	foundExecutionProgress := false
	for _, ev := range events {
		if ev.Stage == progress.StageScannerExecution && ev.Progress != nil {
			foundExecutionProgress = true
			if ev.Progress.HasPercentage() {
				t.Fatalf("expected HasPercentage() = false for scanner without progress support, got %v%%", *ev.Progress.Percentage)
			}
			if ev.Progress.Percentage != nil {
				t.Fatalf("expected nil percentage for honest indeterminate progress, got %v", *ev.Progress.Percentage)
			}
		}
	}
	if !foundExecutionProgress {
		t.Fatal("expected scanner execution progress report")
	}
}

func TestExecuteScannerDeterminateProgressFromAdapter(t *testing.T) {
	registry := adapters.NewRegistry()
	mock := inProcessMockAdapter{
		name:             adapters.ScannerTLSAssessor,
		version:          "1.0.0",
		supportsProgress: true,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			if rep, ok := progress.ReporterFromContext(ctx); ok {
				_ = rep.ReportProgress(ctx, progress.NewDeterminateProgress(75, 100, "templates", "testing TLS cipher suites"))
			}
			exitZero := 0
			now := time.Now().UTC()
			return adapters.Result{
				SchemaVersion: "1.0",
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      task.Scanner,
					ScannerVersion: "1.0.0",
					AdapterVersion: "1.0.0",
					RunID:          task.JobID,
					StartedAt:      now.Add(-time.Millisecond * 50),
					CompletedAt:    now,
					CorrelationID:  task.CorrelationID,
				},
				Status:      adapters.StatusCompleted,
				ExitCode:    &exitZero,
				DurationMS:  50,
				Findings:    []json.RawMessage{},
				Diagnostics: []adapters.ExecutionDiagnostic{},
			}, nil
		},
	}
	if err := registerMock(registry, mock); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	memPub := progress.NewMemoryPublisher()

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerTLSAssessor,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	cfg := Config{ProgressPublisher: memPub}
	_, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("ExecuteScanner failed: %v", err)
	}

	events := memPub.EventsForJob(task.JobID)
	foundDeterminate := false
	for _, ev := range events {
		if ev.Progress != nil && ev.Progress.HasPercentage() {
			foundDeterminate = true
			if *ev.Progress.Percentage != 75.0 {
				t.Errorf("got percentage %.2f, want 75.0", *ev.Progress.Percentage)
			}
			if ev.Progress.ItemsCompleted != 75 || ev.Progress.ItemsTotal != 100 {
				t.Errorf("items mismatch: completed=%d, total=%d", ev.Progress.ItemsCompleted, ev.Progress.ItemsTotal)
			}
			if ev.Progress.Units != "templates" {
				t.Errorf("units = %q, want templates", ev.Progress.Units)
			}
		}
	}
	if !foundDeterminate {
		t.Fatal("expected determinate progress from adapter")
	}
}

func TestExecuteScannerCancellationStageInterruption(t *testing.T) {
	registry := adapters.NewRegistry()
	blockCh := make(chan struct{})
	mock := inProcessMockAdapter{
		name:           adapters.ScannerHTTPPreflight,
		version:        "1.0.0",
		supportsCancel: true,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			close(blockCh)
			<-ctx.Done()
			return adapters.Result{}, ctx.Err()
		},
	}
	if err := registerMock(registry, mock); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	memPub := progress.NewMemoryPublisher()

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      adapters.ScannerHTTPPreflight,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{ProgressPublisher: memPub}

	go func() {
		<-blockCh
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	res, err := orch.ExecuteScanner(ctx, zap.NewNop(), task, cfg)
	if err == nil || !errors.Is(err, sandbox.ErrCancelled) {
		t.Fatalf("expected sandbox.ErrCancelled, got %v", err)
	}
	if res == nil || !res.Cancelled {
		t.Fatalf("expected res.Cancelled = true")
	}

	events := memPub.EventsForJob(task.JobID)
	if len(events) == 0 {
		t.Fatal("expected progress events")
	}
	lastEvent := events[len(events)-1]
	if lastEvent.StageStatus != progress.StageStatusCancelled {
		t.Errorf("last event stage_status = %q, want CANCELLED", lastEvent.StageStatus)
	}
	if len(lastEvent.Transitions) == 0 {
		t.Fatal("expected transition history to be preserved on cancellation")
	}
}

func TestExecutePipelineProgressPhases(t *testing.T) {
	registry := adapters.NewRegistry()
	makeAdapter := func(name string) {
		a := &adapters.ReferenceAdapter{
			AdapterName: name,
			Caps:        adapters.Capabilities{RequiresSandbox: false, SupportedTargetTypes: []string{"url"}},
			Run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
				exitZero := 0
				now := time.Now().UTC()
				return adapters.Result{
					SchemaVersion: adapters.OutputEnvelopeVersion,
					Metadata: adapters.OutputMetadata{
						AssessmentID:   task.AssessmentID,
						ScannerID:      task.Scanner,
						ScannerVersion: "1.0.0",
						AdapterVersion: "1.0.0",
						RunID:          uuid.New().String(),
						StartedAt:      now.Add(-time.Second),
						CompletedAt:    now,
					},
					Status:      adapters.StatusCompleted,
					ExitCode:    &exitZero,
					Findings:    []json.RawMessage{},
					Diagnostics: []adapters.ExecutionDiagnostic{},
				}, nil
			},
		}
		_ = a.Initialize(context.Background(), zap.NewNop())
		_ = registry.RegisterAdapter(adapters.Metadata{
			ID:               name,
			DisplayName:      name,
			Version:          "1.0.0",
			SupportedTargets: []string{"url"},
			Capabilities:     a.Capabilities(),
			ConfigVersion:    adapters.ScannerConfigVersion,
			VersionPolicy:    adapters.VersionPolicy{ScannerVersion: "1.0.0"},
		}, func() adapters.ScannerAdapter { return a })
	}

	makeAdapter("http_preflight")
	makeAdapter("tls_assessor")
	makeAdapter("http_security_headers")
	makeAdapter("nuclei")
	makeAdapter("zap")
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	memPub := progress.NewMemoryPublisher()

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      JobTypeAssessment,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 15 * time.Second,
	}

	cfg := Config{ProgressPublisher: memPub}
	res, err := orch.ExecutePipeline(context.Background(), zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("ExecutePipeline failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("res.ExitCode = %d, want 0", res.ExitCode)
	}

	events := memPub.EventsForJob(task.JobID)
	if len(events) == 0 {
		t.Fatal("expected pipeline events")
	}

	foundPhaseProgress := false
	for _, ev := range events {
		if ev.Progress != nil && ev.Progress.HasPercentage() && ev.Progress.Units == "phases" {
			foundPhaseProgress = true
		}
	}
	if !foundPhaseProgress {
		t.Fatal("expected pipeline phase progress event")
	}
}

func TestExecuteScannerRetriesTransientFailure(t *testing.T) {
	registry := adapters.NewRegistry()
	var attemptCount int32

	a := &adapters.ReferenceAdapter{
		AdapterName: "http_preflight",
		Caps:        adapters.Capabilities{RequiresSandbox: false, SupportedTargetTypes: []string{"url"}},
		Run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			att := atomic.AddInt32(&attemptCount, 1)
			if att == 1 {
				// Transient failure on first attempt
				return adapters.Result{}, errors.New("dial tcp 93.184.216.34:80: connect: connection refused")
			}
			exitZero := 0
			now := time.Now().UTC()
			return adapters.Result{
				SchemaVersion: adapters.OutputEnvelopeVersion,
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      task.Scanner,
					ScannerVersion: "1.0.0",
					AdapterVersion: "1.0.0",
					RunID:          uuid.New().String(),
					StartedAt:      now.Add(-time.Second),
					CompletedAt:    now,
				},
				Status:      adapters.StatusCompleted,
				ExitCode:    &exitZero,
				DurationMS:  1000,
				Findings:    []json.RawMessage{},
				Diagnostics: []adapters.ExecutionDiagnostic{},
			}, nil
		},
	}
	_ = a.Initialize(context.Background(), zap.NewNop())
	_ = registry.RegisterAdapter(adapters.Metadata{
		ID:               "http_preflight",
		DisplayName:      "HTTP Preflight",
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     a.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy:    adapters.VersionPolicy{ScannerVersion: "1.0.0"},
	}, func() adapters.ScannerAdapter { return a })

	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      "http_preflight",
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	res, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, Config{})
	if err != nil {
		t.Fatalf("expected ExecuteScanner to succeed on retry: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("res.ExitCode = %d, want 0", res.ExitCode)
	}
	if atomic.LoadInt32(&attemptCount) != 2 {
		t.Fatalf("expected 2 execution attempts, observed %d", atomic.LoadInt32(&attemptCount))
	}
}

func TestExecuteScannerDoesNotRetryTerminalFailure(t *testing.T) {
	registry := adapters.NewRegistry()
	var attemptCount int32

	a := &adapters.ReferenceAdapter{
		AdapterName: "http_preflight",
		Caps:        adapters.Capabilities{RequiresSandbox: false, SupportedTargetTypes: []string{"url"}},
		Run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			atomic.AddInt32(&attemptCount, 1)
			return adapters.Result{}, errors.New("adapters: invalid scanner config: requests_per_second must be in 1..5")
		},
	}
	_ = a.Initialize(context.Background(), zap.NewNop())
	_ = registry.RegisterAdapter(adapters.Metadata{
		ID:               "http_preflight",
		DisplayName:      "HTTP Preflight",
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     a.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy:    adapters.VersionPolicy{ScannerVersion: "1.0.0"},
	}, func() adapters.ScannerAdapter { return a })

	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      "http_preflight",
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 10 * time.Second,
	}

	_, err := orch.ExecuteScanner(context.Background(), zap.NewNop(), task, Config{})
	if err == nil {
		t.Fatalf("expected ExecuteScanner to fail immediately on terminal error")
	}
	if atomic.LoadInt32(&attemptCount) != 1 {
		t.Fatalf("expected exactly 1 execution attempt for terminal failure, observed %d", atomic.LoadInt32(&attemptCount))
	}
}

func TestExecutePipelinePartialCompletionPreservesSuccessfulFindings(t *testing.T) {
	registry := adapters.NewRegistry()

	registerCustom := func(name string, shouldFail bool, findings []json.RawMessage) {
		adapter := inProcessMockAdapter{
			name:    name,
			version: "1.0.0",
			run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
				if shouldFail {
					return adapters.Result{}, errors.New("scanner container crashed")
				}
				exitZero := 0
				now := time.Now().UTC()
				return adapters.Result{
					SchemaVersion: adapters.OutputEnvelopeVersion,
					Metadata: adapters.OutputMetadata{
						AssessmentID:   task.AssessmentID,
						ScannerID:      task.Scanner,
						ScannerVersion: "1.0.0",
						AdapterVersion: "1.0.0",
						RunID:          uuid.New().String(),
						StartedAt:      now.Add(-time.Second),
						CompletedAt:    now,
					},
					Status:      adapters.StatusCompleted,
					ExitCode:    &exitZero,
					DurationMS:  1000,
					Findings:    findings,
					Diagnostics: []adapters.ExecutionDiagnostic{},
				}, nil
			},
		}
		_ = registerMock(registry, adapter)
	}

	finding1 := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "Missing Security Headers",
		"severity": "INFORMATIONAL",
		"confidence": 0.5,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "headers-missing"},
		"scanner": {"name": "http_preflight", "adapter_version": "1.0.0"},
		"discovered_at": "2026-10-28T00:00:00Z"
	}`)
	finding2 := json.RawMessage(`{
		"schema_version": "1.0",
		"title": "TLS 1.0 Enabled",
		"severity": "MEDIUM",
		"confidence": 0.8,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "tls-deprecated"},
		"scanner": {"name": "tls_assessor", "adapter_version": "1.0.0"},
		"discovered_at": "2026-10-28T00:00:00Z"
	}`)

	registerCustom("http_preflight", false, []json.RawMessage{finding1})
	registerCustom("tls_assessor", false, []json.RawMessage{finding2})
	registerCustom("http_security_headers", false, []json.RawMessage{})
	registerCustom("nuclei", false, []json.RawMessage{})
	registerCustom("zap", true, nil) // ZAP fails!

	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      JobTypeAssessment,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 15 * time.Second,
	}

	res, err := orch.ExecutePipeline(context.Background(), zap.NewNop(), task, Config{})
	if err != nil {
		t.Fatalf("expected ExecutePipeline to complete with partial status, got err: %v", err)
	}

	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}

	if env.Status != adapters.StatusPartial {
		t.Fatalf("expected status PARTIAL, got %s", env.Status)
	}
	if !env.Partial {
		t.Fatalf("expected env.Partial = true")
	}
	if len(env.Findings) != 2 {
		t.Fatalf("expected 2 preserved findings from preflight and tls, got %d", len(env.Findings))
	}

	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		t.Fatalf("failed to unmarshal stdout pipeline report: %v", err)
	}

	if report.OverallStatus != adapters.StatusPartial {
		t.Fatalf("expected report.OverallStatus = PARTIAL, got %s", report.OverallStatus)
	}
	if len(report.ScannersFailed) != 1 || report.ScannersFailed[0] != "zap" {
		t.Fatalf("expected scanners_failed to contain zap, got %+v, phases=%+v", report.ScannersFailed, report.PhaseResults)
	}
	if report.DegradationWarning == "" {
		t.Fatalf("expected non-empty degradation warning in report")
	}
}

func TestExecutePipelineFailsWhenEssentialPreflightFails(t *testing.T) {
	registry := adapters.NewRegistry()

	registerCustom := func(name string, shouldFail bool) {
		adapter := inProcessMockAdapter{
			name:    name,
			version: "1.0.0",
			run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
				if shouldFail {
					return adapters.Result{}, errors.New("reachability failed: host down")
				}
				exitZero := 0
				now := time.Now().UTC()
				return adapters.Result{
					SchemaVersion: adapters.OutputEnvelopeVersion,
					Metadata: adapters.OutputMetadata{
						AssessmentID:   task.AssessmentID,
						ScannerID:      task.Scanner,
						ScannerVersion: "1.0.0",
						AdapterVersion: "1.0.0",
						RunID:          uuid.New().String(),
						StartedAt:      now.Add(-time.Second),
						CompletedAt:    now,
					},
					Status:      adapters.StatusCompleted,
					ExitCode:    &exitZero,
					DurationMS:  1000,
					Findings:    []json.RawMessage{},
					Diagnostics: []adapters.ExecutionDiagnostic{},
				}, nil
			},
		}
		_ = registerMock(registry, adapter)
	}

	registerCustom("http_preflight", true) // Preflight fails!
	registerCustom("tls_assessor", false)
	registerCustom("http_security_headers", false)
	registerCustom("nuclei", false)
	registerCustom("zap", false)

	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	orch := NewOrchestrator(registry, nil, nil, nil, nil, zap.NewNop())

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Scanner:      JobTypeAssessment,
		Target:       "https://example.com",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 15 * time.Second,
	}

	res, err := orch.ExecutePipeline(context.Background(), zap.NewNop(), task, Config{})
	if err != nil {
		t.Fatalf("expected ExecutePipeline to complete with FAILED envelope, got err: %v", err)
	}

	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}

	if env.Status != adapters.StatusFailed {
		t.Fatalf("expected status FAILED when essential preflight fails, got %s", env.Status)
	}
	if env.Partial {
		t.Fatalf("expected env.Partial = false")
	}

	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		t.Fatalf("failed to unmarshal stdout pipeline report: %v", err)
	}

	if report.OverallStatus != adapters.StatusFailed {
		t.Fatalf("expected report.OverallStatus = FAILED, got %s", report.OverallStatus)
	}
	if len(report.ScannersFailed) == 0 || report.ScannersFailed[0] != "http_preflight" {
		t.Fatalf("expected scanners_failed to contain http_preflight, got %+v", report.ScannersFailed)
	}
	if len(report.ScannersSkipped) == 0 {
		t.Fatalf("expected downstream scanners to be skipped, got %+v", report.ScannersSkipped)
	}
}

