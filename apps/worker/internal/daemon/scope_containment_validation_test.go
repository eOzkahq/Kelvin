package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

// TestScopeContainment_PreExecutionRejection_RFC1918AndMetadata verifies that any assessment
// job targeting private RFC1918 networks, cloud metadata endpoints, loopback, or link-local
// addresses is rejected fail-closed before any scanner execution occurs.
func TestScopeContainment_PreExecutionRejection_RFC1918AndMetadata(t *testing.T) {
	prohibitedTargets := []struct {
		name   string
		target string
	}{
		{"RFC1918 10.0.0.0/8 Class A", "http://10.0.0.1:8080/admin"},
		{"RFC1918 172.16.0.0/12 Class B", "http://172.16.50.1:80/internal"},
		{"RFC1918 192.168.0.0/16 Class C", "http://192.168.1.254:443"},
		{"AWS/GCP/OCI Cloud Metadata IPv4", "http://169.254.169.254/latest/meta-data"},
		{"AWS/GCP Cloud Metadata IPv6", "http://[fd00:ec2::254]/latest/meta-data"},
		{"IPv4 Loopback", "http://127.0.0.1:8080/internal"},
		{"IPv6 Loopback", "http://[::1]:8080/internal"},
		{"Localhost Hostname", "http://localhost:3000/api"},
		{"Carrier-Grade NAT RFC6598", "http://100.64.0.1/status"},
	}

	for _, tc := range prohibitedTargets {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			reg := adapters.NewRegistry()
			if err := registerStub(reg); err != nil {
				t.Fatalf("register stub failed: %v", err)
			}
			if err := reg.Initialize(ctx, zap.NewNop()); err != nil {
				t.Fatalf("initialize registry failed: %v", err)
			}

			q := newRecordingQueue()
			metricsReg := metrics.NewRegistry()
			fakeExecutor := sandbox.NewFake()

			cfg := Config{
				WorkerID: "worker-scope-pre-exec-test",
				Metrics:  metricsReg,
				Executor: fakeExecutor,
			}

			jobID := uuid.New().String()
			env := commonqueue.JobEnvelope{
				SchemaVersion:       2,
				JobID:               jobID,
				AssessmentID:        uuid.New().String(),
				TenantID:            uuid.New().String(),
				TargetAddress:       tc.target,
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

			process(ctx, zap.NewNop(), q, reg, job, cfg)

			q.mu.Lock()
			failedCount := len(q.failed)
			var failedReason string
			if failedCount > 0 {
				failedReason = q.failedReasons[0]
			}
			q.mu.Unlock()

			if failedCount != 1 {
				t.Fatalf("expected job with prohibited target %q to fail before execution, got %d failures", tc.target, failedCount)
			}
			if fakeExecutor.Last.Image != "" {
				t.Fatalf("security violation: scanner execution was invoked for prohibited target %q", tc.target)
			}
			if !strings.Contains(failedReason, "scope validation failed") && !strings.Contains(failedReason, "prohibited") {
				t.Errorf("expected failure reason mentioning scope/prohibited, got %q", failedReason)
			}

			snap := metricsReg.Snapshot()
			if snap.ResourceViolations[metrics.ViolationNetwork] < 1 {
				t.Errorf("expected ViolationNetwork metric recorded, got %d", snap.ResourceViolations[metrics.ViolationNetwork])
			}
			if snap.Terminations[metrics.CauseNetwork] < 1 {
				t.Errorf("expected CauseNetwork termination metric recorded, got %d", snap.Terminations[metrics.CauseNetwork])
			}
		})
	}
}

// TestScopeContainment_PreExecutionRejection_UnapprovedDomainPolicy verifies that when
// a tenant-level scope policy permits only specific authorized domains, an assessment
// targeting an unapproved external domain fails closed before execution starts.
func TestScopeContainment_PreExecutionRejection_UnapprovedDomainPolicy(t *testing.T) {
	ctx := context.Background()
	reg := adapters.NewRegistry()
	if err := registerStub(reg); err != nil {
		t.Fatalf("register stub failed: %v", err)
	}
	if err := reg.Initialize(ctx, zap.NewNop()); err != nil {
		t.Fatalf("initialize registry failed: %v", err)
	}

	q := newRecordingQueue()
	metricsReg := metrics.NewRegistry()
	fakeExecutor := sandbox.NewFake()

	authorizedPolicy, _ := scope.NewPolicy([]string{"authorized.example.com"}, nil, nil)
	cfg := Config{
		WorkerID: "worker-scope-domain-test",
		Metrics:  metricsReg,
		Executor: fakeExecutor,
		ScopePolicyProvider: func(context.Context, adapters.Task) (scope.Policy, error) {
			return authorizedPolicy, nil
		},
	}

	jobID := uuid.New().String()
	env := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        uuid.New().String(),
		TenantID:            uuid.New().String(),
		TargetAddress:       "https://unauthorized-target.org/login",
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

	process(ctx, zap.NewNop(), q, reg, job, cfg)

	q.mu.Lock()
	failedCount := len(q.failed)
	var failedReason string
	if failedCount > 0 {
		failedReason = q.failedReasons[0]
	}
	q.mu.Unlock()

	if failedCount != 1 {
		t.Fatalf("expected job on unapproved domain to fail, got %d failures", failedCount)
	}
	if fakeExecutor.Last.Image != "" {
		t.Fatal("security violation: scanner execution was invoked for unapproved domain target")
	}
	if !strings.Contains(failedReason, "outside approved scope") && !strings.Contains(failedReason, "scope validation failed") {
		t.Errorf("expected failure reason mentioning outside approved scope, got %q", failedReason)
	}
}

// TestScopeContainment_RuntimeFindingQuarantineAndDiagnostics verifies that when a scanner
// returns a mix of in-scope and out-of-scope / SSRF pivot findings:
// 1. In-scope findings are retained and accepted.
// 2. Out-of-scope / SSRF findings are quarantined (stripped).
// 3. Output envelope contains OUT_OF_SCOPE_TARGET_REJECTED diagnostic records for every violation.
// 4. State syncer receives and persists ONLY in-scope findings (zero out-of-scope finding persistence).
func TestScopeContainment_RuntimeFindingQuarantineAndDiagnostics(t *testing.T) {
	ctx := context.Background()
	reg := adapters.NewRegistry()

	// Finding generator helper
	makeFinding := func(title, asset, endpoint string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{
			"schema_version": "1.0",
			"title": %q,
			"severity": "HIGH",
			"confidence": 0.9,
			"target": {
				"asset": %q,
				"endpoint": %q
			},
			"vulnerability": {"template_id": "test-cve"},
			"scanner": {"name": "nuclei", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`, title, asset, endpoint))
	}

	inScopeFinding := makeFinding("In-Scope Vulnerability", "authorized.example.com", "https://authorized.example.com/api/v1/users")
	cloudMetadataFinding := makeFinding("SSRF Pivot to AWS Metadata", "169.254.169.254", "http://169.254.169.254/latest/meta-data")
	rfc1918Finding := makeFinding("Internal RFC1918 Service Discovery", "10.0.1.50", "http://10.0.1.50:8080/internal-status")
	loopbackFinding := makeFinding("Loopback Interface Exposure", "127.0.0.1", "http://127.0.0.1:9090/metrics")
	rogueDomainFinding := makeFinding("Third-Party Domain Discovered", "rogue-target.org", "https://rogue-target.org/exfiltrate")

	allEmittedFindings := []json.RawMessage{
		inScopeFinding,
		cloudMetadataFinding,
		rfc1918Finding,
		loopbackFinding,
		rogueDomainFinding,
	}

	digest := "sha256:" + strings.Repeat("f", 64)
	mockAdapter := harnessMockAdapter{
		name:    adapters.ScannerNuclei,
		version: "3.3.0",
		digest:  digest,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			exitCode := 0
			now := time.Now().UTC()
			return adapters.Result{
				SchemaVersion: "1.0",
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      adapters.ScannerNuclei,
					ScannerVersion: "3.3.0",
					AdapterVersion: "3.3.0",
					RunID:          task.JobID,
					StartedAt:      now.Add(-50 * time.Millisecond),
					CompletedAt:    now,
					CorrelationID:  task.CorrelationID,
				},
				Status:       adapters.StatusCompleted,
				ExitCode:     &exitCode,
				Findings:     allEmittedFindings,
				Diagnostics:  []adapters.ExecutionDiagnostic{},
				RawArtifacts: adapters.RawArtifactReferences{},
			}, nil
		},
	}

	if err := reg.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerNuclei,
		DisplayName:      adapters.ScannerNuclei,
		Version:          "3.3.0",
		SupportedTargets: []string{"url"},
		Capabilities:     mockAdapter.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion:         "3.3.0",
			ImageReference:         adapters.ScannerNuclei + "@" + digest,
			ImageDigest:            digest,
			TemplateCatalogVersion: adapters.PinnedNucleiTemplateCatalogVersion,
			TemplateCatalogDigest:  adapters.PinnedNucleiTemplateCatalogDigest,
		},
	}, func() adapters.ScannerAdapter { return mockAdapter }); err != nil {
		t.Fatalf("register adapter: %v", err)
	}

	if err := reg.Initialize(ctx, zap.NewNop()); err != nil {
		t.Fatalf("initialize registry: %v", err)
	}

	q := newRecordingQueue()
	stateSyncer := NewMemoryStateSyncer()
	authorizedPolicy, _ := scope.NewPolicy([]string{"authorized.example.com"}, nil, nil)

	cfg := Config{
		WorkerID:    "worker-quarantine-test",
		StateSyncer: stateSyncer,
		ScopePolicyProvider: func(context.Context, adapters.Task) (scope.Policy, error) {
			return authorizedPolicy, nil
		},
	}

	jobID := uuid.New().String()
	assessmentID := uuid.New().String()
	tenantID := uuid.New().String()

	env := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        assessmentID,
		TenantID:            tenantID,
		TargetAddress:       "https://authorized.example.com/portal",
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

	process(ctx, zap.NewNop(), q, reg, job, cfg)

	q.mu.Lock()
	completedCount := len(q.completed)
	q.mu.Unlock()

	if completedCount != 1 {
		t.Fatalf("expected job to complete, got %d completed jobs", completedCount)
	}

	// 1. Verify StateSyncer persisted ONLY the 1 in-scope finding
	stateSyncer.mu.Lock()
	defer stateSyncer.mu.Unlock()
	if len(stateSyncer.StoredFindings) != 1 {
		t.Fatalf("expected state syncer to hold exactly 1 stored finding, got %d", len(stateSyncer.StoredFindings))
	}
	if stateSyncer.StoredFindings[0].Title != "In-Scope Vulnerability" {
		t.Errorf("persisted finding title expected %q, got %q", "In-Scope Vulnerability", stateSyncer.StoredFindings[0].Title)
	}

	// 2. Also directly test Orchestrator.ExecuteScanner to verify the envelope output and diagnostics
	orchestrator := NewOrchestrator(reg, sandbox.NewFake(), nil, nil, nil, zap.NewNop())
	task := adapters.Task{
		JobID:        jobID,
		AssessmentID: assessmentID,
		TenantID:     tenantID,
		Scanner:      adapters.ScannerNuclei,
		Target:       "https://authorized.example.com/portal",
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 30 * time.Second,
	}

	res, err := orchestrator.ExecuteScanner(ctx, zap.NewNop(), task, cfg)
	if err != nil {
		t.Fatalf("ExecuteScanner failed: %v", err)
	}
	if res == nil || len(res.OutputEnvelope) == 0 {
		t.Fatal("expected non-empty OutputEnvelope from ExecuteScanner")
	}

	outputEnv, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("decode output envelope failed: %v", err)
	}

	// Findings inside the envelope should be filtered to only in-scope targets
	if len(outputEnv.Findings) != 1 {
		t.Fatalf("expected filtered envelope to contain 1 finding after scope filtering, got %d", len(outputEnv.Findings))
	}
	scopeRejections := 0
	for _, diag := range outputEnv.Diagnostics {
		if diag.Code == "OUT_OF_SCOPE_TARGET_REJECTED" {
			scopeRejections++
		}
	}
	if scopeRejections != 4 {
		t.Errorf("expected 4 OUT_OF_SCOPE_TARGET_REJECTED diagnostics, got %d", scopeRejections)
	}
}

// TestScopeContainment_MultiScannerPipelineEndToEndIntegrity verifies that in a full
// multi-scanner assessment pipeline (`ProfileDeep`), scope boundaries are rigorously
// maintained across all scanners, quarantined findings are excluded from the final report,
// and execution diagnostics preserve the security audit trail.
func TestScopeContainment_MultiScannerPipelineEndToEndIntegrity(t *testing.T) {
	ctx := context.Background()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Register 5 baseline scanners under Deep profile
	for _, sc := range []string{
		adapters.ScannerHTTPPreflight,
		adapters.ScannerNmap,
		adapters.ScannerTLSAssessor,
		adapters.ScannerHTTPHeaders,
		adapters.ScannerZAPBaseline,
	} {
		ver := "1.0.0"
		if sc == adapters.ScannerNmap {
			ver = "7.95.0"
		}
		if sc == adapters.ScannerZAPBaseline {
			ver = "2.16.1"
		}
		if err := registerHarnessScannerWithFinding(registry, sc, ver, fmt.Sprintf("%s In-Scope Finding", sc), "INFORMATIONAL", "valid-ref"); err != nil {
			t.Fatalf("register %s: %v", sc, err)
		}
	}

	// Register Nuclei emitting 1 in-scope and 2 out-of-scope findings (metadata + rfc1918)
	digest := "sha256:" + strings.Repeat("7", 64)
	nucleiRogue := harnessMockAdapter{
		name:    adapters.ScannerNuclei,
		version: "3.3.0",
		digest:  digest,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			now := time.Now().UTC()
			code := 0
			findings := []json.RawMessage{
				json.RawMessage(`{
					"schema_version": "1.0",
					"title": "Nuclei In-Scope Issue",
					"severity": "CRITICAL",
					"confidence": 0.95,
					"target": {"asset": "approved.example.com", "endpoint": "https://approved.example.com/vuln"},
					"vulnerability": {"template_id": "cve-2021-44228"},
					"scanner": {"name": "nuclei", "adapter_version": "3.3.0"},
					"discovered_at": "2026-11-18T10:00:00Z"
				}`),
				json.RawMessage(`{
					"schema_version": "1.0",
					"title": "Nuclei Cloud Metadata Pivot",
					"severity": "CRITICAL",
					"confidence": 1.0,
					"target": {"asset": "169.254.169.254", "endpoint": "http://169.254.169.254/latest/user-data"},
					"vulnerability": {"template_id": "aws-metadata"},
					"scanner": {"name": "nuclei", "adapter_version": "3.3.0"},
					"discovered_at": "2026-11-18T10:00:00Z"
				}`),
				json.RawMessage(`{
					"schema_version": "1.0",
					"title": "Nuclei RFC1918 Internal Pivot",
					"severity": "HIGH",
					"confidence": 0.9,
					"target": {"asset": "172.16.0.5", "endpoint": "http://172.16.0.5/admin"},
					"vulnerability": {"template_id": "internal-admin"},
					"scanner": {"name": "nuclei", "adapter_version": "3.3.0"},
					"discovered_at": "2026-11-18T10:00:00Z"
				}`),
			}
			return adapters.Result{
				SchemaVersion: "1.0",
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      adapters.ScannerNuclei,
					ScannerVersion: "3.3.0",
					AdapterVersion: "3.3.0",
					RunID:          task.JobID,
					StartedAt:      now.Add(-50 * time.Millisecond),
					CompletedAt:    now,
					CorrelationID:  task.CorrelationID,
				},
				Status:       adapters.StatusCompleted,
				ExitCode:     &code,
				Findings:     findings,
				Diagnostics:  []adapters.ExecutionDiagnostic{},
				RawArtifacts: adapters.RawArtifactReferences{},
			}, nil
		},
	}

	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerNuclei,
		DisplayName:      adapters.ScannerNuclei,
		Version:          "3.3.0",
		SupportedTargets: []string{"url"},
		Capabilities:     nucleiRogue.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion:         "3.3.0",
			ImageReference:         adapters.ScannerNuclei + "@" + digest,
			ImageDigest:            digest,
			TemplateCatalogVersion: adapters.PinnedNucleiTemplateCatalogVersion,
			TemplateCatalogDigest:  adapters.PinnedNucleiTemplateCatalogDigest,
		},
	}, func() adapters.ScannerAdapter { return nucleiRogue }); err != nil {
		t.Fatalf("register nuclei rogue: %v", err)
	}

	if err := registry.Initialize(ctx, logger); err != nil {
		t.Fatalf("initialize registry: %v", err)
	}

	executor := sandbox.NewFake()
	orchestrator := NewOrchestrator(registry, executor, nil, nil, nil, logger)

	policy, _ := scope.NewPolicy([]string{"approved.example.com"}, nil, nil)
	cfg := Config{
		ScopePolicyProvider: func(context.Context, adapters.Task) (scope.Policy, error) {
			return policy, nil
		},
	}

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Target:       "https://approved.example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 60 * time.Second,
	}

	res, err := orchestrator.ExecutePipeline(ctx, logger, task, cfg)
	if err != nil {
		t.Fatalf("ExecutePipeline failed: %v", err)
	}

	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	// 5 scanners emitted 1 finding each, Nuclei emitted 1 in-scope and 2 rogue.
	// Total accepted in-scope findings must be exactly 6 (5 + 1).
	if report.TotalFindings != 6 {
		t.Errorf("expected exactly 6 accepted findings after quarantine, got %d", report.TotalFindings)
	}

	// Output envelope check
	env, err := adapters.DecodeOutputEnvelope(res.OutputEnvelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(env.Findings) != 6 {
		t.Errorf("expected 6 findings in envelope, got %d", len(env.Findings))
	}

	// Verify diagnostics recorded the 2 quarantined Nuclei findings
	quarantineDiags := 0
	for _, diag := range env.Diagnostics {
		if diag.Code == "OUT_OF_SCOPE_TARGET_REJECTED" {
			quarantineDiags++
		}
	}
	if quarantineDiags != 2 {
		t.Errorf("expected 2 OUT_OF_SCOPE_TARGET_REJECTED diagnostics, got %d (all diags: %+v)", quarantineDiags, env.Diagnostics)
	}

	// Verify manifest digest is valid
	if report.ManifestDigest == "" {
		t.Error("expected non-empty manifest digest")
	}
}
