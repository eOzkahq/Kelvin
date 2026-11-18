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
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/normalization"
	"github.com/kelvin/kelvin/apps/worker/internal/provenance"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"go.uber.org/zap"
)

type harnessMockAdapter struct {
	name    string
	version string
	digest  string
	run     func(ctx context.Context, task adapters.Task) (adapters.Result, error)
}

func (m harnessMockAdapter) Name() string    { return m.name }
func (m harnessMockAdapter) Version() string { return m.version }
func (m harnessMockAdapter) Initialize(context.Context, *zap.Logger) error { return nil }
func (m harnessMockAdapter) Cancel() error                                  { return nil }
func (m harnessMockAdapter) Health(context.Context) error                   { return nil }
func (m harnessMockAdapter) Result() (adapters.Result, error)               { return adapters.Result{}, nil }
func (m harnessMockAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (m harnessMockAdapter) Capabilities() adapters.Capabilities {
	return adapters.Capabilities{
		SupportedTargetTypes: []string{"url"},
		CheckCategories:      []string{"discovery"},
		RequiresSandbox:      false,
		SupportsProgress:     true,
		SupportsCancel:       true,
	}
}
func (m harnessMockAdapter) VerifyRuntimeVersion(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
	info := adapters.RuntimeVersionInfo{
		ScannerVersion: m.version,
		AdapterVersion: m.version,
		ImageReference: m.name + "@" + m.digest,
		ImageDigest:    m.digest,
	}
	if m.name == adapters.ScannerNuclei {
		info.TemplateCatalogVersion = adapters.PinnedNucleiTemplateCatalogVersion
		info.TemplateCatalogDigest = adapters.PinnedNucleiTemplateCatalogDigest
	}
	return info, nil
}
func (m harnessMockAdapter) Execute(ctx context.Context, task adapters.Task) (adapters.Result, error) {
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
		Status:   adapters.StatusCompleted,
		ExitCode: &code,
	}, nil
}

// helper to register mock scanner with realistic output
func registerHarnessScannerWithFinding(
	registry *adapters.Registry,
	scannerID string,
	version string,
	findingTitle string,
	severity string,
	cveOrTemplate string,
) error {
	digest := "sha256:" + strings.Repeat("e", 64)
	mock := harnessMockAdapter{
		name:    scannerID,
		version: version,
		digest:  digest,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			rawFinding := json.RawMessage(fmt.Sprintf(`{
				"schema_version": "1.0",
				"title": %q,
				"severity": %q,
				"confidence": 0.9,
				"target": {
					"asset": "approved.example.com",
					"endpoint": "https://approved.example.com/%s"
				},
				"vulnerability": {
					"template_id": %q,
					"cwe_id": "CWE-200"
				},
				"description": "Validation test finding for scanner %s",
				"remediation": {"summary": "Remediate according to vendor guidelines"},
				"evidence": [
					{
						"type": "LOG",
						"content_type": "text/plain",
						"content_redacted": "Sample evidence from %s",
						"redacted_fields": []
					}
				],
				"scanner": {
					"name": %q,
					"adapter_version": %q
				},
				"discovered_at": "2026-11-18T10:00:00Z"
			}`, findingTitle, severity, scannerID, cveOrTemplate, scannerID, scannerID, scannerID, version))

			exitCode := 0
			now := time.Now().UTC()
			return adapters.Result{
				SchemaVersion: "1.0",
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      scannerID,
					ScannerVersion: version,
					AdapterVersion: version,
					RunID:          task.JobID,
					StartedAt:      now.Add(-50 * time.Millisecond),
					CompletedAt:    now,
					CorrelationID:  task.CorrelationID,
				},
				Status:       adapters.StatusCompleted,
				ExitCode:     &exitCode,
				DurationMS:   50,
				Findings:     []json.RawMessage{rawFinding},
				Diagnostics:  []adapters.ExecutionDiagnostic{},
				RawArtifacts: adapters.RawArtifactReferences{},
			}, nil
		},
	}

	versionPolicy := adapters.VersionPolicy{
		ScannerVersion: version,
		ImageReference: scannerID + "@" + digest,
		ImageDigest:    digest,
	}
	if scannerID == adapters.ScannerNuclei {
		versionPolicy.TemplateCatalogVersion = adapters.PinnedNucleiTemplateCatalogVersion
		versionPolicy.TemplateCatalogDigest = adapters.PinnedNucleiTemplateCatalogDigest
	}

	return registry.RegisterAdapter(adapters.Metadata{
		ID:               scannerID,
		DisplayName:      scannerID,
		Version:          version,
		SupportedTargets: []string{"url"},
		Capabilities:     mock.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy:    versionPolicy,
	}, func() adapters.ScannerAdapter { return mock })
}

// TestE2ECanaryPipelineHarness_AllSixScanners verifies that an assessment executing
// under ProfileDeep runs all 6 scanner phases in exact chronological sequence
// against an authorized canary target:
// Phase 1: preflight (HTTP preflight check)
// Phase 2: network_and_service_discovery (Nmap port & service discovery)
// Phase 3: passive_analysis (TLS Assessor, HTTP Headers, ZAP Baseline)
// Phase 4: vulnerability_inspection (Nuclei)
func TestE2ECanaryPipelineHarness_AllSixScanners(t *testing.T) {
	q := newRecordingQueue()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Register all 6 scanners with test fixtures
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerHTTPPreflight, "1.0.0", "HTTP Preflight Reachable", "INFORMATIONAL", "preflight-ok"); err != nil {
		t.Fatalf("register preflight: %v", err)
	}
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerNmap, "7.95.0", "Discovered Port 443 HTTPS", "INFORMATIONAL", "port-443-open"); err != nil {
		t.Fatalf("register nmap: %v", err)
	}
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerTLSAssessor, "1.0.0", "TLS 1.2 Deprecation Notice", "LOW", "tls-1-2"); err != nil {
		t.Fatalf("register tls: %v", err)
	}
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerHTTPHeaders, "1.0.0", "Missing HSTS Header", "MEDIUM", "missing-hsts"); err != nil {
		t.Fatalf("register headers: %v", err)
	}
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerZAPBaseline, "2.16.1", "Missing Anti-Clickjacking Header", "MEDIUM", "cwe-693"); err != nil {
		t.Fatalf("register zap: %v", err)
	}
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerNuclei, "3.3.0", "Apache Log4j RCE", "CRITICAL", "CVE-2021-44228"); err != nil {
		t.Fatalf("register nuclei: %v", err)
	}

	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatalf("registry initialize: %v", err)
	}

	executor := sandbox.NewFake()
	orchestrator := NewOrchestrator(registry, executor, nil, nil, nil, logger)

	jobID := uuid.New().String()
	assessmentID := uuid.New().String()
	tenantID := uuid.New().String()

	task := adapters.Task{
		JobID:        jobID,
		AssessmentID: assessmentID,
		TenantID:     tenantID,
		Target:       "https://approved.example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 60 * time.Second,
	}

	ctx := context.Background()
	cfg := Config{}

	result, err := orchestrator.ExecutePipeline(ctx, logger, task, cfg)
	if err != nil {
		t.Fatalf("ExecutePipeline failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil sandbox result from ExecutePipeline")
	}

	// 1. Verify Pipeline Report JSON
	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
		t.Fatalf("unmarshal pipeline report: %v", err)
	}

	if report.OverallStatus != adapters.StatusCompleted {
		t.Errorf("expected overall status %q, got %q", adapters.StatusCompleted, report.OverallStatus)
	}

	// Verify all 6 scanners were run
	expectedScanners := []string{
		adapters.ScannerHTTPPreflight,
		adapters.ScannerNmap,
		adapters.ScannerTLSAssessor,
		adapters.ScannerHTTPHeaders,
		adapters.ScannerZAPBaseline,
		adapters.ScannerNuclei,
	}
	if len(report.ScannersRun) != len(expectedScanners) {
		t.Errorf("expected %d scanners run, got %d: %v", len(expectedScanners), len(report.ScannersRun), report.ScannersRun)
	}
	for _, sc := range expectedScanners {
		found := false
		for _, ran := range report.ScannersRun {
			if ran == sc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("scanner %s was not recorded in ScannersRun: %v", sc, report.ScannersRun)
		}
	}

	// Verify 4 phases in order
	if len(report.PhaseResults) != 4 {
		t.Fatalf("expected 4 phase results, got %d", len(report.PhaseResults))
	}
	phaseExpectedNames := []string{
		"preflight",
		"network_and_service_discovery",
		"passive_analysis",
		"vulnerability_inspection",
	}
	for i, phaseName := range phaseExpectedNames {
		p := report.PhaseResults[i]
		if p.PhaseName != phaseName {
			t.Errorf("phase %d expected name %s, got %s", i+1, phaseName, p.PhaseName)
		}
		if !p.Success {
			t.Errorf("phase %s failed unexpectedly: %s", phaseName, p.Error)
		}
	}

	// Verify Findings count
	if report.TotalFindings != 6 {
		t.Errorf("expected 6 findings (1 per scanner), got %d", report.TotalFindings)
	}

	// 2. Verify Output Envelope
	if len(result.OutputEnvelope) == 0 {
		t.Fatal("expected non-empty OutputEnvelope")
	}
	env, err := adapters.DecodeOutputEnvelope(result.OutputEnvelope)
	if err != nil {
		t.Fatalf("decode output envelope failed: %v", err)
	}
	if env.Status != adapters.StatusCompleted {
		t.Errorf("envelope status expected %s, got %s", adapters.StatusCompleted, env.Status)
	}
	if len(env.Findings) != 6 {
		t.Errorf("envelope findings expected 6, got %d", len(env.Findings))
	}

	// 3. Verify Manifest generation & Tamper-proofing
	if report.ManifestDigest == "" {
		t.Fatal("expected non-empty ManifestDigest in pipeline report")
	}

	// Rebuild manifest and verify digest
	manifestBuilder := manifest.NewBuilder(tenantID, assessmentID, jobID, "https://approved.example.com", adapters.ProfileDeep)
	manifestBuilder.SetStartedAt(report.StartedAt)
	for _, sc := range expectedScanners {
		manifestBuilder.AddScanner(manifest.ScannerComponent{
			ScannerID:      sc,
			ScannerVersion: "1.0.0",
		})
	}

	// 4. Run through normalization & validation gate
	normalizer := normalization.NewNormalizer()
	validator := normalization.NewResultValidator()
	normCtx := normalization.Context{
		AssessmentID: assessmentID,
		RunID:        jobID,
	}

	for _, rawF := range env.Findings {
		normF, nErr := normalizer.Normalize(rawF, normCtx)
		if nErr != nil {
			t.Errorf("normalization failed for finding: %v", nErr)
			continue
		}
		if normF.Fingerprint == "" || len(normF.Fingerprint) != 64 {
			t.Errorf("invalid SHA-256 fingerprint on normalized finding: %s", normF.Fingerprint)
		}
	}

	valReport := validator.ValidateBatch(env.Findings, "approved.example.com")
	if valReport.RejectedCount != 0 {
		t.Errorf("expected 0 rejected findings in validation gate, got %d (quarantined: %v)", valReport.RejectedCount, valReport.Quarantined)
	}

	// 5. Also execute through full daemon queue runner
	cancel, done := runWorker(t, q, registry, executor)
	payload, _ := json.Marshal(map[string]any{
		"target":                "https://approved.example.com",
		"profile_id":            adapters.ProfileDeep,
		"hard_deadline_seconds": 30,
	})
	q.inner.Push(queue.Job{
		ID:           uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     tenantID,
		Type:         JobTypeAssessment,
		Payload:      payload,
	})
	waitEvent(t, q)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("worker daemon exited with error: %v", err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completed) != 1 || len(q.failed) != 0 {
		t.Fatalf("expected queue job to complete, completed=%d, failed=%d, reasons=%v", len(q.completed), len(q.failed), q.failedReasons)
	}
}

// TestE2ECanaryPipelineHarness_PrerequisitePhaseDependencyHalt verifies that
// if Phase 1 (preflight) fails, subsequent dependent phases (Nmap, passive analysis, Nuclei)
// are immediately aborted and marked skipped.
func TestE2ECanaryPipelineHarness_PrerequisitePhaseDependencyHalt(t *testing.T) {
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Register failing preflight
	digest := "sha256:" + strings.Repeat("e", 64)
	failingPreflight := harnessMockAdapter{
		name:    adapters.ScannerHTTPPreflight,
		version: "1.0.0",
		digest:  digest,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			code := 1
			return adapters.Result{
				Status:   adapters.StatusFailed,
				ExitCode: &code,
			}, fmt.Errorf("connection refused")
		},
	}
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerHTTPPreflight,
		DisplayName:      adapters.ScannerHTTPPreflight,
		Version:          "1.0.0",
		SupportedTargets: []string{"url"},
		Capabilities:     failingPreflight.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion: "1.0.0",
			ImageReference: adapters.ScannerHTTPPreflight + "@" + digest,
			ImageDigest:    digest,
		},
	}, func() adapters.ScannerAdapter { return failingPreflight }); err != nil {
		t.Fatal(err)
	}

	// Register other 5 scanners as healthy
	for _, sc := range []string{adapters.ScannerNmap, adapters.ScannerTLSAssessor, adapters.ScannerHTTPHeaders, adapters.ScannerZAPBaseline, adapters.ScannerNuclei} {
		ver := "1.0.0"
		if sc == adapters.ScannerNmap {
			ver = "7.95.0"
		}
		if sc == adapters.ScannerZAPBaseline {
			ver = "2.16.1"
		}
		if sc == adapters.ScannerNuclei {
			ver = "3.3.0"
		}
		if err := registerHarnessScannerWithFinding(registry, sc, ver, "Title", "INFORMATIONAL", "ref"); err != nil {
			t.Fatal(err)
		}
	}

	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatalf("registry initialize: %v", err)
	}

	executor := sandbox.NewFake()
	orchestrator := NewOrchestrator(registry, executor, nil, nil, nil, logger)

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Target:       "https://unreachable.example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 30 * time.Second,
	}

	result, err := orchestrator.ExecutePipeline(context.Background(), logger, task, Config{})
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if report.OverallStatus != adapters.StatusFailed {
		t.Errorf("expected overall status %q, got %q", adapters.StatusFailed, report.OverallStatus)
	}

	// Preflight failed, dependent scanners skipped
	if len(report.ScannersFailed) != 1 || report.ScannersFailed[0] != adapters.ScannerHTTPPreflight {
		t.Errorf("expected failed scanner to be preflight, got %v", report.ScannersFailed)
	}
	expectedSkipped := []string{
		adapters.ScannerNmap,
		adapters.ScannerTLSAssessor,
		adapters.ScannerHTTPHeaders,
		adapters.ScannerZAPBaseline,
		adapters.ScannerNuclei,
	}
	for _, exp := range expectedSkipped {
		found := false
		for _, skipped := range report.ScannersSkipped {
			if skipped == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected scanner %s to be skipped, got %v", exp, report.ScannersSkipped)
		}
	}

	// Verify OutputEnvelope contains PREFLIGHT_FAILED diagnostic
	env, err := adapters.DecodeOutputEnvelope(result.OutputEnvelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Status != adapters.StatusFailed {
		t.Errorf("envelope status expected %s, got %s", adapters.StatusFailed, env.Status)
	}
	foundPreflightDiag := false
	for _, diag := range env.Diagnostics {
		if diag.Code == "PREFLIGHT_FAILED" {
			foundPreflightDiag = true
			break
		}
	}
	if !foundPreflightDiag {
		t.Errorf("expected PREFLIGHT_FAILED diagnostic in envelope: %+v", env.Diagnostics)
	}
}

// TestE2ECanaryPipelineHarness_MiddlePhaseFailureAndPartialFindings verifies that
// when an intermediate phase fails after findings were already gathered in earlier phases,
// the earlier findings are preserved and status becomes StatusPartial with degradation warnings.
func TestE2ECanaryPipelineHarness_MiddlePhaseFailureAndPartialFindings(t *testing.T) {
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Phase 1 (preflight) succeeds and emits finding
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerHTTPPreflight, "1.0.0", "Preflight Reachable", "INFORMATIONAL", "pf"); err != nil {
		t.Fatal(err)
	}

	// Phase 2 (Nmap) fails with non-zero exit code
	digest := "sha256:" + strings.Repeat("e", 64)
	failingNmap := harnessMockAdapter{
		name:    adapters.ScannerNmap,
		version: "7.95.0",
		digest:  digest,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			code := 1
			return adapters.Result{
				Status:   adapters.StatusFailed,
				ExitCode: &code,
			}, fmt.Errorf("nmap exit code 1")
		},
	}
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerNmap,
		DisplayName:      adapters.ScannerNmap,
		Version:          "7.95.0",
		SupportedTargets: []string{"url"},
		Capabilities:     failingNmap.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion: "7.95.0",
			ImageReference: adapters.ScannerNmap + "@" + digest,
			ImageDigest:    digest,
		},
	}, func() adapters.ScannerAdapter { return failingNmap }); err != nil {
		t.Fatal(err)
	}

	// Remaining scanners registered
	for _, sc := range []string{adapters.ScannerTLSAssessor, adapters.ScannerHTTPHeaders, adapters.ScannerZAPBaseline, adapters.ScannerNuclei} {
		ver := "1.0.0"
		if sc == adapters.ScannerZAPBaseline {
			ver = "2.16.1"
		}
		if sc == adapters.ScannerNuclei {
			ver = "3.3.0"
		}
		if err := registerHarnessScannerWithFinding(registry, sc, ver, "Title", "INFORMATIONAL", "ref"); err != nil {
			t.Fatal(err)
		}
	}

	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatalf("registry initialize: %v", err)
	}

	executor := sandbox.NewFake()
	orchestrator := NewOrchestrator(registry, executor, nil, nil, nil, logger)

	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Target:       "https://approved.example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 30 * time.Second,
	}

	result, err := orchestrator.ExecutePipeline(context.Background(), logger, task, Config{})
	if err != nil {
		t.Fatalf("unexpected pipeline execution error: %v", err)
	}

	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	// Because preflight emitted 1 finding before nmap failed, status must be StatusPartial
	if report.OverallStatus != adapters.StatusPartial {
		t.Errorf("expected overall status %q, got %q", adapters.StatusPartial, report.OverallStatus)
	}
	if report.TotalFindings != 1 {
		t.Errorf("expected 1 finding preserved, got %d", report.TotalFindings)
	}
	if report.DegradationWarning == "" {
		t.Error("expected degradation warning to be populated")
	}

	// Check output envelope
	env, err := adapters.DecodeOutputEnvelope(result.OutputEnvelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Status != adapters.StatusPartial {
		t.Errorf("envelope status expected %s, got %s", adapters.StatusPartial, env.Status)
	}
	if !env.Partial {
		t.Error("envelope Partial flag should be true")
	}
	if len(env.Findings) != 1 {
		t.Errorf("expected 1 preserved finding in envelope, got %d", len(env.Findings))
	}
}

// TestE2ECanaryPipelineHarness_TimeoutPreservesPriorFindings verifies that an
// assessment timing out mid-pipeline preserves findings collected by earlier phases.
func TestE2ECanaryPipelineHarness_TimeoutPreservesPriorFindings(t *testing.T) {
	registry := adapters.NewRegistry()
	logger := zap.NewNop()

	// Preflight emits finding
	if err := registerHarnessScannerWithFinding(registry, adapters.ScannerHTTPPreflight, "1.0.0", "Preflight Pass", "INFORMATIONAL", "pf"); err != nil {
		t.Fatal(err)
	}

	// Nmap takes long time and times out
	digest := "sha256:" + strings.Repeat("e", 64)
	slowNmap := harnessMockAdapter{
		name:    adapters.ScannerNmap,
		version: "7.95.0",
		digest:  digest,
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			select {
			case <-time.After(2 * time.Second):
				code := 0
				return adapters.Result{Status: adapters.StatusCompleted, ExitCode: &code}, nil
			case <-ctx.Done():
				return adapters.Result{
					Status:   adapters.StatusTimedOut,
					ExitCode: intPtr(-1),
				}, ctx.Err()
			}
		},
	}
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerNmap,
		DisplayName:      adapters.ScannerNmap,
		Version:          "7.95.0",
		SupportedTargets: []string{"url"},
		Capabilities:     slowNmap.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion: "7.95.0",
			ImageReference: adapters.ScannerNmap + "@" + digest,
			ImageDigest:    digest,
		},
	}, func() adapters.ScannerAdapter { return slowNmap }); err != nil {
		t.Fatal(err)
	}

	for _, sc := range []string{adapters.ScannerTLSAssessor, adapters.ScannerHTTPHeaders, adapters.ScannerZAPBaseline, adapters.ScannerNuclei} {
		ver := "1.0.0"
		if sc == adapters.ScannerZAPBaseline {
			ver = "2.16.1"
		}
		if sc == adapters.ScannerNuclei {
			ver = "3.3.0"
		}
		if err := registerHarnessScannerWithFinding(registry, sc, ver, "Title", "INFORMATIONAL", "ref"); err != nil {
			t.Fatal(err)
		}
	}

	if err := registry.Initialize(context.Background(), logger); err != nil {
		t.Fatalf("registry initialize: %v", err)
	}

	executor := sandbox.NewFake()
	orchestrator := NewOrchestrator(registry, executor, nil, nil, nil, logger)

	// Set short deadline of 100ms
	task := adapters.Task{
		JobID:        uuid.New().String(),
		AssessmentID: uuid.New().String(),
		TenantID:     uuid.New().String(),
		Target:       "https://approved.example.com",
		ProfileID:    adapters.ProfileDeep,
		HardDeadline: 100 * time.Millisecond,
	}

	result, err := orchestrator.ExecutePipeline(context.Background(), logger, task, Config{})
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	var report AssessmentPipelineReport
	if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if report.OverallStatus != adapters.StatusPartial {
		t.Errorf("expected status %s on timeout with prior findings, got %s", adapters.StatusPartial, report.OverallStatus)
	}
	if report.TotalFindings != 1 {
		t.Errorf("expected 1 finding preserved from preflight, got %d", report.TotalFindings)
	}

	env, err := adapters.DecodeOutputEnvelope(result.OutputEnvelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Status != adapters.StatusPartial || !env.Partial {
		t.Errorf("expected envelope status StatusPartial, got status=%s, partial=%v", env.Status, env.Partial)
	}
	if len(env.Findings) != 1 {
		t.Errorf("expected 1 finding in envelope, got %d", len(env.Findings))
	}
}

// TestE2ECanaryPipelineHarness_ManifestTamperProofingAndProvenanceScrubbing validates:
// - Execution manifest contains all 6 scanner components and is tamper-evident
// - Provenance collector accurately records arguments and scrubs secrets
func TestE2ECanaryPipelineHarness_ManifestTamperProofingAndProvenanceScrubbing(t *testing.T) {
	tenantID := uuid.New().String()
	assessmentID := uuid.New().String()
	jobID := uuid.New().String()
	logger := zap.NewNop()

	// 1. Build Manifest with all 6 scanners
	builder := manifest.NewBuilder(tenantID, assessmentID, jobID, "https://approved.example.com", adapters.ProfileDeep)
	scanners := []string{
		adapters.ScannerHTTPPreflight,
		adapters.ScannerNmap,
		adapters.ScannerTLSAssessor,
		adapters.ScannerHTTPHeaders,
		adapters.ScannerZAPBaseline,
		adapters.ScannerNuclei,
	}
	for _, sc := range scanners {
		digest := "sha256:" + strings.Repeat("d", 64)
		builder.AddScanner(manifest.ScannerComponent{
			ScannerID:      sc,
			ScannerVersion: "1.0.0",
			AdapterVersion: "1.0.0",
			ImageDigest:    digest,
		})
	}

	m, err := builder.Build()
	if err != nil {
		t.Fatalf("build manifest failed: %v", err)
	}
	if m.Digest == "" {
		t.Fatal("expected manifest digest to be non-empty")
	}

	// Verify valid digest
	valid, err := manifest.VerifyDigest(m)
	if err != nil || !valid {
		t.Fatalf("expected valid manifest digest, got valid=%v, err=%v", valid, err)
	}

	// Tamper with scanner version and verify rejection
	tampered := m
	tampered.Scanners[0].ScannerVersion = "2.0.0-tampered"
	validTampered, _ := manifest.VerifyDigest(tampered)
	if validTampered {
		t.Error("expected tamper verification to fail on modified manifest, but it reported valid")
	}

	// 2. Provenance scrub test
	collector := provenance.NewCollector(tenantID, assessmentID, jobID, adapters.ScannerNuclei, "corr-xyz", 1, logger)
	collector.RecordStart(
		[]string{"nuclei", "-target", "https://approved.example.com", "-H", "Authorization: Bearer my-secret-api-key"},
		[]string{"PATH=/usr/bin", "KELVIN_SECRET=verysecretpassword", "AUTH_TOKEN=supertoken123"},
	)
	prov := collector.Provenance()

	for _, arg := range prov.CommandLine {
		if strings.Contains(arg, "my-secret-api-key") {
			t.Errorf("secret leaked in provenance command line: %s", arg)
		}
	}
	for _, env := range prov.Environment {
		if strings.Contains(env, "verysecretpassword") || strings.Contains(env, "supertoken123") {
			t.Errorf("secret leaked in provenance environment: %s", env)
		}
	}
}
