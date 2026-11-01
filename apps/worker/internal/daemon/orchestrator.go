package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/apps/worker/internal/scannerprocess"
	"github.com/kelvin/kelvin/apps/worker/internal/workspace"
	"go.uber.org/zap"
)

const (
	JobTypeAssessment = "assessment"
	JobTypePipeline   = "pipeline"
)

// AssessmentPipelineReport details multi-phase scanner pipeline execution.
type AssessmentPipelineReport struct {
	AssessmentID  string                           `json:"assessment_id"`
	TenantID      string                           `json:"tenant_id"`
	ProfileID     string                           `json:"profile_id"`
	Target        string                           `json:"target"`
	StartedAt     time.Time                        `json:"started_at"`
	CompletedAt   time.Time                        `json:"completed_at"`
	Duration      time.Duration                    `json:"duration_ms"`
	ScannersRun   []string                         `json:"scanners_run"`
	PhaseResults  []PhaseResult                    `json:"phase_results"`
	TotalFindings int                              `json:"total_findings"`
	Envelopes     []adapters.ScannerOutputEnvelope `json:"envelopes"`
}

type PhaseResult struct {
	PhaseIndex int      `json:"phase_index"`
	PhaseName  string   `json:"phase_name"`
	Scanners   []string `json:"scanners"`
	Success    bool     `json:"success"`
	Error      string   `json:"error,omitempty"`
}

// Orchestrator coordinates adapter discovery, profile validation, and execution dispatch.
type Orchestrator struct {
	registry  *adapters.Registry
	executor  sandbox.Executor
	limits    any
	metrics   *metrics.Registry
	readiness *readiness.Checker
	wsManager *workspace.Manager
	logger    *zap.Logger
}

func NewOrchestrator(registry *adapters.Registry, executor sandbox.Executor, checker *readiness.Checker, wsMgr *workspace.Manager, reg *metrics.Registry, logger *zap.Logger) *Orchestrator {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Orchestrator{
		registry:  registry,
		executor:  executor,
		readiness: checker,
		wsManager: wsMgr,
		metrics:   reg,
		logger:    logger,
	}
}

func (o *Orchestrator) ensureWorkspaceManager(cfg Config) *workspace.Manager {
	if o.wsManager != nil {
		return o.wsManager
	}
	if cfg.WorkspaceManager != nil {
		o.wsManager = cfg.WorkspaceManager
		return o.wsManager
	}
	mgr, _ := workspace.NewManager("", o.logger)
	o.wsManager = mgr
	return o.wsManager
}

// ExecuteScanner executes an individual resolved scanner adapter, choosing in-process
// execution or OCI container sandboxing based on the adapter's declared capabilities.
func (o *Orchestrator) ExecuteScanner(ctx context.Context, jobLog *zap.Logger, task adapters.Task, cfg Config) (*sandbox.Result, error) {
	adapter, ok := o.registry.LookupExecutable(task.Scanner)
	if !ok {
		return nil, fmt.Errorf("no executable adapter registered for scanner %q", task.Scanner)
	}

	if err := o.registry.VerifyRuntime(ctx, task.Scanner); err != nil {
		return nil, fmt.Errorf("scanner version compatibility check failed: %w", err)
	}

	metadata, ok := o.registry.Metadata(task.Scanner)
	if !ok {
		return nil, fmt.Errorf("scanner metadata unavailable for %q", task.Scanner)
	}

	if err := adapter.ValidateConfig(task.Payload); err != nil {
		return nil, fmt.Errorf("invalid scanner configuration: %w", err)
	}

	if err := adapter.Health(ctx); err != nil {
		return nil, fmt.Errorf("scanner adapter unavailable: %w", err)
	}

	executionDeadline, err := scannerprocess.EffectiveDeadline(task)
	if err != nil {
		return nil, fmt.Errorf("scanner duration policy rejected: %w", err)
	}
	task.HardDeadline = executionDeadline

	execCtx, cancel := context.WithTimeout(ctx, task.HardDeadline)
	defer cancel()

	// Provision isolated per-execution workspace
	wsMgr := o.ensureWorkspaceManager(cfg)
	ws, err := wsMgr.Create(ctx, task.TenantID, task.AssessmentID, task.JobID)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution workspace: %w", err)
	}
	defer func() {
		if err := ws.Cleanup(); err != nil {
			jobLog.Warn("failed to cleanup workspace", zap.Error(err), zap.String("workspace", ws.RootDir))
		}
	}()

	// 1. In-process execution (requires no external sandbox/container)
	if !metadata.Capabilities.RequiresSandbox {
		res, err := adapter.Execute(execCtx, task)
		if err != nil {
			return nil, err
		}

		if err := o.registry.StampOutput(task.Scanner, &res); err != nil {
			return nil, fmt.Errorf("stamp output failed: %w", err)
		}

		encoded, err := adapters.EncodeOutputEnvelope(res)
		if err != nil {
			return nil, fmt.Errorf("encode output envelope failed: %w", err)
		}

		duration := time.Duration(res.DurationMS) * time.Millisecond
		if duration <= 0 {
			duration = time.Millisecond
		}

		return &sandbox.Result{
			Duration:       duration,
			OutputEnvelope: encoded,
			ExitCode:       0,
		}, nil
	}

	// 2. Sandboxed container execution
	if cfg.Executor == nil {
		return nil, fmt.Errorf("no sandbox executor configured for containerized scanner %q", task.Scanner)
	}

	invocation, err := scannerprocess.Build(task)
	if err != nil {
		return nil, fmt.Errorf("scanner invocation rejected: %w", err)
	}

	spec := specFromTask(task, metadata.VersionPolicy.ImageReference, invocation, ws.RootDir)
	spec.CaptureZAPReport = task.Scanner == adapters.ScannerZAPBaseline
	spec.Limits = cfg.Limits
	if err := spec.Validate(); err != nil {
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseSpecInvalid)
		}
		return nil, fmt.Errorf("sandbox spec violates isolation profile: %w", err)
	}

	result, execErr := cfg.Executor.Execute(execCtx, spec)
	if task.Scanner == adapters.ScannerZAPBaseline && result != nil && execErr == nil && result.ExitCode == 0 {
		completed := time.Now().UTC()
		started := completed.Add(-result.Duration)
		envelope, normalizeErr := adapters.NormalizeZAPReport(task, result.Findings, metadata.VersionPolicy.ScannerVersion, started, completed)
		if normalizeErr == nil {
			normalizeErr = o.registry.StampOutput(task.Scanner, &envelope)
		}
		if normalizeErr == nil {
			result.OutputEnvelope, normalizeErr = adapters.EncodeOutputEnvelope(envelope)
		}
		if normalizeErr != nil {
			execErr = fmt.Errorf("invalid ZAP report: %w", normalizeErr)
		}
	} else if isNucleiAdapter(adapter) && result != nil && execErr == nil && result.ExitCode == 0 {
		completed := time.Now().UTC()
		started := completed.Add(-result.Duration)
		raw := result.Findings
		if len(raw) == 0 && len(result.Stdout) > 0 {
			raw = []byte(result.Stdout)
		}
		envelope, normalizeErr := adapters.NormalizeNucleiReport(task, raw, metadata.VersionPolicy.ScannerVersion, metadata.VersionPolicy.TemplateCatalogVersion, metadata.VersionPolicy.TemplateCatalogDigest, started, completed)
		if normalizeErr == nil {
			normalizeErr = o.registry.StampOutput(task.Scanner, &envelope)
		}
		if normalizeErr == nil {
			result.OutputEnvelope, normalizeErr = adapters.EncodeOutputEnvelope(envelope)
		}
		if normalizeErr != nil {
			execErr = fmt.Errorf("invalid Nuclei report: %w", normalizeErr)
		}
	}

	return result, execErr
}

// ExecutePipeline coordinates execution of all scanners defined by an assessment profile.
func (o *Orchestrator) ExecutePipeline(ctx context.Context, jobLog *zap.Logger, task adapters.Task, cfg Config) (*sandbox.Result, error) {
	profile, err := adapters.GetAssessmentProfile(task.ProfileID)
	if err != nil {
		return nil, fmt.Errorf("invalid assessment profile %q: %w", task.ProfileID, err)
	}

	started := time.Now().UTC()
	report := AssessmentPipelineReport{
		AssessmentID: task.AssessmentID,
		TenantID:     task.TenantID,
		ProfileID:    profile.ProfileID,
		Target:       task.Target,
		StartedAt:    started,
	}

	prevPhaseSucceeded := true

	for _, phase := range profile.DefaultScannerOrder {
		phaseRes := PhaseResult{
			PhaseIndex: phase.PhaseIndex,
			PhaseName:  phase.PhaseName,
			Scanners:   phase.Scanners,
			Success:    true,
		}

		if phase.RequirePrev && !prevPhaseSucceeded {
			phaseRes.Success = false
			phaseRes.Error = "skipped because previous prerequisite phase failed"
			report.PhaseResults = append(report.PhaseResults, phaseRes)
			jobLog.Warn("skipping assessment phase due to prerequisite failure",
				zap.Int("phase_index", phase.PhaseIndex),
				zap.String("phase_name", phase.PhaseName),
			)
			break
		}

		for _, scannerID := range phase.Scanners {
			if o.readiness != nil && !o.readiness.IsScannerReady(ctx, scannerID) {
				phaseRes.Success = false
				phaseRes.Error = fmt.Sprintf("scanner %q is not ready", scannerID)
				prevPhaseSucceeded = false
				break
			}

			subTask := task
			subTask.Scanner = scannerID

			subResult, err := o.ExecuteScanner(ctx, jobLog, subTask, cfg)
			if err != nil || (subResult != nil && subResult.ExitCode != 0) {
				phaseRes.Success = false
				if err != nil {
					phaseRes.Error = err.Error()
				} else {
					phaseRes.Error = fmt.Sprintf("scanner exited with code %d", subResult.ExitCode)
				}
				prevPhaseSucceeded = false
				break
			}

			report.ScannersRun = append(report.ScannersRun, scannerID)

			if len(subResult.OutputEnvelope) > 0 {
				env, err := adapters.DecodeOutputEnvelope(subResult.OutputEnvelope)
				if err == nil {
					report.Envelopes = append(report.Envelopes, env)
					report.TotalFindings += len(env.Findings)
				}
			}
		}

		report.PhaseResults = append(report.PhaseResults, phaseRes)
		if !phaseRes.Success && phase.RequirePrev {
			break
		}
	}

	report.CompletedAt = time.Now().UTC()
	report.Duration = report.CompletedAt.Sub(started)

	rawReport, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pipeline report: %w", err)
	}

	envelope := adapters.ScannerOutputEnvelope{
		SchemaVersion: "1.0",
		Metadata: adapters.OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      "pipeline",
			ScannerVersion: "1.0.0",
			AdapterVersion: "1.0.0",
			RunID:          task.JobID,
			StartedAt:      started,
			CompletedAt:    report.CompletedAt,
			CorrelationID:  task.CorrelationID,
		},
		Status:      adapters.StatusCompleted,
		ExitCode:    intPtr(0),
		Findings:    []json.RawMessage{},
		Diagnostics: []adapters.ExecutionDiagnostic{},
	}
	encodedEnv, _ := adapters.EncodeOutputEnvelope(envelope)

	return &sandbox.Result{
		Duration:       report.Duration,
		Stdout:         string(rawReport),
		OutputEnvelope: encodedEnv,
		ExitCode:       0,
	}, nil
}

func intPtr(i int) *int {
	return &i
}

func isNucleiAdapter(a adapters.ScannerAdapter) bool {
	_, ok := a.(*adapters.NucleiAdapter)
	return ok
}
