package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/classification"
	"github.com/kelvin/kelvin/apps/worker/internal/egress"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/pacing"
	"github.com/kelvin/kelvin/apps/worker/internal/progress"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/retry"
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
	AssessmentID       string                           `json:"assessment_id"`
	TenantID           string                           `json:"tenant_id"`
	ProfileID          string                           `json:"profile_id"`
	Target             string                           `json:"target"`
	StartedAt          time.Time                        `json:"started_at"`
	CompletedAt        time.Time                        `json:"completed_at"`
	Duration           time.Duration                    `json:"duration_ms"`
	OverallStatus      adapters.ExecutionStatus         `json:"overall_status"`
	ScannersRun        []string                         `json:"scanners_run"`
	ScannersFailed     []string                         `json:"scanners_failed,omitempty"`
	ScannersSkipped    []string                         `json:"scanners_skipped,omitempty"`
	PhaseResults       []PhaseResult                    `json:"phase_results"`
	TotalFindings      int                              `json:"total_findings"`
	DegradationWarning string                           `json:"degradation_warning,omitempty"`
	Envelopes          []adapters.ScannerOutputEnvelope `json:"envelopes"`
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
	publisher progress.Publisher
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
		publisher: progress.NewNopPublisher(),
	}
}

// SetProgressPublisher configures the progress event broadcaster.
func (o *Orchestrator) SetProgressPublisher(p progress.Publisher) {
	if p != nil {
		o.publisher = p
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
// execution or OCI container sandboxing based on the adapter's declared capabilities,
// with safe bounded retries for transient failures.
func (o *Orchestrator) ExecuteScanner(ctx context.Context, jobLog *zap.Logger, task adapters.Task, cfg Config) (*sandbox.Result, error) {
	retryPolicy := retry.ScannerPolicy(task.Scanner)
	deadline := time.Time{}
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}

	var lastResult *sandbox.Result
	var lastErr error

	for attempt := 0; attempt <= retryPolicy.MaxRetries; attempt++ {
		if attempt > 0 {
			jobLog.Info("retrying scanner execution",
				zap.String("job_id", task.JobID),
				zap.String("scanner", task.Scanner),
				zap.Int("attempt", attempt),
			)
		}

		lastResult, lastErr = o.executeScannerAttempt(ctx, jobLog, task, cfg)
		if lastErr == nil && (lastResult == nil || lastResult.ExitCode == 0) {
			return lastResult, nil
		}

		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(lastErr, sandbox.ErrCancelled) {
			return lastResult, lastErr
		}

		exitCode := 0
		oomKilled := false
		timedOut := false
		stdout := ""
		stderr := ""
		if lastResult != nil {
			exitCode = lastResult.ExitCode
			oomKilled = lastResult.OOMKilled
			timedOut = lastResult.DeadlineExceeded
			stdout = string(lastResult.Stdout)
			stderr = string(lastResult.Stderr)
		}
		cf := classification.Classify(ctx, classification.ClassificationInput{
			Scanner:   task.Scanner,
			ExitCode:  exitCode,
			Stdout:    stdout,
			Stderr:    stderr,
			Err:       lastErr,
			OOMKilled: oomKilled,
			TimedOut:  timedOut,
		})

		shouldRetry, backoff := retryPolicy.ShouldRetry(attempt, cf, deadline)
		if !shouldRetry {
			break
		}

		jobLog.Warn("transient failure detected; backing off before retry",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
			zap.Duration("backoff", backoff),
			zap.Int("next_attempt", attempt+1),
		)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastResult, ctx.Err()
		case <-timer.C:
		}
	}

	return lastResult, lastErr
}

func (o *Orchestrator) executeScannerAttempt(ctx context.Context, jobLog *zap.Logger, task adapters.Task, cfg Config) (*sandbox.Result, error) {
	pub := o.publisher
	if cfg.ProgressPublisher != nil {
		pub = cfg.ProgressPublisher
	}
	tracker := progress.NewTracker(task.AssessmentID, task.JobID, task.TenantID, task.Scanner, pub, jobLog)
	_ = tracker.TransitionTo(ctx, progress.StagePreflight, "running scope checks and pre-execution verification")

	if errors.Is(ctx.Err(), context.Canceled) {
		_ = tracker.FailStage(ctx, progress.StageStatusCancelled, "execution cancelled before start")
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseCancelled)
		}
		o.logger.Info("scanner execution cancelled before start",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
		)
		result := &sandbox.Result{
			Cancelled: true,
			ExitCode:  -1,
		}
		result.OutputEnvelope = buildCancelledEnvelope(task, "", 0)
		return result, sandbox.ErrCancelled
	}

	adapter, ok := o.registry.LookupExecutable(task.Scanner)
	if !ok {
		err := fmt.Errorf("no executable adapter registered for scanner %q", task.Scanner)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	if err := o.registry.VerifyRuntime(ctx, task.Scanner); err != nil {
		err = fmt.Errorf("scanner version compatibility check failed: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	metadata, ok := o.registry.Metadata(task.Scanner)
	if !ok {
		err := fmt.Errorf("scanner metadata unavailable for %q", task.Scanner)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	if err := adapter.ValidateConfig(task.Payload); err != nil {
		err = fmt.Errorf("invalid scanner configuration: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	if err := adapter.Health(ctx); err != nil {
		err = fmt.Errorf("scanner adapter unavailable: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	executionDeadline, err := scannerprocess.EffectiveDeadline(task)
	if err != nil {
		err = fmt.Errorf("scanner duration policy rejected: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining < executionDeadline {
			executionDeadline = remaining
		}
	}
	if executionDeadline <= 0 {
		_ = tracker.FailStage(ctx, progress.StageStatusTimedOut, "scanner execution deadline already expired")
		if cfg.Metrics != nil {
			cfg.Metrics.IncResourceViolation(metrics.ViolationDeadline)
			cfg.Metrics.IncTermination(metrics.CauseDeadline)
		}
		o.logger.Error("scanner execution deadline already expired",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
		)
		result := &sandbox.Result{
			Duration:         0,
			DeadlineExceeded: true,
			ExitCode:         -1,
		}
		result.OutputEnvelope = buildTimedOutEnvelope(task, metadata.VersionPolicy.ScannerVersion, 0)
		return result, sandbox.ErrDeadlineExceeded
	}
	task.HardDeadline = executionDeadline

	execCtx, cancel := context.WithTimeout(ctx, task.HardDeadline)
	defer cancel()

	// Provision isolated per-execution workspace
	wsMgr := o.ensureWorkspaceManager(cfg)
	ws, err := wsMgr.Create(ctx, task.TenantID, task.AssessmentID, task.JobID)
	if err != nil {
		err = fmt.Errorf("failed to create execution workspace: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}
	defer func() {
		if err := ws.Cleanup(); err != nil {
			jobLog.Warn("failed to cleanup workspace", zap.Error(err), zap.String("workspace", ws.RootDir))
		}
	}()

	_ = tracker.TransitionTo(ctx, progress.StageScannerInitialization, "initializing scanner runtime and bounds")

	// 1. In-process execution (requires no external sandbox/container)
	if !metadata.Capabilities.RequiresSandbox {
		_ = tracker.TransitionTo(ctx, progress.StageScannerExecution, "executing scanner process")
		execCtxWithReporter := progress.WithReporter(execCtx, tracker)
		if !metadata.Capabilities.SupportsProgress {
			_ = tracker.ReportProgress(execCtxWithReporter, progress.NewIndeterminateProgress(fmt.Sprintf("executing scanner %q", task.Scanner)))
		}

		res, err := adapter.Execute(execCtxWithReporter, task)
		isCancelled := errors.Is(ctx.Err(), context.Canceled) ||
			errors.Is(execCtx.Err(), context.Canceled) ||
			errors.Is(err, context.Canceled) ||
			errors.Is(err, sandbox.ErrCancelled) ||
			res.Status == adapters.StatusCancelled

		if isCancelled {
			_ = tracker.FailStage(ctx, progress.StageStatusCancelled, "scanner execution cancelled")
			if cfg.Metrics != nil {
				cfg.Metrics.IncTermination(metrics.CauseCancelled)
			}
			_ = adapter.Cancel()
			o.logger.Info("scanner execution cancelled",
				zap.String("job_id", task.JobID),
				zap.String("scanner", task.Scanner),
			)
			if res.Status != adapters.StatusCancelled {
				res.Status = adapters.StatusCancelled
				code := -1
				res.ExitCode = &code
				res.Diagnostics = append(res.Diagnostics, adapters.ExecutionDiagnostic{
					Level:   "error",
					Code:    "CANCELLED",
					Message: fmt.Sprintf("scanner %q execution was cancelled", task.Scanner),
				})
			}
			_ = o.registry.StampOutput(task.Scanner, &res)
			encoded, _ := adapters.EncodeOutputEnvelope(res)
			return &sandbox.Result{
				Duration:       time.Duration(res.DurationMS) * time.Millisecond,
				OutputEnvelope: encoded,
				Cancelled:      true,
				ExitCode:       -1,
			}, sandbox.ErrCancelled
		}

		isTimeout := execCtx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) || res.Status == adapters.StatusTimedOut
		if isTimeout {
			_ = tracker.FailStage(ctx, progress.StageStatusTimedOut, "scanner execution deadline exceeded")
			if cfg.Metrics != nil {
				cfg.Metrics.IncResourceViolation(metrics.ViolationDeadline)
				cfg.Metrics.IncTermination(metrics.CauseDeadline)
			}
			o.logger.Error("scanner execution exceeded hard execution deadline",
				zap.String("job_id", task.JobID),
				zap.String("scanner", task.Scanner),
				zap.Duration("deadline", task.HardDeadline),
			)
			if res.Status != adapters.StatusTimedOut {
				res.Status = adapters.StatusTimedOut
				code := -1
				res.ExitCode = &code
				res.Diagnostics = append(res.Diagnostics, adapters.ExecutionDiagnostic{
					Level:   "error",
					Code:    "DEADLINE_EXCEEDED",
					Message: fmt.Sprintf("scanner %q execution exceeded hard execution deadline of %s", task.Scanner, task.HardDeadline),
				})
			}
			_ = o.registry.StampOutput(task.Scanner, &res)
			encoded, _ := adapters.EncodeOutputEnvelope(res)
			return &sandbox.Result{
				Duration:         task.HardDeadline,
				OutputEnvelope:   encoded,
				DeadlineExceeded: true,
				ExitCode:         -1,
			}, sandbox.ErrDeadlineExceeded
		}
		if err != nil {
			_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
			return nil, err
		}

		_ = tracker.TransitionTo(ctx, progress.StageOutputCollection, "collecting scanner output and diagnostics")
		_ = tracker.TransitionTo(ctx, progress.StageResultNormalization, "normalizing findings into canonical schema")

		if err := o.registry.StampOutput(task.Scanner, &res); err != nil {
			err = fmt.Errorf("stamp output failed: %w", err)
			_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
			return nil, err
		}

		encoded, err := adapters.EncodeOutputEnvelope(res)
		if err != nil {
			err = fmt.Errorf("encode output envelope failed: %w", err)
			_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
			return nil, err
		}

		_ = tracker.CompleteStage(ctx, "scanner execution completed successfully")

		duration := time.Duration(res.DurationMS) * time.Millisecond
		if duration <= 0 {
			duration = time.Millisecond
		}

		exitCode := 0
		if res.ExitCode != nil {
			exitCode = *res.ExitCode
		}

		return &sandbox.Result{
			Duration:       duration,
			OutputEnvelope: encoded,
			ExitCode:       exitCode,
		}, nil
	}

	// 2. Sandboxed container execution
	if cfg.Executor == nil {
		err := fmt.Errorf("no sandbox executor configured for containerized scanner %q", task.Scanner)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	invocation, err := scannerprocess.Build(task)
	if err != nil {
		err = fmt.Errorf("scanner invocation rejected: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	spec := specFromTask(task, metadata.VersionPolicy.ImageReference, invocation, ws.RootDir)
	spec.CaptureZAPReport = task.Scanner == adapters.ScannerZAPBaseline

	scannerLimits, err := limits.ForScanner(task.Scanner, cfg.Limits)
	if err == nil {
		spec.Limits = scannerLimits
	} else if cfg.Limits != (limits.Limits{}) {
		spec.Limits = cfg.Limits
	} else {
		spec.Limits = limits.DefaultLimits()
	}
	spec.MemoryLimit = spec.Limits.MemoryLimit
	spec.CPUQuota = spec.Limits.CPUQuota
	spec.PIDsLimit = spec.Limits.MaxPIDs
	if spec.Limits.HardDeadline > 0 && spec.Limits.HardDeadline < task.HardDeadline {
		spec.Deadline = spec.Limits.HardDeadline
	} else {
		spec.Deadline = task.HardDeadline
	}

	var egressProxy *egress.Proxy
	if cfg.ScopePolicyProvider != nil {
		scopePol, err := cfg.ScopePolicyProvider(execCtx, task)
		if err == nil {
			egressPolicy, err := egress.PolicyForScanner(task.Scanner, task.Target, scopePol)
			if err == nil && egressPolicy.RequiresProxy {
				proxy, err := egress.NewProxy(egressPolicy, o.logger, cfg.Metrics)
				if err == nil {
					egressProxy = proxy
					defer proxy.Close()

					effectiveRPS := pacing.EffectiveRate(task.Scanner, 0, 0)
					pacerCfg := pacing.DefaultConfig(task.Scanner, task.Target)
					pacerCfg.RequestsPerSecond = effectiveRPS
					pacer := pacing.NewTokenBucketPacer(pacerCfg)
					defer pacer.Close()
					pacer.AddListener(func(ev pacing.PacingEvent) {
						o.logger.Warn("scanner request throttled by per-target pacing",
							zap.String("job_id", task.JobID),
							zap.String("target", ev.Target),
							zap.String("scanner", task.Scanner),
							zap.Duration("wait", ev.WaitDuration),
						)
					})
					proxy.SetPacer(pacer)

					spec.NetworkDisabled = false
					spec.EgressProxy = proxy.Endpoint()
				}
			}
		}
	}

	if err := spec.Validate(); err != nil {
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseSpecInvalid)
		}
		err = fmt.Errorf("sandbox spec violates isolation profile: %w", err)
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, err
	}

	_ = tracker.TransitionTo(ctx, progress.StageScannerExecution, "executing containerized scanner process")
	execCtxWithReporter := progress.WithReporter(execCtx, tracker)
	if !metadata.Capabilities.SupportsProgress {
		_ = tracker.ReportProgress(execCtxWithReporter, progress.NewIndeterminateProgress(fmt.Sprintf("executing scanner %q", task.Scanner)))
	}

	result, execErr := cfg.Executor.Execute(execCtxWithReporter, spec)
	if result != nil && result.OOMKilled {
		if cfg.Metrics != nil {
			cfg.Metrics.IncResourceViolation(metrics.ViolationOOM)
			cfg.Metrics.IncTermination(metrics.CauseOOM)
		}
		o.logger.Error("scanner execution terminated due to out-of-memory (OOM)",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
			zap.String("memory_limit", spec.Limits.MemoryLimit),
		)
	}

	isCancelled := (result != nil && result.Cancelled) ||
		errors.Is(ctx.Err(), context.Canceled) ||
		errors.Is(execCtx.Err(), context.Canceled) ||
		errors.Is(execErr, sandbox.ErrCancelled) ||
		errors.Is(execErr, context.Canceled)

	if isCancelled {
		_ = tracker.FailStage(ctx, progress.StageStatusCancelled, "scanner execution cancelled")
		if result == nil {
			result = &sandbox.Result{
				Duration:  0,
				Cancelled: true,
				ExitCode:  -1,
			}
		} else {
			result.Cancelled = true
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseCancelled)
		}
		o.logger.Info("scanner execution cancelled",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
		)
		if len(result.OutputEnvelope) == 0 {
			result.OutputEnvelope = buildCancelledEnvelope(task, metadata.VersionPolicy.ScannerVersion, result.Duration)
		}
		_ = adapter.Cancel()
		return result, sandbox.ErrCancelled
	}

	isDeadlineExceeded := (result != nil && result.DeadlineExceeded) ||
		errors.Is(execErr, sandbox.ErrDeadlineExceeded) ||
		execCtx.Err() == context.DeadlineExceeded

	if isDeadlineExceeded {
		_ = tracker.FailStage(ctx, progress.StageStatusTimedOut, "hard execution deadline exceeded")
		if result == nil {
			result = &sandbox.Result{
				Duration:         task.HardDeadline,
				DeadlineExceeded: true,
				ExitCode:         -1,
			}
		} else {
			result.DeadlineExceeded = true
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncResourceViolation(metrics.ViolationDeadline)
			cfg.Metrics.IncTermination(metrics.CauseDeadline)
		}
		o.logger.Error("scanner execution exceeded hard execution deadline",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
			zap.Duration("deadline", spec.Deadline),
		)
		if len(result.OutputEnvelope) == 0 {
			result.OutputEnvelope = buildTimedOutEnvelope(task, metadata.VersionPolicy.ScannerVersion, result.Duration)
		}
		if execErr == nil {
			execErr = sandbox.ErrDeadlineExceeded
		}
	}
	if egressProxy != nil && egressProxy.ViolationsCount() > 0 {
		o.logger.Warn("assessment execution recorded egress policy violations",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
			zap.Int("violations_count", egressProxy.ViolationsCount()),
		)
	}

	if execErr != nil || (result != nil && result.ExitCode != 0) {
		egressBlocked := egressProxy != nil && egressProxy.ViolationsCount() > 0
		exitCode := 0
		oomKilled := false
		timedOut := isDeadlineExceeded
		stdout := ""
		stderr := ""
		if result != nil {
			exitCode = result.ExitCode
			oomKilled = result.OOMKilled
			stdout = string(result.Stdout)
			stderr = string(result.Stderr)
		}
		cf := classification.Classify(ctx, classification.ClassificationInput{
			Scanner:       task.Scanner,
			ExitCode:      exitCode,
			Stdout:        stdout,
			Stderr:        stderr,
			Err:           execErr,
			OOMKilled:     oomKilled,
			TimedOut:      timedOut,
			EgressBlocked: egressBlocked,
		})
		o.logger.Warn("classified scanner failure",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
			zap.String("failure_category", string(cf.Category)),
			zap.String("failure_code", cf.Code),
			zap.Bool("retryable", cf.Retryable),
			zap.String("message", cf.Message),
		)
	}

	if result != nil && (result.StdoutTruncated || result.StderrTruncated) {
		o.logger.Warn("scanner output stream was truncated due to buffer limits",
			zap.String("job_id", task.JobID),
			zap.String("scanner", task.Scanner),
			zap.Bool("stdout_truncated", result.StdoutTruncated),
			zap.Int64("stdout_bytes", result.StdoutBytes),
			zap.Bool("stderr_truncated", result.StderrTruncated),
			zap.Int64("stderr_bytes", result.StderrBytes),
		)
	}

	_ = tracker.TransitionTo(ctx, progress.StageOutputCollection, "collecting scanner output and diagnostics")
	_ = tracker.TransitionTo(ctx, progress.StageResultNormalization, "normalizing findings into canonical schema")

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
			_ = tracker.FailStage(ctx, progress.StageStatusFailed, execErr.Error())
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
			_ = tracker.FailStage(ctx, progress.StageStatusFailed, execErr.Error())
		}
	}

	if execErr != nil {
		_ = tracker.FailStage(ctx, progress.StageStatusFailed, execErr.Error())
	} else {
		_ = tracker.CompleteStage(ctx, "scanner execution completed successfully")
	}

	return result, execErr
}

// TimeoutType distinguishes between an execution deadline timeout and a network connection timeout.
type TimeoutType string

const (
	TimeoutExecution  TimeoutType = "EXECUTION_DEADLINE"
	TimeoutConnection TimeoutType = "CONNECTION_TIMEOUT"
	TimeoutNone       TimeoutType = "NONE"
)

// ClassifyTimeout categorizes whether an error/result represents an execution timeout
// or a network connection timeout.
func ClassifyTimeout(err error, res *sandbox.Result) TimeoutType {
	if (res != nil && res.DeadlineExceeded) || errors.Is(err, sandbox.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return TimeoutExecution
	}
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return TimeoutConnection
		}
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "connection timed out") ||
			strings.Contains(errStr, "i/o timeout") ||
			strings.Contains(errStr, "tls handshake timeout") ||
			strings.Contains(errStr, "dial tcp: i/o timeout") ||
			strings.Contains(errStr, "connect: connection refused") {
			return TimeoutConnection
		}
	}
	return TimeoutNone
}

func buildTimedOutEnvelope(task adapters.Task, scannerVersion string, duration time.Duration) []byte {
	completed := time.Now().UTC()
	started := completed.Add(-duration)
	code := -1
	ver := scannerVersion
	if ver == "" {
		ver = "1.0.0"
	}
	env := adapters.ScannerOutputEnvelope{
		SchemaVersion: adapters.OutputEnvelopeVersion,
		Metadata: adapters.OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      task.Scanner,
			ScannerVersion: ver,
			AdapterVersion: "1.0.0",
			RunID:          task.JobID,
			StartedAt:      started,
			CompletedAt:    completed,
			CorrelationID:  task.CorrelationID,
		},
		Status:      adapters.StatusTimedOut,
		ExitCode:    &code,
		DurationMS:  duration.Milliseconds(),
		Findings:    []json.RawMessage{},
		Diagnostics: []adapters.ExecutionDiagnostic{
			{
				Level:   "error",
				Code:    "DEADLINE_EXCEEDED",
				Message: fmt.Sprintf("scanner %q execution exceeded hard execution deadline of %s", task.Scanner, task.HardDeadline),
			},
		},
	}
	encoded, _ := adapters.EncodeOutputEnvelope(env)
	return encoded
}

func buildCancelledEnvelope(task adapters.Task, scannerVersion string, duration time.Duration) []byte {
	completed := time.Now().UTC()
	started := completed.Add(-duration)
	code := -1
	ver := scannerVersion
	if ver == "" {
		ver = "1.0.0"
	}
	env := adapters.ScannerOutputEnvelope{
		SchemaVersion: adapters.OutputEnvelopeVersion,
		Metadata: adapters.OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      task.Scanner,
			ScannerVersion: ver,
			AdapterVersion: "1.0.0",
			RunID:          task.JobID,
			StartedAt:      started,
			CompletedAt:    completed,
			CorrelationID:  task.CorrelationID,
		},
		Status:      adapters.StatusCancelled,
		ExitCode:    &code,
		DurationMS:  duration.Milliseconds(),
		Findings:    []json.RawMessage{},
		Diagnostics: []adapters.ExecutionDiagnostic{
			{
				Level:   "error",
				Code:    "CANCELLED",
				Message: fmt.Sprintf("scanner %q execution was cancelled", task.Scanner),
			},
		},
	}
	encoded, _ := adapters.EncodeOutputEnvelope(env)
	return encoded
}

// ExecutePipeline coordinates execution of all scanners defined by an assessment profile.
func (o *Orchestrator) ExecutePipeline(ctx context.Context, jobLog *zap.Logger, task adapters.Task, cfg Config) (*sandbox.Result, error) {
	pub := o.publisher
	if cfg.ProgressPublisher != nil {
		pub = cfg.ProgressPublisher
	}
	pipelineTracker := progress.NewTracker(task.AssessmentID, task.JobID, task.TenantID, "pipeline", pub, jobLog)

	profile, err := adapters.GetAssessmentProfile(task.ProfileID)
	if err != nil {
		_ = pipelineTracker.FailStage(ctx, progress.StageStatusFailed, err.Error())
		return nil, fmt.Errorf("invalid assessment profile %q: %w", task.ProfileID, err)
	}

	_ = pipelineTracker.TransitionTo(ctx, progress.StagePreflight, fmt.Sprintf("pipeline preflight for profile %q", profile.ProfileID))

	started := time.Now().UTC()
	report := AssessmentPipelineReport{
		AssessmentID: task.AssessmentID,
		TenantID:     task.TenantID,
		ProfileID:    profile.ProfileID,
		Target:       task.Target,
		StartedAt:    started,
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		_ = pipelineTracker.FailStage(ctx, progress.StageStatusCancelled, "assessment execution was cancelled before execution began")
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseCancelled)
		}
		completed := time.Now().UTC()
		report.CompletedAt = completed
		report.Duration = 0
		rawReport, _ := json.Marshal(report)
		envelope := adapters.ScannerOutputEnvelope{
			SchemaVersion: adapters.OutputEnvelopeVersion,
			Metadata: adapters.OutputMetadata{
				AssessmentID:   task.AssessmentID,
				ScannerID:      "pipeline",
				ScannerVersion: "1.0.0",
				AdapterVersion: "1.0.0",
				RunID:          task.JobID,
				StartedAt:      started,
				CompletedAt:    completed,
				CorrelationID:  task.CorrelationID,
			},
			Status:      adapters.StatusCancelled,
			ExitCode:    intPtr(-1),
			Findings:    []json.RawMessage{},
			Diagnostics: []adapters.ExecutionDiagnostic{
				{
					Level:   "error",
					Code:    "CANCELLED",
					Message: "assessment execution was cancelled before execution began",
				},
			},
		}
		encodedEnv, _ := adapters.EncodeOutputEnvelope(envelope)
		return &sandbox.Result{
			Duration:       0,
			Stdout:         string(rawReport),
			OutputEnvelope: encodedEnv,
			ExitCode:       -1,
			Cancelled:      true,
		}, sandbox.ErrCancelled
	}

	assessmentDeadline := task.HardDeadline
	if assessmentDeadline <= 0 {
		if profile.Budget.MaxDuration > 0 {
			assessmentDeadline = profile.Budget.MaxDuration
		} else {
			assessmentDeadline = limits.PlatformCeiling.HardDeadline
		}
	}
	if assessmentDeadline > limits.PlatformCeiling.HardDeadline {
		assessmentDeadline = limits.PlatformCeiling.HardDeadline
	}
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining < assessmentDeadline {
			assessmentDeadline = remaining
		}
	}

	if assessmentDeadline <= 0 {
		_ = pipelineTracker.FailStage(ctx, progress.StageStatusTimedOut, "assessment execution deadline exceeded before execution began")
		if cfg.Metrics != nil {
			cfg.Metrics.IncResourceViolation(metrics.ViolationDeadline)
			cfg.Metrics.IncTermination(metrics.CauseDeadline)
		}
		completed := time.Now().UTC()
		report.CompletedAt = completed
		report.Duration = 0
		rawReport, _ := json.Marshal(report)
		envelope := adapters.ScannerOutputEnvelope{
			SchemaVersion: adapters.OutputEnvelopeVersion,
			Metadata: adapters.OutputMetadata{
				AssessmentID:   task.AssessmentID,
				ScannerID:      "pipeline",
				ScannerVersion: "1.0.0",
				AdapterVersion: "1.0.0",
				RunID:          task.JobID,
				StartedAt:      started,
				CompletedAt:    completed,
				CorrelationID:  task.CorrelationID,
			},
			Status:      adapters.StatusTimedOut,
			ExitCode:    intPtr(-1),
			Findings:    []json.RawMessage{},
			Diagnostics: []adapters.ExecutionDiagnostic{
				{
					Level:   "error",
					Code:    "DEADLINE_EXCEEDED",
					Message: "assessment execution deadline exceeded before execution began",
				},
			},
		}
		encodedEnv, _ := adapters.EncodeOutputEnvelope(envelope)
		return &sandbox.Result{
			Duration:         0,
			Stdout:           string(rawReport),
			OutputEnvelope:   encodedEnv,
			ExitCode:         -1,
			DeadlineExceeded: true,
		}, sandbox.ErrDeadlineExceeded
	}

	assessmentCtx, cancelAssessment := context.WithTimeout(ctx, assessmentDeadline)
	defer cancelAssessment()

	assessmentTimedOut := false
	assessmentCancelled := false
	prevPhaseSucceeded := true
	var scannersFailed []string
	var scannersSkipped []string
	allFindings := []json.RawMessage{}

	totalPhases := int64(len(profile.DefaultScannerOrder))
	for _, phase := range profile.DefaultScannerOrder {
		phaseRes := PhaseResult{
			PhaseIndex: phase.PhaseIndex,
			PhaseName:  phase.PhaseName,
			Scanners:   phase.Scanners,
			Success:    true,
		}

		_ = pipelineTracker.TransitionTo(assessmentCtx, progress.StageScannerExecution, fmt.Sprintf("executing phase %d/%d (%s)", phase.PhaseIndex+1, totalPhases, phase.PhaseName))
		_ = pipelineTracker.ReportProgress(assessmentCtx, progress.NewDeterminateProgress(int64(phase.PhaseIndex), totalPhases, "phases", fmt.Sprintf("running phase %s", phase.PhaseName)))

		if phase.RequirePrev && !prevPhaseSucceeded {
			phaseRes.Success = false
			phaseRes.Error = "skipped because previous prerequisite phase failed"
			scannersSkipped = append(scannersSkipped, phase.Scanners...)
			report.PhaseResults = append(report.PhaseResults, phaseRes)
			jobLog.Warn("skipping assessment phase due to prerequisite failure",
				zap.Int("phase_index", phase.PhaseIndex),
				zap.String("phase_name", phase.PhaseName),
			)
			break
		}

		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(assessmentCtx.Err(), context.Canceled) {
			phaseRes.Success = false
			phaseRes.Error = "assessment execution cancelled"
			scannersSkipped = append(scannersSkipped, phase.Scanners...)
			report.PhaseResults = append(report.PhaseResults, phaseRes)
			assessmentCancelled = true
			break
		}

		if assessmentCtx.Err() != nil {
			phaseRes.Success = false
			phaseRes.Error = "assessment execution deadline exceeded"
			scannersSkipped = append(scannersSkipped, phase.Scanners...)
			report.PhaseResults = append(report.PhaseResults, phaseRes)
			assessmentTimedOut = true
			break
		}

		remainingAssessment := time.Until(started.Add(assessmentDeadline))
		if remainingAssessment <= 0 {
			phaseRes.Success = false
			phaseRes.Error = "assessment execution deadline exceeded"
			scannersSkipped = append(scannersSkipped, phase.Scanners...)
			report.PhaseResults = append(report.PhaseResults, phaseRes)
			assessmentTimedOut = true
			break
		}

		for _, scannerID := range phase.Scanners {
			if o.readiness != nil && !o.readiness.IsScannerReady(assessmentCtx, scannerID) {
				phaseRes.Success = false
				phaseRes.Error = fmt.Sprintf("scanner %q is not ready", scannerID)
				prevPhaseSucceeded = false
				scannersFailed = append(scannersFailed, scannerID)
				break
			}

			subTask := task
			subTask.Scanner = scannerID

			// Propagate bounded deadline: scanner cannot exceed assessment remaining time
			scannerDeadline := subTask.HardDeadline
			if scannerDeadline <= 0 {
				if scLimits, err := limits.ForScanner(scannerID, cfg.Limits); err == nil && scLimits.HardDeadline > 0 {
					scannerDeadline = scLimits.HardDeadline
				} else {
					scannerDeadline = remainingAssessment
				}
			}
			if scannerDeadline > remainingAssessment {
				scannerDeadline = remainingAssessment
			}
			subTask.HardDeadline = scannerDeadline

			subResult, err := o.ExecuteScanner(assessmentCtx, jobLog, subTask, cfg)
			isCancelled := (subResult != nil && subResult.Cancelled) ||
				errors.Is(err, sandbox.ErrCancelled) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(ctx.Err(), context.Canceled) ||
				errors.Is(assessmentCtx.Err(), context.Canceled)

			if isCancelled {
				phaseRes.Success = false
				phaseRes.Error = fmt.Sprintf("scanner %q execution cancelled", scannerID)
				prevPhaseSucceeded = false
				assessmentCancelled = true
				scannersFailed = append(scannersFailed, scannerID)
				if subResult != nil && len(subResult.OutputEnvelope) > 0 {
					env, decErr := adapters.DecodeOutputEnvelope(subResult.OutputEnvelope)
					if decErr == nil {
						report.Envelopes = append(report.Envelopes, env)
						allFindings = append(allFindings, env.Findings...)
					}
				}
				report.PhaseResults = append(report.PhaseResults, phaseRes)
				break
			}

			isTimedOut := (subResult != nil && subResult.DeadlineExceeded) ||
				errors.Is(err, sandbox.ErrDeadlineExceeded) ||
				errors.Is(err, context.DeadlineExceeded) ||
				assessmentCtx.Err() != nil

			if isTimedOut {
				phaseRes.Success = false
				phaseRes.Error = fmt.Sprintf("scanner %q execution deadline exceeded", scannerID)
				prevPhaseSucceeded = false
				scannersFailed = append(scannersFailed, scannerID)
				if assessmentCtx.Err() != nil {
					assessmentTimedOut = true
				}
				if subResult != nil && len(subResult.OutputEnvelope) > 0 {
					env, decErr := adapters.DecodeOutputEnvelope(subResult.OutputEnvelope)
					if decErr == nil {
						report.Envelopes = append(report.Envelopes, env)
						allFindings = append(allFindings, env.Findings...)
					}
				}
				break
			}

			if err != nil || (subResult != nil && subResult.ExitCode != 0) {
				phaseRes.Success = false
				if err != nil {
					phaseRes.Error = err.Error()
				} else {
					phaseRes.Error = fmt.Sprintf("scanner exited with code %d", subResult.ExitCode)
				}
				prevPhaseSucceeded = false
				scannersFailed = append(scannersFailed, scannerID)
				break
			}

			report.ScannersRun = append(report.ScannersRun, scannerID)

			if len(subResult.OutputEnvelope) > 0 {
				env, err := adapters.DecodeOutputEnvelope(subResult.OutputEnvelope)
				if err == nil {
					report.Envelopes = append(report.Envelopes, env)
					report.TotalFindings += len(env.Findings)
					allFindings = append(allFindings, env.Findings...)
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

	status := adapters.StatusCompleted
	exitCode := 0
	partial := false
	diagnostics := []adapters.ExecutionDiagnostic{}

	if assessmentCancelled {
		_ = pipelineTracker.FailStage(ctx, progress.StageStatusCancelled, "assessment execution was cancelled")
		status = adapters.StatusCancelled
		exitCode = -1
		diagnostics = []adapters.ExecutionDiagnostic{
			{
				Level:   "error",
				Code:    "CANCELLED",
				Message: "assessment execution was cancelled",
			},
		}
	} else if assessmentTimedOut {
		if len(allFindings) > 0 {
			_ = pipelineTracker.FailStage(ctx, progress.StageStatusTimedOut, "assessment timed out with partial results")
			status = adapters.StatusPartial
			partial = true
			exitCode = 0
			report.DegradationWarning = fmt.Sprintf("assessment timed out after executing %d scanner(s); partial findings preserved", len(report.ScannersRun))
			diagnostics = []adapters.ExecutionDiagnostic{
				{
					Level:   "warning",
					Code:    "PARTIAL_TIMED_OUT",
					Message: report.DegradationWarning,
				},
			}
		} else {
			_ = pipelineTracker.FailStage(ctx, progress.StageStatusTimedOut, "assessment execution deadline exceeded")
			status = adapters.StatusTimedOut
			exitCode = -1
			diagnostics = []adapters.ExecutionDiagnostic{
				{
					Level:   "error",
					Code:    "DEADLINE_EXCEEDED",
					Message: "assessment execution deadline exceeded",
				},
			}
		}
	} else {
		preflightSucceeded := len(report.PhaseResults) > 0 && report.PhaseResults[0].Success

		if len(scannersFailed) == 0 && len(scannersSkipped) == 0 {
			_ = pipelineTracker.CompleteStage(ctx, "assessment pipeline completed successfully")
			status = adapters.StatusCompleted
			exitCode = 0
		} else if !preflightSucceeded {
			_ = pipelineTracker.FailStage(ctx, progress.StageStatusFailed, "essential baseline preflight failed")
			status = adapters.StatusFailed
			exitCode = 1
			diagnostics = []adapters.ExecutionDiagnostic{
				{
					Level:   "error",
					Code:    "PREFLIGHT_FAILED",
					Message: "essential baseline preflight reachability check failed; dependent scans aborted",
				},
			}
		} else {
			failedList := strings.Join(scannersFailed, ", ")
			skippedList := strings.Join(scannersSkipped, ", ")
			warningMsg := fmt.Sprintf("assessment partially completed: failed scanners [%s], skipped scanners [%s]", failedList, skippedList)
			report.DegradationWarning = warningMsg

			if len(allFindings) > 0 {
				_ = pipelineTracker.CompleteStage(ctx, "assessment pipeline partially completed")
				status = adapters.StatusPartial
				partial = true
				exitCode = 0
				diagnostics = []adapters.ExecutionDiagnostic{
					{
						Level:   "warning",
						Code:    "PARTIAL_SCANNER_FAILURE",
						Message: warningMsg,
					},
				}
			} else {
				_ = pipelineTracker.CompleteStage(ctx, "assessment pipeline completed with warnings")
				status = adapters.StatusCompletedWithWarnings
				exitCode = 0
				diagnostics = []adapters.ExecutionDiagnostic{
					{
						Level:   "warning",
						Code:    "DEGRADED_SCANNER_FAILURE",
						Message: warningMsg,
					},
				}
			}
		}
	}

	report.OverallStatus = status
	report.ScannersFailed = scannersFailed
	report.ScannersSkipped = scannersSkipped

	rawReport, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pipeline report: %w", err)
	}

	envelope := adapters.ScannerOutputEnvelope{
		SchemaVersion: adapters.OutputEnvelopeVersion,
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
		Status:      status,
		Partial:     partial,
		ExitCode:    intPtr(exitCode),
		Findings:    allFindings,
		Diagnostics: diagnostics,
	}
	encodedEnv, err := adapters.EncodeOutputEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to encode output envelope: %w", err)
	}

	res := &sandbox.Result{
		Duration:         report.Duration,
		Stdout:           string(rawReport),
		OutputEnvelope:   encodedEnv,
		ExitCode:         0,
		DeadlineExceeded: assessmentTimedOut && !partial,
		Cancelled:        assessmentCancelled,
	}
	if assessmentCancelled {
		return res, sandbox.ErrCancelled
	}
	if assessmentTimedOut && !partial {
		return res, sandbox.ErrDeadlineExceeded
	}
	return res, nil
}

func intPtr(i int) *int {
	return &i
}

func isNucleiAdapter(a adapters.ScannerAdapter) bool {
	_, ok := a.(*adapters.NucleiAdapter)
	return ok
}
