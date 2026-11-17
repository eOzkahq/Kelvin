// Package daemon runs the worker queue consumer and dispatches jobs to sandboxed adapters.
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/concurrency"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/progress"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/apps/worker/internal/workspace"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

type Config struct {
	WorkerID              string
	Env                   string
	PollInterval          time.Duration
	HeartbeatEvery        time.Duration
	Executor              sandbox.Executor
	Limits                limits.Limits
	Metrics               *metrics.Registry
	ReadinessChecker      *readiness.Checker
	WorkspaceManager      *workspace.Manager
	ScopePolicyProvider   adapters.ScopePolicyProvider
	ProgressPublisher     progress.Publisher
	ConcurrencyController concurrency.Controller
	CanaryOnly            bool
	CanaryAllowedTargets  []string
	StateSyncer           StateSyncer
}

func Run(ctx context.Context, log *zap.Logger, cfg Config, q queue.Queue, registry *adapters.Registry) error {
	if err := registry.Initialize(ctx, log); err != nil {
		return err
	}
	if cfg.ReadinessChecker != nil {
		report := cfg.ReadinessChecker.EvaluateAll(ctx)
		if report.ApplicationStatus == readiness.StatusUnavailable {
			log.Error("worker pre-flight readiness check failed; refusing to accept jobs",
				zap.String("application_status", string(report.ApplicationStatus)),
				zap.String("worker_id", cfg.WorkerID),
			)
			return fmt.Errorf("daemon: pre-flight readiness check failed")
		}
		log.Info("worker pre-flight readiness verified",
			zap.String("application_status", string(report.ApplicationStatus)),
			zap.String("worker_id", cfg.WorkerID),
		)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	log = log.With(zap.String("worker_id", cfg.WorkerID))
	log.Info("worker daemon started", zap.Duration("poll_interval", cfg.PollInterval), zap.Strings("adapters", registry.Names()))

	heartbeat := time.NewTicker(cfg.HeartbeatEvery)
	defer heartbeat.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				if hb, ok := q.(interface {
					Heartbeat(context.Context, string, string, time.Duration) error
				}); ok {
					_ = hb.Heartbeat(ctx, "worker:"+cfg.WorkerID, cfg.WorkerID, cfg.HeartbeatEvery*3)
				}
				log.Info("worker heartbeat", zap.String("vitality_key", "worker:"+cfg.WorkerID))
			}
		}
	}()

	if cfg.ConcurrencyController != nil {
		reapTicker := time.NewTicker(30 * time.Second)
		defer reapTicker.Stop()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-reapTicker.C:
					_, _ = cfg.ConcurrencyController.ReapExpired(ctx)
				}
			}
		}()
	}

	for {
		job, err := q.Dequeue(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			log.Error("dequeue failed", zap.Error(err))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(cfg.PollInterval):
			}
			continue
		}
		jobCtx, err := tenant.ParseAndWithID(ctx, job.TenantID)
		if err != nil {
			log.Warn("job has invalid tenant context; refusing execution", zap.String("job_id", job.ID))
			_ = q.Fail(ctx, job, "invalid tenant context")
			continue
		}
		process(jobCtx, log, q, registry, job, cfg)
	}
}

func process(ctx context.Context, log *zap.Logger, q queue.Queue, registry *adapters.Registry, job queue.Job, cfg Config) {
	jobLog := log.With(zap.String("job_id", job.ID), zap.String("job_type", job.Type), zap.String("correlation_id", job.CorrelationID))

	// Enforce distributed lease locking (ADR-M9-01) to prevent duplicate concurrent execution
	if lm, ok := q.(queue.LeaseManager); ok {
		leaseTTL := cfg.HeartbeatEvery * 3
		if leaseTTL <= 0 {
			leaseTTL = 90 * time.Second
		}
		acquired, err := lm.AcquireLease(ctx, job.ID, leaseTTL)
		if err != nil {
			jobLog.Error("failed to query distributed job lease; failing closed", zap.Error(err))
			fail(jobLog, q, ctx, job, "distributed lease acquisition failed: "+err.Error(), cfg)
			return
		}
		if !acquired {
			jobLog.Warn("distributed lease already held by another worker; skipping duplicate execution", zap.String("job_id", job.ID))
			return
		}
		defer func() {
			_ = lm.ReleaseLease(context.Background(), job.ID)
		}()

		leaseRenewCtx, cancelLeaseRenew := context.WithCancel(ctx)
		defer cancelLeaseRenew()
		go func() {
			renewInterval := cfg.HeartbeatEvery
			if renewInterval <= 0 {
				renewInterval = 30 * time.Second
			}
			ticker := time.NewTicker(renewInterval)
			defer ticker.Stop()
			for {
				select {
				case <-leaseRenewCtx.Done():
					return
				case <-ticker.C:
					if err := lm.RenewLease(leaseRenewCtx, job.ID, leaseTTL); err != nil {
						jobLog.Warn("distributed lease renewal failed", zap.String("job_id", job.ID), zap.Error(err))
						return
					}
				}
			}
		}()
	}

	task, err := taskFromJob(job)
	if err == nil {
		err = adapters.ValidateTask(task)
	}
	if err != nil {
		fail(jobLog, q, ctx, job, err.Error(), cfg)
		return
	}

	if cfg.StateSyncer != nil {
		_ = cfg.StateSyncer.SyncJobState(ctx, job.TenantID, job.AssessmentID, job.ID, "RUNNING", "")
	}

	isAssessmentPipeline := strings.EqualFold(job.Type, JobTypeAssessment) || strings.EqualFold(job.Type, JobTypePipeline)

	if !isAssessmentPipeline {
		scannerKey := strings.ToLower(job.Type)
		if cfg.ReadinessChecker != nil {
			if !cfg.ReadinessChecker.IsScannerReady(ctx, scannerKey) && !cfg.ReadinessChecker.IsScannerReady(ctx, job.Type) {
				fail(jobLog, q, ctx, job, fmt.Sprintf("scanner %q runtime readiness check failed", job.Type), cfg)
				return
			}
		}

		if _, ok := registry.LookupExecutable(job.Type); !ok {
			if _, ok := registry.LookupExecutable(scannerKey); !ok {
				fail(jobLog, q, ctx, job, "no executable adapter registered for job type", cfg)
				return
			}
		}
	}

	// Fail closed if CanaryOnly is active and the target is not on the canary allowlist
	if cfg.CanaryOnly {
		if !isCanaryTargetAllowed(task.Target, cfg.CanaryAllowedTargets) {
			jobLog.Warn("job rejected by canary-only execution policy: target not permitted",
				zap.String("job_id", job.ID),
				zap.String("target", task.Target),
			)
			fail(jobLog, q, ctx, job, fmt.Sprintf("rejected by canary-only execution policy: target %q not permitted", task.Target), cfg)
			return
		}
	}

	// Prevent workers from accepting unvalidated execution requests
	if task.ProfileID != "" && !isAssessmentPipeline {
		if _, err := adapters.ValidateProfileSelection(task.ProfileID, task.Scanner); err != nil {
			fail(jobLog, q, ctx, job, "unauthorized scanner for assessment profile: "+err.Error(), cfg)
			return
		}
	}

	if hb, ok := q.(interface {
		Heartbeat(context.Context, string, string, time.Duration) error
	}); ok {
		_ = hb.Heartbeat(ctx, job.ID, cfg.WorkerID, cfg.HeartbeatEvery*3)
	}

	jobCtx, cancelJob := context.WithCancel(ctx)
	defer cancelJob()

	// Cancellation watcher: polls queue for cancellation events out-of-band
	if statusGetter, ok := q.(interface {
		GetStatus(context.Context, string) (commonqueue.Status, error)
	}); ok {
		stopWatch := make(chan struct{})
		defer close(stopWatch)
		go func() {
			pollInterval := cfg.HeartbeatEvery
			if pollInterval <= 0 || pollInterval > 50*time.Millisecond {
				pollInterval = 20 * time.Millisecond
			}
			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-stopWatch:
					return
				case <-jobCtx.Done():
					return
				case <-ticker.C:
					status, err := statusGetter.GetStatus(ctx, job.ID)
					if err == nil && status.State == "CANCELLED" {
						jobLog.Info("cancellation signal received for active job", zap.String("job_id", job.ID))
						cancelJob()
						return
					}
				}
			}
		}()
	}

	if cfg.ProgressPublisher == nil {
		if pub, ok := q.(progress.Publisher); ok {
			cfg.ProgressPublisher = pub
		}
	}

	if cfg.ConcurrencyController != nil {
		req := concurrency.Request{
			JobID:    job.ID,
			TenantID: job.TenantID,
			Scanner:  task.Scanner,
		}
		lease, err := cfg.ConcurrencyController.Acquire(jobCtx, req)
		if err != nil {
			if cfg.Metrics != nil {
				cfg.Metrics.IncResourceViolation(metrics.ViolationConcurrency)
			}
			jobLog.Warn("concurrency capacity unavailable for job", zap.String("job_id", job.ID), zap.Error(err))
			fail(jobLog, q, ctx, job, "concurrency capacity unavailable: "+err.Error(), cfg)
			return
		}
		defer func() {
			_ = cfg.ConcurrencyController.Release(context.Background(), lease)
		}()

		leaseHeartbeatCtx, cancelLeaseHb := context.WithCancel(jobCtx)
		defer cancelLeaseHb()
		go func() {
			hbInterval := cfg.HeartbeatEvery
			if hbInterval <= 0 || hbInterval > 20*time.Second {
				hbInterval = 10 * time.Second
			}
			ticker := time.NewTicker(hbInterval)
			defer ticker.Stop()
			for {
				select {
				case <-leaseHeartbeatCtx.Done():
					return
				case <-ticker.C:
					_ = cfg.ConcurrencyController.Heartbeat(leaseHeartbeatCtx, lease, hbInterval*3)
				}
			}
		}()
	}

	orchestrator := NewOrchestrator(registry, cfg.Executor, cfg.ReadinessChecker, cfg.WorkspaceManager, cfg.Metrics, jobLog)
	if cfg.ProgressPublisher != nil {
		orchestrator.SetProgressPublisher(cfg.ProgressPublisher)
	}

	var result *sandbox.Result
	var execErr error

	if isAssessmentPipeline {
		result, execErr = orchestrator.ExecutePipeline(jobCtx, jobLog, task, cfg)
	} else {
		result, execErr = orchestrator.ExecuteScanner(jobCtx, jobLog, task, cfg)
	}

	processResult(jobLog, q, job, task, result, execErr, ctx, cfg)
}

func fail(log *zap.Logger, q queue.Queue, ctx context.Context, job queue.Job, reason string, cfg Config) {
	cleanupCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		cleanupCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	if cfg.StateSyncer != nil {
		_ = cfg.StateSyncer.SyncJobState(cleanupCtx, job.TenantID, job.AssessmentID, job.ID, "FAILED", reason)
	}
	if err := q.Fail(cleanupCtx, job, reason); err != nil {
		log.Error("failed to record job failure", zap.Error(err))
	}
}

func processResult(log *zap.Logger, q queue.Queue, job queue.Job, task adapters.Task, result *sandbox.Result, execErr error, ctx context.Context, cfg Config) {
	mark := func(c metrics.TerminationCause) {
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(c)
		}
		log.Info("job terminated", zap.String("cause", string(c)))
	}
	if (result != nil && result.Cancelled) || errors.Is(execErr, sandbox.ErrCancelled) || errors.Is(execErr, context.Canceled) {
		mark(metrics.CauseCancelled)
		cleanupCtx := ctx
		if ctx.Err() != nil {
			var cancel context.CancelFunc
			cleanupCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		if cfg.StateSyncer != nil {
			_ = cfg.StateSyncer.SyncJobState(cleanupCtx, job.TenantID, job.AssessmentID, job.ID, "CANCELLED", "execution cancelled")
		}
		fail(log, q, cleanupCtx, job, "execution cancelled", cfg)
		return
	}
	if result != nil && result.DeadlineExceeded {
		mark(metrics.CauseDeadline)
		if cfg.Metrics != nil {
			cfg.Metrics.IncResourceViolation(metrics.ViolationDeadline)
		}
		fail(log, q, ctx, job, "execution deadline exceeded", cfg)
		return
	}
	if execErr != nil {
		if result != nil && result.OOMKilled {
			mark(metrics.CauseOOM)
			if cfg.Metrics != nil {
				cfg.Metrics.IncResourceViolation(metrics.ViolationOOM)
			}
			fail(log, q, ctx, job, "out of memory", cfg)
			return
		}
		if result != nil && result.PIDLimitExceeded {
			mark(metrics.CauseCrash)
			if cfg.Metrics != nil {
				cfg.Metrics.IncResourceViolation(metrics.ViolationPIDs)
			}
			fail(log, q, ctx, job, "process limit exceeded (pids exhausted)", cfg)
			return
		}
		mark(metrics.CauseCrash)
		fail(log, q, ctx, job, execErr.Error(), cfg)
		return
	}
	if result == nil {
		mark(metrics.CauseCrash)
		fail(log, q, ctx, job, "sandbox returned no result", cfg)
		return
	}
	if result.ExitCode != 0 {
		if result.OOMKilled {
			mark(metrics.CauseOOM)
			if cfg.Metrics != nil {
				cfg.Metrics.IncResourceViolation(metrics.ViolationOOM)
			}
			fail(log, q, ctx, job, "out of memory", cfg)
			return
		}
		if result.PIDLimitExceeded {
			mark(metrics.CauseCrash)
			if cfg.Metrics != nil {
				cfg.Metrics.IncResourceViolation(metrics.ViolationPIDs)
			}
			fail(log, q, ctx, job, "process limit exceeded (pids exhausted)", cfg)
			return
		}
		mark(metrics.CauseCrash)
		fail(log, q, ctx, job, fmt.Sprintf("scanner exited with code %d", result.ExitCode), cfg)
		return
	}
	if len(result.OutputEnvelope) > 0 {
		if _, err := adapters.DecodeOutputEnvelope(result.OutputEnvelope); err != nil {
			mark(metrics.CauseValidation)
			fail(log, q, ctx, job, "scanner output envelope failed validation: "+err.Error(), cfg)
			return
		}
	} else if len(result.Findings) > 0 {
		if err := adapters.ValidateFindings(result.Findings); err != nil {
			mark(metrics.CauseValidation)
			fail(log, q, ctx, job, "findings failed schema validation: "+err.Error(), cfg)
			return
		}
	}
	mark(metrics.CauseCompleted)
	log.Info("job completed successfully", zap.Duration("duration", result.Duration), zap.Duration("deadline", task.HardDeadline))
	cleanupCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		cleanupCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	if cfg.StateSyncer != nil {
		_ = cfg.StateSyncer.SyncJobState(cleanupCtx, job.TenantID, job.AssessmentID, job.ID, "COMPLETED", "")
	}
	if err := q.Complete(cleanupCtx, job); err != nil {
		log.Error("failed to record job completion", zap.Error(err))
	}
}

func taskFromJob(job queue.Job) (adapters.Task, error) {
	msg := commonqueue.Message{
		Version:       job.Version,
		ID:            job.ID,
		AssessmentID:  job.AssessmentID,
		TenantID:      job.TenantID,
		CorrelationID: job.CorrelationID,
		Type:          job.Type,
		Payload:       job.Payload,
	}
	if msg.Version == 0 {
		if bytes.Contains(job.Payload, []byte(`"schema_version":2`)) || bytes.Contains(job.Payload, []byte(`"schema_version": 2`)) {
			msg.Version = 2
		} else {
			msg.Version = 1
		}
	}
	env, err := commonqueue.UnpackJobEnvelope(msg)
	if err != nil {
		return adapters.Task{}, fmt.Errorf("job envelope validation failed: %w", err)
	}

	deadline := time.Duration(env.HardDeadlineSeconds) * time.Second
	if deadline <= 0 {
		deadline = 10 * time.Minute
	}

	return adapters.Task{
		JobID:         env.JobID,
		AssessmentID:  env.AssessmentID,
		TenantID:      env.TenantID,
		CorrelationID: env.CorrelationID,
		Scanner:       job.Type,
		Target:        env.TargetAddress,
		ProfileID:     env.ScanProfile,
		HardDeadline:  deadline,
		Payload:       env.CustomParameters,
	}, nil
}

func specFromTask(task adapters.Task, imageReference string, invocation sandbox.ProcessInvocation, workspaceDir string) sandbox.Spec {
	workingDir := "/tmp"
	env := []string{
		"KELVIN_JOB_ID=" + task.JobID,
		"KELVIN_TENANT_ID=" + task.TenantID,
		"KELVIN_ASSESSMENT_ID=" + task.AssessmentID,
	}
	if workspaceDir != "" {
		workingDir = "/workspace"
		env = append(env, "KELVIN_WORKSPACE=/workspace")
	}
	return sandbox.Spec{
		Scanner:         task.Scanner,
		Image:           imageReference,
		Invocation:      invocation,
		User:            "10001:10001",
		Env:             env,
		WorkingDir:      workingDir,
		WorkspaceMount:  workspaceDir,
		MemoryLimit:     "512m",
		CPUQuota:        "2",
		PIDsLimit:       64,
		ReadOnlyRootfs:  true,
		NetworkDisabled: true,
		TmpfsMounts:     []string{"/tmp:noexec,size=64m", "/run:noexec,size=16m"},
		CapDrop:         []string{"ALL"},
		SecurityOpt:     []string{"no-new-privileges", "seccomp=scan.json", "apparmor=kelvin-scan"},
		Deadline:        task.HardDeadline,
		Labels: map[string]string{
			"job_id":     task.JobID,
			"assessment": task.AssessmentID,
			"tenant_id":  task.TenantID,
			"scanner":    task.Scanner,
			"profile_id": task.ProfileID,
		},
	}
}

func isCanaryTargetAllowed(target string, allowed []string) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	targetCandidate := strings.TrimSpace(target)
	if strings.Contains(targetCandidate, "://") {
		if u, err := url.Parse(targetCandidate); err == nil && u.Hostname() != "" {
			targetCandidate = u.Hostname()
		}
	} else if strings.Contains(targetCandidate, ":") {
		parts := strings.Split(targetCandidate, ":")
		targetCandidate = parts[0]
	}
	targetCandidate = strings.ToLower(targetCandidate)

	defaultCanaryHosts := []string{
		"scanner-mock.kelvin.internal",
		"mock-target.kelvin.internal",
		"localhost",
		"127.0.0.1",
	}

	for _, d := range defaultCanaryHosts {
		if targetCandidate == d || strings.HasSuffix(targetCandidate, "."+d) {
			return true
		}
	}

	for _, a := range allowed {
		a = strings.TrimSpace(strings.ToLower(a))
		if a == "" {
			continue
		}
		if strings.Contains(a, "://") {
			if au, err := url.Parse(a); err == nil && au.Hostname() != "" {
				a = au.Hostname()
			}
		} else if strings.Contains(a, ":") {
			parts := strings.Split(a, ":")
			a = parts[0]
		}
		if targetCandidate == a || strings.HasSuffix(targetCandidate, "."+a) {
			return true
		}
	}

	return false
}
