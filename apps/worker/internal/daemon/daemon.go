// Package daemon runs the worker queue consumer and dispatches jobs to sandboxed adapters.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/apps/worker/internal/workspace"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

type Config struct {
	WorkerID         string
	PollInterval     time.Duration
	HeartbeatEvery   time.Duration
	Executor         sandbox.Executor
	Limits           limits.Limits
	Metrics          *metrics.Registry
	ReadinessChecker *readiness.Checker
	WorkspaceManager    *workspace.Manager
	ScopePolicyProvider adapters.ScopePolicyProvider
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
				log.Info("worker heartbeat")
			}
		}
	}()

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

	if cfg.ReadinessChecker != nil && job.Type != JobTypeAssessment && job.Type != JobTypePipeline {
		if !cfg.ReadinessChecker.IsScannerReady(ctx, job.Type) {
			fail(jobLog, q, ctx, job, fmt.Sprintf("scanner %q runtime readiness check failed", job.Type))
			return
		}
	}

	if job.Type != JobTypeAssessment && job.Type != JobTypePipeline {
		if _, ok := registry.LookupExecutable(job.Type); !ok {
			fail(jobLog, q, ctx, job, "no executable adapter registered for job type")
			return
		}
	}

	task, err := taskFromJob(job)
	if err == nil {
		err = adapters.ValidateTask(task)
	}
	if err != nil {
		fail(jobLog, q, ctx, job, err.Error())
		return
	}

	// Prevent workers from accepting unvalidated execution requests
	if task.ProfileID != "" && job.Type != JobTypeAssessment && job.Type != JobTypePipeline {
		if _, err := adapters.ValidateProfileSelection(task.ProfileID, task.Scanner); err != nil {
			fail(jobLog, q, ctx, job, "unauthorized scanner for assessment profile: "+err.Error())
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

	orchestrator := NewOrchestrator(registry, cfg.Executor, cfg.ReadinessChecker, cfg.WorkspaceManager, cfg.Metrics, jobLog)

	var result *sandbox.Result
	var execErr error

	if job.Type == JobTypeAssessment || job.Type == JobTypePipeline {
		result, execErr = orchestrator.ExecutePipeline(jobCtx, jobLog, task, cfg)
	} else {
		result, execErr = orchestrator.ExecuteScanner(jobCtx, jobLog, task, cfg)
	}

	processResult(jobLog, q, job, task, result, execErr, ctx, cfg.Metrics)
}

func fail(log *zap.Logger, q queue.Queue, ctx context.Context, job queue.Job, reason string) {
	if err := q.Fail(ctx, job, reason); err != nil {
		log.Error("failed to record job failure", zap.Error(err))
	}
}

func processResult(log *zap.Logger, q queue.Queue, job queue.Job, task adapters.Task, result *sandbox.Result, execErr error, ctx context.Context, reg *metrics.Registry) {
	mark := func(c metrics.TerminationCause) {
		if reg != nil {
			reg.IncTermination(c)
		}
		log.Info("job terminated", zap.String("cause", string(c)))
	}
	if (result != nil && result.Cancelled) || errors.Is(execErr, sandbox.ErrCancelled) || errors.Is(execErr, context.Canceled) {
		mark(metrics.CauseCancelled)
		fail(log, q, ctx, job, "execution cancelled")
		return
	}
	if result != nil && result.DeadlineExceeded {
		mark(metrics.CauseDeadline)
		fail(log, q, ctx, job, "execution deadline exceeded")
		return
	}
	if execErr != nil {
		if result != nil && result.OOMKilled {
			mark(metrics.CauseOOM)
			fail(log, q, ctx, job, "out of memory")
			return
		}
		mark(metrics.CauseCrash)
		fail(log, q, ctx, job, execErr.Error())
		return
	}
	if result == nil {
		mark(metrics.CauseCrash)
		fail(log, q, ctx, job, "sandbox returned no result")
		return
	}
	if result.ExitCode != 0 {
		mark(metrics.CauseCrash)
		fail(log, q, ctx, job, fmt.Sprintf("scanner exited with code %d", result.ExitCode))
		return
	}
	if len(result.OutputEnvelope) > 0 {
		if _, err := adapters.DecodeOutputEnvelope(result.OutputEnvelope); err != nil {
			mark(metrics.CauseValidation)
			fail(log, q, ctx, job, "scanner output envelope failed validation: "+err.Error())
			return
		}
	} else if len(result.Findings) > 0 {
		if err := adapters.ValidateFindings(result.Findings); err != nil {
			mark(metrics.CauseValidation)
			fail(log, q, ctx, job, "findings failed schema validation: "+err.Error())
			return
		}
	}
	mark(metrics.CauseCompleted)
	log.Info("job completed successfully", zap.Duration("duration", result.Duration), zap.Duration("deadline", task.HardDeadline))
	if err := q.Complete(ctx, job); err != nil {
		log.Error("failed to record job completion", zap.Error(err))
	}
}

func taskFromJob(job queue.Job) (adapters.Task, error) {
	var payload struct {
		Target              string          `json:"target"`
		ProfileID           string          `json:"profile_id"`
		Params              json.RawMessage `json:"params,omitempty"`
		HardDeadlineSeconds int64           `json:"hard_deadline_seconds"`
	}
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return adapters.Task{}, fmt.Errorf("invalid job payload: %w", err)
		}
	}
	deadline := time.Duration(payload.HardDeadlineSeconds) * time.Second
	if deadline <= 0 {
		deadline = 10 * time.Minute
	}
	return adapters.Task{JobID: job.ID, AssessmentID: job.AssessmentID, TenantID: job.TenantID, CorrelationID: job.CorrelationID, Scanner: job.Type, Target: payload.Target, ProfileID: payload.ProfileID, HardDeadline: deadline, Payload: payload.Params}, nil
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
