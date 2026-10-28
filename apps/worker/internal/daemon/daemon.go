// Package daemon hosts the worker job-listener loop: dequeue → dispatch to an
// adapter inside the sandbox → complete/fail, with heartbeat logging and
// graceful shutdown.
//
// Execution isolation: each job runs in a rootless OCI container provisioned
// by cfg.Executor. The worker supervisor enforces the hard execution deadline
// (context timeout) and terminates the container on cancellation, so scanner
// faults (OOM, crash, hung socket) are contained to a single job and cannot
// impact platform stability.
//
// See docs/architecture/EXECUTION_ISOLATION.md §6 for failure handling.
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
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

// Config tunes the listener loop.
type Config struct {
	WorkerID       string
	PollInterval   time.Duration
	HeartbeatEvery time.Duration
	// Executor provisions scanner containers; nil means no sandboxed execution
	// is available (jobs fail with "no executor").
	Executor sandbox.Executor
	// Limits are the enforceable resource bounds applied to every job.
	Limits limits.Limits
	// Metrics records auditable resource violations and termination causes.
	Metrics *metrics.Registry
}

// Run blocks until ctx is cancelled, processing jobs from q.
func Run(ctx context.Context, log *zap.Logger, cfg Config, q queue.Queue, registry *adapters.Registry) error {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	log = log.With(zap.String("worker_id", cfg.WorkerID))
	log.Info("worker daemon started",
		zap.Duration("poll_interval", cfg.PollInterval),
		zap.Strings("adapters", registry.Names()),
	)

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
				log.Info("worker daemon stopped")
				return nil
			}
			log.Error("dequeue failed", zap.Error(err))
			select {
			case <-ctx.Done():
				log.Info("worker daemon stopped")
				return nil
			case <-time.After(cfg.PollInterval):
			}
			continue
		}
		jobCtx, tenantErr := tenant.ParseAndWithID(ctx, job.TenantID)
		if tenantErr != nil {
			log.Warn("job has invalid tenant context; refusing execution", zap.String("job_id", job.ID))
			if failErr := q.Fail(ctx, job, "invalid tenant context"); failErr != nil {
				log.Error("failed to reject unscoped job", zap.Error(failErr))
			}
			continue
		}
		process(jobCtx, log, q, registry, job, cfg)
	}
}

func process(ctx context.Context, log *zap.Logger, q queue.Queue, registry *adapters.Registry, job queue.Job, cfg Config) {
	jobLog := log.With(
		zap.String("job_id", job.ID),
		zap.String("job_type", job.Type),
		zap.String("correlation_id", job.CorrelationID),
	)

	// Heartbeat the job while it executes (if the queue supports it).
	if heartbeats, ok := q.(interface {
		Heartbeat(context.Context, string, string, time.Duration) error
	}); ok {
		if err := heartbeats.Heartbeat(ctx, job.ID, cfg.WorkerID, cfg.HeartbeatEvery*3); err != nil {
			jobLog.Warn("job heartbeat failed", zap.Error(err))
		}
		heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
		heartbeatDone := make(chan struct{})
		go func() {
			defer close(heartbeatDone)
			ticker := time.NewTicker(cfg.HeartbeatEvery)
			defer ticker.Stop()
			for {
				select {
				case <-heartbeatCtx.Done():
					return
				case <-ticker.C:
					if err := heartbeats.Heartbeat(heartbeatCtx, job.ID, cfg.WorkerID, cfg.HeartbeatEvery*3); err != nil {
						jobLog.Warn("job heartbeat failed", zap.Error(err))
					}
				}
			}
		}()
		defer func() { stopHeartbeat(); <-heartbeatDone }()
	}

	// Validate that a scanner adapter is registered for this job type. The
	// container is then run by cfg.Executor (sandbox.Executor), which enforces
	// the P1-29 resource limits and process-tree termination.
	if _, ok := registry.Lookup(job.Type); !ok {
		jobLog.Warn("no adapter registered for job type; failing job")
		if err := q.Fail(ctx, job, "no adapter registered for job type"); err != nil {
			jobLog.Error("failed to record job failure", zap.Error(err))
		}
		return
	}

	// Build and validate the task from the job envelope.
	task, taskErr := taskFromJob(job)
	if taskErr != nil {
		jobLog.Warn("job task is invalid; failing job", zap.Error(taskErr))
		if err := q.Fail(ctx, job, taskErr.Error()); err != nil {
			jobLog.Error("failed to record job failure", zap.Error(err))
		}
		return
	}
	if err := adapters.ValidateTask(task); err != nil {
		jobLog.Warn("job task failed validation; failing job", zap.Error(err))
		if err := q.Fail(ctx, job, err.Error()); err != nil {
			jobLog.Error("failed to record job failure", zap.Error(err))
		}
		return
	}

	// The supervisor enforces the hard execution deadline: ctx cancellation
	// (deadline, shutdown signal, or job cancel) kills the container and its
	// process tree.
	execCtx, cancel := context.WithTimeout(ctx, task.HardDeadline)
	defer cancel()

	jobLog.Info("dispatching job to sandboxed adapter",
		zap.String("scanner", task.Scanner),
		zap.String("profile", task.ProfileID),
		zap.Duration("hard_deadline", task.HardDeadline),
		zap.String("limits", cfg.Limits.String()),
	)

	// Build the sandbox spec and apply the configured resource limits. Scanner
	// overrides cannot weaken the mandatory isolation fields.
	spec := specFromTask(task)
	spec.Limits = cfg.Limits
	if spec.Deadline <= 0 {
		spec.Deadline = task.HardDeadline
	}
	// Fail closed if the container spec violates the isolation profile.
	if err := spec.Validate(); err != nil {
		jobLog.Warn("job sandbox spec violates isolation profile; failing job",
			zap.String("job_id", job.ID), zap.Error(err))
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseSpecInvalid)
		}
		if err := q.Fail(ctx, job, "sandbox spec violates isolation profile: "+err.Error()); err != nil {
			jobLog.Error("failed to record spec failure", zap.Error(err))
		}
		return
	}

	if cfg.Executor == nil {
		jobLog.Warn("no sandbox executor configured; failing job")
		if err := q.Fail(ctx, job, "no sandbox executor configured"); err != nil {
			jobLog.Error("failed to record executor failure", zap.Error(err))
		}
		return
	}
	result, execErr := cfg.Executor.Execute(execCtx, spec)
	processResult(jobLog, q, job, task, result, execErr, ctx, cfg.Metrics)
}

// processResult translates the sandbox outcome into a queue completion or
// failure, mapping scanner faults (deadline, OOM, crash, invalid findings,
// egress blocks) to the appropriate terminal reason. Every termination cause
// is audited via structured logging and a metrics counter.
func processResult(jobLog *zap.Logger, q queue.Queue, job queue.Job, task adapters.Task, result *sandbox.Result, execErr error, ctx context.Context, reg *metrics.Registry) {
	recordTermination := func(cause metrics.TerminationCause) {
		jobLog.Info("job terminated", zap.String("job_id", job.ID), zap.String("cause", string(cause)))
		if reg != nil {
			reg.IncTermination(cause)
		}
	}
	recordViolation := func(v metrics.ViolationType) {
		jobLog.Warn("job resource violation", zap.String("job_id", job.ID), zap.String("violation", string(v)))
		if reg != nil {
			reg.IncResourceViolation(v)
		}
	}

	// Deadline exceeded: the supervisor terminated the container process tree
	// at the hard execution deadline.
	if result != nil && (result.DeadlineExceeded || result.ExitCode < 0) {
		recordTermination(metrics.CauseDeadline)
		recordViolation(metrics.ViolationDeadline)
		jobLog.Warn("job exceeded hard execution deadline; container process tree terminated",
			zap.String("job_id", job.ID), zap.Duration("deadline", task.HardDeadline))
		if err := q.Fail(ctx, job, "execution deadline exceeded"); err != nil {
			jobLog.Error("failed to record deadline failure", zap.Error(err))
		}
		return
	}

	// Container crash / infrastructure failure.
	if execErr != nil {
		if result != nil && result.OOMKilled {
			recordTermination(metrics.CauseOOM)
			recordViolation(metrics.ViolationOOM)
			jobLog.Warn("job container OOM-killed", zap.String("job_id", job.ID))
			if err := q.Fail(ctx, job, "out of memory"); err != nil {
				jobLog.Error("failed to record OOM failure", zap.Error(err))
			}
			return
		}
		recordTermination(metrics.CauseCrash)
		jobLog.Warn("job adapter execution failed", zap.String("job_id", job.ID), zap.Error(execErr))
		if err := q.Fail(ctx, job, execErr.Error()); err != nil {
			jobLog.Error("failed to record execution failure", zap.Error(err))
		}
		return
	}

	// Non-zero exit code from the scanner (crash, not deadline/OOM).
	if result != nil && result.ExitCode != 0 {
		recordTermination(metrics.CauseCrash)
		jobLog.Warn("job scanner exited non-zero",
			zap.String("job_id", job.ID), zap.Int("exit_code", result.ExitCode),
			zap.String("stderr", result.Stderr))
		if err := q.Fail(ctx, job, fmt.Sprintf("scanner exited with code %d", result.ExitCode)); err != nil {
			jobLog.Error("failed to record scanner failure", zap.Error(err))
		}
		return
	}

	// Scanner output is untrusted: validate findings before completion.
	if result != nil && len(result.Findings) > 0 {
		if err := adapters.ValidateFindings(result.Findings); err != nil {
			recordTermination(metrics.CauseValidation)
			jobLog.Warn("job findings failed schema validation; rejecting",
				zap.String("job_id", job.ID), zap.Error(err))
			if err := q.Fail(ctx, job, "findings failed schema validation: "+err.Error()); err != nil {
				jobLog.Error("failed to record validation failure", zap.Error(err))
			}
			return
		}
	}

	recordTermination(metrics.CauseCompleted)
	jobLog.Info("job completed successfully", zap.String("job_id", job.ID),
		zap.Duration("duration", result.Duration))
	if err := q.Complete(ctx, job); err != nil {
		jobLog.Error("failed to record job completion", zap.Error(err))
	}
}

// taskFromJob reconstructs the validated Task from the job envelope. The
// scanner-specific target/profile are carried in the job Payload.
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
	hardDeadline := time.Duration(payload.HardDeadlineSeconds) * time.Second
	if hardDeadline <= 0 {
		hardDeadline = 10 * time.Minute // safe Phase 1 default
	}
	return adapters.Task{
		JobID:         job.ID,
		AssessmentID:  job.AssessmentID,
		TenantID:      job.TenantID,
		CorrelationID: job.CorrelationID,
		Scanner:       job.Type,
		Target:        payload.Target,
		ProfileID:     payload.ProfileID,
		HardDeadline:  hardDeadline,
		Payload:       payload.Params,
	}, nil
}

// specFromTask builds the sandbox container Spec from the validated task.
// All mandatory isolation fields (rootless, read-only rootfs, dropped caps,
// pids limit, deadline) are enforced; scanner overrides cannot weaken them.
func specFromTask(task adapters.Task) sandbox.Spec {
	return sandbox.Spec{
		Image:          "kelvin/scanner-" + task.Scanner + ":latest",
		Command:        []string{"/kelvin/bin/" + task.Scanner + "-adapter"},
		Args:           []string{"-target", task.Target, "-profile", task.ProfileID},
		User:           "scanner",
		Env:            []string{"KELVIN_JOB_ID=" + task.JobID, "KELVIN_TENANT_ID=" + task.TenantID},
		WorkingDir:     "/home/scanner",
		MemoryLimit:    "512m",
		CPUQuota:       "2",
		PIDsLimit:      64,
		ReadOnlyRootfs: true,
		TmpfsMounts:    []string{"/tmp:noexec,size=64m", "/run:noexec,size=16m"},
		CapDrop:        []string{"ALL"},
		CapAdd:         []string{},
		SecurityOpt:    []string{"seccomp=scan.json", "apparmor=kelvin-scan"},
		Deadline:       task.HardDeadline,
		Labels: map[string]string{
			"job_id":     task.JobID,
			"assessment": task.AssessmentID,
			"tenant_id":  task.TenantID,
			"scanner":    task.Scanner,
			"profile_id": task.ProfileID,
		},
	}
}
