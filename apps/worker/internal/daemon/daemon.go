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
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/apps/worker/internal/scannerprocess"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

type Config struct {
	WorkerID       string
	PollInterval   time.Duration
	HeartbeatEvery time.Duration
	Executor       sandbox.Executor
	Limits         limits.Limits
	Metrics        *metrics.Registry
}

func Run(ctx context.Context, log *zap.Logger, cfg Config, q queue.Queue, registry *adapters.Registry) error {
	if err := registry.Initialize(ctx, log); err != nil {
		return err
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
	adapter, ok := registry.LookupExecutable(job.Type)
	if !ok {
		fail(jobLog, q, ctx, job, "no executable adapter registered for job type")
		return
	}
	if err := registry.VerifyRuntime(ctx, job.Type); err != nil {
		fail(jobLog, q, ctx, job, "scanner version compatibility check failed: "+err.Error())
		return
	}
	metadata, ok := registry.Metadata(job.Type)
	if !ok {
		fail(jobLog, q, ctx, job, "scanner metadata unavailable")
		return
	}
	task, err := taskFromJob(job)
	if err == nil {
		err = adapters.ValidateTask(task)
	}
	if err != nil {
		fail(jobLog, q, ctx, job, err.Error())
		return
	}
	if err := adapter.ValidateConfig(task.Payload); err != nil {
		fail(jobLog, q, ctx, job, "invalid scanner configuration: "+err.Error())
		return
	}
	if err := adapter.Health(ctx); err != nil {
		fail(jobLog, q, ctx, job, "scanner adapter unavailable: "+err.Error())
		return
	}
	if cfg.Executor == nil {
		fail(jobLog, q, ctx, job, "no sandbox executor configured")
		return
	}
	invocation, err := scannerprocess.Build(task)
	if err != nil {
		fail(jobLog, q, ctx, job, "scanner invocation rejected: "+err.Error())
		return
	}
	executionDeadline, err := scannerprocess.EffectiveDeadline(task)
	if err != nil {
		fail(jobLog, q, ctx, job, "scanner duration policy rejected: "+err.Error())
		return
	}
	task.HardDeadline = executionDeadline

	if hb, ok := q.(interface {
		Heartbeat(context.Context, string, string, time.Duration) error
	}); ok {
		_ = hb.Heartbeat(ctx, job.ID, cfg.WorkerID, cfg.HeartbeatEvery*3)
	}

	execCtx, cancel := context.WithTimeout(ctx, task.HardDeadline)
	defer cancel()
	spec := specFromTask(task, metadata.VersionPolicy.ImageReference, invocation)
	spec.CaptureZAPReport = task.Scanner == adapters.ScannerZAPBaseline
	spec.Limits = cfg.Limits
	if err := spec.Validate(); err != nil {
		fail(jobLog, q, ctx, job, "sandbox spec violates isolation profile: "+err.Error())
		if cfg.Metrics != nil {
			cfg.Metrics.IncTermination(metrics.CauseSpecInvalid)
		}
		return
	}
	result, execErr := cfg.Executor.Execute(execCtx, spec)
	if task.Scanner == adapters.ScannerZAPBaseline && result != nil && execErr == nil && result.ExitCode == 0 {
		completed := time.Now().UTC()
		started := completed.Add(-result.Duration)
		envelope, normalizeErr := adapters.NormalizeZAPReport(task, result.Findings, metadata.VersionPolicy.ScannerVersion, started, completed)
		if normalizeErr == nil {
			normalizeErr = registry.StampOutput(job.Type, &envelope)
		}
		if normalizeErr == nil {
			result.OutputEnvelope, normalizeErr = adapters.EncodeOutputEnvelope(envelope)
		}
		if normalizeErr != nil {
			execErr = fmt.Errorf("invalid ZAP report: %w", normalizeErr)
		}
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
	if result != nil && result.Cancelled {
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

func specFromTask(task adapters.Task, imageReference string, invocation sandbox.ProcessInvocation) sandbox.Spec {
	return sandbox.Spec{
		Image: imageReference, Invocation: invocation, User: "10001:10001",
		Env: []string{"KELVIN_JOB_ID=" + task.JobID, "KELVIN_TENANT_ID=" + task.TenantID, "KELVIN_ASSESSMENT_ID=" + task.AssessmentID}, WorkingDir: "/tmp",
		MemoryLimit: "512m", CPUQuota: "2", PIDsLimit: 64, ReadOnlyRootfs: true,
		NetworkDisabled: true,
		TmpfsMounts:     []string{"/tmp:noexec,size=64m", "/run:noexec,size=16m"}, CapDrop: []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges", "seccomp=scan.json", "apparmor=kelvin-scan"}, Deadline: task.HardDeadline,
		Labels: map[string]string{"job_id": task.JobID, "assessment": task.AssessmentID, "tenant_id": task.TenantID, "scanner": task.Scanner, "profile_id": task.ProfileID},
	}
}
