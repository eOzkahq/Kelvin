// Package daemon hosts the worker job-listener loop: dequeue → dispatch to an
// adapter → complete/fail, with heartbeat logging and graceful shutdown.
package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

// Config tunes the listener loop.
type Config struct {
	WorkerID       string
	PollInterval   time.Duration
	HeartbeatEvery time.Duration
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
		process(jobCtx, log, q, registry, job, cfg.WorkerID, cfg.HeartbeatEvery)
		process(ctx, log, q, registry, job, cfg.WorkerID, cfg.HeartbeatEvery)
	}
}

func process(ctx context.Context, log *zap.Logger, q queue.Queue, registry *adapters.Registry, job queue.Job, workerID string, heartbeatEvery time.Duration) {
	jobLog := log.With(
		zap.String("job_id", job.ID),
		zap.String("job_type", job.Type),
		zap.String("correlation_id", job.CorrelationID),
	)
	if heartbeats, ok := q.(interface {
		Heartbeat(context.Context, string, string, time.Duration) error
	}); ok {
		if err := heartbeats.Heartbeat(ctx, job.ID, workerID, heartbeatEvery*3); err != nil {
			jobLog.Warn("job heartbeat failed", zap.Error(err))
		}
		heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
		heartbeatDone := make(chan struct{})
		go func() {
			defer close(heartbeatDone)
			ticker := time.NewTicker(heartbeatEvery)
			defer ticker.Stop()
			for {
				select {
				case <-heartbeatCtx.Done():
					return
				case <-ticker.C:
					if err := heartbeats.Heartbeat(heartbeatCtx, job.ID, workerID, heartbeatEvery*3); err != nil {
						jobLog.Warn("job heartbeat failed", zap.Error(err))
					}
				}
			}
		}()
		defer func() { stopHeartbeat(); <-heartbeatDone }()
	}
	if _, ok := registry.Lookup(job.Type); !ok {
		jobLog.Warn("no adapter registered for job type; failing job")
		if err := q.Fail(ctx, job, "no adapter registered for job type"); err != nil {
			jobLog.Error("failed to record job failure", zap.Error(err))
		}
		return
	}
	jobLog.Info("job received; adapter execution lands with Phase 2 engine milestones")
	if err := q.Complete(ctx, job); err != nil {
		jobLog.Error("failed to record job completion", zap.Error(err))
	}
}
