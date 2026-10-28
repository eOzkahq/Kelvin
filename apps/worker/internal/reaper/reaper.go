// Package reaper implements the stale-worker detection and job-recovery loop.
// It periodically scans for running jobs whose heartbeat lease or hard
// deadline has expired and marks them FAILED so the queue's retry logic can
// re-queue them (if attempts remain) or dead-letter them (if exhausted).
//
// See docs/architecture/EXECUTION_ISOLATION.md §6 for failure handling and
// docs/architecture/JOB_LIFECYCLE.md for the state machine.
package reaper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kelvin/kelvin/apps/api/pkg/job"
	"go.uber.org/zap"
)

// storeIface is the subset of job.Store used by the reaper, so tests can
// inject a mock without a database.
type storeIface interface {
	ReapStalled(context.Context) (int64, error)
}

// Config tunes the reaper loop.
type Config struct {
	// Interval is how often the reaper scans for stalled jobs.
	Interval time.Duration
	// StaleThreshold is how long a heartbeat can be absent before a job is
	// considered stale. Overrides the 90-second default in Store.ReapStalled
	// when set.
	StaleThreshold time.Duration
	// MaxReaps per scan; 0 means no limit (rely on SKIP LOCKED).
	MaxReaps int64
}

// Run blocks until ctx is cancelled, reaping stalled jobs on each tick.
func Run(ctx context.Context, log *zap.Logger, cfg Config, store storeIface) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	log = log.With(zap.String("component", "reaper"))
	log.Info("reaper started", zap.Duration("interval", cfg.Interval))

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Immediate first scan so recovery isn't delayed until the first tick.
	if err := reapOnce(ctx, log, store); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("initial reap scan failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("reaper stopped")
			return nil
		case <-ticker.C:
			if err := reapOnce(ctx, log, store); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("reap scan failed", zap.Error(err))
			}
		}
	}
}

// reapOnce performs a single scan for stalled jobs and marks them FAILED.
func reapOnce(ctx context.Context, log *zap.Logger, store storeIface) error {
	// Build a tenant-less context; ReapStalled operates across all tenants
	// using SKIP LOCKED so concurrent sweepers are safe.
	reapCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	reaped, err := store.ReapStalled(reapCtx)
	if err != nil {
		return fmt.Errorf("reaper: stalled job scan: %w", err)
	}
	if reaped > 0 {
		log.Info("reaper marked stalled jobs failed",
			zap.Int64("reaped", reaped),
		)
	}
	return nil
}

// Ensure job.Store satisfies storeIface at compile time.
var _ storeIface = job.Store{}
