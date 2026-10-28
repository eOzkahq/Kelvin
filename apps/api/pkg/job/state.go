// Package job defines and persists assessment job lifecycle state.
package job

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelvin/kelvin/apps/api/internal/database"
	"github.com/redis/go-redis/v9"
)

type State string

const (
	Queued     State = "QUEUED"
	Validating State = "VALIDATING"
	Running    State = "RUNNING"
	Completed  State = "COMPLETED"
	Failed     State = "FAILED"
	Cancelled  State = "CANCELLED"
	TimedOut   State = "TIMED_OUT"
)

var ErrInvalidTransition = errors.New("invalid job state transition")
var ErrNotFound = errors.New("job not found")

func (s State) Valid() bool {
	switch s {
	case Queued, Validating, Running, Completed, Failed, Cancelled, TimedOut:
		return true
	}
	return false
}

func (s State) Terminal() bool {
	return s == Completed || s == Failed || s == Cancelled || s == TimedOut
}

func ValidateTransition(from, to State) error {
	if !from.Valid() || !to.Valid() {
		return fmt.Errorf("%w: unknown state %q -> %q", ErrInvalidTransition, from, to)
	}
	allowed := map[State]map[State]bool{
		Queued:     {Validating: true},
		Validating: {Running: true, Failed: true, Cancelled: true},
		Running:    {Completed: true, Failed: true, Cancelled: true, TimedOut: true},
	}
	if !allowed[from][to] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	return nil
}

// Store serializes transitions with a row lock. Times are supplied by PostgreSQL
// so concurrent API/worker calls share one clock and one atomic update.
type Store struct{ DB *pgxpool.Pool }

func (s Store) Transition(ctx context.Context, id string, to State, workerID string) error {
	tx, err := database.BeginTenantTx(ctx, s.DB)
	if err != nil {
		return fmt.Errorf("begin job transition: %w", err)
	}
	defer tx.Rollback(ctx)
	var from State
	err = tx.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1 FOR UPDATE`, id).Scan(&from)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock job: %w", err)
	}
	if err = ValidateTransition(from, to); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE jobs SET status=$2,
        worker_id=CASE WHEN $2='RUNNING' AND $3 <> '' THEN $3 ELSE worker_id END,
        started_at=CASE WHEN $2='RUNNING' THEN COALESCE(started_at, now()) ELSE started_at END,
        finished_at=CASE WHEN $2 IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT') THEN now() ELSE NULL END,
        heartbeat_at=CASE WHEN $2='RUNNING' THEN now() ELSE heartbeat_at END,
        updated_at=now() WHERE id=$1`, id, to, workerID)
	if err != nil {
		return fmt.Errorf("update job: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit job transition: %w", err)
	}
	return nil
}

// SetDeadline records the absolute scanner deadline when a worker starts. A
// non-positive duration is rejected so jobs cannot accidentally run unbounded.
func (s Store) SetDeadline(ctx context.Context, id string, duration time.Duration) error {
	if duration <= 0 {
		return errors.New("job execution deadline must be positive")
	}
	tx, err := database.BeginTenantTx(ctx, s.DB)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE jobs SET hard_deadline_at=now()+($2 * interval '1 second'), updated_at=now()
		WHERE id=$1 AND status='RUNNING'`, id, duration.Seconds())
	if err != nil {
		return fmt.Errorf("set job execution deadline: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// RecordHeartbeat extends the PostgreSQL worker lease for a live running job.
// Redis is used for fast worker liveness checks; this durable timestamp lets
// the control plane recover correctly if Redis is unavailable.
func (s Store) RecordHeartbeat(ctx context.Context, id, workerID string, lease time.Duration) error {
	if workerID == "" || lease <= 0 {
		return errors.New("job heartbeat requires a worker ID and positive lease")
	}
	tx, err := database.BeginTenantTx(ctx, s.DB)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE jobs SET heartbeat_at=now(), lease_expires_at=now()+($3 * interval '1 second'), updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='RUNNING'`, id, workerID, lease.Seconds())
	if err != nil {
		return fmt.Errorf("record job heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// Heartbeats are keyed by job and worker. TTL provides automatic cleanup;
// callers should heartbeat substantially more often than ttl.
type Heartbeats struct {
	Redis  redis.UniversalClient
	Prefix string
	TTL    time.Duration
}

func (h Heartbeats) key(jobID string) string {
	prefix := h.Prefix
	if prefix == "" {
		prefix = "kelvin:job:heartbeat:"
	}
	return prefix + jobID
}
func (h Heartbeats) Touch(ctx context.Context, jobID, workerID string) error {
	if jobID == "" || workerID == "" {
		return errors.New("job heartbeat requires job and worker IDs")
	}
	ttl := h.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return h.Redis.Set(ctx, h.key(jobID), workerID, ttl).Err()
}
func (h Heartbeats) Active(ctx context.Context, jobID, workerID string) (bool, error) {
	got, err := h.Redis.Get(ctx, h.key(jobID)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return got == workerID, nil
}

// ReapStalled marks running jobs failed after either their hard deadline or
// their database heartbeat lease expires; SKIP LOCKED permits concurrent sweepers.
func (s Store) ReapStalled(ctx context.Context) (int64, error) {
	tx, err := database.BeginTenantTx(ctx, s.DB)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE jobs SET status='FAILED', finished_at=now(),
        error_ref=COALESCE(error_ref,'worker heartbeat expired or execution deadline exceeded'), updated_at=now()
        WHERE id IN (SELECT id FROM jobs WHERE status='RUNNING' AND
        ((hard_deadline_at IS NOT NULL AND hard_deadline_at <= now()) OR
         (lease_expires_at IS NOT NULL AND lease_expires_at <= now()) OR
		 (COALESCE(heartbeat_at,started_at) <= now() - interval '90 seconds'))
        FOR UPDATE SKIP LOCKED)`)
	if err != nil {
		return 0, fmt.Errorf("reap stalled jobs: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit stalled job reap: %w", err)
	}
	return tag.RowsAffected(), nil
}
