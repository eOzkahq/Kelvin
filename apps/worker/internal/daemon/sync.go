package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelvin/kelvin/apps/worker/internal/database"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

// StateSyncer synchronizes job and assessment status transitions between
// the queue and the relational database, ensuring zero silent state divergence.
type StateSyncer interface {
	SyncJobState(ctx context.Context, tenantID, assessmentID, jobID string, status string, errMsg string) error
}

// MemoryStateSyncer provides a thread-safe in-memory state tracker for testing and dev runs.
type MemoryStateSyncer struct {
	mu          sync.Mutex
	Transitions []JobTransition
}

// JobTransition records a single state transition event.
type JobTransition struct {
	TenantID     string
	AssessmentID string
	JobID        string
	Status       string
	ErrorMessage string
	Timestamp    time.Time
}

// NewMemoryStateSyncer constructs an empty MemoryStateSyncer.
func NewMemoryStateSyncer() *MemoryStateSyncer {
	return &MemoryStateSyncer{
		Transitions: make([]JobTransition, 0),
	}
}

// SyncJobState records the transition event in memory.
func (m *MemoryStateSyncer) SyncJobState(_ context.Context, tenantID, assessmentID, jobID string, status string, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Transitions = append(m.Transitions, JobTransition{
		TenantID:     tenantID,
		AssessmentID: assessmentID,
		JobID:        jobID,
		Status:       status,
		ErrorMessage: errMsg,
		Timestamp:    time.Now().UTC(),
	})
	return nil
}

// GetTransitions returns a copy of recorded state transitions.
func (m *MemoryStateSyncer) GetTransitions() []JobTransition {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]JobTransition, len(m.Transitions))
	copy(res, m.Transitions)
	return res
}

// PostgresStateSyncer updates assessment and job records inside tenant-isolated transactions.
type PostgresStateSyncer struct {
	pool *pgxpool.Pool
}

// NewPostgresStateSyncer creates a state syncer backed by PostgreSQL.
func NewPostgresStateSyncer(pool *pgxpool.Pool) *PostgresStateSyncer {
	return &PostgresStateSyncer{pool: pool}
}

// SyncJobState applies state changes within a tenant RLS transaction.
func (s *PostgresStateSyncer) SyncJobState(ctx context.Context, tenantID, assessmentID, jobID string, status string, errMsg string) error {
	if s.pool == nil {
		return nil
	}

	tenantCtx, err := tenant.ParseAndWithID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("state_sync: invalid tenant context: %w", err)
	}

	tx, err := database.BeginTenantTx(tenantCtx, s.pool)
	if err != nil {
		return fmt.Errorf("state_sync: begin tenant tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Update assessment status
	const updateAssessment = `
		UPDATE assessments
		SET status = $1, error_message = $2, updated_at = NOW()
		WHERE id = $3 AND tenant_id = $4;
	`
	if _, err := tx.Exec(ctx, updateAssessment, status, errMsg, assessmentID, tenantID); err != nil {
		return fmt.Errorf("state_sync: update assessment: %w", err)
	}

	// Update jobs status if job ID is provided
	if jobID != "" {
		const updateJob = `
			UPDATE jobs
			SET state = $1, error_message = $2, updated_at = NOW()
			WHERE id = $3 AND tenant_id = $4;
		`
		if _, err := tx.Exec(ctx, updateJob, status, errMsg, jobID, tenantID); err != nil {
			return fmt.Errorf("state_sync: update job: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("state_sync: commit tx: %w", err)
	}
	return nil
}
