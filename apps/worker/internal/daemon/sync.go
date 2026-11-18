package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelvin/kelvin/apps/worker/internal/database"
	"github.com/kelvin/kelvin/apps/worker/internal/normalization"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

// StateSyncer synchronizes job and assessment status transitions between
// the queue and the relational database, ensuring zero silent state divergence.
type StateSyncer interface {
	SyncJobState(ctx context.Context, tenantID, assessmentID, jobID string, status string, errMsg string) error
	SyncJobResults(ctx context.Context, tenantID, assessmentID, jobID string, rawFindings []json.RawMessage, correlationID string) error
}

// MemoryStateSyncer provides a thread-safe in-memory state tracker for testing and dev runs.
type MemoryStateSyncer struct {
	mu             sync.Mutex
	Transitions    []JobTransition
	StoredFindings []StoredFinding
}

// StoredFinding captures finding records tracked in-memory.
type StoredFinding struct {
	FindingID    string
	TenantID     string
	AssessmentID string
	JobID        string
	Fingerprint  string
	Title        string
	Severity     string
	ScannerID    string
	Occurrences  int
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
		Transitions:    make([]JobTransition, 0),
		StoredFindings: make([]StoredFinding, 0),
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

// SyncJobResults processes and persists normalized findings in memory.
func (m *MemoryStateSyncer) SyncJobResults(
	_ context.Context,
	tenantID, assessmentID, jobID string,
	rawFindings []json.RawMessage,
	_ string,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalizer := normalization.NewNormalizer()
	validator := normalization.NewResultValidator()
	report := validator.ValidateBatch(rawFindings, "")

	for _, f := range report.Accepted {
		normF, err := normalizer.Normalize([]byte(fmt.Sprintf(`{"title":%q}`, f.Title)), normalization.Context{
			AssessmentID: assessmentID,
			RunID:        jobID,
		})
		fp := f.Fingerprint
		if fp == "" && err == nil {
			fp = normF.Fingerprint
		}

		matched := false
		for i := range m.StoredFindings {
			if m.StoredFindings[i].TenantID == tenantID && m.StoredFindings[i].Fingerprint == fp {
				m.StoredFindings[i].Occurrences++
				m.StoredFindings[i].AssessmentID = assessmentID
				m.StoredFindings[i].JobID = jobID
				matched = true
				break
			}
		}
		if !matched {
			m.StoredFindings = append(m.StoredFindings, StoredFinding{
				FindingID:    uuid.New().String(),
				TenantID:     tenantID,
				AssessmentID: assessmentID,
				JobID:        jobID,
				Fingerprint:  fp,
				Title:        f.Title,
				Severity:     f.Severity,
				ScannerID:    f.Scanner.Name,
				Occurrences:  1,
			})
		}
	}
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

// GetStoredFindings returns all findings stored in memory.
func (m *MemoryStateSyncer) GetStoredFindings() []StoredFinding {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]StoredFinding, len(m.StoredFindings))
	copy(res, m.StoredFindings)
	return res
}

// GetSeverityCounts returns finding severity counts for an assessment.
func (m *MemoryStateSyncer) GetSeverityCounts(assessmentID string) map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]int{
		"CRITICAL":      0,
		"HIGH":          0,
		"MEDIUM":        0,
		"LOW":           0,
		"INFORMATIONAL": 0,
		"TOTAL":         0,
	}
	for _, f := range m.StoredFindings {
		if f.AssessmentID == assessmentID {
			counts[f.Severity]++
			counts["TOTAL"]++
		}
	}
	return counts
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
		SET status = $1, error_detail = $2, updated_at = NOW()
		WHERE id = $3 AND tenant_id = $4;
	`
	if _, err := tx.Exec(ctx, updateAssessment, status, errMsg, assessmentID, tenantID); err != nil {
		return fmt.Errorf("state_sync: update assessment: %w", err)
	}

	// Update jobs status if job ID is provided
	if jobID != "" {
		const updateJob = `
			UPDATE jobs
			SET status = $1, error_ref = $2, updated_at = NOW()
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

// SyncJobResults normalizes, validates, and persists findings and observations into PostgreSQL inside tenant RLS transaction.
func (s *PostgresStateSyncer) SyncJobResults(
	ctx context.Context,
	tenantID, assessmentID, jobID string,
	rawFindings []json.RawMessage,
	correlationID string,
) error {
	if s.pool == nil || len(rawFindings) == 0 {
		return nil
	}

	tenantCtx, err := tenant.ParseAndWithID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("sync_results: invalid tenant context: %w", err)
	}

	tx, err := database.BeginTenantTx(tenantCtx, s.pool)
	if err != nil {
		return fmt.Errorf("sync_results: begin tenant tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Retrieve project ID from assessment
	var projectID uuid.UUID
	var targetAddress string
	const getAssessment = `
		SELECT project_id, COALESCE(profile_snapshot->>'target_url', '') FROM assessments WHERE id = $1 AND tenant_id = $2;
	`
	if err := tx.QueryRow(ctx, getAssessment, assessmentID, tenantID).Scan(&projectID, &targetAddress); err != nil {
		return fmt.Errorf("sync_results: lookup assessment project: %w", err)
	}

	// Ensure job record exists to satisfy foreign key constraint findings_job_id_fkey
	const ensureJob = `
		INSERT INTO jobs (id, tenant_id, assessment_id, correlation_id, status)
		VALUES ($1, $2, $3, $4, 'RUNNING')
		ON CONFLICT (id) DO UPDATE SET updated_at = NOW();
	`
	corrUUID, _ := uuid.Parse(correlationID)
	if corrUUID == uuid.Nil {
		corrUUID = uuid.New()
	}
	if _, err := tx.Exec(ctx, ensureJob, jobID, tenantID, assessmentID, corrUUID); err != nil {
		return fmt.Errorf("sync_results: ensure job: %w", err)
	}

	validator := normalization.NewResultValidator()
	report := validator.ValidateBatch(rawFindings, normalization.NormalizeAsset(targetAddress))
	if len(report.Quarantined) > 0 {
		for _, q := range report.Quarantined {
			fmt.Printf("sync_results: quarantined finding [%d] reason=%q violations=%v snippet=%q\n", q.Index, q.Reason, q.Violations, q.RawSnippet)
		}
	}

	for _, f := range report.Accepted {
		findingID, err := uuid.NewV7()
		if err != nil {
			findingID = uuid.New()
		}

		cveIDs := f.Vulnerability.CVEIDs
		if cveIDs == nil {
			cveIDs = []string{}
		}
		tags := f.Tags
		if tags == nil {
			tags = []string{}
		}
		scannerData, err := json.Marshal(f.ScannerMeta)
		if err != nil {
			scannerData = []byte("{}")
		}

		var cvssScore *float64
		if f.Vulnerability.CVSS != nil {
			cvssScore = &f.Vulnerability.CVSS.Score
		}

		observedAt := time.Now().UTC()
		if f.DiscoveredAt != "" {
			if parsed, parseErr := time.Parse(time.RFC3339, f.DiscoveredAt); parseErr == nil {
				observedAt = parsed
			}
		}

		const upsertFinding = `
			INSERT INTO findings (
				id, tenant_id, project_id, assessment_id, job_id,
				fingerprint, title, severity, confidence, cvss_score, cwe_id, cve_ids, status,
				affected_endpoint, scanner_data, tags, first_seen_at, last_seen_at,
				first_job_id, last_job_id, occurrence_count, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10, $11, $12, 'OPEN',
				$13, $14, $15, $16, $16,
				$5, $5, 1, NOW(), NOW()
			)
			ON CONFLICT (project_id, fingerprint) DO UPDATE SET
				assessment_id = EXCLUDED.assessment_id,
				job_id = EXCLUDED.job_id,
				last_seen_at = EXCLUDED.last_seen_at,
				last_job_id = EXCLUDED.last_job_id,
				occurrence_count = findings.occurrence_count + 1,
				updated_at = EXCLUDED.updated_at
			RETURNING id;
		`

		var persistedID uuid.UUID
		err = tx.QueryRow(ctx, upsertFinding,
			findingID, tenantID, projectID, assessmentID, jobID,
			f.Fingerprint, f.Title, f.Severity, f.Confidence, cvssScore, f.Vulnerability.CWEID, cveIDs,
			f.Target.Endpoint, scannerData, tags, observedAt,
		).Scan(&persistedID)
		if err != nil {
			return fmt.Errorf("sync_results: upsert finding: %w", err)
		}

		obsID, err := uuid.NewV7()
		if err != nil {
			obsID = uuid.New()
		}

		evidenceRefs := make([]string, 0, len(f.Evidence))
		for _, ev := range f.Evidence {
			if ev.ChecksumSHA256 != "" {
				evidenceRefs = append(evidenceRefs, ev.ChecksumSHA256)
			}
		}
		evidenceJSON, _ := json.Marshal(evidenceRefs)

		const insertObservation = `
			INSERT INTO finding_observations (
				id, tenant_id, finding_id, assessment_id, job_id, scanner_id,
				observed_at, evidence_refs, raw_metadata, created_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, NOW()
			)
			ON CONFLICT (id, tenant_id) DO NOTHING;
		`
		if _, err := tx.Exec(ctx, insertObservation,
			obsID, tenantID, persistedID, assessmentID, jobID, f.Scanner.Name,
			observedAt, evidenceJSON, scannerData,
		); err != nil {
			return fmt.Errorf("sync_results: insert observation: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("sync_results: commit tx: %w", err)
	}
	return nil
}
