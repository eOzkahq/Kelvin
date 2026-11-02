package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrFindingNotFound = errors.New("findings: finding not found")
)

// DBTX defines the database executor interface satisfied by *pgxpool.Pool, *pgx.Conn, and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PostgresFindingRepository provides PostgreSQL persistence for persistent findings, observations, and events.
type PostgresFindingRepository struct {
	db DBTX
}

// NewPostgresFindingRepository creates a PostgreSQL finding repository.
func NewPostgresFindingRepository(db DBTX) *PostgresFindingRepository {
	return &PostgresFindingRepository{db: db}
}

// GetFindingsByProject retrieves active (non-deleted) findings for a tenant and project.
func (r *PostgresFindingRepository) GetFindingsByProject(
	ctx context.Context,
	tenantID, projectID uuid.UUID,
) ([]*PersistentFinding, error) {
	const query = `
		SELECT
			id, tenant_id, project_id, assessment_id, job_id, asset_id, correlation_group_id,
			fingerprint, title, severity, confidence, cvss_score, cwe_id, cve_ids, status,
			affected_endpoint, scanner_data, tags, first_seen_at, last_seen_at,
			first_job_id, last_job_id, occurrence_count, created_at, updated_at
		FROM findings
		WHERE tenant_id = $1 AND project_id = $2 AND deleted_at IS NULL
		ORDER BY last_seen_at DESC;
	`

	rows, err := r.db.Query(ctx, query, tenantID, projectID)
	if err != nil {
		return nil, fmt.Errorf("findings: query project findings failed: %w", err)
	}
	defer rows.Close()

	var findings []*PersistentFinding
	for rows.Next() {
		f := &PersistentFinding{}
		var scannerDataBytes []byte
		var cvssScore *float64

		err := rows.Scan(
			&f.ID, &f.TenantID, &f.ProjectID, &f.AssessmentID, &f.JobID, &f.AssetID, &f.CorrelationGroupID,
			&f.Fingerprint, &f.Title, &f.Severity, &f.Confidence, &cvssScore, &f.CWEID, &f.CVEIDs, &f.Status,
			&f.AffectedEndpoint, &scannerDataBytes, &f.Tags, &f.FirstSeenAt, &f.LastSeenAt,
			&f.FirstJobID, &f.LastJobID, &f.OccurrenceCount, &f.CreatedAt, &f.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("findings: scan finding row failed: %w", err)
		}

		f.CVSSScore = cvssScore
		if len(scannerDataBytes) > 0 {
			_ = json.Unmarshal(scannerDataBytes, &f.ScannerData)
		}
		findings = append(findings, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: rows iteration error: %w", err)
	}

	return findings, nil
}

// GetFindingByID retrieves a single finding by tenant and ID.
func (r *PostgresFindingRepository) GetFindingByID(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) (*PersistentFinding, error) {
	const query = `
		SELECT
			id, tenant_id, project_id, assessment_id, job_id, asset_id, correlation_group_id,
			fingerprint, title, severity, confidence, cvss_score, cwe_id, cve_ids, status,
			affected_endpoint, scanner_data, tags, first_seen_at, last_seen_at,
			first_job_id, last_job_id, occurrence_count, created_at, updated_at
		FROM findings
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL;
	`

	f := &PersistentFinding{}
	var scannerDataBytes []byte
	var cvssScore *float64

	err := r.db.QueryRow(ctx, query, tenantID, findingID).Scan(
		&f.ID, &f.TenantID, &f.ProjectID, &f.AssessmentID, &f.JobID, &f.AssetID, &f.CorrelationGroupID,
		&f.Fingerprint, &f.Title, &f.Severity, &f.Confidence, &cvssScore, &f.CWEID, &f.CVEIDs, &f.Status,
		&f.AffectedEndpoint, &scannerDataBytes, &f.Tags, &f.FirstSeenAt, &f.LastSeenAt,
		&f.FirstJobID, &f.LastJobID, &f.OccurrenceCount, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, fmt.Errorf("findings: get finding by id failed: %w", err)
	}

	f.CVSSScore = cvssScore
	if len(scannerDataBytes) > 0 {
		_ = json.Unmarshal(scannerDataBytes, &f.ScannerData)
	}
	return f, nil
}

// GetObservationsByFinding retrieves paginated historical observation records for a finding.
func (r *PostgresFindingRepository) GetObservationsByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	limit, offset int,
) ([]*FindingObservation, error) {
	const query = `
		SELECT
			id, tenant_id, finding_id, assessment_id, job_id, scanner_id,
			observed_at, evidence_refs, raw_metadata, created_at
		FROM finding_observations
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY observed_at DESC
		LIMIT $3 OFFSET $4;
	`

	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.db.Query(ctx, query, tenantID, findingID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("findings: query observations failed: %w", err)
	}
	defer rows.Close()

	var observations []*FindingObservation
	for rows.Next() {
		obs := &FindingObservation{}
		var evidenceBytes []byte
		var metaBytes []byte

		err := rows.Scan(
			&obs.ID, &obs.TenantID, &obs.FindingID, &obs.AssessmentID, &obs.JobID, &obs.ScannerID,
			&obs.ObservedAt, &evidenceBytes, &metaBytes, &obs.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("findings: scan observation row failed: %w", err)
		}

		if len(evidenceBytes) > 0 {
			_ = json.Unmarshal(evidenceBytes, &obs.EvidenceRefs)
		}
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &obs.RawMetadata)
		}
		observations = append(observations, obs)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: observation rows iteration error: %w", err)
	}

	return observations, nil
}

// SaveFinding inserts or updates a persistent finding record.
func (r *PostgresFindingRepository) SaveFinding(ctx context.Context, f *PersistentFinding) error {
	const query = `
		INSERT INTO findings (
			id, tenant_id, project_id, assessment_id, job_id, asset_id, correlation_group_id,
			fingerprint, title, severity, confidence, cvss_score, cwe_id, cve_ids, status,
			affected_endpoint, scanner_data, tags, first_seen_at, last_seen_at,
			first_job_id, last_job_id, occurrence_count, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25
		)
		ON CONFLICT (project_id, fingerprint) DO UPDATE SET
			assessment_id = EXCLUDED.assessment_id,
			job_id = EXCLUDED.job_id,
			last_seen_at = EXCLUDED.last_seen_at,
			last_job_id = EXCLUDED.last_job_id,
			occurrence_count = findings.occurrence_count + 1,
			updated_at = EXCLUDED.updated_at;
	`

	scannerDataJSON, err := json.Marshal(f.ScannerData)
	if err != nil {
		scannerDataJSON = []byte("{}")
	}

	cveIDs := f.CVEIDs
	if cveIDs == nil {
		cveIDs = []string{}
	}
	tags := f.Tags
	if tags == nil {
		tags = []string{}
	}

	_, err = r.db.Exec(ctx, query,
		f.ID, f.TenantID, f.ProjectID, f.AssessmentID, f.JobID, f.AssetID, f.CorrelationGroupID,
		f.Fingerprint, f.Title, f.Severity, f.Confidence, f.CVSSScore, f.CWEID, cveIDs, string(f.Status),
		f.AffectedEndpoint, scannerDataJSON, tags, f.FirstSeenAt, f.LastSeenAt,
		f.FirstJobID, f.LastJobID, f.OccurrenceCount, f.CreatedAt, f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: upsert finding failed: %w", err)
	}
	return nil
}

// SaveObservation inserts an immutable point-in-time observation record.
func (r *PostgresFindingRepository) SaveObservation(ctx context.Context, obs *FindingObservation) error {
	const query = `
		INSERT INTO finding_observations (
			id, tenant_id, finding_id, assessment_id, job_id, scanner_id,
			observed_at, evidence_refs, raw_metadata, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		);
	`

	evidenceJSON, err := json.Marshal(obs.EvidenceRefs)
	if err != nil {
		evidenceJSON = []byte("[]")
	}
	metaJSON, err := json.Marshal(obs.RawMetadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	_, err = r.db.Exec(ctx, query,
		obs.ID, obs.TenantID, obs.FindingID, obs.AssessmentID, obs.JobID, obs.ScannerID,
		obs.ObservedAt, evidenceJSON, metaJSON, obs.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: insert observation failed: %w", err)
	}
	return nil
}

// SaveEvent appends an audit event to finding_events.
func (r *PostgresFindingRepository) SaveEvent(ctx context.Context, ev *FindingEvent) error {
	const query = `
		INSERT INTO finding_events (
			id, tenant_id, finding_id, from_status, to_status,
			event_type, actor_user_id, note, correlation_id, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		);
	`

	var fromStatus *string
	if ev.FromStatus != nil {
		s := string(*ev.FromStatus)
		fromStatus = &s
	}

	_, err := r.db.Exec(ctx, query,
		ev.ID, ev.TenantID, ev.FindingID, fromStatus, string(ev.ToStatus),
		string(ev.EventType), ev.ActorUserID, ev.Note, ev.CorrelationID, ev.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: insert event failed: %w", err)
	}
	return nil
}
