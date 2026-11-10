package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

// GetEvidenceByFindingID retrieves all evidence linked to a finding within tenant boundaries.
func (r *PostgresFindingRepository) GetEvidenceByFindingID(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) ([]*evidence.EvidenceItem, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	const query = `
		SELECT
			e.id, e.tenant_id, e.project_id, e.assessment_id, e.job_id,
			e.finding_id, e.observation_id, e.evidence_type, e.provenance,
			e.content_type, e.storage_ref, e.inline_content, e.checksum_sha256,
			e.size_bytes, e.redaction_status, e.redacted_fields, e.sensitivity_level,
			e.status, e.retention_days, e.expires_at, e.created_at, e.updated_at
		FROM evidence e
		LEFT JOIN finding_evidence_links fel ON fel.evidence_id = e.id AND fel.tenant_id = e.tenant_id
		WHERE e.tenant_id = $1 AND (e.finding_id = $2 OR fel.finding_id = $2)
		ORDER BY e.created_at DESC;
	`

	rows, err := r.db.Query(ctx, query, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("findings: query evidence by finding failed: %w", err)
	}
	defer rows.Close()

	var items []*evidence.EvidenceItem
	for rows.Next() {
		item := &evidence.EvidenceItem{}
		var id, tID, pID, aID, jID uuid.UUID
		var fID, oID *uuid.UUID
		var storageRef, inlineContent *string
		var redactedFieldsBytes []byte

		err := rows.Scan(
			&id, &tID, &pID, &aID, &jID,
			&fID, &oID, &item.EvidenceType, &item.Provenance,
			&item.ContentType, &storageRef, &inlineContent, &item.ChecksumSHA256,
			&item.SizeBytes, &item.RedactionStatus, &redactedFieldsBytes, &item.SensitivityLevel,
			&item.Status, &item.RetentionDays, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("findings: scan evidence row failed: %w", err)
		}

		item.ID = id.String()
		item.TenantID = tID.String()
		item.ProjectID = pID.String()
		item.AssessmentID = aID.String()
		item.JobID = jID.String()
		if fID != nil {
			s := fID.String()
			item.FindingID = &s
		}
		if oID != nil {
			s := oID.String()
			item.ObservationID = &s
		}
		if storageRef != nil {
			item.StorageRef = *storageRef
		}
		if inlineContent != nil {
			item.InlineContent = *inlineContent
		}
		if len(redactedFieldsBytes) > 0 {
			_ = json.Unmarshal(redactedFieldsBytes, &item.RedactedFields)
		}
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: evidence rows iteration error: %w", err)
	}
	return items, nil
}

// GetEvidenceByID retrieves an individual evidence item by tenant and ID.
func (r *PostgresFindingRepository) GetEvidenceByID(
	ctx context.Context,
	tenantID, evidenceID uuid.UUID,
) (*evidence.EvidenceItem, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if evidenceID == uuid.Nil {
		return nil, errors.New("findings: evidence_id is required")
	}

	const query = `
		SELECT
			id, tenant_id, project_id, assessment_id, job_id,
			finding_id, observation_id, evidence_type, provenance,
			content_type, storage_ref, inline_content, checksum_sha256,
			size_bytes, redaction_status, redacted_fields, sensitivity_level,
			status, retention_days, expires_at, created_at, updated_at
		FROM evidence
		WHERE tenant_id = $1 AND id = $2;
	`

	item := &evidence.EvidenceItem{}
	var id, tID, pID, aID, jID uuid.UUID
	var fID, oID *uuid.UUID
	var storageRef, inlineContent *string
	var redactedFieldsBytes []byte

	err := r.db.QueryRow(ctx, query, tenantID, evidenceID).Scan(
		&id, &tID, &pID, &aID, &jID,
		&fID, &oID, &item.EvidenceType, &item.Provenance,
		&item.ContentType, &storageRef, &inlineContent, &item.ChecksumSHA256,
		&item.SizeBytes, &item.RedactionStatus, &redactedFieldsBytes, &item.SensitivityLevel,
		&item.Status, &item.RetentionDays, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("evidence not found")
		}
		return nil, fmt.Errorf("findings: get evidence by id failed: %w", err)
	}

	item.ID = id.String()
	item.TenantID = tID.String()
	item.ProjectID = pID.String()
	item.AssessmentID = aID.String()
	item.JobID = jID.String()
	if fID != nil {
		s := fID.String()
		item.FindingID = &s
	}
	if oID != nil {
		s := oID.String()
		item.ObservationID = &s
	}
	if storageRef != nil {
		item.StorageRef = *storageRef
	}
	if inlineContent != nil {
		item.InlineContent = *inlineContent
	}
	if len(redactedFieldsBytes) > 0 {
		_ = json.Unmarshal(redactedFieldsBytes, &item.RedactedFields)
	}
	return item, nil
}

// GetObservationsByAssessment retrieves observations and executed scanners for an assessment.
func (r *PostgresFindingRepository) GetObservationsByAssessment(
	ctx context.Context,
	tenantID, assessmentID uuid.UUID,
) ([]*FindingObservation, []string, error) {
	if tenantID == uuid.Nil {
		return nil, nil, ErrTenantRequired
	}
	if assessmentID == uuid.Nil {
		return nil, nil, errors.New("findings: assessment_id is required")
	}

	var exists bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM assessments WHERE tenant_id = $1 AND id = $2)`, tenantID, assessmentID).Scan(&exists)
	if err != nil {
		return nil, nil, fmt.Errorf("findings: verify assessment exists: %w", err)
	}
	if !exists {
		return nil, nil, errors.New("assessment not found")
	}

	const query = `
		SELECT
			id, tenant_id, finding_id, assessment_id, job_id, scanner_id,
			observed_at, evidence_refs, raw_metadata, created_at
		FROM finding_observations
		WHERE tenant_id = $1 AND assessment_id = $2
		ORDER BY observed_at DESC;
	`

	rows, err := r.db.Query(ctx, query, tenantID, assessmentID)
	if err != nil {
		return nil, nil, fmt.Errorf("findings: query observations by assessment failed: %w", err)
	}
	defer rows.Close()

	var observations []*FindingObservation
	scannerSet := make(map[string]struct{})
	for rows.Next() {
		obs := &FindingObservation{}
		var evidenceBytes, metaBytes []byte
		err := rows.Scan(
			&obs.ID, &obs.TenantID, &obs.FindingID, &obs.AssessmentID, &obs.JobID, &obs.ScannerID,
			&obs.ObservedAt, &evidenceBytes, &metaBytes, &obs.CreatedAt,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("findings: scan assessment observation failed: %w", err)
		}
		if len(evidenceBytes) > 0 {
			_ = json.Unmarshal(evidenceBytes, &obs.EvidenceRefs)
		}
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &obs.RawMetadata)
		}
		if obs.ScannerID != "" {
			scannerSet[obs.ScannerID] = struct{}{}
		}
		observations = append(observations, obs)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("findings: assessment observations iteration failed: %w", err)
	}

	scanners := make([]string, 0, len(scannerSet))
	for s := range scannerSet {
		scanners = append(scanners, s)
	}
	return observations, scanners, nil
}

// SearchFindings executes filtered, sorted, paginated search over findings backed by PostgreSQL.
func (r *PostgresFindingRepository) SearchFindings(
	ctx context.Context,
	q FindingSearchQuery,
) (*FindingSearchResult, error) {
	if q.TenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}

	const query = `
		SELECT
			id, tenant_id, project_id, assessment_id, job_id, asset_id, correlation_group_id,
			fingerprint, title, severity, confidence, cvss_score, cwe_id, cve_ids, status,
			affected_endpoint, scanner_data, tags, first_seen_at, last_seen_at,
			first_job_id, last_job_id, occurrence_count, created_at, updated_at
		FROM findings
		WHERE tenant_id = $1 AND deleted_at IS NULL;
	`

	rows, err := r.db.Query(ctx, query, q.TenantID)
	if err != nil {
		return nil, fmt.Errorf("findings: search query failed: %w", err)
	}
	defer rows.Close()

	engine := NewMemoryFindingSearchEngine()
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
			return nil, fmt.Errorf("findings: scan search finding failed: %w", err)
		}
		f.CVSSScore = cvssScore
		if len(scannerDataBytes) > 0 {
			_ = json.Unmarshal(scannerDataBytes, &f.ScannerData)
		}
		engine.IndexFinding(f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: search rows iteration failed: %w", err)
	}

	// Load active suppressions
	suppRows, err := r.db.Query(ctx, `SELECT finding_id FROM finding_suppressions WHERE tenant_id = $1 AND expires_at > now()`, q.TenantID)
	if err == nil {
		defer suppRows.Close()
		for suppRows.Next() {
			var fID uuid.UUID
			if err := suppRows.Scan(&fID); err == nil {
				engine.SetSuppressed(fID, true)
			}
		}
	}

	return engine.SearchFindings(ctx, q)
}

// GetDashboardMetrics compiles KPI dashboard aggregates strictly for the tenant backed by PostgreSQL.
func (r *PostgresFindingRepository) GetDashboardMetrics(
	ctx context.Context,
	tenantID uuid.UUID,
) (*FindingDashboardMetrics, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}

	const query = `
		SELECT
			id, tenant_id, project_id, assessment_id, job_id, asset_id, correlation_group_id,
			fingerprint, title, severity, confidence, cvss_score, cwe_id, cve_ids, status,
			affected_endpoint, scanner_data, tags, first_seen_at, last_seen_at,
			first_job_id, last_job_id, occurrence_count, created_at, updated_at
		FROM findings
		WHERE tenant_id = $1 AND deleted_at IS NULL;
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("findings: dashboard query failed: %w", err)
	}
	defer rows.Close()

	engine := NewMemoryFindingSearchEngine()
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
			return nil, fmt.Errorf("findings: scan dashboard finding failed: %w", err)
		}
		f.CVSSScore = cvssScore
		if len(scannerDataBytes) > 0 {
			_ = json.Unmarshal(scannerDataBytes, &f.ScannerData)
		}
		engine.IndexFinding(f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: dashboard rows iteration failed: %w", err)
	}

	return engine.GetDashboardMetrics(ctx, tenantID)
}
