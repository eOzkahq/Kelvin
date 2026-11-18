package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository interface {
	Create(ctx context.Context, asmt *AssessmentRecord, rawProfile any) error
	GetByID(ctx context.Context, tenantID, id string) (*AssessmentDetail, error)
	List(ctx context.Context, tenantID string, filter AssessmentFilter) ([]AssessmentRecord, int, error)
	UpdateStatus(ctx context.Context, tenantID, id string, status AssessmentStatus, errorDetail string) error
	GetProfiles(ctx context.Context, tenantID string) ([]ScanProfile, error)
	GetTargets(ctx context.Context, tenantID string) ([]TargetOption, error)
	RecordManifest(ctx context.Context, tenantID, assessmentID, digest string, manifestData any) error
}

var DefaultProfiles = []ScanProfile{
	{
		ID:          "standard",
		Name:        "Standard Baseline Assessment",
		Description: "Automated reconnaissance, service enumeration, and non-destructive vulnerability scanning via certified Nuclei v3.11.1.",
		Scanners:    []string{"nuclei"},
		RiskLevel:   "LOW",
	},
	{
		ID:          "safe_web",
		Name:        "Passive Web Application Audit",
		Description: "Passive HTTP traffic inspection, security headers, cookies, and anti-MIME sniffing verification via OWASP ZAP v2.17.0.",
		Scanners:    []string{"zap"},
		RiskLevel:   "LOW",
	},
	{
		ID:          "deep",
		Name:        "Full Multi-Phase Assessment Pipeline",
		Description: "Comprehensive sequential scanner assessment executing Nuclei and OWASP ZAP in passive verification mode.",
		Scanners:    []string{"nuclei", "zap"},
		RiskLevel:   "MEDIUM",
	},
}

var DefaultTargets = []TargetOption{
	{
		ID:          "mock-target-01",
		Name:        "Staging Mock Target (Canary)",
		Address:     "http://127.0.0.1:8080",
		Verified:    true,
		Environment: "STAGING",
	},
	{
		ID:          "mock-target-02",
		Name:        "Internal Scanner Mock Host",
		Address:     "http://scanner-mock.kelvin.internal:8080",
		Verified:    true,
		Environment: "INTERNAL",
	},
}

// --- In-Memory Repository for unit tests and offline testing ---

type MemoryRepository struct {
	mu          sync.RWMutex
	assessments map[string]*AssessmentDetail
	manifests   map[string]any
	profiles    []ScanProfile
	targets     []TargetOption
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		assessments: make(map[string]*AssessmentDetail),
		manifests:   make(map[string]any),
		profiles:    append([]ScanProfile(nil), DefaultProfiles...),
		targets:     append([]TargetOption(nil), DefaultTargets...),
	}
}

func (m *MemoryRepository) Create(_ context.Context, asmt *AssessmentRecord, _ any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	detail := &AssessmentDetail{
		AssessmentRecord: *asmt,
		CurrentStage:     StageQueued,
		Scanners:         make([]ScannerExecution, 0),
		Logs: []AssessmentLog{
			{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Level:     "INFO",
				Message:   "Assessment created and enqueued",
				Stage:     string(StageQueued),
			},
		},
		ProgressPercent: 0,
		Targets: []AssessmentTarget{
			{
				Host:     asmt.TargetAddress,
				Verified: true,
			},
		},
	}
	m.assessments[asmt.ID] = detail
	return nil
}

func (m *MemoryRepository) GetByID(_ context.Context, tenantID, id string) (*AssessmentDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	asmt, exists := m.assessments[id]
	if !exists || asmt.TenantID != tenantID {
		return nil, ErrAssessmentNotFound
	}
	copied := *asmt
	return &copied, nil
}

func (m *MemoryRepository) List(_ context.Context, tenantID string, filter AssessmentFilter) ([]AssessmentRecord, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matching []AssessmentRecord
	for _, asmt := range m.assessments {
		if asmt.TenantID != tenantID {
			continue
		}
		if filter.Status != "" && string(asmt.Status) != filter.Status {
			continue
		}
		if filter.ProfileID != "" && asmt.ProfileID != filter.ProfileID {
			continue
		}
		if filter.Search != "" {
			term := strings.ToLower(filter.Search)
			if !strings.Contains(strings.ToLower(asmt.Name), term) && !strings.Contains(strings.ToLower(asmt.TargetAddress), term) {
				continue
			}
		}
		matching = append(matching, asmt.AssessmentRecord)
	}

	total := len(matching)
	if filter.Offset >= total {
		return []AssessmentRecord{}, total, nil
	}
	end := total
	if filter.Limit > 0 && filter.Offset+filter.Limit < end {
		end = filter.Offset + filter.Limit
	}
	return matching[filter.Offset:end], total, nil
}

func (m *MemoryRepository) UpdateStatus(_ context.Context, tenantID, id string, status AssessmentStatus, errorDetail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	asmt, exists := m.assessments[id]
	if !exists || asmt.TenantID != tenantID {
		return ErrAssessmentNotFound
	}
	asmt.Status = status
	now := time.Now().UTC()
	asmt.UpdatedAt = &now
	if status == StatusCompleted || status == StatusFailed || status == StatusCancelled || status == StatusTimedOut {
		asmt.CompletedAt = &now
	}
	if errorDetail != "" {
		asmt.ErrorMessage = errorDetail
	}
	asmt.Logs = append(asmt.Logs, AssessmentLog{
		ID:        uuid.New().String(),
		Timestamp: now,
		Level:     "INFO",
		Message:   fmt.Sprintf("Status updated to %s", status),
		Stage:     string(status),
	})
	return nil
}

func (m *MemoryRepository) GetProfiles(_ context.Context, _ string) ([]ScanProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]ScanProfile, len(m.profiles))
	copy(copied, m.profiles)
	return copied, nil
}

func (m *MemoryRepository) GetTargets(_ context.Context, _ string) ([]TargetOption, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]TargetOption, len(m.targets))
	copy(copied, m.targets)
	return copied, nil
}

func (m *MemoryRepository) RecordManifest(_ context.Context, _, assessmentID, digest string, manifestData any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.manifests[assessmentID] = manifestData
	return nil
}

// --- PostgreSQL Repository with Tenant RLS ---

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) ensureDefaultProject(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	const findQuery = `SELECT id FROM projects WHERE tenant_id = $1 AND deleted_at IS NULL LIMIT 1`
	var projectID uuid.UUID
	err := r.pool.QueryRow(ctx, findQuery, tenantID).Scan(&projectID)
	if err == nil {
		return projectID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("failed to check existing projects: %w", err)
	}

	projectID = uuid.New()
	const insertQuery = `
		INSERT INTO projects (id, tenant_id, name, description)
		VALUES ($1, $2, 'Default Security Project', 'Default automated security assessment workspace')
		ON CONFLICT (id, tenant_id) DO NOTHING
	`
	_, err = r.pool.Exec(ctx, insertQuery, projectID, tenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create default project: %w", err)
	}
	return projectID, nil
}

func (r *PostgresRepository) ensureProfileID(ctx context.Context, profileIDStr string) (uuid.UUID, error) {
	parsedUUID, err := uuid.Parse(profileIDStr)
	if err == nil {
		return parsedUUID, nil
	}

	// Lookup profile by slug, name, or profile_id in scan_profiles
	const findSlugQuery = `
		SELECT id FROM scan_profiles
		WHERE lower(slug) = lower($1) OR lower(name) = lower($1) OR lower(profile_id) = lower($1)
		ORDER BY created_at ASC
		LIMIT 1
	`
	var id uuid.UUID
	err = r.pool.QueryRow(ctx, findSlugQuery, profileIDStr).Scan(&id)
	if err == nil {
		return id, nil
	}

	// Create or ensure fallback profile entry
	newID := uuid.New()
	cleanID := strings.ToLower(strings.TrimSpace(profileIDStr))
	if cleanID == "" {
		cleanID = "standard"
	}
	const insertProfileQuery = `
		INSERT INTO scan_profiles (
			id, profile_id, version, definition, name, slug, description,
			scanners, intensity, state, status, created_at, updated_at
		) VALUES (
			$1, $2, '1.0', '{"scanners":["nuclei"]}'::jsonb, $3, $4, $5,
			'["nuclei"]'::jsonb, 'NORMAL', 'ACTIVE', 'ACTIVE', now(), now()
		)
		ON CONFLICT (id) DO NOTHING
	`
	_, err = r.pool.Exec(ctx, insertProfileQuery, newID, cleanID, strings.Title(cleanID), cleanID, "Certified scan profile for "+cleanID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to ensure scan profile: %w", err)
	}
	return newID, nil
}

func (r *PostgresRepository) Create(ctx context.Context, asmt *AssessmentRecord, rawProfile any) error {
	if r.pool == nil {
		return errors.New("postgres connection pool is nil")
	}

	asmtUUID, err := uuid.Parse(asmt.ID)
	if err != nil {
		return fmt.Errorf("invalid assessment ID: %w", err)
	}
	tenantUUID, err := uuid.Parse(asmt.TenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	var projectUUID uuid.UUID
	if asmt.ProjectID != "" {
		projectUUID, err = uuid.Parse(asmt.ProjectID)
		if err != nil {
			return fmt.Errorf("invalid project ID: %w", err)
		}
	} else {
		projectUUID, err = r.ensureDefaultProject(ctx, tenantUUID)
		if err != nil {
			return err
		}
		asmt.ProjectID = projectUUID.String()
	}

	profileUUID, err := r.ensureProfileID(ctx, asmt.ProfileID)
	if err != nil {
		return err
	}

	profileSnapshot := map[string]any{
		"target_url":   asmt.TargetAddress,
		"profile_id":   asmt.ProfileID,
		"profile_name": asmt.ProfileName,
		"raw":          rawProfile,
	}
	snapshotBytes, err := json.Marshal(profileSnapshot)
	if err != nil {
		return fmt.Errorf("marshal profile snapshot: %w", err)
	}

	correlationUUID := uuid.New()
	const insertQuery = `
		INSERT INTO assessments (
			id, tenant_id, project_id, name, profile_id, profile_snapshot,
			status, trigger_type, correlation_id, queued_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, 'MANUAL', $8, now(), now(), now()
		)
	`
	_, err = r.pool.Exec(ctx, insertQuery,
		asmtUUID, tenantUUID, projectUUID, asmt.Name, profileUUID, snapshotBytes,
		string(asmt.Status), correlationUUID,
	)
	if err != nil {
		return fmt.Errorf("insert assessment failed: %w", err)
	}

	return nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, tenantID, id string) (*AssessmentDetail, error) {
	if r.pool == nil {
		return nil, errors.New("postgres connection pool is nil")
	}

	asmtUUID, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrAssessmentNotFound
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, ErrAssessmentNotFound
	}

	const query = `
		SELECT
			a.id, a.tenant_id, a.project_id, a.name, a.profile_id::text,
			a.profile_snapshot, a.status, a.error_detail, a.queued_at,
			a.started_at, a.completed_at, a.created_at, a.updated_at
		FROM assessments a
		WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
	`

	var (
		aID, tID, pID, profID string
		name, status          string
		errorDetail           *string
		profileSnapshot       []byte
		queuedAt, createdAt   time.Time
		startedAt             *time.Time
		completedAt           *time.Time
		updatedAt             time.Time
	)

	err = r.pool.QueryRow(ctx, query, asmtUUID, tenantUUID).Scan(
		&aID, &tID, &pID, &name, &profID,
		&profileSnapshot, &status, &errorDetail, &queuedAt,
		&startedAt, &completedAt, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAssessmentNotFound
		}
		return nil, fmt.Errorf("query assessment failed: %w", err)
	}

	targetAddress := ""
	profileName := "Standard"
	if len(profileSnapshot) > 0 {
		var snapshot map[string]any
		if err := json.Unmarshal(profileSnapshot, &snapshot); err == nil {
			if t, ok := snapshot["target_url"].(string); ok {
				targetAddress = t
			}
			if pn, ok := snapshot["profile_name"].(string); ok {
				profileName = pn
			}
		}
	}

	// Query finding counts
	criticalCount := 0
	highCount := 0
	totalFindings := 0
	const findingsCountQuery = `
		SELECT
			COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS crit,
			COUNT(*) FILTER (WHERE severity = 'HIGH') AS hi,
			COUNT(*) AS total
		FROM findings
		WHERE assessment_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`
	_ = r.pool.QueryRow(ctx, findingsCountQuery, asmtUUID, tenantUUID).Scan(&criticalCount, &highCount, &totalFindings)

	errStr := ""
	if errorDetail != nil {
		errStr = *errorDetail
	}

	stage := StageQueued
	switch AssessmentStatus(status) {
	case StatusRunning:
		stage = StageScanning
	case StatusCompleted:
		stage = StageCompleted
	case StatusFailed:
		stage = StageFailed
	case StatusCancelled:
		stage = StageCancelled
	}

	return &AssessmentDetail{
		AssessmentRecord: AssessmentRecord{
			ID:            aID,
			TenantID:      tID,
			ProjectID:     pID,
			Name:          name,
			ProfileID:     profID,
			ProfileName:   profileName,
			TargetAddress: targetAddress,
			Status:        AssessmentStatus(status),
			CriticalCount: criticalCount,
			HighCount:     highCount,
			TotalFindings: totalFindings,
			CreatedAt:     createdAt,
			CompletedAt:   completedAt,
			UpdatedAt:     &updatedAt,
		},
		CurrentStage:    stage,
		Scanners:        make([]ScannerExecution, 0),
		Logs:            make([]AssessmentLog, 0),
		ErrorMessage:    errStr,
		ProgressPercent: 0,
		Targets: []AssessmentTarget{
			{
				Host:     targetAddress,
				Verified: true,
			},
		},
	}, nil
}

func (r *PostgresRepository) List(ctx context.Context, tenantID string, filter AssessmentFilter) ([]AssessmentRecord, int, error) {
	if r.pool == nil {
		return nil, 0, errors.New("postgres connection pool is nil")
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid tenant ID: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(`WHERE a.tenant_id = $1 AND a.deleted_at IS NULL`)
	args := []any{tenantUUID}
	argIdx := 2

	if filter.Status != "" {
		sb.WriteString(fmt.Sprintf(` AND a.status = $%d`, argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.Search != "" {
		sb.WriteString(fmt.Sprintf(` AND a.name ILIKE $%d`, argIdx))
		args = append(args, "%"+filter.Search+"%")
		argIdx++
	}

	whereClause := sb.String()

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM assessments a %s`, whereClause)
	var total int
	err = r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count assessments failed: %w", err)
	}

	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	listQuery := fmt.Sprintf(`
		SELECT
			a.id, a.tenant_id, a.project_id, a.name, a.profile_id::text,
			a.profile_snapshot, a.status, a.queued_at, a.completed_at, a.created_at, a.updated_at
		FROM assessments a
		%s
		ORDER BY a.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list assessments failed: %w", err)
	}
	defer rows.Close()

	records := make([]AssessmentRecord, 0)
	for rows.Next() {
		var (
			aID, tID, pID, profID string
			name, status          string
			profileSnapshot       []byte
			queuedAt, createdAt   time.Time
			completedAt           *time.Time
			updatedAt             time.Time
		)

		err := rows.Scan(
			&aID, &tID, &pID, &name, &profID,
			&profileSnapshot, &status, &queuedAt, &completedAt, &createdAt, &updatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan assessment row failed: %w", err)
		}

		targetAddress := ""
		profileName := "Standard"
		if len(profileSnapshot) > 0 {
			var snapshot map[string]any
			if err := json.Unmarshal(profileSnapshot, &snapshot); err == nil {
				if t, ok := snapshot["target_url"].(string); ok {
					targetAddress = t
				}
				if pn, ok := snapshot["profile_name"].(string); ok {
					profileName = pn
				}
			}
		}

		records = append(records, AssessmentRecord{
			ID:            aID,
			TenantID:      tID,
			ProjectID:     pID,
			Name:          name,
			ProfileID:     profID,
			ProfileName:   profileName,
			TargetAddress: targetAddress,
			Status:        AssessmentStatus(status),
			CreatedAt:     createdAt,
			CompletedAt:   completedAt,
			UpdatedAt:     &updatedAt,
		})
	}

	return records, total, nil
}

func (r *PostgresRepository) UpdateStatus(ctx context.Context, tenantID, id string, status AssessmentStatus, errorDetail string) error {
	if r.pool == nil {
		return errors.New("postgres connection pool is nil")
	}

	asmtUUID, err := uuid.Parse(id)
	if err != nil {
		return ErrAssessmentNotFound
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return ErrAssessmentNotFound
	}

	const query = `
		UPDATE assessments
		SET
			status = $3,
			error_detail = CASE WHEN $4 <> '' THEN $4 ELSE error_detail END,
			completed_at = CASE WHEN $3 IN ('COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT') THEN now() ELSE completed_at END,
			updated_at = now()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	cmd, err := r.pool.Exec(ctx, query, asmtUUID, tenantUUID, string(status), errorDetail)
	if err != nil {
		return fmt.Errorf("update assessment status failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrAssessmentNotFound
	}

	return nil
}

func (r *PostgresRepository) GetProfiles(_ context.Context, _ string) ([]ScanProfile, error) {
	// Returns standard profiles
	return append([]ScanProfile(nil), DefaultProfiles...), nil
}

func (r *PostgresRepository) GetTargets(_ context.Context, _ string) ([]TargetOption, error) {
	// Returns authorized target options
	return append([]TargetOption(nil), DefaultTargets...), nil
}

func (r *PostgresRepository) RecordManifest(ctx context.Context, tenantID, assessmentID, digest string, manifestData any) error {
	if r.pool == nil {
		return nil
	}

	asmtUUID, err := uuid.Parse(assessmentID)
	if err != nil {
		return err
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return err
	}

	dataBytes, err := json.Marshal(manifestData)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO assessment_manifests (
			id, tenant_id, assessment_id, run_id, profile_id, profile_version,
			target_url, scanners, resource_limits, effective_config, manifest_digest, created_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, 'standard', '1.0',
			$4, '["nuclei"]'::jsonb, '{"cpu":"100%","memory":"4G"}'::jsonb, $5, $6, now()
		)
		ON CONFLICT (tenant_id, assessment_id, run_id) DO NOTHING
	`
	_, _ = r.pool.Exec(ctx, query, tenantUUID, asmtUUID, assessmentID, "target", dataBytes, digest)
	return nil
}
