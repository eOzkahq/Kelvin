package governance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRetentionBelowPlatformMinimum = errors.New("governance: retention period is below platform enforced minimum")
	ErrRetentionAbovePlatformMaximum = errors.New("governance: retention period exceeds platform allowed maximum")
	ErrLegalHoldNotFound             = errors.New("governance: active legal hold not found")
	ErrMissingPolicyTenant           = errors.New("governance: missing tenant id for retention policy")
)

// Platform-enforced retention bounds (in days)
const (
	MinEvidenceDays   = 30
	MaxEvidenceDays   = 365
	DefaultEvidence   = 90

	MinAssessmentDays = 90
	MaxAssessmentDays = 730
	DefaultAssessment = 365

	MinFindingDays    = 180
	MaxFindingDays    = 1825
	DefaultFinding    = 730

	MinReportDays     = 90
	MaxReportDays     = 1095
	DefaultReport     = 365

	MinAuditDays      = 365
	MaxAuditDays      = 3650
	DefaultAudit      = 365

	HoldTargetTenant     = "TENANT"
	HoldTargetProject    = "PROJECT"
	HoldTargetAssessment = "ASSESSMENT"

	HoldStatusActive   = "ACTIVE"
	HoldStatusReleased = "RELEASED"

	CategoryEvidence   = "EVIDENCE"
	CategoryAssessment = "ASSESSMENT"
	CategoryFinding    = "FINDING"
	CategoryReport     = "REPORT"
	CategoryAudit      = "AUDIT"
)

// DataRetentionPolicy defines configurable retention periods bounded by platform safety invariants.
type DataRetentionPolicy struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	EvidenceDays   int       `json:"evidence_retention_days"`
	AssessmentDays int       `json:"assessment_retention_days"`
	FindingDays    int       `json:"finding_retention_days"`
	ReportDays     int       `json:"report_retention_days"`
	AuditDays      int       `json:"audit_retention_days"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// LegalHold prevents purging or deletion of data when under statutory, regulatory, or litigation freeze.
type LegalHold struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	Reason     string     `json:"reason"`
	TargetType string     `json:"target_type"` // TENANT, PROJECT, ASSESSMENT
	TargetID   string     `json:"target_id,omitempty"`
	Status     string     `json:"status"` // ACTIVE, RELEASED
	CreatedBy  string     `json:"created_by"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// RetentionRecord represents an item evaluated by the retention purge worker.
type RetentionRecord struct {
	ID           string    `json:"id"`
	Category     string    `json:"category"`
	ProjectID    string    `json:"project_id,omitempty"`
	AssessmentID string    `json:"assessment_id,omitempty"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	IsPurged     bool      `json:"is_purged"`
}

// PurgeExecution documents the outcome and metrics of a scheduled data retention sweep.
type PurgeExecution struct {
	ID                     uuid.UUID `json:"id"`
	TenantID               uuid.UUID `json:"tenant_id"`
	RecordsScanned         int       `json:"records_scanned"`
	RecordsPurged          int       `json:"records_purged"`
	RecordsHeld            int       `json:"records_held"`
	EvidenceBytesReclaimed int64     `json:"evidence_bytes_reclaimed"`
	Status                 string    `json:"status"` // SUCCESS, PARTIAL, FAILED
	Details                string    `json:"details"`
	ExecutedAt             time.Time `json:"executed_at"`
}

// RetentionService orchestrates retention policy compliance, legal holds, and cascading purges.
type RetentionService struct {
	mu         sync.RWMutex
	policies   map[uuid.UUID]*DataRetentionPolicy
	legalHolds map[uuid.UUID]*LegalHold
	executions []*PurgeExecution
}

func NewRetentionService() *RetentionService {
	return &RetentionService{
		policies:   make(map[uuid.UUID]*DataRetentionPolicy),
		legalHolds: make(map[uuid.UUID]*LegalHold),
		executions: make([]*PurgeExecution, 0),
	}
}

// SetPolicy sets organization data retention policy, strictly enforcing platform bounds.
func (s *RetentionService) SetPolicy(policy DataRetentionPolicy) error {
	if policy.TenantID == uuid.Nil {
		return ErrMissingPolicyTenant
	}

	if policy.EvidenceDays < MinEvidenceDays {
		return fmt.Errorf("%w: evidence min %d days (got %d)", ErrRetentionBelowPlatformMinimum, MinEvidenceDays, policy.EvidenceDays)
	}
	if policy.EvidenceDays > MaxEvidenceDays {
		return fmt.Errorf("%w: evidence max %d days (got %d)", ErrRetentionAbovePlatformMaximum, MaxEvidenceDays, policy.EvidenceDays)
	}

	if policy.AssessmentDays < MinAssessmentDays {
		return fmt.Errorf("%w: assessment min %d days (got %d)", ErrRetentionBelowPlatformMinimum, MinAssessmentDays, policy.AssessmentDays)
	}
	if policy.AssessmentDays > MaxAssessmentDays {
		return fmt.Errorf("%w: assessment max %d days (got %d)", ErrRetentionAbovePlatformMaximum, MaxAssessmentDays, policy.AssessmentDays)
	}

	if policy.FindingDays < MinFindingDays {
		return fmt.Errorf("%w: finding min %d days (got %d)", ErrRetentionBelowPlatformMinimum, MinFindingDays, policy.FindingDays)
	}
	if policy.FindingDays > MaxFindingDays {
		return fmt.Errorf("%w: finding max %d days (got %d)", ErrRetentionAbovePlatformMaximum, MaxFindingDays, policy.FindingDays)
	}

	if policy.ReportDays < MinReportDays {
		return fmt.Errorf("%w: report min %d days (got %d)", ErrRetentionBelowPlatformMinimum, MinReportDays, policy.ReportDays)
	}
	if policy.ReportDays > MaxReportDays {
		return fmt.Errorf("%w: report max %d days (got %d)", ErrRetentionAbovePlatformMaximum, MaxReportDays, policy.ReportDays)
	}

	if policy.AuditDays < MinAuditDays {
		return fmt.Errorf("%w: audit log min %d days (got %d)", ErrRetentionBelowPlatformMinimum, MinAuditDays, policy.AuditDays)
	}
	if policy.AuditDays > MaxAuditDays {
		return fmt.Errorf("%w: audit log max %d days (got %d)", ErrRetentionAbovePlatformMaximum, MaxAuditDays, policy.AuditDays)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	policy.UpdatedAt = time.Now().UTC()
	s.policies[policy.TenantID] = &policy
	return nil
}

// GetPolicy retrieves tenant retention policy or returns default safe platform baselines.
func (s *RetentionService) GetPolicy(tenantID uuid.UUID) DataRetentionPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if p, ok := s.policies[tenantID]; ok {
		return *p
	}

	return DataRetentionPolicy{
		TenantID:       tenantID,
		EvidenceDays:   DefaultEvidence,
		AssessmentDays: DefaultAssessment,
		FindingDays:    DefaultFinding,
		ReportDays:     DefaultReport,
		AuditDays:      DefaultAudit,
		UpdatedAt:      time.Now().UTC(),
	}
}

// ApplyLegalHold institutes a hold across the tenant, a specific project, or an individual assessment.
func (s *RetentionService) ApplyLegalHold(hold LegalHold) (*LegalHold, error) {
	if hold.TenantID == uuid.Nil {
		return nil, ErrMissingPolicyTenant
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if hold.ID == uuid.Nil {
		hold.ID = uuid.New()
	}
	hold.Status = HoldStatusActive
	hold.CreatedAt = time.Now().UTC()

	s.legalHolds[hold.ID] = &hold
	return &hold, nil
}

// ReleaseLegalHold releases a legal hold, returning it to standard lifecycle scheduling.
func (s *RetentionService) ReleaseLegalHold(tenantID, holdID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hold, ok := s.legalHolds[holdID]
	if !ok || hold.TenantID != tenantID || hold.Status != HoldStatusActive {
		return ErrLegalHoldNotFound
	}

	now := time.Now().UTC()
	hold.Status = HoldStatusReleased
	hold.ReleasedAt = &now
	return nil
}

// IsUnderLegalHold checks if an object is frozen by a tenant-wide, project, or assessment legal hold.
func (s *RetentionService) IsUnderLegalHold(tenantID uuid.UUID, projectID, assessmentID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, hold := range s.legalHolds {
		if hold.TenantID != tenantID || hold.Status != HoldStatusActive {
			continue
		}
		if hold.TargetType == HoldTargetTenant {
			return true
		}
		if hold.TargetType == HoldTargetProject && projectID != "" && hold.TargetID == projectID {
			return true
		}
		if hold.TargetType == HoldTargetAssessment && assessmentID != "" && hold.TargetID == assessmentID {
			return true
		}
	}
	return false
}

// ExecutePurge performs an ordered, audit-logged cascading purge for records exceeding retention limits.
func (s *RetentionService) ExecutePurge(
	ctx context.Context,
	tenantID uuid.UUID,
	records []*RetentionRecord,
	now time.Time,
) (*PurgeExecution, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingPolicyTenant
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	policy := s.GetPolicy(tenantID)

	execution := &PurgeExecution{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Status:     "SUCCESS",
		ExecutedAt: now,
	}

	for _, rec := range records {
		execution.RecordsScanned++

		if rec.IsPurged {
			continue
		}

		var retentionDays int
		switch rec.Category {
		case CategoryEvidence:
			retentionDays = policy.EvidenceDays
		case CategoryAssessment:
			retentionDays = policy.AssessmentDays
		case CategoryFinding:
			retentionDays = policy.FindingDays
		case CategoryReport:
			retentionDays = policy.ReportDays
		case CategoryAudit:
			retentionDays = policy.AuditDays
		default:
			retentionDays = 365
		}

		age := now.Sub(rec.CreatedAt)
		maxAge := time.Duration(retentionDays) * 24 * time.Hour

		if age < maxAge {
			// Record has not reached expiration
			continue
		}

		// Check Legal Hold Precedence
		if s.IsUnderLegalHold(tenantID, rec.ProjectID, rec.AssessmentID) {
			execution.RecordsHeld++
			continue
		}

		// Cascading Purge:
		rec.IsPurged = true
		execution.RecordsPurged++
		if rec.Category == CategoryEvidence {
			execution.EvidenceBytesReclaimed += rec.SizeBytes
		}
	}

	execution.Details = fmt.Sprintf("Scanned %d records: purged %d, preserved %d under legal hold, reclaimed %d bytes",
		execution.RecordsScanned, execution.RecordsPurged, execution.RecordsHeld, execution.EvidenceBytesReclaimed)

	s.mu.Lock()
	s.executions = append(s.executions, execution)
	s.mu.Unlock()

	return execution, nil
}
