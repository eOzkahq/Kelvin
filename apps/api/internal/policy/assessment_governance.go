package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrGovernanceViolation       = errors.New("assessment request violates organization governance policy")
	ErrExceedsPlatformLimit     = errors.New("policy configuration exceeds maximum allowed platform boundaries")
	ErrDisallowedScanner         = errors.New("requested scanner is not permitted by organization whitelist")
	ErrDisallowedAssessmentType  = errors.New("requested assessment type is not approved by policy")
	ErrConcurrencyExceeded       = errors.New("organization assessment concurrency ceiling reached")
	ErrIntrusiveProdScan         = errors.New("intrusive active scanning is prohibited on production targets")
	ErrOutsideMaintenanceWindow  = errors.New("assessment execution is restricted to authorized maintenance windows")
)

const (
	ActionAssessmentGovConfigured = "assessment_governance.policy_configured"
	ActionAssessmentGovEvaluated  = "assessment_governance.evaluated"
)

const PlatformMaxConcurrency = 20

// AssessmentGovernancePolicy records organization-level rules for assessment and scanner execution.
type AssessmentGovernancePolicy struct {
	ID                        uuid.UUID `json:"id"`
	OrganizationID           uuid.UUID `json:"organization_id"`
	AllowedScanners           []string  `json:"allowed_scanners"`
	AllowedAssessmentTypes     []string  `json:"allowed_assessment_types"`
	MaxConcurrency           int       `json:"max_concurrency"`
	MaxTargetPacingMS         int       `json:"max_target_pacing_ms"`
	ProhibitIntrusiveOnProd   bool      `json:"prohibit_intrusive_on_prod"`
	EnforceMaintenanceWindows bool      `json:"enforce_maintenance_windows"`
	MaintenanceWindowStart     string    `json:"maintenance_window_start"` // "HH:MM" UTC
	MaintenanceWindowEnd       string    `json:"maintenance_window_end"`   // "HH:MM" UTC
	Version                   int       `json:"version"`
	Status                    string    `json:"status"` // ACTIVE, DISABLED
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// DefaultAssessmentGovernancePolicy returns safe organization baseline settings.
func DefaultAssessmentGovernancePolicy(orgID uuid.UUID) *AssessmentGovernancePolicy {
	now := time.Now().UTC()
	return &AssessmentGovernancePolicy{
		ID:                        uuid.New(),
		OrganizationID:           orgID,
		AllowedScanners:           []string{"zap", "nuclei", "http", "tls"},
		AllowedAssessmentTypes:     []string{"DAST", "NETWORK", "CONFIG"},
		MaxConcurrency:           5,
		MaxTargetPacingMS:         1000,
		ProhibitIntrusiveOnProd:   true,
		EnforceMaintenanceWindows: false,
		MaintenanceWindowStart:     "00:00",
		MaintenanceWindowEnd:       "06:00",
		Version:                   1,
		Status:                    "ACTIVE",
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
}

// AssessmentSubmission describes an assessment creation request to be validated.
type AssessmentSubmission struct {
	OrganizationID          uuid.UUID `json:"organization_id"`
	WorkspaceID             uuid.UUID `json:"workspace_id"`
	AssessmentType          string    `json:"assessment_type"`
	TargetEnvironment       string    `json:"target_environment"` // PRODUCTION, STAGING, DEVELOPMENT
	RequestedScanners       []string  `json:"requested_scanners"`
	IntrusiveScan           bool      `json:"intrusive_scan"`
	CurrentActiveAssessments int       `json:"current_active_assessments"`
	ScheduledTime           time.Time `json:"scheduled_time"`
}

// GovernanceEvaluation reports the evaluation outcome and any detected violations.
type GovernanceEvaluation struct {
	Allowed       bool      `json:"allowed"`
	PolicyVersion int       `json:"policy_version"`
	Violations    []string  `json:"violations"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

// AssessmentGovernanceRepository defines persistence operations for governance policies.
type AssessmentGovernanceRepository interface {
	Save(ctx context.Context, policy *AssessmentGovernancePolicy) error
	GetByOrgID(ctx context.Context, orgID uuid.UUID) (*AssessmentGovernancePolicy, error)
	Update(ctx context.Context, policy *AssessmentGovernancePolicy) error
}

// MemoryAssessmentGovernanceRepository provides an in-memory implementation of AssessmentGovernanceRepository.
type MemoryAssessmentGovernanceRepository struct {
	mu       sync.RWMutex
	policies map[uuid.UUID]*AssessmentGovernancePolicy
}

func NewMemoryAssessmentGovernanceRepository() *MemoryAssessmentGovernanceRepository {
	return &MemoryAssessmentGovernanceRepository{
		policies: make(map[uuid.UUID]*AssessmentGovernancePolicy),
	}
}

func (m *MemoryAssessmentGovernanceRepository) Save(ctx context.Context, policy *AssessmentGovernancePolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[policy.OrganizationID] = policy
	return nil
}

func (m *MemoryAssessmentGovernanceRepository) GetByOrgID(ctx context.Context, orgID uuid.UUID) (*AssessmentGovernancePolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[orgID]
	if !ok {
		return DefaultAssessmentGovernancePolicy(orgID), nil
	}
	return p, nil
}

func (m *MemoryAssessmentGovernanceRepository) Update(ctx context.Context, policy *AssessmentGovernancePolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[policy.OrganizationID]; !ok {
		return errors.New("governance policy not found")
	}
	m.policies[policy.OrganizationID] = policy
	return nil
}

// AssessmentGovernanceService coordinates organization assessment governance enforcement.
type AssessmentGovernanceService struct {
	repo  AssessmentGovernanceRepository
	audit audit.Recorder
}

func NewAssessmentGovernanceService(repo AssessmentGovernanceRepository, audit audit.Recorder) *AssessmentGovernanceService {
	return &AssessmentGovernanceService{
		repo:  repo,
		audit: audit,
	}
}

// ConfigurePolicy validates and saves organization assessment governance settings.
func (s *AssessmentGovernanceService) ConfigurePolicy(ctx context.Context, actorUserID string, policy *AssessmentGovernancePolicy) error {
	if policy.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	// Platform Security Invariant: Concurrency cannot exceed platform maximum ceiling
	if policy.MaxConcurrency <= 0 || policy.MaxConcurrency > PlatformMaxConcurrency {
		return fmt.Errorf("%w: max concurrency must be between 1 and %d", ErrExceedsPlatformLimit, PlatformMaxConcurrency)
	}

	if len(policy.AllowedScanners) == 0 {
		return errors.New("allowed_scanners list cannot be empty")
	}

	now := time.Now().UTC()
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
		policy.CreatedAt = now
	}
	policy.Version++
	policy.UpdatedAt = now

	if err := s.repo.Save(ctx, policy); err != nil {
		return err
	}

	s.recordAudit(ctx, policy.OrganizationID, actorUserID, ActionAssessmentGovConfigured, policy.ID)
	return nil
}

// EvaluateSubmission verifies an assessment against the organization's governance rules.
func (s *AssessmentGovernanceService) EvaluateSubmission(ctx context.Context, sub AssessmentSubmission) (*GovernanceEvaluation, error) {
	policy, err := s.repo.GetByOrgID(ctx, sub.OrganizationID)
	if err != nil {
		return nil, err
	}

	var violations []string

	// 1. Scanner Whitelist Check
	allowedScannerMap := make(map[string]bool)
	for _, sc := range policy.AllowedScanners {
		allowedScannerMap[strings.ToLower(strings.TrimSpace(sc))] = true
	}
	for _, reqScanner := range sub.RequestedScanners {
		norm := strings.ToLower(strings.TrimSpace(reqScanner))
		if !allowedScannerMap[norm] {
			violations = append(violations, fmt.Sprintf("%v: scanner %q is not in the approved whitelist %v", ErrDisallowedScanner, reqScanner, policy.AllowedScanners))
		}
	}

	// 2. Assessment Type Check
	allowedTypeMap := make(map[string]bool)
	for _, t := range policy.AllowedAssessmentTypes {
		allowedTypeMap[strings.ToUpper(strings.TrimSpace(t))] = true
	}
	if !allowedTypeMap[strings.ToUpper(strings.TrimSpace(sub.AssessmentType))] {
		violations = append(violations, fmt.Sprintf("%v: assessment type %q is not approved", ErrDisallowedAssessmentType, sub.AssessmentType))
	}

	// 3. Concurrency Ceiling Check
	if sub.CurrentActiveAssessments >= policy.MaxConcurrency {
		violations = append(violations, fmt.Sprintf("%v: active count %d meets or exceeds organization limit %d", ErrConcurrencyExceeded, sub.CurrentActiveAssessments, policy.MaxConcurrency))
	}

	// 4. Intrusive Scan on Production Check
	if strings.ToUpper(sub.TargetEnvironment) == "PRODUCTION" && sub.IntrusiveScan && policy.ProhibitIntrusiveOnProd {
		violations = append(violations, fmt.Sprintf("%v: intrusive scanning is prohibited on production environment", ErrIntrusiveProdScan))
	}

	// 5. Maintenance Window Check
	if policy.EnforceMaintenanceWindows {
		schedTime := sub.ScheduledTime
		if schedTime.IsZero() {
			schedTime = time.Now().UTC()
		}
		timeStr := schedTime.UTC().Format("15:04")
		if timeStr < policy.MaintenanceWindowStart || timeStr > policy.MaintenanceWindowEnd {
			violations = append(violations, fmt.Sprintf("%v: scheduled time %s UTC outside window %s-%s UTC", ErrOutsideMaintenanceWindow, timeStr, policy.MaintenanceWindowStart, policy.MaintenanceWindowEnd))
		}
	}

	now := time.Now().UTC()
	eval := &GovernanceEvaluation{
		Allowed:       len(violations) == 0,
		PolicyVersion: policy.Version,
		Violations:    violations,
		EvaluatedAt:   now,
	}

	s.recordAudit(ctx, sub.OrganizationID, "", ActionAssessmentGovEvaluated, policy.ID)

	if !eval.Allowed {
		return eval, fmt.Errorf("%w: %s", ErrGovernanceViolation, strings.Join(violations, "; "))
	}

	return eval, nil
}

func (s *AssessmentGovernanceService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID, action string, entityID uuid.UUID) {
	if s.audit == nil {
		return
	}
	var actorUUID *uuid.UUID
	if aID, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &aID
	}
	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    &orgID,
		ActorUserID: actorUUID,
		ActorType:   audit.ActorSystem,
		Action:      action,
		EntityType:  "assessment_governance_policy",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
