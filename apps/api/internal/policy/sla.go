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
	ErrSLAPolicyNotFound   = errors.New("SLA policy not found for organization")
	ErrFindingSLANotFound  = errors.New("SLA tracker not found for finding")
	ErrSLAAlreadyPaused    = errors.New("SLA clock is already paused for this finding")
	ErrSLANotPaused        = errors.New("SLA clock is not currently paused")
	ErrInvalidSLADuration  = errors.New("SLA policy durations must be positive integers")
)

const (
	SLAStatusOnTrack  = "ON_TRACK"
	SLAStatusMet      = "MET"
	SLAStatusBreached = "BREACHED"
	SLAStatusPaused   = "PAUSED"
	SLAStatusExempted = "EXEMPTED"
)

const (
	ActionSLAPolicyConfigured = "sla.policy_configured"
	ActionSLACalculated       = "sla.calculated"
	ActionSLAPaused           = "sla.paused"
	ActionSLAResumed          = "sla.resumed"
	ActionSLABreached         = "sla.breached"
)

// SLAPolicy defines organization remediation and triage timeframes.
type SLAPolicy struct {
	ID                      uuid.UUID `json:"id"`
	OrganizationID          uuid.UUID `json:"organization_id"`
	Name                    string    `json:"name"`
	CriticalRemediationDays int       `json:"critical_remediation_days"` // e.g. 7 days
	HighRemediationDays     int       `json:"high_remediation_days"`     // e.g. 30 days
	MediumRemediationDays   int       `json:"medium_remediation_days"`   // e.g. 90 days
	LowRemediationDays      int       `json:"low_remediation_days"`      // e.g. 180 days
	CriticalTriageHours     int       `json:"critical_triage_hours"`     // e.g. 24 hours
	HighTriageHours         int       `json:"high_triage_hours"`         // e.g. 72 hours
	PauseOnException        bool      `json:"pause_on_exception"`
	PauseOnVerification     bool      `json:"pause_on_verification"`
	Version                 int       `json:"version"`
	Status                  string    `json:"status"` // ACTIVE, DISABLED
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// DefaultSLAPolicy returns standard enterprise security SLA targets.
func DefaultSLAPolicy(orgID uuid.UUID) *SLAPolicy {
	now := time.Now().UTC()
	return &SLAPolicy{
		ID:                      uuid.New(),
		OrganizationID:          orgID,
		Name:                    "Default Enterprise SLA Policy",
		CriticalRemediationDays: 7,
		HighRemediationDays:     30,
		MediumRemediationDays:   90,
		LowRemediationDays:      180,
		CriticalTriageHours:     24,
		HighTriageHours:         72,
		PauseOnException:        true,
		PauseOnVerification:     true,
		Version:                 1,
		Status:                  "ACTIVE",
		CreatedAt:               now,
		UpdatedAt:               now,
	}
}

// FindingSLATracker records timeline milestones, pauses, and due dates for an individual finding.
type FindingSLATracker struct {
	ID                         uuid.UUID  `json:"id"`
	FindingID                  uuid.UUID  `json:"finding_id"`
	OrganizationID             uuid.UUID  `json:"organization_id"`
	PolicyVersion              int        `json:"policy_version"`
	ClockStartedAt             time.Time  `json:"clock_started_at"`
	TriageDueAt                time.Time  `json:"triage_due_at"`
	RemediationDueAt           time.Time  `json:"remediation_due_at"`
	PausedAt                   *time.Time `json:"paused_at,omitempty"`
	TotalPausedDurationSeconds int        `json:"total_paused_duration_seconds"`
	TriageStatus               string     `json:"triage_status"`      // ON_TRACK, MET, BREACHED
	RemediationStatus          string     `json:"remediation_status"` // ON_TRACK, MET, BREACHED, PAUSED, EXEMPTED
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
}

// SLADecision provides an explainable report of finding SLA health.
type SLADecision struct {
	FindingID         uuid.UUID `json:"finding_id"`
	PolicyVersion     int       `json:"policy_version"`
	RemediationDueAt  time.Time `json:"remediation_due_at"`
	RemediationStatus string    `json:"remediation_status"`
	IsBreached        bool      `json:"is_breached"`
	HoursRemaining    float64   `json:"hours_remaining"`
	Explainability    string    `json:"explainability"`
}

// SLARepository defines persistence operations for SLA policies and finding trackers.
type SLARepository interface {
	SavePolicy(ctx context.Context, p *SLAPolicy) error
	GetPolicy(ctx context.Context, orgID uuid.UUID) (*SLAPolicy, error)

	SaveTracker(ctx context.Context, t *FindingSLATracker) error
	GetTracker(ctx context.Context, findingID uuid.UUID) (*FindingSLATracker, error)
	UpdateTracker(ctx context.Context, t *FindingSLATracker) error
}

// MemorySLARepository provides an in-memory implementation of SLARepository.
type MemorySLARepository struct {
	mu       sync.RWMutex
	policies map[uuid.UUID]*SLAPolicy
	trackers map[uuid.UUID]*FindingSLATracker
}

func NewMemorySLARepository() *MemorySLARepository {
	return &MemorySLARepository{
		policies: make(map[uuid.UUID]*SLAPolicy),
		trackers: make(map[uuid.UUID]*FindingSLATracker),
	}
}

func (m *MemorySLARepository) SavePolicy(ctx context.Context, p *SLAPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[p.OrganizationID] = p
	return nil
}

func (m *MemorySLARepository) GetPolicy(ctx context.Context, orgID uuid.UUID) (*SLAPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[orgID]
	if !ok {
		return DefaultSLAPolicy(orgID), nil
	}
	return p, nil
}

func (m *MemorySLARepository) SaveTracker(ctx context.Context, t *FindingSLATracker) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trackers[t.FindingID] = t
	return nil
}

func (m *MemorySLARepository) GetTracker(ctx context.Context, findingID uuid.UUID) (*FindingSLATracker, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.trackers[findingID]
	if !ok {
		return nil, ErrFindingSLANotFound
	}
	return t, nil
}

func (m *MemorySLARepository) UpdateTracker(ctx context.Context, t *FindingSLATracker) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.trackers[t.FindingID]; !ok {
		return ErrFindingSLANotFound
	}
	m.trackers[t.FindingID] = t
	return nil
}

// SLAService manages finding remediation deadlines, pause windows, and breach detection.
type SLAService struct {
	repo  SLARepository
	audit audit.Recorder
}

func NewSLAService(repo SLARepository, audit audit.Recorder) *SLAService {
	return &SLAService{
		repo:  repo,
		audit: audit,
	}
}

// ConfigurePolicy validates and updates organization SLA policy.
func (s *SLAService) ConfigurePolicy(ctx context.Context, actorUserID string, policy *SLAPolicy) error {
	if policy.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	if policy.CriticalRemediationDays <= 0 || policy.HighRemediationDays <= 0 ||
		policy.MediumRemediationDays <= 0 || policy.LowRemediationDays <= 0 {
		return ErrInvalidSLADuration
	}

	now := time.Now().UTC()
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
		policy.CreatedAt = now
	}
	policy.Version++
	policy.UpdatedAt = now

	if err := s.repo.SavePolicy(ctx, policy); err != nil {
		return err
	}

	s.recordAudit(ctx, policy.OrganizationID, actorUserID, ActionSLAPolicyConfigured, policy.ID)
	return nil
}

// CalculateSLA initializes deterministic triage and remediation deadlines for an ingested finding.
func (s *SLAService) CalculateSLA(
	ctx context.Context,
	orgID uuid.UUID,
	findingID uuid.UUID,
	severity string,
	firstSeenAt time.Time,
) (*FindingSLATracker, error) {
	policy, err := s.repo.GetPolicy(ctx, orgID)
	if err != nil {
		return nil, err
	}

	if firstSeenAt.IsZero() {
		firstSeenAt = time.Now().UTC()
	}

	normSev := strings.ToUpper(strings.TrimSpace(severity))
	var remDuration time.Duration
	var triageDuration time.Duration

	switch normSev {
	case "CRITICAL":
		remDuration = time.Duration(policy.CriticalRemediationDays) * 24 * time.Hour
		triageDuration = time.Duration(policy.CriticalTriageHours) * time.Hour
	case "HIGH":
		remDuration = time.Duration(policy.HighRemediationDays) * 24 * time.Hour
		triageDuration = time.Duration(policy.HighTriageHours) * time.Hour
	case "MEDIUM":
		remDuration = time.Duration(policy.MediumRemediationDays) * 24 * time.Hour
		triageDuration = time.Duration(policy.HighTriageHours*2) * time.Hour
	default: // LOW / INFO
		remDuration = time.Duration(policy.LowRemediationDays) * 24 * time.Hour
		triageDuration = time.Duration(policy.HighTriageHours*3) * time.Hour
	}

	now := time.Now().UTC()
	tracker := &FindingSLATracker{
		ID:                         uuid.New(),
		FindingID:                  findingID,
		OrganizationID:             orgID,
		PolicyVersion:              policy.Version,
		ClockStartedAt:             firstSeenAt,
		TriageDueAt:                firstSeenAt.Add(triageDuration),
		RemediationDueAt:           firstSeenAt.Add(remDuration),
		TotalPausedDurationSeconds: 0,
		TriageStatus:               SLAStatusOnTrack,
		RemediationStatus:          SLAStatusOnTrack,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}

	if err := s.repo.SaveTracker(ctx, tracker); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, orgID, "", ActionSLACalculated, tracker.ID)
	return tracker, nil
}

// PauseSLA halts the SLA clock when a finding enters risk acceptance or exception review.
func (s *SLAService) PauseSLA(ctx context.Context, findingID uuid.UUID, reason string) error {
	t, err := s.repo.GetTracker(ctx, findingID)
	if err != nil {
		return err
	}

	if t.PausedAt != nil {
		return ErrSLAAlreadyPaused
	}

	now := time.Now().UTC()
	t.PausedAt = &now
	t.RemediationStatus = SLAStatusPaused
	t.UpdatedAt = now

	if err := s.repo.UpdateTracker(ctx, t); err != nil {
		return err
	}

	s.recordAudit(ctx, t.OrganizationID, "", ActionSLAPaused, t.ID)
	return nil
}

// ResumeSLA resumes the SLA clock and extends the due date by the exact paused duration.
func (s *SLAService) ResumeSLA(ctx context.Context, findingID uuid.UUID) error {
	t, err := s.repo.GetTracker(ctx, findingID)
	if err != nil {
		return err
	}

	if t.PausedAt == nil {
		return ErrSLANotPaused
	}

	now := time.Now().UTC()
	pausedSeconds := int(now.Sub(*t.PausedAt).Seconds())
	t.TotalPausedDurationSeconds += pausedSeconds
	t.RemediationDueAt = t.RemediationDueAt.Add(time.Duration(pausedSeconds) * time.Second)
	t.PausedAt = nil
	t.RemediationStatus = SLAStatusOnTrack
	t.UpdatedAt = now

	if err := s.repo.UpdateTracker(ctx, t); err != nil {
		return err
	}

	s.recordAudit(ctx, t.OrganizationID, "", ActionSLAResumed, t.ID)
	return nil
}

// EvaluateFindingSLAStatus checks the SLA progress against current lifecycle and timestamp.
func (s *SLAService) EvaluateFindingSLAStatus(
	ctx context.Context,
	findingID uuid.UUID,
	findingLifecycleStatus string,
	now time.Time,
) (*SLADecision, error) {
	t, err := s.repo.GetTracker(ctx, findingID)
	if err != nil {
		return nil, err
	}

	normLifecycle := strings.ToUpper(strings.TrimSpace(findingLifecycleStatus))

	decision := &SLADecision{
		FindingID:        t.FindingID,
		PolicyVersion:    t.PolicyVersion,
		RemediationDueAt: t.RemediationDueAt,
	}

	// 1. Resolved / Suppressed / False Positive Exemption
	if normLifecycle == "RESOLVED" || normLifecycle == "FALSE_POSITIVE" || normLifecycle == "SUPPRESSED" {
		decision.RemediationStatus = SLAStatusMet
		decision.IsBreached = false
		decision.Explainability = fmt.Sprintf("Finding lifecycle is %s; SLA target satisfied", normLifecycle)
		t.RemediationStatus = SLAStatusMet
		_ = s.repo.UpdateTracker(ctx, t)
		return decision, nil
	}

	// 2. Currently Paused
	if t.PausedAt != nil {
		decision.RemediationStatus = SLAStatusPaused
		decision.IsBreached = false
		decision.HoursRemaining = t.RemediationDueAt.Sub(*t.PausedAt).Hours()
		decision.Explainability = "SLA clock is paused due to active exception or verification hold"
		return decision, nil
	}

	// 3. Active Evaluation (On Track vs Breached)
	hoursRem := t.RemediationDueAt.Sub(now).Hours()
	decision.HoursRemaining = hoursRem

	if now.After(t.RemediationDueAt) {
		decision.RemediationStatus = SLAStatusBreached
		decision.IsBreached = true
		decision.Explainability = fmt.Sprintf("Overdue: deadline was %s UTC (%.1f hours overdue)", t.RemediationDueAt.Format(time.RFC3339), -hoursRem)

		if t.RemediationStatus != SLAStatusBreached {
			t.RemediationStatus = SLAStatusBreached
			_ = s.repo.UpdateTracker(ctx, t)
			s.recordAudit(ctx, t.OrganizationID, "", ActionSLABreached, t.ID)
		}
	} else {
		decision.RemediationStatus = SLAStatusOnTrack
		decision.IsBreached = false
		decision.Explainability = fmt.Sprintf("On track: %.1f hours remaining before deadline %s UTC", hoursRem, t.RemediationDueAt.Format(time.RFC3339))
		t.RemediationStatus = SLAStatusOnTrack
		_ = s.repo.UpdateTracker(ctx, t)
	}

	return decision, nil
}

func (s *SLAService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID, action string, entityID uuid.UUID) {
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
		EntityType:  "finding_sla",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
