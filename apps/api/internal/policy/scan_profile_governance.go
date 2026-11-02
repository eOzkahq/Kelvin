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
	ErrProfileNotFound                 = errors.New("scan profile not found")
	ErrInvalidProfileStateTransition   = errors.New("invalid scan profile state transition")
	ErrSelfApprovalProhibited          = errors.New("separation of duties violation: author cannot approve their own scan profile")
	ErrProfileNotUsable                = errors.New("scan profile is not approved or active for execution")
	ErrProfileRetired                  = errors.New("scan profile has been retired and cannot be used for new assessments")
	ErrRejectionReasonRequired         = errors.New("rejection reason is required when rejecting a profile")
)

const (
	ProfileStateDraft           = "DRAFT"
	ProfileStatePendingApproval = "PENDING_APPROVAL"
	ProfileStateApproved        = "APPROVED"
	ProfileStateActive          = "ACTIVE"
	ProfileStateRejected        = "REJECTED"
	ProfileStateRetired         = "RETIRED"
)

const (
	ActionProfileCreated   = "scan_profile.created"
	ActionProfileSubmitted = "scan_profile.submitted"
	ActionProfileApproved  = "scan_profile.approved"
	ActionProfileRejected  = "scan_profile.rejected"
	ActionProfileActivated = "scan_profile.activated"
	ActionProfileRetired   = "scan_profile.retired"
	ActionProfileVersioned = "scan_profile.versioned"
)

// ScanProfile represents an enterprise scan profile specification subject to governance.
type ScanProfile struct {
	ID                uuid.UUID      `json:"id"`
	OrganizationID    uuid.UUID      `json:"organization_id"`
	Name              string         `json:"name"`
	Slug              string         `json:"slug"`
	Description       string         `json:"description"`
	Scanners          []string       `json:"scanners"`
	Intensity         string         `json:"intensity"` // PASSIVE, NORMAL, AGGRESSIVE, INVASIVE
	Config            map[string]any `json:"config"`
	State             string         `json:"state"`
	Version           int            `json:"version"`
	RequiresApproval  bool           `json:"requires_approval"`
	CreatedByUserID   string         `json:"created_by_user_id"`
	ApprovedByUserID  string         `json:"approved_by_user_id,omitempty"`
	ApprovedAt        *time.Time     `json:"approved_at,omitempty"`
	RejectionReason   string         `json:"rejection_reason,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// ProfileSnapshot represents an immutable version snapshot of an approved scan profile.
type ProfileSnapshot struct {
	ID        uuid.UUID      `json:"id"`
	ProfileID uuid.UUID      `json:"profile_id"`
	Version   int            `json:"version"`
	Spec      map[string]any `json:"spec"`
	CreatedAt time.Time      `json:"created_at"`
}

// ScanProfileRepository defines storage operations for scan profiles and immutable snapshots.
type ScanProfileRepository interface {
	SaveProfile(ctx context.Context, p *ScanProfile) error
	GetProfile(ctx context.Context, id uuid.UUID) (*ScanProfile, error)
	GetProfileBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*ScanProfile, error)
	UpdateProfile(ctx context.Context, p *ScanProfile) error

	SaveSnapshot(ctx context.Context, s *ProfileSnapshot) error
	GetSnapshot(ctx context.Context, profileID uuid.UUID, version int) (*ProfileSnapshot, error)
}

// MemoryScanProfileRepository provides an in-memory implementation of ScanProfileRepository.
type MemoryScanProfileRepository struct {
	mu        sync.RWMutex
	profiles  map[uuid.UUID]*ScanProfile
	snapshots map[string]*ProfileSnapshot // key: profileID:version
}

func NewMemoryScanProfileRepository() *MemoryScanProfileRepository {
	return &MemoryScanProfileRepository{
		profiles:  make(map[uuid.UUID]*ScanProfile),
		snapshots: make(map[string]*ProfileSnapshot),
	}
}

func (m *MemoryScanProfileRepository) SaveProfile(ctx context.Context, p *ScanProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.profiles[p.ID] = p
	return nil
}

func (m *MemoryScanProfileRepository) GetProfile(ctx context.Context, id uuid.UUID) (*ScanProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[id]
	if !ok {
		return nil, ErrProfileNotFound
	}
	return p, nil
}

func (m *MemoryScanProfileRepository) GetProfileBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*ScanProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.profiles {
		if p.OrganizationID == orgID && p.Slug == slug {
			return p, nil
		}
	}
	return nil, ErrProfileNotFound
}

func (m *MemoryScanProfileRepository) UpdateProfile(ctx context.Context, p *ScanProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[p.ID]; !ok {
		return ErrProfileNotFound
	}
	m.profiles[p.ID] = p
	return nil
}

func (m *MemoryScanProfileRepository) SaveSnapshot(ctx context.Context, s *ProfileSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%d", s.ProfileID.String(), s.Version)
	m.snapshots[key] = s
	return nil
}

func (m *MemoryScanProfileRepository) GetSnapshot(ctx context.Context, profileID uuid.UUID, version int) (*ProfileSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%s:%d", profileID.String(), version)
	s, ok := m.snapshots[key]
	if !ok {
		return nil, errors.New("snapshot not found")
	}
	return s, nil
}

// ScanProfileService orchestrates scan profile approval governance and immutability.
type ScanProfileService struct {
	repo  ScanProfileRepository
	audit audit.Recorder
}

func NewScanProfileService(repo ScanProfileRepository, audit audit.Recorder) *ScanProfileService {
	return &ScanProfileService{
		repo:  repo,
		audit: audit,
	}
}

// CreateProfile provisions a new scan profile in DRAFT state.
func (s *ScanProfileService) CreateProfile(ctx context.Context, actorUserID string, profile *ScanProfile) (*ScanProfile, error) {
	if profile.OrganizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}
	if strings.TrimSpace(profile.Name) == "" || strings.TrimSpace(profile.Slug) == "" {
		return nil, errors.New("profile name and slug are required")
	}

	// Intensity safety rule: AGGRESSIVE and INVASIVE scans always mandate approval
	normIntensity := strings.ToUpper(profile.Intensity)
	if normIntensity == "AGGRESSIVE" || normIntensity == "INVASIVE" {
		profile.RequiresApproval = true
	}

	now := time.Now().UTC()
	profile.ID = uuid.New()
	profile.State = ProfileStateDraft
	profile.Version = 1
	profile.CreatedByUserID = actorUserID
	profile.CreatedAt = now
	profile.UpdatedAt = now

	if err := s.repo.SaveProfile(ctx, profile); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, profile.OrganizationID, actorUserID, ActionProfileCreated, profile.ID)
	return profile, nil
}

// SubmitForApproval transitions a DRAFT profile to PENDING_APPROVAL.
func (s *ScanProfileService) SubmitForApproval(ctx context.Context, actorUserID string, profileID uuid.UUID) (*ScanProfile, error) {
	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	if p.State != ProfileStateDraft && p.State != ProfileStateRejected {
		return nil, fmt.Errorf("%w: cannot submit profile in state %s", ErrInvalidProfileStateTransition, p.State)
	}

	p.State = ProfileStatePendingApproval
	p.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, p.OrganizationID, actorUserID, ActionProfileSubmitted, p.ID)
	return p, nil
}

// ApproveProfile approves a pending profile with separation of duties enforcement.
func (s *ScanProfileService) ApproveProfile(ctx context.Context, actorUserID string, profileID uuid.UUID) (*ScanProfile, error) {
	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	if p.State != ProfileStatePendingApproval {
		return nil, fmt.Errorf("%w: profile must be in PENDING_APPROVAL to approve", ErrInvalidProfileStateTransition)
	}

	// Separation of Duties Invariant: Author cannot approve their own profile
	if p.CreatedByUserID == actorUserID {
		return nil, ErrSelfApprovalProhibited
	}

	now := time.Now().UTC()
	p.State = ProfileStateApproved
	p.ApprovedByUserID = actorUserID
	p.ApprovedAt = &now
	p.UpdatedAt = now

	// Save immutable snapshot for this approved version
	snapshot := &ProfileSnapshot{
		ID:        uuid.New(),
		ProfileID: p.ID,
		Version:   p.Version,
		Spec: map[string]any{
			"name":      p.Name,
			"slug":      p.Slug,
			"scanners":  p.Scanners,
			"intensity": p.Intensity,
			"config":    p.Config,
		},
		CreatedAt: now,
	}
	_ = s.repo.SaveSnapshot(ctx, snapshot)

	if err := s.repo.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, p.OrganizationID, actorUserID, ActionProfileApproved, p.ID)
	return p, nil
}

// RejectProfile rejects a pending profile, recording the mandatory rejection reason.
func (s *ScanProfileService) RejectProfile(ctx context.Context, actorUserID string, profileID uuid.UUID, reason string) (*ScanProfile, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, ErrRejectionReasonRequired
	}

	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	if p.State != ProfileStatePendingApproval {
		return nil, fmt.Errorf("%w: profile must be in PENDING_APPROVAL to reject", ErrInvalidProfileStateTransition)
	}

	p.State = ProfileStateRejected
	p.RejectionReason = reason
	p.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, p.OrganizationID, actorUserID, ActionProfileRejected, p.ID)
	return p, nil
}

// ActivateProfile promotes an approved profile to ACTIVE.
func (s *ScanProfileService) ActivateProfile(ctx context.Context, actorUserID string, profileID uuid.UUID) (*ScanProfile, error) {
	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	if p.State != ProfileStateApproved {
		return nil, fmt.Errorf("%w: only APPROVED profiles can be activated", ErrInvalidProfileStateTransition)
	}

	p.State = ProfileStateActive
	p.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, p.OrganizationID, actorUserID, ActionProfileActivated, p.ID)
	return p, nil
}

// RetireProfile deprecates an active profile, preventing future assessments from selecting it.
func (s *ScanProfileService) RetireProfile(ctx context.Context, actorUserID string, profileID uuid.UUID) (*ScanProfile, error) {
	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	p.State = ProfileStateRetired
	p.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, p.OrganizationID, actorUserID, ActionProfileRetired, p.ID)
	return p, nil
}

// UpdateSpec modifies an active/approved profile by creating a new version in DRAFT state, preserving snapshots.
func (s *ScanProfileService) UpdateSpec(ctx context.Context, actorUserID string, profileID uuid.UUID, newScanners []string, newConfig map[string]any) (*ScanProfile, error) {
	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	p.Version++
	p.Scanners = newScanners
	p.Config = newConfig
	p.State = ProfileStateDraft // Requires re-approval if changes are made to approved profile
	p.ApprovedByUserID = ""
	p.ApprovedAt = nil
	p.UpdatedAt = now

	if err := s.repo.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, p.OrganizationID, actorUserID, ActionProfileVersioned, p.ID)
	return p, nil
}

// ValidateProfileUsable verifies that a profile is in ACTIVE or APPROVED state for execution.
func (s *ScanProfileService) ValidateProfileUsable(ctx context.Context, profileID uuid.UUID) error {
	p, err := s.repo.GetProfile(ctx, profileID)
	if err != nil {
		return err
	}

	if p.State == ProfileStateRetired {
		return ErrProfileRetired
	}

	if p.State != ProfileStateActive && p.State != ProfileStateApproved {
		return fmt.Errorf("%w: profile %q is in state %s", ErrProfileNotUsable, p.Name, p.State)
	}

	return nil
}

func (s *ScanProfileService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID, action string, entityID uuid.UUID) {
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
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "scan_profile",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
