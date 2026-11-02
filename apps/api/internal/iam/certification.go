package iam

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
	ErrCampaignNotFound      = errors.New("access review campaign not found")
	ErrCampaignNotActive     = errors.New("access review campaign is not active")
	ErrReviewItemNotFound    = errors.New("access review item not found")
	ErrSelfReviewProhibited  = errors.New("separation of duties violation: reviewer cannot certify or revoke their own access")
	ErrJustificationRequired = errors.New("justification is required for sensitive access decisions (REVOKE or INVESTIGATE)")
	ErrCampaignIncomplete    = errors.New("campaign cannot be completed: unreviewed items remain in PENDING state")
	ErrInvalidReviewDecision = errors.New("invalid review decision: must be RETAIN, REVOKE, or INVESTIGATE")
)

const (
	ActionCampaignCreated   = "access_review.campaign_created"
	ActionCampaignCompleted = "access_review.campaign_completed"
	ActionDecisionSubmitted = "access_review.decision_submitted"
	ActionAccessRevoked     = "access_review.access_revoked"
)

type CampaignCadence string

const (
	CadenceQuarterly CampaignCadence = "QUARTERLY"
	CadenceAnnual    CampaignCadence = "ANNUAL"
	CadenceAdHoc     CampaignCadence = "AD_HOC"
)

type CampaignScope string

const (
	ScopeOrganizationWide CampaignScope = "ORGANIZATION"
	ScopeWorkspaceScoped  CampaignScope = "WORKSPACE"
	ScopePrivilegedOnly   CampaignScope = "PRIVILEGED_ONLY"
)

type ReviewDecision string

const (
	DecisionPending     ReviewDecision = "PENDING"
	DecisionRetain      ReviewDecision = "RETAIN"
	DecisionRevoke      ReviewDecision = "REVOKE"
	DecisionInvestigate ReviewDecision = "INVESTIGATE"
)

// AccessReviewCampaign represents an official access certification period.
type AccessReviewCampaign struct {
	ID              uuid.UUID       `json:"id"`
	OrganizationID  uuid.UUID       `json:"organization_id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Cadence         CampaignCadence `json:"cadence"`
	Scope           CampaignScope   `json:"scope"`
	Status          string          `json:"status"` // ACTIVE, COMPLETED, CANCELLED
	CreatedByUserID string          `json:"created_by_user_id"`
	DueDate         time.Time       `json:"due_date"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// AccessReviewItem represents a single entitlement subject to human certification.
type AccessReviewItem struct {
	ID                    uuid.UUID      `json:"id"`
	CampaignID            uuid.UUID      `json:"campaign_id"`
	OrganizationID        uuid.UUID      `json:"organization_id"`
	TargetUserID          string         `json:"target_user_id"`
	TargetUserEmail       string         `json:"target_user_email"`
	ResourceType          string         `json:"resource_type"` // ORG_ROLE, WORKSPACE_ROLE, TEAM_MEMBERSHIP, CUSTOM_ROLE, SERVICE_ACCOUNT
	ResourceID            string         `json:"resource_id"`
	AssignedRole          string         `json:"assigned_role"`
	IsPrivileged          bool           `json:"is_privileged"`
	Decision              ReviewDecision `json:"decision"`
	DecisionJustification string         `json:"decision_justification"`
	ReviewedByUserID      string         `json:"reviewed_by_user_id,omitempty"`
	ReviewedAt            *time.Time     `json:"reviewed_at,omitempty"`
	ActionTaken           bool           `json:"action_taken"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

// CampaignSummary summarizes campaign progress and completion metrics.
type CampaignSummary struct {
	TotalItems       int     `json:"total_items"`
	RetainedCount    int     `json:"retained_count"`
	RevokedCount     int     `json:"revoked_count"`
	InvestigateCount int     `json:"investigate_count"`
	PendingCount     int     `json:"pending_count"`
	PercentComplete  float64 `json:"percent_complete"`
}

// AccessRevoker handles external revocation callbacks when REVOKE is decided.
type AccessRevoker interface {
	RevokeAccess(ctx context.Context, item *AccessReviewItem) error
}

// AccessReviewRepository defines storage operations for review campaigns and items.
type AccessReviewRepository interface {
	SaveCampaign(ctx context.Context, c *AccessReviewCampaign) error
	GetCampaign(ctx context.Context, id uuid.UUID) (*AccessReviewCampaign, error)
	UpdateCampaign(ctx context.Context, c *AccessReviewCampaign) error

	SaveItem(ctx context.Context, item *AccessReviewItem) error
	GetItem(ctx context.Context, id uuid.UUID) (*AccessReviewItem, error)
	UpdateItem(ctx context.Context, item *AccessReviewItem) error
	ListItemsByCampaign(ctx context.Context, campaignID uuid.UUID) ([]*AccessReviewItem, error)
}

// MemoryAccessReviewRepository provides an in-memory implementation of AccessReviewRepository.
type MemoryAccessReviewRepository struct {
	mu        sync.RWMutex
	campaigns map[uuid.UUID]*AccessReviewCampaign
	items     map[uuid.UUID]*AccessReviewItem
}

func NewMemoryAccessReviewRepository() *MemoryAccessReviewRepository {
	return &MemoryAccessReviewRepository{
		campaigns: make(map[uuid.UUID]*AccessReviewCampaign),
		items:     make(map[uuid.UUID]*AccessReviewItem),
	}
}

func (m *MemoryAccessReviewRepository) SaveCampaign(ctx context.Context, c *AccessReviewCampaign) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.campaigns[c.ID] = c
	return nil
}

func (m *MemoryAccessReviewRepository) GetCampaign(ctx context.Context, id uuid.UUID) (*AccessReviewCampaign, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.campaigns[id]
	if !ok {
		return nil, ErrCampaignNotFound
	}
	return c, nil
}

func (m *MemoryAccessReviewRepository) UpdateCampaign(ctx context.Context, c *AccessReviewCampaign) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.campaigns[c.ID]; !ok {
		return ErrCampaignNotFound
	}
	m.campaigns[c.ID] = c
	return nil
}

func (m *MemoryAccessReviewRepository) SaveItem(ctx context.Context, item *AccessReviewItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[item.ID] = item
	return nil
}

func (m *MemoryAccessReviewRepository) GetItem(ctx context.Context, id uuid.UUID) (*AccessReviewItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.items[id]
	if !ok {
		return nil, ErrReviewItemNotFound
	}
	return item, nil
}

func (m *MemoryAccessReviewRepository) UpdateItem(ctx context.Context, item *AccessReviewItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[item.ID]; !ok {
		return ErrReviewItemNotFound
	}
	m.items[item.ID] = item
	return nil
}

func (m *MemoryAccessReviewRepository) ListItemsByCampaign(ctx context.Context, campaignID uuid.UUID) ([]*AccessReviewItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*AccessReviewItem
	for _, it := range m.items {
		if it.CampaignID == campaignID {
			list = append(list, it)
		}
	}
	return list, nil
}

// AccessReviewService orchestrates enterprise certification campaigns.
type AccessReviewService struct {
	repo    AccessReviewRepository
	revoker AccessRevoker
	audit   audit.Recorder
}

func NewAccessReviewService(repo AccessReviewRepository, revoker AccessRevoker, audit audit.Recorder) *AccessReviewService {
	return &AccessReviewService{
		repo:    repo,
		revoker: revoker,
		audit:   audit,
	}
}

// CreateCampaign initializes an access review campaign with target entitlement items.
func (s *AccessReviewService) CreateCampaign(
	ctx context.Context,
	actorUserID string,
	orgID uuid.UUID,
	name string,
	description string,
	cadence CampaignCadence,
	scope CampaignScope,
	dueDate time.Time,
	items []*AccessReviewItem,
) (*AccessReviewCampaign, error) {
	if orgID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("campaign name cannot be empty")
	}
	if dueDate.Before(time.Now().UTC()) {
		return nil, errors.New("due date must be in the future")
	}

	now := time.Now().UTC()
	campaign := &AccessReviewCampaign{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		Name:            name,
		Description:     description,
		Cadence:         cadence,
		Scope:           scope,
		Status:          "ACTIVE",
		CreatedByUserID: actorUserID,
		DueDate:         dueDate,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := s.repo.SaveCampaign(ctx, campaign); err != nil {
		return nil, err
	}

	for _, it := range items {
		it.ID = uuid.New()
		it.CampaignID = campaign.ID
		it.OrganizationID = orgID
		it.Decision = DecisionPending
		it.ActionTaken = false
		it.CreatedAt = now
		it.UpdatedAt = now
		if err := s.repo.SaveItem(ctx, it); err != nil {
			return nil, err
		}
	}

	s.recordAudit(ctx, orgID, actorUserID, ActionCampaignCreated, campaign.ID)
	return campaign, nil
}

// SubmitDecision records a human reviewer certification decision with self-review defense.
func (s *AccessReviewService) SubmitDecision(
	ctx context.Context,
	actorUserID string,
	itemID uuid.UUID,
	decision ReviewDecision,
	justification string,
) (*AccessReviewItem, error) {
	item, err := s.repo.GetItem(ctx, itemID)
	if err != nil {
		return nil, err
	}

	campaign, err := s.repo.GetCampaign(ctx, item.CampaignID)
	if err != nil {
		return nil, err
	}
	if campaign.Status != "ACTIVE" {
		return nil, ErrCampaignNotActive
	}

	// 1. Separation of Duties Invariant: Reviewer cannot certify or revoke their own access
	if item.TargetUserID == actorUserID {
		return nil, ErrSelfReviewProhibited
	}

	// 2. Decision validity
	switch decision {
	case DecisionRetain:
		// Justification optional for retain unless privileged
	case DecisionRevoke, DecisionInvestigate:
		if strings.TrimSpace(justification) == "" {
			return nil, ErrJustificationRequired
		}
	default:
		return nil, ErrInvalidReviewDecision
	}

	now := time.Now().UTC()
	item.Decision = decision
	item.DecisionJustification = justification
	item.ReviewedByUserID = actorUserID
	item.ReviewedAt = &now
	item.UpdatedAt = now

	// 3. Automated Revocation Trigger
	if decision == DecisionRevoke {
		if s.revoker != nil {
			if err := s.revoker.RevokeAccess(ctx, item); err != nil {
				return nil, fmt.Errorf("revocation workflow execution failed: %w", err)
			}
		}
		item.ActionTaken = true
		s.recordAudit(ctx, item.OrganizationID, actorUserID, ActionAccessRevoked, item.ID)
	}

	if err := s.repo.UpdateItem(ctx, item); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, item.OrganizationID, actorUserID, ActionDecisionSubmitted, item.ID)
	return item, nil
}

// CompleteCampaign seals an active campaign once all items have been decided.
func (s *AccessReviewService) CompleteCampaign(ctx context.Context, actorUserID string, campaignID uuid.UUID) (*AccessReviewCampaign, error) {
	campaign, err := s.repo.GetCampaign(ctx, campaignID)
	if err != nil {
		return nil, err
	}
	if campaign.Status != "ACTIVE" {
		return nil, ErrCampaignNotActive
	}

	items, err := s.repo.ListItemsByCampaign(ctx, campaignID)
	if err != nil {
		return nil, err
	}

	for _, it := range items {
		if it.Decision == DecisionPending {
			return nil, ErrCampaignIncomplete
		}
	}

	now := time.Now().UTC()
	campaign.Status = "COMPLETED"
	campaign.CompletedAt = &now
	campaign.UpdatedAt = now

	if err := s.repo.UpdateCampaign(ctx, campaign); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, campaign.OrganizationID, actorUserID, ActionCampaignCompleted, campaign.ID)
	return campaign, nil
}

// GetCampaignSummary computes completion percentage and decision tallies.
func (s *AccessReviewService) GetCampaignSummary(ctx context.Context, campaignID uuid.UUID) (*CampaignSummary, error) {
	items, err := s.repo.ListItemsByCampaign(ctx, campaignID)
	if err != nil {
		return nil, err
	}

	summary := &CampaignSummary{
		TotalItems: len(items),
	}

	if len(items) == 0 {
		return summary, nil
	}

	decided := 0
	for _, it := range items {
		switch it.Decision {
		case DecisionRetain:
			summary.RetainedCount++
			decided++
		case DecisionRevoke:
			summary.RevokedCount++
			decided++
		case DecisionInvestigate:
			summary.InvestigateCount++
			decided++
		case DecisionPending:
			summary.PendingCount++
		}
	}

	summary.PercentComplete = (float64(decided) / float64(summary.TotalItems)) * 100.0
	return summary, nil
}

func (s *AccessReviewService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID, action string, entityID uuid.UUID) {
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
		EntityType:  "access_review",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
