package hierarchy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ShareableResourceType string

const (
	ResourceTypeScanProfile ShareableResourceType = "SCAN_PROFILE"
	ResourceTypeReport      ShareableResourceType = "REPORT"
	ResourceTypeFinding     ShareableResourceType = "FINDING"
)

type ShareAccessLevel string

const (
	ShareAccessLevelRead    ShareAccessLevel = "READ"
	ShareAccessLevelExecute ShareAccessLevel = "EXECUTE"
)

var (
	ErrResourceNotShareable      = errors.New("resource type is not shareable across teams or workspaces")
	ErrCrossOrgSharingForbidden  = errors.New("cross-organization resource sharing is strictly forbidden")
	ErrSharingGrantNotFound      = errors.New("sharing grant not found")
	ErrSharingGrantRevoked       = errors.New("sharing grant has been revoked or expired")
)

// ResourceSharingGrant records an explicit sharing authorization between workspaces or teams.
type ResourceSharingGrant struct {
	ID                uuid.UUID             `json:"id"`
	OrganizationID   uuid.UUID             `json:"organization_id"`
	ResourceType     ShareableResourceType `json:"resource_type"`
	ResourceID       uuid.UUID             `json:"resource_id"`
	SourceWorkspaceID uuid.UUID             `json:"source_workspace_id"`
	TargetType       string                `json:"target_type"` // TEAM, WORKSPACE
	TargetID         uuid.UUID             `json:"target_id"`
	AccessLevel      ShareAccessLevel      `json:"access_level"`
	GrantedByUserID  string                `json:"granted_by_user_id"`
	Status           string                `json:"status"` // ACTIVE, REVOKED, EXPIRED
	ExpiresAt        *time.Time            `json:"expires_at,omitempty"`
	RevokedAt        *time.Time            `json:"revoked_at,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
}

// SharingRepository defines storage operations for sharing grants.
type SharingRepository interface {
	SaveGrant(ctx context.Context, grant *ResourceSharingGrant) error
	GetGrant(ctx context.Context, id uuid.UUID) (*ResourceSharingGrant, error)
	UpdateGrant(ctx context.Context, grant *ResourceSharingGrant) error
	ListGrantsForResource(ctx context.Context, resourceType ShareableResourceType, resourceID uuid.UUID) ([]*ResourceSharingGrant, error)
}

// MemorySharingRepository provides a thread-safe in-memory store for sharing grants.
type MemorySharingRepository struct {
	mu     sync.RWMutex
	grants map[uuid.UUID]*ResourceSharingGrant
}

func NewMemorySharingRepository() *MemorySharingRepository {
	return &MemorySharingRepository{
		grants: make(map[uuid.UUID]*ResourceSharingGrant),
	}
}

func (m *MemorySharingRepository) SaveGrant(ctx context.Context, grant *ResourceSharingGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[grant.ID] = grant
	return nil
}

func (m *MemorySharingRepository) GetGrant(ctx context.Context, id uuid.UUID) (*ResourceSharingGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, ErrSharingGrantNotFound
	}
	return g, nil
}

func (m *MemorySharingRepository) UpdateGrant(ctx context.Context, grant *ResourceSharingGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.grants[grant.ID]; !ok {
		return ErrSharingGrantNotFound
	}
	m.grants[grant.ID] = grant
	return nil
}

func (m *MemorySharingRepository) ListGrantsForResource(ctx context.Context, resourceType ShareableResourceType, resourceID uuid.UUID) ([]*ResourceSharingGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*ResourceSharingGrant
	for _, g := range m.grants {
		if g.ResourceType == resourceType && g.ResourceID == resourceID {
			result = append(result, g)
		}
	}
	return result, nil
}

// ResourceSharingService coordinates controlled resource sharing across teams and workspaces.
type ResourceSharingService struct {
	repo          SharingRepository
	hierarchyRepo HierarchyRepository
	audit         *HierarchyAuditRecorder
}

func NewResourceSharingService(repo SharingRepository, hierarchyRepo HierarchyRepository, audit *HierarchyAuditRecorder) *ResourceSharingService {
	return &ResourceSharingService{
		repo:          repo,
		hierarchyRepo: hierarchyRepo,
		audit:         audit,
	}
}

// ValidateShareableResourceType ensures raw evidence or forbidden types cannot be shared.
func ValidateShareableResourceType(rType ShareableResourceType) error {
	switch rType {
	case ResourceTypeScanProfile, ResourceTypeReport, ResourceTypeFinding:
		return nil
	default:
		return ErrResourceNotShareable
	}
}

// CreateSharingGrant grants cross-team or cross-workspace access to a permitted resource.
func (s *ResourceSharingService) CreateSharingGrant(ctx context.Context, grant *ResourceSharingGrant) error {
	// 1. Validate resource type
	if err := ValidateShareableResourceType(grant.ResourceType); err != nil {
		return err
	}

	// 2. Verify source workspace exists and belongs to the specified organization
	srcWS, err := s.hierarchyRepo.GetWorkspace(ctx, grant.SourceWorkspaceID)
	if err != nil {
		return err
	}
	if srcWS.OrganizationID != grant.OrganizationID {
		return ErrCrossOrgSharingForbidden
	}

	// 3. Verify target exists and belongs to the SAME organization
	if grant.TargetType == "TEAM" {
		team, err := s.hierarchyRepo.GetTeam(ctx, grant.TargetID)
		if err != nil {
			return err
		}
		if team.OrganizationID != grant.OrganizationID {
			return ErrCrossOrgSharingForbidden
		}
	} else if grant.TargetType == "WORKSPACE" {
		targetWS, err := s.hierarchyRepo.GetWorkspace(ctx, grant.TargetID)
		if err != nil {
			return err
		}
		if targetWS.OrganizationID != grant.OrganizationID {
			return ErrCrossOrgSharingForbidden
		}
	}

	now := time.Now().UTC()
	grant.ID = uuid.New()
	grant.Status = "ACTIVE"
	grant.CreatedAt = now

	if err := s.repo.SaveGrant(ctx, grant); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordSharingLifecycleEvent(ctx, ActionResourceShared, grant.ID, string(grant.ResourceType), grant.ResourceID, grant.GrantedByUserID, map[string]interface{}{
			"source_workspace_id": grant.SourceWorkspaceID.String(),
			"target_type":         grant.TargetType,
			"target_id":           grant.TargetID.String(),
			"access_level":        string(grant.AccessLevel),
		})
	}

	return nil
}

// RevokeSharingGrant immediately terminates cross-team access to the resource.
func (s *ResourceSharingService) RevokeSharingGrant(ctx context.Context, grantID uuid.UUID, actorUserID string) error {
	grant, err := s.repo.GetGrant(ctx, grantID)
	if err != nil {
		return err
	}

	if grant.Status != "ACTIVE" {
		return nil // Idempotent
	}

	now := time.Now().UTC()
	grant.Status = "REVOKED"
	grant.RevokedAt = &now

	if err := s.repo.UpdateGrant(ctx, grant); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordSharingLifecycleEvent(ctx, ActionResourceUnshared, grant.ID, string(grant.ResourceType), grant.ResourceID, actorUserID, map[string]interface{}{
			"action": "revoked",
		})
	}

	return nil
}

// AuthorizeSharedResourceAccess checks if a request is authorized via an active sharing grant.
func (s *ResourceSharingService) AuthorizeSharedResourceAccess(
	ctx context.Context,
	resourceType ShareableResourceType,
	resourceID uuid.UUID,
	userTeamIDs []uuid.UUID,
	requestingWorkspaceID uuid.UUID,
	minLevel ShareAccessLevel,
) error {
	grants, err := s.repo.ListGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	teamMap := make(map[uuid.UUID]bool)
	for _, tID := range userTeamIDs {
		teamMap[tID] = true
	}

	for _, g := range grants {
		if g.Status != "ACTIVE" {
			continue
		}
		if g.ExpiresAt != nil && now.After(*g.ExpiresAt) {
			continue
		}

		// Check target match
		targetMatched := false
		if g.TargetType == "WORKSPACE" && g.TargetID == requestingWorkspaceID {
			targetMatched = true
		} else if g.TargetType == "TEAM" && teamMap[g.TargetID] {
			targetMatched = true
		}

		if targetMatched {
			if isShareLevelSufficient(g.AccessLevel, minLevel) {
				return nil
			}
		}
	}

	return ErrUnauthorized
}

func isShareLevelSufficient(actual, required ShareAccessLevel) bool {
	if actual == ShareAccessLevelExecute {
		return true // Execute includes Read
	}
	return actual == required
}
