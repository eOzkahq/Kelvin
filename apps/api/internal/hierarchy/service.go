package hierarchy

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

// HierarchyRepository defines the persistent operations for organizations, workspaces, and memberships.
type HierarchyRepository interface {
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganization(ctx context.Context, id uuid.UUID) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	CreateWorkspace(ctx context.Context, ws *Workspace) error
	GetWorkspace(ctx context.Context, id uuid.UUID) (*Workspace, error)
	GetWorkspaceByTenantID(ctx context.Context, tenantID uuid.UUID) (*Workspace, error)
	ListWorkspaces(ctx context.Context, orgID uuid.UUID) ([]*Workspace, error)

	SaveOrgMembership(ctx context.Context, mem *OrganizationMembership) error
	GetOrgMembership(ctx context.Context, orgID uuid.UUID, userID string) (*OrganizationMembership, error)

	SaveWorkspaceMembership(ctx context.Context, mem *WorkspaceMembership) error
	GetWorkspaceMembership(ctx context.Context, workspaceID uuid.UUID, userID string) (*WorkspaceMembership, error)

	CreateTeam(ctx context.Context, team *Team) error
	GetTeam(ctx context.Context, id uuid.UUID) (*Team, error)
	UpdateTeam(ctx context.Context, team *Team) error
	ListTeams(ctx context.Context, orgID uuid.UUID) ([]*Team, error)
	AddTeamMember(ctx context.Context, mem *TeamMembership) error
	RemoveTeamMember(ctx context.Context, teamID uuid.UUID, userID string) error
	GetTeamMembers(ctx context.Context, teamID uuid.UUID) ([]*TeamMembership, error)
	GetUserTeams(ctx context.Context, orgID uuid.UUID, userID string) ([]*Team, error)
	GrantTeamWorkspaceRole(ctx context.Context, grant *WorkspaceTeamGrant) error
	GetTeamWorkspaceGrant(ctx context.Context, workspaceID uuid.UUID, teamID uuid.UUID) (*WorkspaceTeamGrant, error)
}

// MemoryHierarchyRepository provides a concurrency-safe in-memory implementation of HierarchyRepository.
type MemoryHierarchyRepository struct {
	mu           sync.RWMutex
	orgs         map[uuid.UUID]*Organization
	workspaces   map[uuid.UUID]*Workspace
	teams        map[uuid.UUID]*Team
	orgMembers   map[string]*OrganizationMembership // key: orgID:userID
	wsMembers    map[string]*WorkspaceMembership    // key: wsID:userID
	teamMembers  map[string]*TeamMembership         // key: teamID:userID
	wsTeamGrants map[string]*WorkspaceTeamGrant     // key: wsID:teamID
}

func NewMemoryHierarchyRepository() *MemoryHierarchyRepository {
	return &MemoryHierarchyRepository{
		orgs:         make(map[uuid.UUID]*Organization),
		workspaces:   make(map[uuid.UUID]*Workspace),
		teams:        make(map[uuid.UUID]*Team),
		orgMembers:   make(map[string]*OrganizationMembership),
		wsMembers:    make(map[string]*WorkspaceMembership),
		teamMembers:  make(map[string]*TeamMembership),
		wsTeamGrants: make(map[string]*WorkspaceTeamGrant),
	}
}

func (m *MemoryHierarchyRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orgs[org.ID] = org
	return nil
}

func (m *MemoryHierarchyRepository) GetOrganization(ctx context.Context, id uuid.UUID) (*Organization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	org, ok := m.orgs[id]
	if !ok {
		return nil, ErrOrganizationNotFound
	}
	return org, nil
}

func (m *MemoryHierarchyRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orgs[org.ID]; !ok {
		return ErrOrganizationNotFound
	}
	m.orgs[org.ID] = org
	return nil
}

func (m *MemoryHierarchyRepository) CreateWorkspace(ctx context.Context, ws *Workspace) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workspaces[ws.ID] = ws
	return nil
}

func (m *MemoryHierarchyRepository) GetWorkspace(ctx context.Context, id uuid.UUID) (*Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ws, ok := m.workspaces[id]
	if !ok {
		return nil, ErrWorkspaceNotFound
	}
	return ws, nil
}

func (m *MemoryHierarchyRepository) GetWorkspaceByTenantID(ctx context.Context, tenantID uuid.UUID) (*Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ws := range m.workspaces {
		if ws.TenantID == tenantID {
			return ws, nil
		}
	}
	return nil, ErrWorkspaceNotFound
}

func (m *MemoryHierarchyRepository) ListWorkspaces(ctx context.Context, orgID uuid.UUID) ([]*Workspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Workspace
	for _, ws := range m.workspaces {
		if ws.OrganizationID == orgID {
			result = append(result, ws)
		}
	}
	return result, nil
}

func (m *MemoryHierarchyRepository) SaveOrgMembership(ctx context.Context, mem *OrganizationMembership) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := mem.OrganizationID.String() + ":" + mem.UserID
	m.orgMembers[key] = mem
	return nil
}

func (m *MemoryHierarchyRepository) GetOrgMembership(ctx context.Context, orgID uuid.UUID, userID string) (*OrganizationMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := orgID.String() + ":" + userID
	mem, ok := m.orgMembers[key]
	if !ok {
		return nil, ErrUnauthorized
	}
	return mem, nil
}

func (m *MemoryHierarchyRepository) SaveWorkspaceMembership(ctx context.Context, mem *WorkspaceMembership) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := mem.WorkspaceID.String() + ":" + mem.UserID
	m.wsMembers[key] = mem
	return nil
}

func (m *MemoryHierarchyRepository) GetWorkspaceMembership(ctx context.Context, workspaceID uuid.UUID, userID string) (*WorkspaceMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := workspaceID.String() + ":" + userID
	mem, ok := m.wsMembers[key]
	if !ok {
		return nil, ErrUnauthorized
	}
	return mem, nil
}

func (m *MemoryHierarchyRepository) CreateTeam(ctx context.Context, team *Team) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.teams[team.ID] = team
	return nil
}

func (m *MemoryHierarchyRepository) GetTeam(ctx context.Context, id uuid.UUID) (*Team, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	team, ok := m.teams[id]
	if !ok {
		return nil, ErrTeamNotFound
	}
	return team, nil
}

func (m *MemoryHierarchyRepository) UpdateTeam(ctx context.Context, team *Team) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.teams[team.ID]; !ok {
		return ErrTeamNotFound
	}
	m.teams[team.ID] = team
	return nil
}

func (m *MemoryHierarchyRepository) ListTeams(ctx context.Context, orgID uuid.UUID) ([]*Team, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Team
	for _, team := range m.teams {
		if team.OrganizationID == orgID {
			result = append(result, team)
		}
	}
	return result, nil
}

func (m *MemoryHierarchyRepository) AddTeamMember(ctx context.Context, mem *TeamMembership) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := mem.TeamID.String() + ":" + mem.UserID
	m.teamMembers[key] = mem
	return nil
}

func (m *MemoryHierarchyRepository) RemoveTeamMember(ctx context.Context, teamID uuid.UUID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := teamID.String() + ":" + userID
	delete(m.teamMembers, key)
	return nil
}

func (m *MemoryHierarchyRepository) GetTeamMembers(ctx context.Context, teamID uuid.UUID) ([]*TeamMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*TeamMembership
	for _, mem := range m.teamMembers {
		if mem.TeamID == teamID {
			result = append(result, mem)
		}
	}
	return result, nil
}

func (m *MemoryHierarchyRepository) GetUserTeams(ctx context.Context, orgID uuid.UUID, userID string) ([]*Team, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Team
	for _, mem := range m.teamMembers {
		if mem.UserID == userID {
			if team, ok := m.teams[mem.TeamID]; ok && team.OrganizationID == orgID && (team.Status == "" || team.Status == "ACTIVE") {
				result = append(result, team)
			}
		}
	}
	return result, nil
}

func (m *MemoryHierarchyRepository) GrantTeamWorkspaceRole(ctx context.Context, grant *WorkspaceTeamGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := grant.WorkspaceID.String() + ":" + grant.TeamID.String()
	m.wsTeamGrants[key] = grant
	return nil
}

func (m *MemoryHierarchyRepository) GetTeamWorkspaceGrant(ctx context.Context, workspaceID uuid.UUID, teamID uuid.UUID) (*WorkspaceTeamGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := workspaceID.String() + ":" + teamID.String()
	grant, ok := m.wsTeamGrants[key]
	if !ok {
		return nil, ErrUnauthorized
	}
	return grant, nil
}

// HierarchyService coordinates enterprise organizations, workspaces, and access validation.
type HierarchyService struct {
	repo  HierarchyRepository
	audit *HierarchyAuditRecorder
}

func NewHierarchyService(repo HierarchyRepository) *HierarchyService {
	return &HierarchyService{repo: repo}
}

func (s *HierarchyService) WithAuditRecorder(audit *HierarchyAuditRecorder) *HierarchyService {
	s.audit = audit
	return s
}

// CreateOrganization registers a new enterprise organization and assigns the initial creator as OWNER.
func (s *HierarchyService) CreateOrganization(ctx context.Context, name, slug string, creatorUserID string) (*Organization, error) {
	now := time.Now().UTC()
	org := &Organization{
		ID:          uuid.New(),
		Name:        name,
		Slug:        slug,
		BillingTier: "ENTERPRISE",
		Status:      OrgStateActive,
		Settings:    make(map[string]interface{}),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.repo.CreateOrganization(ctx, org); err != nil {
		return nil, err
	}

	mem := &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         creatorUserID,
		Role:           OrgRoleOwner,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.repo.SaveOrgMembership(ctx, mem); err != nil {
		return nil, err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgCreated, org, creatorUserID, map[string]interface{}{
			"action": "created",
		})
	}

	return org, nil
}

// SuspendOrganization transitions an organization to SUSPENDED.
func (s *HierarchyService) SuspendOrganization(ctx context.Context, orgID uuid.UUID, actorUserID string, reason string) error {
	if err := s.authorizeOrgAdmin(ctx, orgID, actorUserID); err != nil {
		return err
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	if err := ValidateOrgStateTransition(org.Status, OrgStateSuspended); err != nil {
		return err
	}

	if org.Status == OrgStateSuspended {
		return nil
	}

	now := time.Now().UTC()
	org.Status = OrgStateSuspended
	org.SuspendedAt = &now
	org.SuspensionReason = reason
	org.UpdatedAt = now

	if err := s.repo.UpdateOrganization(ctx, org); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgSuspended, org, actorUserID, map[string]interface{}{
			"reason": reason,
		})
	}

	return nil
}

// ReactivateOrganization restores an organization from SUSPENDED or PENDING_DELETION to ACTIVE.
func (s *HierarchyService) ReactivateOrganization(ctx context.Context, orgID uuid.UUID, actorUserID string) error {
	if err := s.authorizeOrgAdmin(ctx, orgID, actorUserID); err != nil {
		return err
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	if err := ValidateOrgStateTransition(org.Status, OrgStateActive); err != nil {
		return err
	}

	if org.Status == OrgStateActive {
		return nil
	}

	now := time.Now().UTC()
	org.Status = OrgStateActive
	org.SuspendedAt = nil
	org.SuspensionReason = ""
	org.DeletionRequestedAt = nil
	org.PurgeAfter = nil
	org.UpdatedAt = now

	if err := s.repo.UpdateOrganization(ctx, org); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgReactivated, org, actorUserID, map[string]interface{}{
			"action": "reactivated",
		})
	}

	return nil
}

// RequestOrganizationDeletion places an organization in PENDING_DELETION with a retention grace period.
func (s *HierarchyService) RequestOrganizationDeletion(ctx context.Context, orgID uuid.UUID, actorUserID string, gracePeriod time.Duration) error {
	mem, err := s.repo.GetOrgMembership(ctx, orgID, actorUserID)
	if err != nil {
		return err
	}
	if mem.Role != OrgRoleOwner {
		return ErrUnauthorized
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	if err := ValidateOrgStateTransition(org.Status, OrgStatePendingDeletion); err != nil {
		return err
	}

	if org.Status == OrgStatePendingDeletion {
		return nil
	}

	now := time.Now().UTC()
	if gracePeriod <= 0 {
		gracePeriod = 30 * 24 * time.Hour
	}
	purgeAt := now.Add(gracePeriod)

	org.Status = OrgStatePendingDeletion
	org.DeletionRequestedAt = &now
	org.PurgeAfter = &purgeAt
	org.UpdatedAt = now

	if err := s.repo.UpdateOrganization(ctx, org); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgDeletionRequested, org, actorUserID, map[string]interface{}{
			"purge_after": purgeAt.Format(time.RFC3339),
		})
	}

	return nil
}

// CancelOrganizationDeletion cancels a pending deletion request and restores ACTIVE status.
func (s *HierarchyService) CancelOrganizationDeletion(ctx context.Context, orgID uuid.UUID, actorUserID string) error {
	return s.ReactivateOrganization(ctx, orgID, actorUserID)
}

// EnsureWorkspaceOperational verifies that the workspace's parent organization is ACTIVE.
func (s *HierarchyService) EnsureWorkspaceOperational(ctx context.Context, workspaceID uuid.UUID) error {
	ws, err := s.repo.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return err
	}

	org, err := s.repo.GetOrganization(ctx, ws.OrganizationID)
	if err != nil {
		return err
	}

	switch org.Status {
	case OrgStateActive:
		return nil
	case OrgStateSuspended:
		return ErrOrgSuspended
	case OrgStatePendingDeletion:
		return ErrOrgPendingDeletion
	case OrgStatePurged:
		return ErrOrgPurged
	default:
		return ErrOrgSuspended
	}
}

// CreateTeam provisions a new team within an organization.
// Only Org OWNER or ADMIN can create teams.
func (s *HierarchyService) CreateTeam(ctx context.Context, orgID uuid.UUID, actorUserID string, name, slug, description string) (*Team, error) {
	if err := s.authorizeOrgAdmin(ctx, orgID, actorUserID); err != nil {
		return nil, err
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org.Status != OrgStateActive {
		return nil, ErrOrgSuspended
	}

	now := time.Now().UTC()
	team := &Team{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Name:           name,
		Slug:           slug,
		Description:    description,
		Status:         "ACTIVE",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.CreateTeam(ctx, team); err != nil {
		return nil, err
	}

	if s.audit != nil {
		_ = s.audit.RecordTeamLifecycleEvent(ctx, ActionTeamCreated, team, actorUserID, map[string]interface{}{
			"action": "team_created",
		})
	}

	return team, nil
}

// UpdateTeam updates a team's name and description.
func (s *HierarchyService) UpdateTeam(ctx context.Context, teamID uuid.UUID, actorUserID string, name, description string) (*Team, error) {
	team, err := s.repo.GetTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}
	if team.Status == "ARCHIVED" {
		return nil, ErrTeamArchived
	}

	if err := s.authorizeTeamAdmin(ctx, team, actorUserID); err != nil {
		return nil, err
	}

	team.Name = name
	team.Description = description
	team.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateTeam(ctx, team); err != nil {
		return nil, err
	}

	if s.audit != nil {
		_ = s.audit.RecordTeamLifecycleEvent(ctx, ActionTeamUpdated, team, actorUserID, map[string]interface{}{
			"name": name,
		})
	}

	return team, nil
}

// ArchiveTeam marks a team as ARCHIVED (soft-archive preserving historic links).
func (s *HierarchyService) ArchiveTeam(ctx context.Context, teamID uuid.UUID, actorUserID string) error {
	team, err := s.repo.GetTeam(ctx, teamID)
	if err != nil {
		return err
	}
	if err := s.authorizeTeamAdmin(ctx, team, actorUserID); err != nil {
		return err
	}

	team.Status = "ARCHIVED"
	team.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateTeam(ctx, team); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordTeamLifecycleEvent(ctx, ActionTeamArchived, team, actorUserID, map[string]interface{}{
			"action": "archived",
		})
	}

	return nil
}

// AddTeamMember adds a user to a team.
// Crucial boundary check: target user MUST belong to the team's parent organization.
func (s *HierarchyService) AddTeamMember(ctx context.Context, teamID uuid.UUID, actorUserID string, targetUserID string, role TeamRole) error {
	team, err := s.repo.GetTeam(ctx, teamID)
	if err != nil {
		return err
	}
	if team.Status == "ARCHIVED" {
		return ErrTeamArchived
	}

	if err := s.authorizeTeamAdmin(ctx, team, actorUserID); err != nil {
		return err
	}

	// Verify target user belongs to the parent organization
	if _, err := s.repo.GetOrgMembership(ctx, team.OrganizationID, targetUserID); err != nil {
		return ErrUserNotInOrganization
	}

	mem := &TeamMembership{
		ID:        uuid.New(),
		TeamID:    teamID,
		UserID:    targetUserID,
		Role:      role,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repo.AddTeamMember(ctx, mem); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordTeamLifecycleEvent(ctx, ActionTeamMemberAdded, team, actorUserID, map[string]interface{}{
			"target_user_id": targetUserID,
			"role":           string(role),
		})
	}

	return nil
}

// RemoveTeamMember removes a user from a team.
func (s *HierarchyService) RemoveTeamMember(ctx context.Context, teamID uuid.UUID, actorUserID string, targetUserID string) error {
	team, err := s.repo.GetTeam(ctx, teamID)
	if err != nil {
		return err
	}
	if err := s.authorizeTeamAdmin(ctx, team, actorUserID); err != nil {
		return err
	}

	if err := s.repo.RemoveTeamMember(ctx, teamID, targetUserID); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordTeamLifecycleEvent(ctx, ActionTeamMemberRemoved, team, actorUserID, map[string]interface{}{
			"target_user_id": targetUserID,
		})
	}

	return nil
}

// ListTeams returns all teams for an organization.
func (s *HierarchyService) ListTeams(ctx context.Context, orgID uuid.UUID) ([]*Team, error) {
	return s.repo.ListTeams(ctx, orgID)
}

// GetTeamMembers returns all members of a team.
func (s *HierarchyService) GetTeamMembers(ctx context.Context, teamID uuid.UUID) ([]*TeamMembership, error) {
	return s.repo.GetTeamMembers(ctx, teamID)
}

func (s *HierarchyService) authorizeTeamAdmin(ctx context.Context, team *Team, actorUserID string) error {
	// 1. Check if actor is Org Owner or Org Admin
	if mem, err := s.repo.GetOrgMembership(ctx, team.OrganizationID, actorUserID); err == nil {
		if mem.Role == OrgRoleOwner || mem.Role == OrgRoleAdmin {
			return nil
		}
	}

	// 2. Check if actor is Team Lead
	teamMembers, err := s.repo.GetTeamMembers(ctx, team.ID)
	if err == nil {
		for _, tm := range teamMembers {
			if tm.UserID == actorUserID && tm.Role == TeamRoleLead {
				return nil
			}
		}
	}

	return ErrUnauthorized
}

func (s *HierarchyService) authorizeOrgAdmin(ctx context.Context, orgID uuid.UUID, userID string) error {
	mem, err := s.repo.GetOrgMembership(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if mem.Role != OrgRoleOwner && mem.Role != OrgRoleAdmin {
		return ErrUnauthorized
	}
	return nil
}

// CreateWorkspace registers an operational workspace mapped directly to an isolated tenant.
func (s *HierarchyService) CreateWorkspace(ctx context.Context, orgID uuid.UUID, tenantID uuid.UUID, name, slug, environment string) (*Workspace, error) {
	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org.Status != OrgStateActive {
		return nil, ErrOrgSuspended
	}

	now := time.Now().UTC()
	ws := &Workspace{
		ID:             uuid.New(),
		OrganizationID: orgID,
		TenantID:       tenantID,
		Name:           name,
		Slug:           slug,
		Environment:    environment,
		Status:         "ACTIVE",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.CreateWorkspace(ctx, ws); err != nil {
		return nil, err
	}
	return ws, nil
}

// AuthorizeWorkspaceAccess validates that:
// 1. Context tenant matches the workspace tenant (strict tenant isolation per ADR-0002).
// 2. User has an explicit direct membership or team grant with sufficient role privileges.
func (s *HierarchyService) AuthorizeWorkspaceAccess(ctx context.Context, workspaceID uuid.UUID, userID string, minRole WorkspaceRole) error {
	ws, err := s.repo.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return err
	}

	if tID, err := tenant.ID(ctx); err == nil {
		if tID != ws.TenantID {
			return ErrTenantMismatch
		}
	}

	if mem, err := s.repo.GetWorkspaceMembership(ctx, workspaceID, userID); err == nil {
		if isWorkspaceRoleSufficient(mem.Role, minRole) {
			return nil
		}
	}

	teams, err := s.repo.GetUserTeams(ctx, ws.OrganizationID, userID)
	if err == nil {
		for _, t := range teams {
			if grant, err := s.repo.GetTeamWorkspaceGrant(ctx, workspaceID, t.ID); err == nil {
				if isWorkspaceRoleSufficient(grant.Role, minRole) {
					return nil
				}
			}
		}
	}

	return ErrUnauthorized
}

func isWorkspaceRoleSufficient(actual, required WorkspaceRole) bool {
	weights := map[WorkspaceRole]int{
		WorkspaceRoleViewer:   1,
		WorkspaceRoleOperator: 2,
		WorkspaceRoleAdmin:    3,
	}
	return weights[actual] >= weights[required]
}
