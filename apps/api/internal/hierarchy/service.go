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
	ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]*OrganizationMembership, error)
	RemoveOrgMembership(ctx context.Context, orgID uuid.UUID, userID string) error

	SaveWorkspaceMembership(ctx context.Context, mem *WorkspaceMembership) error
	GetWorkspaceMembership(ctx context.Context, workspaceID uuid.UUID, userID string) (*WorkspaceMembership, error)
	RemoveWorkspaceMembership(ctx context.Context, workspaceID uuid.UUID, userID string) error

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

	SaveInvitation(ctx context.Context, invite *OrganizationInvitation) error
	GetInvitation(ctx context.Context, id uuid.UUID) (*OrganizationInvitation, error)
	GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*OrganizationInvitation, error)
	UpdateInvitation(ctx context.Context, invite *OrganizationInvitation) error
	ListInvitations(ctx context.Context, orgID uuid.UUID) ([]*OrganizationInvitation, error)
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
	invitations  map[uuid.UUID]*OrganizationInvitation
	inviteTokens map[string]uuid.UUID // tokenHash -> inviteID
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
		invitations:  make(map[uuid.UUID]*OrganizationInvitation),
		inviteTokens: make(map[string]uuid.UUID),
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

func (m *MemoryHierarchyRepository) ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]*OrganizationMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*OrganizationMembership
	for _, mem := range m.orgMembers {
		if mem.OrganizationID == orgID {
			result = append(result, mem)
		}
	}
	return result, nil
}

func (m *MemoryHierarchyRepository) RemoveOrgMembership(ctx context.Context, orgID uuid.UUID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID.String() + ":" + userID
	delete(m.orgMembers, key)
	return nil
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

func (m *MemoryHierarchyRepository) RemoveWorkspaceMembership(ctx context.Context, workspaceID uuid.UUID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := workspaceID.String() + ":" + userID
	delete(m.wsMembers, key)
	return nil
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

func (m *MemoryHierarchyRepository) SaveInvitation(ctx context.Context, invite *OrganizationInvitation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invitations[invite.ID] = invite
	m.inviteTokens[invite.TokenHash] = invite.ID
	return nil
}

func (m *MemoryHierarchyRepository) GetInvitation(ctx context.Context, id uuid.UUID) (*OrganizationInvitation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	invite, ok := m.invitations[id]
	if !ok {
		return nil, ErrInvitationNotFound
	}
	return invite, nil
}

func (m *MemoryHierarchyRepository) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*OrganizationInvitation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.inviteTokens[tokenHash]
	if !ok {
		return nil, ErrInvitationNotFound
	}
	return m.invitations[id], nil
}

func (m *MemoryHierarchyRepository) UpdateInvitation(ctx context.Context, invite *OrganizationInvitation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.invitations[invite.ID]; !ok {
		return ErrInvitationNotFound
	}
	m.invitations[invite.ID] = invite
	m.inviteTokens[invite.TokenHash] = invite.ID
	return nil
}

func (m *MemoryHierarchyRepository) ListInvitations(ctx context.Context, orgID uuid.UUID) ([]*OrganizationInvitation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*OrganizationInvitation
	for _, inv := range m.invitations {
		if inv.OrganizationID == orgID {
			result = append(result, inv)
		}
	}
	return result, nil
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

// CreateInvitation provisions a cryptographically signed, single-use invitation.
func (s *HierarchyService) CreateInvitation(
	ctx context.Context,
	orgID uuid.UUID,
	actorUserID string,
	email string,
	role OrgRole,
	teamID *uuid.UUID,
	ttl time.Duration,
) (*OrganizationInvitation, string, error) {
	// Verify caller is Org Owner or Admin
	if err := s.authorizeOrgAdmin(ctx, orgID, actorUserID); err != nil {
		return nil, "", err
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, "", err
	}
	if org.Status != OrgStateActive {
		return nil, "", ErrOrgSuspended
	}

	// If teamID provided, verify it belongs to this org
	if teamID != nil {
		team, err := s.repo.GetTeam(ctx, *teamID)
		if err != nil {
			return nil, "", err
		}
		if team.OrganizationID != orgID {
			return nil, "", ErrUserNotInOrganization
		}
		if team.Status == "ARCHIVED" {
			return nil, "", ErrTeamArchived
		}
	}

	rawToken, tokenHash, err := GenerateInvitationToken()
	if err != nil {
		return nil, "", err
	}

	now := time.Now().UTC()
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour // Default 7 days
	}
	expiresAt := now.Add(ttl)

	invite := &OrganizationInvitation{
		ID:             uuid.New(),
		OrganizationID: orgID,
		InviterUserID:  actorUserID,
		InviteeEmail:   email,
		Role:           role,
		TeamID:         teamID,
		TokenHash:      tokenHash,
		Status:         InvitationStatusPending,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
	}

	if err := s.repo.SaveInvitation(ctx, invite); err != nil {
		return nil, "", err
	}

	if s.audit != nil {
		_ = s.audit.RecordInvitationLifecycleEvent(ctx, ActionInvitationCreated, invite, actorUserID, map[string]interface{}{
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	}

	return invite, rawToken, nil
}

// AcceptInvitation consumes a single-use token and creates or updates organization membership.
func (s *HierarchyService) AcceptInvitation(ctx context.Context, rawToken string, acceptingUserID string) (*OrganizationMembership, error) {
	tokenHash := HashInvitationToken(rawToken)
	invite, err := s.repo.GetInvitationByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrInvitationNotFound
	}

	// Check status
	if invite.Status != InvitationStatusPending {
		return nil, ErrInvitationAlreadyUsed
	}

	now := time.Now().UTC()
	// Check expiry
	if now.After(invite.ExpiresAt) {
		invite.Status = InvitationStatusExpired
		_ = s.repo.UpdateInvitation(ctx, invite)
		return nil, ErrInvitationExpired
	}

	// Single-use update
	invite.Status = InvitationStatusAccepted
	invite.AcceptedAt = &now
	if err := s.repo.UpdateInvitation(ctx, invite); err != nil {
		return nil, err
	}

	// Create or update organization membership
	mem := &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: invite.OrganizationID,
		UserID:         acceptingUserID,
		Role:           invite.Role,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.repo.SaveOrgMembership(ctx, mem); err != nil {
		return nil, err
	}

	// If teamID attached, add to team
	if invite.TeamID != nil {
		teamMem := &TeamMembership{
			ID:        uuid.New(),
			TeamID:    *invite.TeamID,
			UserID:    acceptingUserID,
			Role:      TeamRoleMember,
			CreatedAt: now,
		}
		_ = s.repo.AddTeamMember(ctx, teamMem)
	}

	if s.audit != nil {
		_ = s.audit.RecordInvitationLifecycleEvent(ctx, ActionInvitationAccepted, invite, acceptingUserID, map[string]interface{}{
			"accepted_by": acceptingUserID,
		})
	}

	return mem, nil
}

// RevokeInvitation revokes a pending invitation.
func (s *HierarchyService) RevokeInvitation(ctx context.Context, inviteID uuid.UUID, actorUserID string) error {
	invite, err := s.repo.GetInvitation(ctx, inviteID)
	if err != nil {
		return err
	}

	if err := s.authorizeOrgAdmin(ctx, invite.OrganizationID, actorUserID); err != nil {
		return err
	}

	if invite.Status != InvitationStatusPending {
		return ErrInvitationAlreadyUsed
	}

	now := time.Now().UTC()
	invite.Status = InvitationStatusRevoked
	invite.RevokedAt = &now

	if err := s.repo.UpdateInvitation(ctx, invite); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordInvitationLifecycleEvent(ctx, ActionInvitationRevoked, invite, actorUserID, map[string]interface{}{
			"revoked_by": actorUserID,
		})
	}

	return nil
}

// ReissueInvitation invalidates the old token and generates a fresh token with renewed expiration.
func (s *HierarchyService) ReissueInvitation(ctx context.Context, inviteID uuid.UUID, actorUserID string, ttl time.Duration) (string, error) {
	invite, err := s.repo.GetInvitation(ctx, inviteID)
	if err != nil {
		return "", err
	}

	if err := s.authorizeOrgAdmin(ctx, invite.OrganizationID, actorUserID); err != nil {
		return "", err
	}

	rawToken, tokenHash, err := GenerateInvitationToken()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	expiresAt := now.Add(ttl)

	invite.TokenHash = tokenHash
	invite.Status = InvitationStatusPending
	invite.ExpiresAt = expiresAt
	invite.RevokedAt = nil
	invite.AcceptedAt = nil

	if err := s.repo.UpdateInvitation(ctx, invite); err != nil {
		return "", err
	}

	if s.audit != nil {
		_ = s.audit.RecordInvitationLifecycleEvent(ctx, ActionInvitationReissued, invite, actorUserID, map[string]interface{}{
			"reissued_by": actorUserID,
			"expires_at":  expiresAt.Format(time.RFC3339),
		})
	}

	return rawToken, nil
}

// ListInvitations lists all invitations for an organization.
func (s *HierarchyService) ListInvitations(ctx context.Context, orgID uuid.UUID, actorUserID string) ([]*OrganizationInvitation, error) {
	if err := s.authorizeOrgAdmin(ctx, orgID, actorUserID); err != nil {
		return nil, err
	}
	return s.repo.ListInvitations(ctx, orgID)
}
