package hierarchy

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TransferOrganizationOwnership transfers the root ownership of an enterprise organization.
func (s *HierarchyService) TransferOrganizationOwnership(
	ctx context.Context,
	orgID uuid.UUID,
	currentOwnerID string,
	newOwnerID string,
) error {
	// 1. Verify current caller is an active OWNER
	currentMem, err := s.repo.GetOrgMembership(ctx, orgID, currentOwnerID)
	if err != nil {
		return err
	}
	if currentMem.Role != OrgRoleOwner {
		return ErrUnauthorized
	}

	if currentOwnerID == newOwnerID {
		return nil // No-op
	}

	// 2. Verify target user is in the organization
	newOwnerMem, err := s.repo.GetOrgMembership(ctx, orgID, newOwnerID)
	if err != nil {
		return ErrUserNotInOrganization
	}

	now := time.Now().UTC()
	// Promote new owner
	newOwnerMem.Role = OrgRoleOwner
	newOwnerMem.UpdatedAt = now
	if err := s.repo.SaveOrgMembership(ctx, newOwnerMem); err != nil {
		return err
	}

	// Demote previous owner to Admin
	currentMem.Role = OrgRoleAdmin
	currentMem.UpdatedAt = now
	if err := s.repo.SaveOrgMembership(ctx, currentMem); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgOwnershipTransferred, &Organization{
			ID:     orgID,
			Status: OrgStateActive,
		}, currentOwnerID, map[string]interface{}{
			"previous_owner": currentOwnerID,
			"new_owner":      newOwnerID,
		})
	}

	return nil
}

// UpdateOrganizationMemberRole modifies an existing member's organization role,
// enforcing privilege escalation blocks and last-administrator protection.
func (s *HierarchyService) UpdateOrganizationMemberRole(
	ctx context.Context,
	orgID uuid.UUID,
	actorUserID string,
	targetUserID string,
	newRole OrgRole,
) error {
	actorMem, err := s.repo.GetOrgMembership(ctx, orgID, actorUserID)
	if err != nil {
		return err
	}
	if actorMem.Role != OrgRoleOwner && actorMem.Role != OrgRoleAdmin {
		return ErrUnauthorized
	}

	targetMem, err := s.repo.GetOrgMembership(ctx, orgID, targetUserID)
	if err != nil {
		return err
	}

	// Privilege escalation prevention:
	// A delegated Admin cannot promote anyone to OWNER, nor can they demote an OWNER.
	if newRole == OrgRoleOwner && actorMem.Role != OrgRoleOwner {
		return ErrPrivilegeEscalationForbidden
	}
	if targetMem.Role == OrgRoleOwner && actorMem.Role != OrgRoleOwner {
		return ErrPrivilegeEscalationForbidden
	}

	// Last-administrator protection guard:
	// If demoting an OWNER to non-owner, ensure at least one other OWNER exists
	if targetMem.Role == OrgRoleOwner && newRole != OrgRoleOwner {
		members, err := s.repo.ListOrgMembers(ctx, orgID)
		if err != nil {
			return err
		}
		ownerCount := 0
		for _, m := range members {
			if m.Role == OrgRoleOwner {
				ownerCount++
			}
		}
		if ownerCount <= 1 {
			return ErrLastAdministratorProtection
		}
	}

	now := time.Now().UTC()
	previousRole := targetMem.Role
	targetMem.Role = newRole
	targetMem.UpdatedAt = now

	if err := s.repo.SaveOrgMembership(ctx, targetMem); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgMemberRoleUpdated, &Organization{
			ID:     orgID,
			Status: OrgStateActive,
		}, actorUserID, map[string]interface{}{
			"target_user_id": targetUserID,
			"previous_role":  string(previousRole),
			"new_role":       string(newRole),
		})
	}

	return nil
}

// RemoveOrganizationMember removes a user from an organization,
// safeguarding against removing the last active organization owner.
func (s *HierarchyService) RemoveOrganizationMember(
	ctx context.Context,
	orgID uuid.UUID,
	actorUserID string,
	targetUserID string,
) error {
	actorMem, err := s.repo.GetOrgMembership(ctx, orgID, actorUserID)
	if err != nil {
		return err
	}
	if actorMem.Role != OrgRoleOwner && actorMem.Role != OrgRoleAdmin {
		return ErrUnauthorized
	}

	targetMem, err := s.repo.GetOrgMembership(ctx, orgID, targetUserID)
	if err != nil {
		return err
	}

	// Delegated Admin cannot remove an Owner
	if targetMem.Role == OrgRoleOwner && actorMem.Role != OrgRoleOwner {
		return ErrPrivilegeEscalationForbidden
	}

	// Last-administrator protection guard
	if targetMem.Role == OrgRoleOwner {
		members, err := s.repo.ListOrgMembers(ctx, orgID)
		if err != nil {
			return err
		}
		ownerCount := 0
		for _, m := range members {
			if m.Role == OrgRoleOwner {
				ownerCount++
			}
		}
		if ownerCount <= 1 {
			return ErrLastAdministratorProtection
		}
	}

	if err := s.repo.RemoveOrgMembership(ctx, orgID, targetUserID); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgMemberRemoved, &Organization{
			ID:     orgID,
			Status: OrgStateActive,
		}, actorUserID, map[string]interface{}{
			"removed_user_id": targetUserID,
		})
	}

	return nil
}

// AssignWorkspaceAdmin delegates workspace administration privileges to a user.
func (s *HierarchyService) AssignWorkspaceAdmin(
	ctx context.Context,
	workspaceID uuid.UUID,
	actorUserID string,
	targetUserID string,
) error {
	ws, err := s.repo.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return err
	}

	// Verify actor has admin authorization
	if err := s.AuthorizeWorkspaceAccess(ctx, workspaceID, actorUserID, WorkspaceRoleAdmin); err != nil {
		// Fallback to checking Org Admin
		if orgErr := s.authorizeOrgAdmin(ctx, ws.OrganizationID, actorUserID); orgErr != nil {
			return ErrUnauthorized
		}
	}

	// Verify target user is part of the parent organization
	if _, err := s.repo.GetOrgMembership(ctx, ws.OrganizationID, targetUserID); err != nil {
		return ErrUserNotInOrganization
	}

	now := time.Now().UTC()
	wsMem := &WorkspaceMembership{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		UserID:      targetUserID,
		Role:        WorkspaceRoleAdmin,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.SaveWorkspaceMembership(ctx, wsMem); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionWorkspaceAdminAssigned, &Organization{
			ID:     ws.OrganizationID,
			Status: OrgStateActive,
		}, actorUserID, map[string]interface{}{
			"workspace_id":    workspaceID.String(),
			"assigned_admin": targetUserID,
		})
	}

	return nil
}

// RevokeWorkspaceAdmin removes workspace administration privileges.
func (s *HierarchyService) RevokeWorkspaceAdmin(
	ctx context.Context,
	workspaceID uuid.UUID,
	actorUserID string,
	targetUserID string,
) error {
	ws, err := s.repo.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return err
	}

	if err := s.AuthorizeWorkspaceAccess(ctx, workspaceID, actorUserID, WorkspaceRoleAdmin); err != nil {
		if orgErr := s.authorizeOrgAdmin(ctx, ws.OrganizationID, actorUserID); orgErr != nil {
			return ErrUnauthorized
		}
	}

	if err := s.repo.RemoveWorkspaceMembership(ctx, workspaceID, targetUserID); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionWorkspaceAdminRevoked, &Organization{
			ID:     ws.OrganizationID,
			Status: OrgStateActive,
		}, actorUserID, map[string]interface{}{
			"workspace_id":   workspaceID.String(),
			"revoked_admin": targetUserID,
		})
	}

	return nil
}
