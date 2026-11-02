package hierarchy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDelegatedAdministrationAndGuards(t *testing.T) {
	repo := NewMemoryHierarchyRepository()
	auditMem := NewMemoryAuditRecorder()
	auditRecorder := NewHierarchyAuditRecorder(auditMem)
	svc := NewHierarchyService(repo).WithAuditRecorder(auditRecorder)
	ctx := context.Background()

	// 1. Setup Org with initial Owner (Professor X)
	org, err := svc.CreateOrganization(ctx, "Xavier Institute", "xavier-inst", "user-charles")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	ws, err := svc.CreateWorkspace(ctx, org.ID, uuid.New(), "Danger Room", "danger-room", "production")
	if err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}

	userScott := "user-scott" // Will be Delegated Admin
	userLogan := "user-logan" // Member

	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         userScott,
		Role:           OrgRoleAdmin,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})
	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         userLogan,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// 2. Last-Administrator Protection:
	// Charles is the sole owner. Attempting to demote or remove him must fail!
	err = svc.UpdateOrganizationMemberRole(ctx, org.ID, "user-charles", "user-charles", OrgRoleMember)
	if err != ErrLastAdministratorProtection {
		t.Errorf("expected ErrLastAdministratorProtection when demoting sole owner, got %v", err)
	}

	err = svc.RemoveOrganizationMember(ctx, org.ID, "user-charles", "user-charles")
	if err != ErrLastAdministratorProtection {
		t.Errorf("expected ErrLastAdministratorProtection when removing sole owner, got %v", err)
	}

	// 3. Privilege Escalation Defense:
	// Scott (Admin) attempts to promote Logan to OWNER -> must be rejected!
	err = svc.UpdateOrganizationMemberRole(ctx, org.ID, userScott, userLogan, OrgRoleOwner)
	if err != ErrPrivilegeEscalationForbidden {
		t.Errorf("expected ErrPrivilegeEscalationForbidden when Admin attempts to promote user to Owner, got %v", err)
	}

	// Scott (Admin) attempts to remove Charles (Owner) -> must be rejected!
	err = svc.RemoveOrganizationMember(ctx, org.ID, userScott, "user-charles")
	if err != ErrPrivilegeEscalationForbidden {
		t.Errorf("expected ErrPrivilegeEscalationForbidden when Admin attempts to remove Owner, got %v", err)
	}

	// 4. Delegated Admin updates regular member role (Scott promotes Logan to Billing)
	err = svc.UpdateOrganizationMemberRole(ctx, org.ID, userScott, userLogan, OrgRoleBilling)
	if err != nil {
		t.Fatalf("delegated admin failed to update member role: %v", err)
	}

	updatedLogan, _ := repo.GetOrgMembership(ctx, org.ID, userLogan)
	if updatedLogan.Role != OrgRoleBilling {
		t.Errorf("expected Logan to have role BILLING, got %s", updatedLogan.Role)
	}

	// 5. Transfer Ownership from Charles to Scott
	err = svc.TransferOrganizationOwnership(ctx, org.ID, "user-charles", userScott)
	if err != nil {
		t.Fatalf("failed to transfer ownership: %v", err)
	}

	scottMem, _ := repo.GetOrgMembership(ctx, org.ID, userScott)
	if scottMem.Role != OrgRoleOwner {
		t.Errorf("expected Scott to be OWNER, got %s", scottMem.Role)
	}

	charlesMem, _ := repo.GetOrgMembership(ctx, org.ID, "user-charles")
	if charlesMem.Role != OrgRoleAdmin {
		t.Errorf("expected Charles to be demoted to ADMIN, got %s", charlesMem.Role)
	}

	// 6. Delegated Workspace Administration:
	// Scott (Owner) assigns Logan as Workspace Admin on Danger Room
	err = svc.AssignWorkspaceAdmin(ctx, ws.ID, userScott, userLogan)
	if err != nil {
		t.Fatalf("failed to assign workspace admin: %v", err)
	}

	wsMem, _ := repo.GetWorkspaceMembership(ctx, ws.ID, userLogan)
	if wsMem.Role != WorkspaceRoleAdmin {
		t.Errorf("expected Logan to be WorkspaceRoleAdmin, got %s", wsMem.Role)
	}

	// Cannot assign workspace admin to an external user not in organization
	err = svc.AssignWorkspaceAdmin(ctx, ws.ID, userScott, "user-magneto")
	if err != ErrUserNotInOrganization {
		t.Errorf("expected ErrUserNotInOrganization for external user, got %v", err)
	}

	// Revoke workspace admin
	err = svc.RevokeWorkspaceAdmin(ctx, ws.ID, userScott, userLogan)
	if err != nil {
		t.Fatalf("failed to revoke workspace admin: %v", err)
	}

	// 7. Verify audit events recorded
	expectedActions := []string{
		ActionOrgMemberRoleUpdated,
		ActionOrgOwnershipTransferred,
		ActionWorkspaceAdminAssigned,
		ActionWorkspaceAdminRevoked,
	}

	for _, action := range expectedActions {
		found := false
		for _, e := range auditMem.Events {
			if e.Action == action {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected audit event %s not found in recorded events", action)
		}
	}
}
