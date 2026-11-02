package iam

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

type mockAuditRecorder struct {
	events []audit.Event
}

func (m *mockAuditRecorder) Record(ctx context.Context, evt audit.Event) error {
	m.events = append(m.events, evt)
	return nil
}

func TestCustomRoleService_CreateCustomRole(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryCustomRoleRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewCustomRoleService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("successful custom role creation", func(t *testing.T) {
		role, err := service.CreateCustomRole(
			ctx,
			orgID,
			actorID,
			"Security Auditor Junior",
			"security-auditor-jr",
			"Read-only auditor with report generation access",
			ScopeWorkspace,
			[]Permission{PermissionFindingRead, PermissionReportGenerate},
		)
		if err != nil {
			t.Fatalf("unexpected error creating custom role: %v", err)
		}
		if role.ID == uuid.Nil {
			t.Errorf("expected non-nil UUID for role ID")
		}
		if role.Version != 1 {
			t.Errorf("expected version 1, got %d", role.Version)
		}
		if role.Status != "ACTIVE" {
			t.Errorf("expected status ACTIVE, got %s", role.Status)
		}
		if len(role.Permissions) != 2 {
			t.Errorf("expected 2 permissions, got %d", len(role.Permissions))
		}
		if len(mockAudit.events) != 1 || mockAudit.events[0].Action != ActionCustomRoleCreated {
			t.Errorf("expected audit event %s, got %+v", ActionCustomRoleCreated, mockAudit.events)
		}
	})

	t.Run("privilege escalation defense - forbidden root permissions rejected", func(t *testing.T) {
		forbiddenList := []Permission{
			PermissionOrgBillingManage,
			PermissionOrgSSOManage,
			PermissionEvidencePurge,
		}

		for _, p := range forbiddenList {
			_, err := service.CreateCustomRole(
				ctx,
				orgID,
				actorID,
				"Escalated Role",
				"escalated-role-"+string(p),
				"Trying to get forbidden permission",
				ScopeOrganization,
				[]Permission{PermissionFindingRead, p},
			)
			if err == nil {
				t.Fatalf("expected error for forbidden permission %q, got nil", p)
			}
		}
	})

	t.Run("invalid permission rejected", func(t *testing.T) {
		_, err := service.CreateCustomRole(
			ctx,
			orgID,
			actorID,
			"Invalid Perm Role",
			"invalid-perm-role",
			"Has invalid permission",
			ScopeWorkspace,
			[]Permission{"invalid:action"},
		)
		if err == nil {
			t.Fatalf("expected error for invalid permission, got nil")
		}
	})

	t.Run("built-in role slug collision rejected", func(t *testing.T) {
		_, err := service.CreateCustomRole(
			ctx,
			orgID,
			actorID,
			"Custom Owner",
			"ORG_OWNER",
			"Trying to collide with built-in role slug",
			ScopeOrganization,
			[]Permission{PermissionFindingRead},
		)
		if err == nil {
			t.Fatalf("expected error for built-in role slug collision, got nil")
		}
	})

	t.Run("duplicate slug within org rejected", func(t *testing.T) {
		_, err := service.CreateCustomRole(
			ctx,
			orgID,
			actorID,
			"Duplicate Role",
			"security-auditor-jr",
			"Duplicate slug in same org",
			ScopeWorkspace,
			[]Permission{PermissionFindingRead},
		)
		if err == nil {
			t.Fatalf("expected error for duplicate slug, got nil")
		}
	})
}

func TestCustomRoleService_UpdateAndArchive(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryCustomRoleRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewCustomRoleService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	role, err := service.CreateCustomRole(
		ctx,
		orgID,
		actorID,
		"Initial Role",
		"initial-role",
		"Initial description",
		ScopeWorkspace,
		[]Permission{PermissionFindingRead},
	)
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	t.Run("update increments version and updates permissions", func(t *testing.T) {
		updated, err := service.UpdateCustomRole(
			ctx,
			role.ID,
			actorID,
			"Updated Role",
			"New description",
			[]Permission{PermissionFindingRead, PermissionFindingTriage},
		)
		if err != nil {
			t.Fatalf("unexpected error updating role: %v", err)
		}
		if updated.Version != 2 {
			t.Errorf("expected version 2, got %d", updated.Version)
		}
		if len(updated.Permissions) != 2 {
			t.Errorf("expected 2 permissions, got %d", len(updated.Permissions))
		}
	})

	t.Run("update with forbidden permission fails", func(t *testing.T) {
		_, err := service.UpdateCustomRole(
			ctx,
			role.ID,
			actorID,
			"Escalated Update",
			"Trying to add root permission",
			[]Permission{PermissionFindingRead, PermissionEvidencePurge},
		)
		if err == nil {
			t.Fatalf("expected error adding forbidden permission in update, got nil")
		}
	})

	t.Run("archive custom role and reject subsequent updates", func(t *testing.T) {
		err := service.ArchiveCustomRole(ctx, role.ID, actorID)
		if err != nil {
			t.Fatalf("failed to archive custom role: %v", err)
		}

		archivedRole, err := repo.GetCustomRole(ctx, role.ID)
		if err != nil {
			t.Fatalf("failed to get role: %v", err)
		}
		if archivedRole.Status != "ARCHIVED" {
			t.Errorf("expected ARCHIVED status, got %s", archivedRole.Status)
		}

		// Subsequent update should fail
		_, err = service.UpdateCustomRole(
			ctx,
			role.ID,
			actorID,
			"Cannot Update Archived",
			"Should fail",
			[]Permission{PermissionFindingRead},
		)
		if err == nil {
			t.Fatalf("expected error updating archived role, got nil")
		}
	})
}

func TestCustomRoleService_ResolvePermissions(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryCustomRoleRepository()
	service := NewCustomRoleService(repo, nil)

	orgID := uuid.New()
	actorID := uuid.New().String()

	role1, _ := service.CreateCustomRole(
		ctx, orgID, actorID, "Role 1", "role-1", "", ScopeWorkspace,
		[]Permission{PermissionFindingRead, PermissionFindingTriage},
	)
	role2, _ := service.CreateCustomRole(
		ctx, orgID, actorID, "Role 2", "role-2", "", ScopeWorkspace,
		[]Permission{PermissionReportGenerate, PermissionAssessmentRead},
	)
	roleArchived, _ := service.CreateCustomRole(
		ctx, orgID, actorID, "Role Archived", "role-archived", "", ScopeWorkspace,
		[]Permission{PermissionPolicyExceptionApprove},
	)
	_ = service.ArchiveCustomRole(ctx, roleArchived.ID, actorID)

	perms, err := service.ResolveCustomRolePermissions(ctx, []uuid.UUID{role1.ID, role2.ID, roleArchived.ID})
	if err != nil {
		t.Fatalf("unexpected error resolving custom role perms: %v", err)
	}

	if len(perms) != 4 {
		t.Errorf("expected 4 resolved permissions, got %d", len(perms))
	}
	if !perms[PermissionFindingRead] || !perms[PermissionFindingTriage] || !perms[PermissionReportGenerate] || !perms[PermissionAssessmentRead] {
		t.Errorf("missing expected permissions in resolved map")
	}
	if perms[PermissionPolicyExceptionApprove] {
		t.Errorf("archived role's permission should not have been included")
	}
}
