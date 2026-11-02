package hierarchy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

func TestClassifyResourceScope(t *testing.T) {
	tests := []struct {
		resourceType string
		wantScope    ResourceScope
		wantErr      bool
	}{
		{"sso_config", ResourceScopeOrganization, false},
		{"enterprise_policy", ResourceScopeOrganization, false},
		{"billing_account", ResourceScopeOrganization, false},
		{"assessment", ResourceScopeWorkspace, false},
		{"finding", ResourceScopeWorkspace, false},
		{"evidence", ResourceScopeWorkspace, false},
		{"report", ResourceScopeWorkspace, false},
		{"unknown_resource_xyz", "", true},
	}

	for _, tt := range tests {
		scope, err := ClassifyResourceScope(tt.resourceType)
		if tt.wantErr && err == nil {
			t.Errorf("ClassifyResourceScope(%s) expected error, got nil", tt.resourceType)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ClassifyResourceScope(%s) unexpected error: %v", tt.resourceType, err)
		}
		if scope != tt.wantScope {
			t.Errorf("ClassifyResourceScope(%s) = %s, want %s", tt.resourceType, scope, tt.wantScope)
		}
	}
}

func TestHierarchyAccessControl(t *testing.T) {
	repo := NewMemoryHierarchyRepository()
	svc := NewHierarchyService(repo)
	ctx := context.Background()

	// 1. Create Organization
	org, err := svc.CreateOrganization(ctx, "Acme Corp", "acme-corp", "user-admin")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	// 2. Create two Workspaces mapped to separate tenants
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	ws1, err := svc.CreateWorkspace(ctx, org.ID, tenant1, "Production", "prod", "production")
	if err != nil {
		t.Fatalf("failed to create ws1: %v", err)
	}

	ws2, err := svc.CreateWorkspace(ctx, org.ID, tenant2, "Staging", "staging", "staging")
	if err != nil {
		t.Fatalf("failed to create ws2: %v", err)
	}

	// 3. User A is granted direct ADMIN on Workspace 1
	err = repo.SaveWorkspaceMembership(ctx, &WorkspaceMembership{
		ID:          uuid.New(),
		WorkspaceID: ws1.ID,
		UserID:      "user-a",
		Role:        WorkspaceRoleAdmin,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("failed to save ws membership: %v", err)
	}

	// 4. Test User A access to ws1
	ctxTenant1, err := tenant.WithID(ctx, tenant1)
	if err != nil {
		t.Fatalf("failed to set context tenant: %v", err)
	}

	err = svc.AuthorizeWorkspaceAccess(ctxTenant1, ws1.ID, "user-a", WorkspaceRoleOperator)
	if err != nil {
		t.Errorf("user-a should be authorized on ws1: %v", err)
	}

	// 5. Test User A access to ws2 (no implicit cross-workspace access)
	err = svc.AuthorizeWorkspaceAccess(ctxTenant1, ws2.ID, "user-a", WorkspaceRoleViewer)
	if err == nil {
		t.Errorf("user-a should NOT be authorized on ws2 (implicit cross-workspace should fail)")
	}

	// 6. Test Tenant mismatch (context tenant2 trying to access ws1)
	ctxTenant2, err := tenant.WithID(ctx, tenant2)
	if err != nil {
		t.Fatalf("failed to set context tenant2: %v", err)
	}
	err = svc.AuthorizeWorkspaceAccess(ctxTenant2, ws1.ID, "user-a", WorkspaceRoleViewer)
	if err != ErrTenantMismatch {
		t.Errorf("expected ErrTenantMismatch, got %v", err)
	}

	// 7. Team-based role grant test
	team := &Team{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "SecOps Team",
		Slug:           "secops",
	}
	if err := repo.CreateTeam(ctx, team); err != nil {
		t.Fatalf("failed to create team: %v", err)
	}

	// Add user-b to SecOps team
	if err := repo.AddTeamMember(ctx, &TeamMembership{
		ID:      uuid.New(),
		TeamID:  team.ID,
		UserID:  "user-b",
		Role:    TeamRoleMember,
	}); err != nil {
		t.Fatalf("failed to add team member: %v", err)
	}

	// Grant SecOps team OPERATOR role on ws2
	if err := repo.GrantTeamWorkspaceRole(ctx, &WorkspaceTeamGrant{
		ID:          uuid.New(),
		WorkspaceID: ws2.ID,
		TeamID:      team.ID,
		Role:        WorkspaceRoleOperator,
	}); err != nil {
		t.Fatalf("failed to grant team workspace role: %v", err)
	}

	// User-b should be authorized on ws2 as OPERATOR
	err = svc.AuthorizeWorkspaceAccess(ctxTenant2, ws2.ID, "user-b", WorkspaceRoleOperator)
	if err != nil {
		t.Errorf("user-b should be authorized on ws2 via team grant: %v", err)
	}

	// User-b should NOT be authorized on ws2 as ADMIN (higher role than granted)
	err = svc.AuthorizeWorkspaceAccess(ctxTenant2, ws2.ID, "user-b", WorkspaceRoleAdmin)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for user-b ADMIN check, got %v", err)
	}
}
