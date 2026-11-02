package hierarchy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

func TestMembershipResolver(t *testing.T) {
	repo := NewMemoryHierarchyRepository()
	cache := NewMemoryMembershipCache()
	resolver := NewMembershipResolver(repo, cache, 5*time.Minute)
	svc := NewHierarchyService(repo)
	ctx := context.Background()

	// 1. Setup Organization, Workspaces, and Team
	org, err := svc.CreateOrganization(ctx, "Wayne Enterprises", "wayne-enterprises", "user-bruce")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	tenant1 := uuid.New()
	tenant2 := uuid.New()

	ws1, err := svc.CreateWorkspace(ctx, org.ID, tenant1, "R&D Lab", "rd-lab", "production")
	if err != nil {
		t.Fatalf("failed to create ws1: %v", err)
	}

	ws2, err := svc.CreateWorkspace(ctx, org.ID, tenant2, "Applied Sciences", "applied-sci", "production")
	if err != nil {
		t.Fatalf("failed to create ws2: %v", err)
	}

	userLucius := "user-lucius"
	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         userLucius,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// 2. Direct membership on ws1 (Role: OPERATOR)
	_ = repo.SaveWorkspaceMembership(ctx, &WorkspaceMembership{
		ID:          uuid.New(),
		WorkspaceID: ws1.ID,
		UserID:      userLucius,
		Role:        WorkspaceRoleOperator,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	})

	// Resolve context for ws1
	sec1, err := resolver.ResolveContext(ctx, userLucius, &ws1.ID)
	if err != nil {
		t.Fatalf("failed to resolve context for ws1: %v", err)
	}

	if sec1.WorkspaceRole != WorkspaceRoleOperator {
		t.Errorf("expected WorkspaceRoleOperator, got %s", sec1.WorkspaceRole)
	}
	if sec1.TenantID != tenant1 {
		t.Errorf("expected tenant1 %s, got %s", tenant1, sec1.TenantID)
	}

	// Verify cached on second call
	cachedSec, ok := cache.Get(ctx, userLucius, ws1.ID)
	if !ok || cachedSec == nil {
		t.Fatalf("expected context to be cached")
	}

	// 3. User Lucius tries to access ws2 (not assigned directly or via team)
	_, err = resolver.ResolveContext(ctx, userLucius, &ws2.ID)
	if err != ErrNoWorkspaceAccess {
		t.Errorf("expected ErrNoWorkspaceAccess for ws2, got %v", err)
	}

	// 4. Create team and grant team access to ws2
	team := &Team{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "Applied Sci Team",
		Slug:           "applied-sci",
		Status:         "ACTIVE",
	}
	_ = repo.CreateTeam(ctx, team)
	_ = repo.AddTeamMember(ctx, &TeamMembership{
		ID:      uuid.New(),
		TeamID:  team.ID,
		UserID:  userLucius,
		Role:    TeamRoleMember,
	})
	_ = repo.GrantTeamWorkspaceRole(ctx, &WorkspaceTeamGrant{
		ID:          uuid.New(),
		WorkspaceID: ws2.ID,
		TeamID:      team.ID,
		Role:        WorkspaceRoleViewer,
	})

	// Now Lucius accesses ws2 via team grant
	sec2, err := resolver.ResolveContext(ctx, userLucius, &ws2.ID)
	if err != nil {
		t.Fatalf("failed to resolve context for ws2 via team grant: %v", err)
	}
	if sec2.WorkspaceRole != WorkspaceRoleViewer {
		t.Errorf("expected WorkspaceRoleViewer, got %s", sec2.WorkspaceRole)
	}

	// 5. Test Cache Invalidation
	cache.InvalidateUser(ctx, userLucius)
	if _, ok := cache.Get(ctx, userLucius, ws1.ID); ok {
		t.Errorf("cache for userLucius should have been invalidated")
	}

	// 6. Test Context Injection and Extraction
	ctxWithSec, err := WithSecurityContext(ctx, sec1)
	if err != nil {
		t.Fatalf("failed to inject security context: %v", err)
	}

	extractedSec, err := SecurityContextFromContext(ctxWithSec)
	if err != nil || extractedSec.UserID != userLucius {
		t.Fatalf("failed to extract security context: %v", err)
	}

	// Verify tenant context was also set
	extractedTenantID, err := tenant.ID(ctxWithSec)
	if err != nil || extractedTenantID != tenant1 {
		t.Fatalf("expected tenant context to match tenant1: %v", err)
	}

	// 7. Test Organization Suspension blocks resolution
	_ = svc.SuspendOrganization(ctx, org.ID, "user-bruce", "Security audit")
	cache.InvalidateUser(ctx, userLucius)

	_, err = resolver.ResolveContext(ctx, userLucius, &ws1.ID)
	if err != ErrOrgSuspended {
		t.Errorf("expected ErrOrgSuspended when org is suspended, got %v", err)
	}
}
