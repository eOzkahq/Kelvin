package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type mockSharingResolver struct {
	grants map[string]bool
}

func newMockSharingResolver() *mockSharingResolver {
	return &mockSharingResolver{
		grants: make(map[string]bool),
	}
}

func (m *mockSharingResolver) AddGrant(resourceType, resourceID string, targetWorkspaceID uuid.UUID) {
	key := resourceType + ":" + resourceID + ":" + targetWorkspaceID.String()
	m.grants[key] = true
}

func (m *mockSharingResolver) HasActiveSharingGrant(
	ctx context.Context,
	orgID uuid.UUID,
	resourceType string,
	resourceID string,
	targetWorkspaceID uuid.UUID,
	targetTeamIDs []uuid.UUID,
) bool {
	key := resourceType + ":" + resourceID + ":" + targetWorkspaceID.String()
	return m.grants[key]
}

func TestObjectAuthorizer_DirectObjectAccess(t *testing.T) {
	ctx := context.Background()
	authorizer := NewObjectAuthorizer(nil)

	orgID := uuid.New()
	tenantID := uuid.New()
	workspaceID := uuid.New()

	baseSubject := Subject{
		UserID:         "user-1",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspaceID,
		Roles:          []RoleName{RoleSecurityAnalyst},
		Permissions:    nil,
	}

	findingResource := ResourceDescriptor{
		Type:           "finding",
		ID:             "fnd-12345",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspaceID,
	}

	t.Run("authorized access within same tenant and workspace", func(t *testing.T) {
		err := authorizer.Authorize(ctx, baseSubject, findingResource, PermissionFindingRead)
		if err != nil {
			t.Fatalf("expected authorized access, got error: %v", err)
		}
	})

	t.Run("anti-IDOR defense: cross-tenant access returns ErrResourceNotFound", func(t *testing.T) {
		foreignTenantResource := ResourceDescriptor{
			Type:           "finding",
			ID:             "fnd-99999",
			OrganizationID: orgID,
			TenantID:       uuid.New(), // Foreign tenant
			WorkspaceID:    workspaceID,
		}

		err := authorizer.Authorize(ctx, baseSubject, foreignTenantResource, PermissionFindingRead)
		if !errors.Is(err, ErrResourceNotFound) {
			t.Fatalf("expected anti-IDOR ErrResourceNotFound, got: %v", err)
		}

		foreignOrgResource := ResourceDescriptor{
			Type:           "finding",
			ID:             "fnd-88888",
			OrganizationID: uuid.New(), // Foreign org
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
		}

		err = authorizer.Authorize(ctx, baseSubject, foreignOrgResource, PermissionFindingRead)
		if !errors.Is(err, ErrResourceNotFound) {
			t.Fatalf("expected anti-IDOR ErrResourceNotFound for foreign org, got: %v", err)
		}
	})

	t.Run("unauthenticated/missing subject rejected", func(t *testing.T) {
		invalidSubject := Subject{
			UserID: "",
		}
		err := authorizer.Authorize(ctx, invalidSubject, findingResource, PermissionFindingRead)
		if !errors.Is(err, ErrUnauthorizedSubject) {
			t.Fatalf("expected ErrUnauthorizedSubject, got: %v", err)
		}
	})
}

func TestObjectAuthorizer_WorkspaceBoundaries(t *testing.T) {
	ctx := context.Background()
	sharing := newMockSharingResolver()
	authorizer := NewObjectAuthorizer(sharing)

	orgID := uuid.New()
	tenantID := uuid.New()
	workspace1 := uuid.New()
	workspace2 := uuid.New()

	regularSubject := Subject{
		UserID:         "user-reg",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspace1,
		Roles:          []RoleName{RoleSecurityAnalyst},
	}

	ws2Resource := ResourceDescriptor{
		Type:           "report",
		ID:             "rep-456",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspace2,
	}

	t.Run("cross-workspace access denied without grant or org role", func(t *testing.T) {
		err := authorizer.Authorize(ctx, regularSubject, ws2Resource, PermissionReportRead)
		if !errors.Is(err, ErrWorkspaceBoundaryDenied) {
			t.Fatalf("expected ErrWorkspaceBoundaryDenied, got: %v", err)
		}
	})

	t.Run("cross-workspace access permitted via active sharing grant", func(t *testing.T) {
		sharing.AddGrant("report", "rep-456", workspace1)

		err := authorizer.Authorize(ctx, regularSubject, ws2Resource, PermissionReportRead)
		if err != nil {
			t.Fatalf("expected authorized access via sharing grant, got error: %v", err)
		}
	})

	t.Run("cross-workspace access permitted for Org Owner across all workspaces", func(t *testing.T) {
		ownerSubject := Subject{
			UserID:         "user-owner",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspace1,
			Roles:          []RoleName{RoleOrgOwner},
		}

		unsharedResource := ResourceDescriptor{
			Type:           "report",
			ID:             "rep-unshared-789",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspace2,
		}

		err := authorizer.Authorize(ctx, ownerSubject, unsharedResource, PermissionReportRead)
		if err != nil {
			t.Fatalf("expected Org Owner to access across workspaces, got error: %v", err)
		}
	})
}

func TestObjectAuthorizer_TeamRestrictions(t *testing.T) {
	ctx := context.Background()
	authorizer := NewObjectAuthorizer(nil)

	orgID := uuid.New()
	tenantID := uuid.New()
	workspaceID := uuid.New()
	teamAlpha := uuid.New()
	teamBeta := uuid.New()

	teamRestrictedResource := ResourceDescriptor{
		Type:           "target",
		ID:             "tgt-alpha-prod",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspaceID,
		AssignedTeamID: &teamAlpha,
	}

	t.Run("non-team member access denied", func(t *testing.T) {
		betaSubject := Subject{
			UserID:         "user-beta",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
			Roles:          []RoleName{RoleSecurityAnalyst},
			TeamIDs:        []uuid.UUID{teamBeta},
		}

		err := authorizer.Authorize(ctx, betaSubject, teamRestrictedResource, PermissionTargetRead)
		if !errors.Is(err, ErrTeamBoundaryDenied) {
			t.Fatalf("expected ErrTeamBoundaryDenied, got: %v", err)
		}
	})

	t.Run("team member access permitted", func(t *testing.T) {
		alphaSubject := Subject{
			UserID:         "user-alpha",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
			Roles:          []RoleName{RoleSecurityAnalyst},
			TeamIDs:        []uuid.UUID{teamAlpha},
		}

		err := authorizer.Authorize(ctx, alphaSubject, teamRestrictedResource, PermissionTargetRead)
		if err != nil {
			t.Fatalf("expected team member access permitted, got error: %v", err)
		}
	})

	t.Run("workspace admin bypasses team restrictions", func(t *testing.T) {
		adminSubject := Subject{
			UserID:         "user-admin",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
			Roles:          []RoleName{RoleWorkspaceAdmin},
			TeamIDs:        []uuid.UUID{}, // No specific team
		}

		err := authorizer.Authorize(ctx, adminSubject, teamRestrictedResource, PermissionTargetRead)
		if err != nil {
			t.Fatalf("expected workspace admin to bypass team boundary, got error: %v", err)
		}
	})
}

func TestObjectAuthorizer_PermissionRestrictions(t *testing.T) {
	ctx := context.Background()
	authorizer := NewObjectAuthorizer(nil)

	orgID := uuid.New()
	tenantID := uuid.New()
	workspaceID := uuid.New()

	resource := ResourceDescriptor{
		Type:           "finding",
		ID:             "fnd-action-check",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspaceID,
	}

	t.Run("read-only viewer cannot triage finding", func(t *testing.T) {
		viewerSubject := Subject{
			UserID:         "user-viewer",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
			Roles:          []RoleName{RoleReadOnlyViewer},
		}

		err := authorizer.Authorize(ctx, viewerSubject, resource, PermissionFindingTriage)
		if !errors.Is(err, ErrActionForbidden) {
			t.Fatalf("expected ErrActionForbidden for triage, got: %v", err)
		}
	})

	t.Run("custom role direct permission grant permits action", func(t *testing.T) {
		customSubject := Subject{
			UserID:         "user-custom",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
			Roles:          []RoleName{RoleReadOnlyViewer}, // By default cannot triage
			Permissions: map[Permission]bool{
				PermissionFindingTriage: true, // Granted via custom role
			},
		}

		err := authorizer.Authorize(ctx, customSubject, resource, PermissionFindingTriage)
		if err != nil {
			t.Fatalf("expected custom permission to permit action, got error: %v", err)
		}
	})
}

func TestObjectAuthorizer_BackgroundJobContext(t *testing.T) {
	ctx := context.Background()
	authorizer := NewObjectAuthorizer(nil)

	orgID := uuid.New()
	tenantID := uuid.New()
	workspaceID := uuid.New()

	resource := ResourceDescriptor{
		Type:           "assessment",
		ID:             "asm-bg-123",
		OrganizationID: orgID,
		TenantID:       tenantID,
		WorkspaceID:    workspaceID,
	}

	jobCtx := BackgroundJobContext{
		JobID: "job-scan-999",
		Initiator: Subject{
			UserID:         "user-initiator",
			OrganizationID: orgID,
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
			Roles:          []RoleName{RoleSecurityAnalyst},
		},
		CreatedAt: time.Now().UTC(),
	}

	t.Run("authorized background job succeeds", func(t *testing.T) {
		err := authorizer.AuthorizeBackgroundJob(ctx, jobCtx, resource, PermissionAssessmentExecute)
		if err != nil {
			t.Fatalf("expected background job to be authorized, got: %v", err)
		}
	})

	t.Run("cross-tenant background job denied with anti-IDOR error", func(t *testing.T) {
		foreignResource := ResourceDescriptor{
			Type:           "assessment",
			ID:             "asm-foreign",
			OrganizationID: orgID,
			TenantID:       uuid.New(), // Foreign tenant
			WorkspaceID:    workspaceID,
		}

		err := authorizer.AuthorizeBackgroundJob(ctx, jobCtx, foreignResource, PermissionAssessmentExecute)
		if !errors.Is(err, ErrResourceNotFound) {
			t.Fatalf("expected ErrResourceNotFound, got: %v", err)
		}
	})
}

func TestSubjectContextHelpers(t *testing.T) {
	ctx := context.Background()
	s := Subject{
		UserID: "test-user",
	}

	ctxWithSubject := WithSubject(ctx, s)
	retrieved, ok := SubjectFromContext(ctxWithSubject)
	if !ok || retrieved.UserID != "test-user" {
		t.Fatalf("failed to retrieve subject from context")
	}

	_, ok = SubjectFromContext(ctx)
	if ok {
		t.Fatalf("expected ok=false for empty context")
	}
}
