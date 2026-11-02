package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSCIMService_TokenAndAuth(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySCIMRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSCIMService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("generate and authenticate SCIM token", func(t *testing.T) {
		rawToken, token, err := service.GenerateSCIMToken(ctx, actorID, orgID, "Okta SCIM")
		if err != nil {
			t.Fatalf("unexpected error generating token: %v", err)
		}
		if rawToken == "" || token.TokenHash == "" {
			t.Errorf("expected valid raw token and hash")
		}

		authedOrg, err := service.AuthenticateToken(ctx, rawToken)
		if err != nil {
			t.Fatalf("unexpected error authenticating token: %v", err)
		}
		if authedOrg != orgID {
			t.Errorf("expected org ID %s, got %s", orgID, authedOrg)
		}
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		_, err := service.AuthenticateToken(ctx, "invalid_bearer_token")
		if !errors.Is(err, ErrSCIMUnauthorized) {
			t.Fatalf("expected ErrSCIMUnauthorized, got %v", err)
		}
	})
}

func TestSCIMService_UserLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySCIMRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSCIMService(repo, mockAudit)

	orgID := uuid.New()

	userReq := &SCIMUser{
		ExternalID: "okta_usr_1001",
		UserName:   "bob.ross@enterprise.com",
		Name: SCIMName{
			Formatted:  "Bob Ross",
			GivenName:  "Bob",
			FamilyName: "Ross",
		},
		Emails: []SCIMEmail{
			{Value: "bob.ross@enterprise.com", Primary: true},
		},
		Active: true,
	}

	t.Run("create SCIM user successfully", func(t *testing.T) {
		created, err := service.CreateUser(ctx, orgID, userReq)
		if err != nil {
			t.Fatalf("unexpected error creating user: %v", err)
		}
		if created.ID == "" {
			t.Errorf("expected non-empty ID")
		}
		if !created.Active {
			t.Errorf("expected active=true")
		}

		// Verify retrieval
		fetched, err := service.GetUser(ctx, orgID, created.ID)
		if err != nil {
			t.Fatalf("failed to fetch user: %v", err)
		}
		if fetched.UserName != "bob.ross@enterprise.com" {
			t.Errorf("expected userName bob.ross@enterprise.com, got %s", fetched.UserName)
		}
	})

	t.Run("idempotent create on repeated request with same externalID", func(t *testing.T) {
		repeated, err := service.CreateUser(ctx, orgID, userReq)
		if err != nil {
			t.Fatalf("unexpected error on repeated idempotent create: %v", err)
		}
		if repeated.UserName != userReq.UserName {
			t.Errorf("expected matching user on idempotent create")
		}
	})

	t.Run("conflict error when userName exists with different externalID", func(t *testing.T) {
		conflictReq := &SCIMUser{
			ExternalID: "different_okta_usr_2002",
			UserName:   "bob.ross@enterprise.com", // Same email/username
			Active:     true,
		}
		_, err := service.CreateUser(ctx, orgID, conflictReq)
		if !errors.Is(err, ErrSCIMConflict) {
			t.Fatalf("expected ErrSCIMConflict, got %v", err)
		}
	})

	t.Run("deactivate user via PATCH active=false", func(t *testing.T) {
		existing, _ := repo.GetUserByUserName(ctx, orgID, "bob.ross@enterprise.com")

		patch := SCIMPatchRequest{
			Schemas: []string{SCIMPatchOpSchema},
			Operations: []SCIMPatchOp{
				{
					Op:    "replace",
					Path:  "active",
					Value: false,
				},
			},
		}

		patched, err := service.PatchUser(ctx, orgID, existing.ID, patch)
		if err != nil {
			t.Fatalf("unexpected error patching user: %v", err)
		}
		if patched.Active {
			t.Errorf("expected active to be false after deactivation")
		}

		// Verify in repo
		reloaded, _ := service.GetUser(ctx, orgID, existing.ID)
		if reloaded.Active {
			t.Errorf("expected reloaded user to be deactivated")
		}
	})

	t.Run("cross-tenant isolation: user not visible in another org", func(t *testing.T) {
		existing, _ := repo.GetUserByUserName(ctx, orgID, "bob.ross@enterprise.com")
		otherOrgID := uuid.New()

		_, err := service.GetUser(ctx, otherOrgID, existing.ID)
		if !errors.Is(err, ErrSCIMNotFound) {
			t.Fatalf("expected ErrSCIMNotFound for cross-org lookup, got %v", err)
		}
	})
}

func TestSCIMService_GroupLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySCIMRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSCIMService(repo, mockAudit)

	orgID := uuid.New()

	t.Run("create SCIM group successfully", func(t *testing.T) {
		grp := &SCIMGroup{
			DisplayName: "SecOps Engineering",
			ExternalID:  "grp_okta_555",
			Members: []SCIMMember{
				{Value: "usr_1", Display: "Analyst One"},
			},
		}

		created, err := service.CreateGroup(ctx, orgID, grp)
		if err != nil {
			t.Fatalf("unexpected error creating group: %v", err)
		}
		if created.ID == "" {
			t.Errorf("expected non-empty ID")
		}

		fetched, err := service.GetGroup(ctx, orgID, created.ID)
		if err != nil {
			t.Fatalf("failed to fetch group: %v", err)
		}
		if fetched.DisplayName != "SecOps Engineering" {
			t.Errorf("expected SecOps Engineering, got %s", fetched.DisplayName)
		}
	})

	t.Run("block SCIM group trying to map to privileged role", func(t *testing.T) {
		privilegedGroup := &SCIMGroup{
			DisplayName: "ORG_OWNER",
		}
		_, err := service.CreateGroup(ctx, orgID, privilegedGroup)
		if !errors.Is(err, ErrSCIMPrivilegedGroupForbidden) {
			t.Fatalf("expected ErrSCIMPrivilegedGroupForbidden for ORG_OWNER, got %v", err)
		}

		adminGroup := &SCIMGroup{
			DisplayName: "ORG_ADMIN",
		}
		_, err = service.CreateGroup(ctx, orgID, adminGroup)
		if !errors.Is(err, ErrSCIMPrivilegedGroupForbidden) {
			t.Fatalf("expected ErrSCIMPrivilegedGroupForbidden for ORG_ADMIN, got %v", err)
		}
	})
}
