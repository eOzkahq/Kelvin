package iam

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccount_ProvisionAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	svc := NewServiceAccountService()

	orgID := uuid.New()
	wsID := uuid.New()

	req := CreateSARequest{
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Name:           "CI/CD Scanner Runner",
		Description:    "Automated pipeline scanner",
		Roles:          []string{"SCANNER_RUNNER"},
		Permissions:    []string{"scans:trigger", "scans:read"},
		CreatorID:      "admin-alice",
		ExpiresInDays:  90,
	}

	sa, cred, err := svc.CreateServiceAccount(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "CI/CD Scanner Runner", sa.Name)
	assert.Equal(t, SAActive, sa.Status)
	assert.NotEmpty(t, sa.ClientID)
	assert.NotEmpty(t, cred.RawSecret)
	assert.Equal(t, sa.ClientID, cred.ClientID)

	t.Run("successful authentication updates last used metadata", func(t *testing.T) {
		authed, err := svc.Authenticate(ctx, sa.ClientID, cred.RawSecret, "10.0.0.5")
		require.NoError(t, err)
		assert.Equal(t, sa.ID, authed.ID)
		assert.NotNil(t, authed.LastUsedAt)
		assert.Equal(t, "10.0.0.5", authed.LastUsedIP)
	})

	t.Run("rejects authentication with invalid secret", func(t *testing.T) {
		_, err := svc.Authenticate(ctx, sa.ClientID, "wrong-secret", "10.0.0.5")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCredentials)
	})

	t.Run("rejects authentication with unknown client id", func(t *testing.T) {
		_, err := svc.Authenticate(ctx, "sa_unknown", cred.RawSecret, "10.0.0.5")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCredentials)
	})
}

func TestServiceAccount_InteractiveLoginDefense(t *testing.T) {
	ctx := context.Background()
	svc := NewServiceAccountService()

	orgID := uuid.New()
	req := CreateSARequest{
		OrganizationID: orgID,
		Name:           "Pipeline Identity",
		CreatorID:      "admin-alice",
	}

	sa, _, err := svc.CreateServiceAccount(ctx, req)
	require.NoError(t, err)

	t.Run("interactive login strictly rejected for machine account", func(t *testing.T) {
		err := svc.AttemptInteractiveLogin(ctx, sa.ClientID)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInteractiveLoginForbidden)
	})
}

func TestServiceAccount_LifecycleAndSuspension(t *testing.T) {
	ctx := context.Background()
	svc := NewServiceAccountService()

	orgID := uuid.New()
	sa, cred, err := svc.CreateServiceAccount(ctx, CreateSARequest{
		OrganizationID: orgID,
		Name:           "Test Runner",
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	t.Run("suspending account immediately blocks authentication", func(t *testing.T) {
		err := svc.SuspendServiceAccount(ctx, sa.ID, "admin", "Suspected credential leak")
		require.NoError(t, err)

		_, err = svc.Authenticate(ctx, sa.ClientID, cred.RawSecret, "10.0.0.1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrServiceAccountSuspended)
	})

	t.Run("reactivating account restores authentication", func(t *testing.T) {
		err := svc.ActivateServiceAccount(ctx, sa.ID, "admin")
		require.NoError(t, err)

		authed, err := svc.Authenticate(ctx, sa.ClientID, cred.RawSecret, "10.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, sa.ID, authed.ID)
	})

	t.Run("revoking account permanently blocks access", func(t *testing.T) {
		err := svc.RevokeServiceAccount(ctx, sa.ID, "admin", "Decommissioned pipeline")
		require.NoError(t, err)

		_, err = svc.Authenticate(ctx, sa.ClientID, cred.RawSecret, "10.0.0.1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrServiceAccountRevoked)
	})
}

func TestServiceAccount_CredentialRotation(t *testing.T) {
	ctx := context.Background()
	svc := NewServiceAccountService()

	orgID := uuid.New()
	sa, oldCred, err := svc.CreateServiceAccount(ctx, CreateSARequest{
		OrganizationID: orgID,
		Name:           "Rotation Target",
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	t.Run("rotate credentials revoking old secret immediately", func(t *testing.T) {
		newCred, err := svc.RotateCredentials(ctx, sa.ID, "admin", true)
		require.NoError(t, err)
		assert.NotEqual(t, oldCred.RawSecret, newCred.RawSecret)

		// Old secret must be rejected
		_, err = svc.Authenticate(ctx, sa.ClientID, oldCred.RawSecret, "10.0.0.1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrCredentialRevoked)

		// New secret must authenticate successfully
		authed, err := svc.Authenticate(ctx, sa.ClientID, newCred.RawSecret, "10.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, sa.ID, authed.ID)
	})
}

func TestServiceAccount_AuditLogs(t *testing.T) {
	ctx := context.Background()
	svc := NewServiceAccountService()

	orgID := uuid.New()
	sa, cred, err := svc.CreateServiceAccount(ctx, CreateSARequest{
		OrganizationID: orgID,
		Name:           "Audited Identity",
		CreatorID:      "admin-user",
	})
	require.NoError(t, err)

	_, _ = svc.Authenticate(ctx, sa.ClientID, cred.RawSecret, "127.0.0.1")
	_ = svc.AttemptInteractiveLogin(ctx, sa.ClientID)

	logs := svc.GetAuditLogs(sa.ID)
	require.GreaterOrEqual(t, len(logs), 3)

	actions := make(map[string]bool)
	for _, l := range logs {
		actions[l.Action] = true
	}
	assert.True(t, actions["CREATE"])
	assert.True(t, actions["AUTHENTICATE"])
	assert.True(t, actions["REJECT_INTERACTIVE_LOGIN"])
}
