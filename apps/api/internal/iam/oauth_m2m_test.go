package iam

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthM2M_TokenIssuanceAndVerification(t *testing.T) {
	ctx := context.Background()
	saSvc := NewServiceAccountService()
	oauthSvc := NewOAuthM2MService(saSvc, nil)

	orgID := uuid.New()
	wsID := uuid.New()

	sa, cred, err := saSvc.CreateServiceAccount(ctx, CreateSARequest{
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Name:           "GitHub Actions Runner",
		Permissions:    []string{"scans:trigger", "scans:read"},
		CreatorID:      "admin-user",
	})
	require.NoError(t, err)

	t.Run("successfully issue token with authorized scopes", func(t *testing.T) {
		tokenResp, err := oauthSvc.IssueToken(ctx, TokenRequest{
			GrantType:    GrantTypeClientCredentials,
			ClientID:     sa.ClientID,
			ClientSecret: cred.RawSecret,
			Scope:        "scans:trigger scans:read",
		})
		require.NoError(t, err)
		assert.Equal(t, TokenTypeBearer, tokenResp.TokenType)
		assert.Equal(t, DefaultTokenLifetimeSeconds, tokenResp.ExpiresIn)
		assert.NotEmpty(t, tokenResp.AccessToken)

		// Verify token
		claims, err := oauthSvc.VerifyToken(ctx, tokenResp.AccessToken, "scans:trigger")
		require.NoError(t, err)
		assert.Equal(t, sa.ID.String(), claims.Subject)
		assert.Equal(t, sa.ClientID, claims.ClientID)
		assert.Equal(t, orgID, claims.OrganizationID)
		assert.Contains(t, claims.Scopes, "scans:trigger")
	})

	t.Run("unsupported grant type rejected", func(t *testing.T) {
		_, err := oauthSvc.IssueToken(ctx, TokenRequest{
			GrantType:    "password",
			ClientID:     sa.ClientID,
			ClientSecret: cred.RawSecret,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnsupportedGrantType)
	})

	t.Run("invalid client credentials rejected", func(t *testing.T) {
		_, err := oauthSvc.IssueToken(ctx, TokenRequest{
			GrantType:    GrantTypeClientCredentials,
			ClientID:     sa.ClientID,
			ClientSecret: "bad-secret",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCredentials)
	})
}

func TestOAuthM2M_ScopeEscalationDefense(t *testing.T) {
	ctx := context.Background()
	saSvc := NewServiceAccountService()
	oauthSvc := NewOAuthM2MService(saSvc, nil)

	orgID := uuid.New()
	sa, cred, err := saSvc.CreateServiceAccount(ctx, CreateSARequest{
		OrganizationID: orgID,
		Name:           "Read-Only Integration",
		Permissions:    []string{"scans:read", "findings:read"},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	t.Run("scope escalation beyond assigned permissions is denied", func(t *testing.T) {
		_, err := oauthSvc.IssueToken(ctx, TokenRequest{
			GrantType:    GrantTypeClientCredentials,
			ClientID:     sa.ClientID,
			ClientSecret: cred.RawSecret,
			Scope:        "scans:read org:delete", // org:delete is not granted
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrScopeEscalationDenied)
	})
}

func TestOAuthM2M_TokenRevocationAndSuspension(t *testing.T) {
	ctx := context.Background()
	saSvc := NewServiceAccountService()
	oauthSvc := NewOAuthM2MService(saSvc, nil)

	orgID := uuid.New()
	sa, cred, err := saSvc.CreateServiceAccount(ctx, CreateSARequest{
		OrganizationID: orgID,
		Name:           "Automation Worker",
		Permissions:    []string{"scans:read"},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	tokenResp, err := oauthSvc.IssueToken(ctx, TokenRequest{
		GrantType:    GrantTypeClientCredentials,
		ClientID:     sa.ClientID,
		ClientSecret: cred.RawSecret,
	})
	require.NoError(t, err)

	t.Run("revoking individual token blocks verification", func(t *testing.T) {
		claims, err := oauthSvc.VerifyToken(ctx, tokenResp.AccessToken, "scans:read")
		require.NoError(t, err)

		err = oauthSvc.RevokeToken(claims.TokenID)
		require.NoError(t, err)

		_, err = oauthSvc.VerifyToken(ctx, tokenResp.AccessToken, "scans:read")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenRevoked)
	})

	t.Run("suspending service account blocks token issuance and cascades revocation", func(t *testing.T) {
		// Issue a new token first
		t2, err := oauthSvc.IssueToken(ctx, TokenRequest{
			GrantType:    GrantTypeClientCredentials,
			ClientID:     sa.ClientID,
			ClientSecret: cred.RawSecret,
		})
		require.NoError(t, err)

		// Suspend SA
		err = saSvc.SuspendServiceAccount(ctx, sa.ID, "security", "Compromised pipeline")
		require.NoError(t, err)

		// Cascade revoke all SA tokens
		err = oauthSvc.RevokeTokensForServiceAccount(sa.ID)
		require.NoError(t, err)

		// Verification must fail
		_, err = oauthSvc.VerifyToken(ctx, t2.AccessToken, "scans:read")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenRevoked)

		// New token issuance must fail
		_, err = oauthSvc.IssueToken(ctx, TokenRequest{
			GrantType:    GrantTypeClientCredentials,
			ClientID:     sa.ClientID,
			ClientSecret: cred.RawSecret,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrServiceAccountSuspended)
	})
}
