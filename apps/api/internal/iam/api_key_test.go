package iam

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKey_CreationAndAuthentication(t *testing.T) {
	ctx := context.Background()
	svc := NewAPIKeyService()

	orgID := uuid.New()
	wsID := uuid.New()

	req := CreateKeyRequest{
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Name:           "Production Automation Key",
		IsLive:         true,
		Scopes:         []string{"scans:trigger", "scans:read"},
		ExpiryDays:     90,
	}

	created, err := svc.CreateKey(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, created.RawKey)
	assert.True(t, len(created.RawKey) > 32)
	assert.Equal(t, LiveKeyPrefix, created.RawKey[:len(LiveKeyPrefix)])
	assert.Equal(t, KeyActive, created.Credential.Status)
	assert.Equal(t, int64(0), created.Credential.UsageCount)

	t.Run("successful authentication with matching scope", func(t *testing.T) {
		cred, err := svc.AuthenticateKey(ctx, created.RawKey, "scans:trigger", "192.168.1.100")
		require.NoError(t, err)
		assert.Equal(t, created.Credential.ID, cred.ID)
		assert.Equal(t, int64(1), cred.UsageCount)
		assert.NotNil(t, cred.LastUsedAt)
		assert.Equal(t, "192.168.1.100", cred.LastUsedIP)
	})

	t.Run("rejected authentication when scope is missing", func(t *testing.T) {
		_, err := svc.AuthenticateKey(ctx, created.RawKey, "admin:delete_org", "192.168.1.100")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAPIKeyMissingScope)
	})

	t.Run("rejected authentication with invalid format", func(t *testing.T) {
		_, err := svc.AuthenticateKey(ctx, "invalid_prefix_123", "", "192.168.1.100")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAPIKeyInvalidFormat)
	})
}

func TestAPIKey_RevocationAndCompromise(t *testing.T) {
	ctx := context.Background()
	svc := NewAPIKeyService()

	orgID := uuid.New()
	created, err := svc.CreateKey(ctx, CreateKeyRequest{
		OrganizationID: orgID,
		Name:           "Short-lived Key",
		IsLive:         false,
		Scopes:         []string{"read"},
		ExpiryDays:     30,
	})
	require.NoError(t, err)

	t.Run("immediate revocation invalidates key", func(t *testing.T) {
		err := svc.RevokeKey(ctx, created.Credential.ID, "admin-dan", "Decommissioned test runner")
		require.NoError(t, err)

		_, err = svc.AuthenticateKey(ctx, created.RawKey, "read", "127.0.0.1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAPIKeyRevoked)
	})

	t.Run("reporting compromise marks key compromised and disables access", func(t *testing.T) {
		key2, err := svc.CreateKey(ctx, CreateKeyRequest{
			OrganizationID: orgID,
			Name:           "Leaked Key",
			IsLive:         true,
			Scopes:         []string{"read"},
		})
		require.NoError(t, err)

		err = svc.ReportCompromisedKey(ctx, key2.Credential.ID, "security-scanner", "Found exposed on public pastebin")
		require.NoError(t, err)

		_, err = svc.AuthenticateKey(ctx, key2.RawKey, "read", "127.0.0.1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAPIKeyCompromised)
	})
}

func TestAPIKey_Rotation(t *testing.T) {
	ctx := context.Background()
	svc := NewAPIKeyService()

	orgID := uuid.New()
	original, err := svc.CreateKey(ctx, CreateKeyRequest{
		OrganizationID: orgID,
		Name:           "Rotatable Key",
		IsLive:         true,
		Scopes:         []string{"scans:read"},
	})
	require.NoError(t, err)

	t.Run("rotate with zero overlap immediately revokes original key", func(t *testing.T) {
		rotated, err := svc.RotateKey(ctx, original.Credential.ID, "admin", 0)
		require.NoError(t, err)
		assert.NotEqual(t, original.RawKey, rotated.RawKey)

		// Old key must be revoked
		_, err = svc.AuthenticateKey(ctx, original.RawKey, "scans:read", "127.0.0.1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAPIKeyRevoked)

		// New key must be active
		authed, err := svc.AuthenticateKey(ctx, rotated.RawKey, "scans:read", "127.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, rotated.Credential.ID, authed.ID)
	})

	t.Run("rotate with grace period keeps old key active temporarily", func(t *testing.T) {
		keyA, err := svc.CreateKey(ctx, CreateKeyRequest{
			OrganizationID: orgID,
			Name:           "Grace Rotation Key",
			IsLive:         true,
			Scopes:         []string{"scans:read"},
		})
		require.NoError(t, err)

		keyB, err := svc.RotateKey(ctx, keyA.Credential.ID, "admin", 1*time.Hour)
		require.NoError(t, err)

		// Both keys are valid within grace window
		_, err = svc.AuthenticateKey(ctx, keyA.RawKey, "scans:read", "127.0.0.1")
		require.NoError(t, err)

		_, err = svc.AuthenticateKey(ctx, keyB.RawKey, "scans:read", "127.0.0.1")
		require.NoError(t, err)
	})
}

func TestAPIKey_LeakagePrevention(t *testing.T) {
	ctx := context.Background()
	svc := NewAPIKeyService()

	created, err := svc.CreateKey(ctx, CreateKeyRequest{
		OrganizationID: uuid.New(),
		Name:           "Secret Key",
		IsLive:         true,
	})
	require.NoError(t, err)

	t.Run("json serialization does not leak key hash or raw secret", func(t *testing.T) {
		marshaled, err := json.Marshal(created.Credential)
		require.NoError(t, err)
		jsonStr := string(marshaled)

		assert.NotContains(t, jsonStr, created.Credential.KeyHash)
		assert.NotContains(t, jsonStr, created.RawKey)
		assert.NotContains(t, jsonStr, "key_hash")
	})

	t.Run("string formatter does not leak key hash or raw secret", func(t *testing.T) {
		str := created.Credential.String()
		assert.NotContains(t, str, created.Credential.KeyHash)
		assert.NotContains(t, str, created.RawKey)
	})

	t.Run("redact key utility safely masks keys", func(t *testing.T) {
		redacted := RedactKey(created.RawKey)
		assert.Contains(t, redacted, "klv_live_")
		assert.Contains(t, redacted, "...")
		assert.NotEqual(t, created.RawKey, redacted)
	})
}
