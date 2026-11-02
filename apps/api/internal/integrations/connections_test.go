package integrations

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionManager_CreationAndEncryption(t *testing.T) {
	ctx := context.Background()
	mgr := NewConnectionManager(nil, "test-kek-1")

	orgID := uuid.New()
	wsID := uuid.New()
	secret := "xoxb-secret-slack-bot-token-12345"

	req := CreateConnectionRequest{
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Name:           "Security Alerts Slack",
		Provider:       ProviderSlack,
		EndpointURL:    "https://hooks.slack.com/services/T00/B00/XXXX",
		Secret:         secret,
		Config:         map[string]any{"channel": "#security-alerts"},
		CreatorID:      "admin-alice",
	}

	conn, err := mgr.CreateConnection(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "Security Alerts Slack", conn.Name)
	assert.Equal(t, ProviderSlack, conn.Provider)
	assert.Equal(t, StatusActive, conn.Status)
	assert.NotEqual(t, []byte(secret), conn.EncryptedSecretPayload)
	assert.NotEmpty(t, conn.EncryptionNonce)

	t.Run("adapter can retrieve decrypted secret in memory", func(t *testing.T) {
		decrypted, err := mgr.GetDecryptedSecretForAdapter(ctx, conn.ID)
		require.NoError(t, err)
		assert.Equal(t, secret, decrypted)
	})

	t.Run("json serialization does not leak encrypted secret payload or plaintext", func(t *testing.T) {
		marshaled, err := json.Marshal(conn)
		require.NoError(t, err)
		jsonStr := string(marshaled)

		assert.NotContains(t, jsonStr, secret)
		assert.NotContains(t, jsonStr, "EncryptedSecretPayload")
		assert.NotContains(t, jsonStr, "encrypted_secret_payload")
	})
}

func TestConnectionManager_AntiSSRF(t *testing.T) {
	ctx := context.Background()
	mgr := NewConnectionManager(nil, "test-kek-1")
	orgID := uuid.New()

	unsafeURLs := []string{
		"http://localhost:8080/webhook",
		"http://127.0.0.1:9000/callback",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/admin",
		"http://192.168.1.1/hook",
		"http://172.16.5.10/api",
		"http://100.64.0.1/internal",
	}

	for _, u := range unsafeURLs {
		t.Run("blocks unsafe SSRF target: "+u, func(t *testing.T) {
			_, err := mgr.CreateConnection(ctx, CreateConnectionRequest{
				OrganizationID: orgID,
				Name:           "SSRF Test",
				Provider:       ProviderGenericWebhook,
				EndpointURL:    u,
				Secret:         "dummy",
				CreatorID:      "admin",
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSSRFDestinationBlocked)
		})
	}

	t.Run("rejects unsupported url scheme", func(t *testing.T) {
		_, err := mgr.CreateConnection(ctx, CreateConnectionRequest{
			OrganizationID: orgID,
			Name:           "FTP Test",
			Provider:       ProviderGenericWebhook,
			EndpointURL:    "ftp://example.com/webhook",
			Secret:         "dummy",
			CreatorID:      "admin",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEndpointScheme)
	})

	t.Run("allows public legitimate endpoint", func(t *testing.T) {
		err := ValidateSafeEndpointURL("https://api.github.com/repos/org/repo/dispatches")
		require.NoError(t, err)
	})
}

func TestConnectionManager_RotationAndLifecycle(t *testing.T) {
	ctx := context.Background()
	mgr := NewConnectionManager(nil, "test-kek-1")

	orgID := uuid.New()
	initialSecret := "initial-secret-token"

	conn, err := mgr.CreateConnection(ctx, CreateConnectionRequest{
		OrganizationID: orgID,
		Name:           "Jira Integration",
		Provider:       ProviderJira,
		EndpointURL:    "https://company.atlassian.net/rest/api/3/issue",
		Secret:         initialSecret,
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	t.Run("rotate secret updates ciphertext and decryption returns new secret", func(t *testing.T) {
		newSecret := "rotated-jira-api-token-999"
		err := mgr.RotateSecret(ctx, conn.ID, "admin", newSecret)
		require.NoError(t, err)

		decrypted, err := mgr.GetDecryptedSecretForAdapter(ctx, conn.ID)
		require.NoError(t, err)
		assert.Equal(t, newSecret, decrypted)
	})

	t.Run("disabling connection blocks adapter retrieval", func(t *testing.T) {
		err := mgr.DisableConnection(ctx, conn.ID, "admin")
		require.NoError(t, err)

		_, err = mgr.GetDecryptedSecretForAdapter(ctx, conn.ID)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionDisabled)
	})

	t.Run("enabling connection restores adapter retrieval", func(t *testing.T) {
		err := mgr.EnableConnection(ctx, conn.ID, "admin")
		require.NoError(t, err)

		decrypted, err := mgr.GetDecryptedSecretForAdapter(ctx, conn.ID)
		require.NoError(t, err)
		assert.NotEmpty(t, decrypted)
	})

	t.Run("audit logs record changes without leaking secrets", func(t *testing.T) {
		logs := mgr.GetAuditLogs(conn.ID)
		require.GreaterOrEqual(t, len(logs), 4)

		for _, l := range logs {
			assert.NotContains(t, l.Details, initialSecret)
			assert.NotContains(t, l.Details, "rotated-jira-api-token-999")
		}
	})
}
