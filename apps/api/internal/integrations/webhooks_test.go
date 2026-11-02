package integrations

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhook_SubscriptionCreationAndSecrets(t *testing.T) {
	ctx := context.Background()
	mgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")

	orgID := uuid.New()
	wsID := uuid.New()

	req := CreateSubscriptionRequest{
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Name:           "SecOps Webhook",
		EndpointURL:    "https://api.security.company.com/webhook",
		EventTypes:     []string{EventAssessmentCompleted, EventFindingCreated},
		CreatorID:      "admin-user",
	}

	created, err := mgr.CreateSubscription(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "SecOps Webhook", created.Subscription.Name)
	assert.Equal(t, SubActive, created.Subscription.Status)
	assert.Contains(t, created.RawSecret, "whsec_")
	assert.NotEmpty(t, created.Subscription.EncryptedSigningSecret)

	t.Run("dispatcher can decrypt secret in memory", func(t *testing.T) {
		decrypted, err := mgr.GetDecryptedSecretForDispatcher(ctx, created.Subscription.ID)
		require.NoError(t, err)
		assert.Equal(t, created.RawSecret, decrypted)
	})

	t.Run("json serialization does not leak raw secret or encrypted payload", func(t *testing.T) {
		marshaled, err := json.Marshal(created.Subscription)
		require.NoError(t, err)
		jsonStr := string(marshaled)

		assert.NotContains(t, jsonStr, created.RawSecret)
		assert.NotContains(t, jsonStr, "EncryptedSigningSecret")
		assert.NotContains(t, jsonStr, "encrypted_signing_secret")
	})
}

func TestWebhook_EventCatalogValidation(t *testing.T) {
	ctx := context.Background()
	mgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")
	orgID := uuid.New()

	t.Run("rejects unapproved event type", func(t *testing.T) {
		_, err := mgr.CreateSubscription(ctx, CreateSubscriptionRequest{
			OrganizationID: orgID,
			Name:           "Invalid Event Sub",
			EndpointURL:    "https://api.company.com/webhook",
			EventTypes:     []string{"unapproved.custom.event"},
			CreatorID:      "admin",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidWebhookEvent)
	})

	t.Run("rejects empty event types", func(t *testing.T) {
		_, err := mgr.CreateSubscription(ctx, CreateSubscriptionRequest{
			OrganizationID: orgID,
			Name:           "Empty Events",
			EndpointURL:    "https://api.company.com/webhook",
			EventTypes:     nil,
			CreatorID:      "admin",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoEventsSelected)
	})
}

func TestWebhook_AntiSSRFAndHTTPS(t *testing.T) {
	ctx := context.Background()
	mgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")
	orgID := uuid.New()

	t.Run("rejects plain http in strict mode", func(t *testing.T) {
		_, err := mgr.CreateSubscription(ctx, CreateSubscriptionRequest{
			OrganizationID: orgID,
			Name:           "Insecure HTTP",
			EndpointURL:    "http://api.company.com/webhook",
			EventTypes:     []string{EventWildcard},
			CreatorID:      "admin",
			AllowHTTP:      false,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHTTPSRequired)
	})

	t.Run("rejects private SSRF target even if https specified", func(t *testing.T) {
		_, err := mgr.CreateSubscription(ctx, CreateSubscriptionRequest{
			OrganizationID: orgID,
			Name:           "Internal Subnet",
			EndpointURL:    "https://10.0.0.5:8443/webhook",
			EventTypes:     []string{EventWildcard},
			CreatorID:      "admin",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSSRFDestinationBlocked)
	})
}

func TestWebhook_RotationAndLifecycle(t *testing.T) {
	ctx := context.Background()
	mgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")

	orgID := uuid.New()
	wsID := uuid.New()

	created, err := mgr.CreateSubscription(ctx, CreateSubscriptionRequest{
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Name:           "Rotatable Sub",
		EndpointURL:    "https://api.company.com/webhook",
		EventTypes:     []string{EventAssessmentCompleted},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	t.Run("rotate signing secret updates secret", func(t *testing.T) {
		newSecret, err := mgr.RotateSigningSecret(ctx, created.Subscription.ID, "admin")
		require.NoError(t, err)
		assert.NotEqual(t, created.RawSecret, newSecret)
		assert.Contains(t, newSecret, "whsec_")

		decrypted, err := mgr.GetDecryptedSecretForDispatcher(ctx, created.Subscription.ID)
		require.NoError(t, err)
		assert.Equal(t, newSecret, decrypted)
	})

	t.Run("disabling subscription prevents secret retrieval", func(t *testing.T) {
		err := mgr.DisableSubscription(ctx, created.Subscription.ID, "admin")
		require.NoError(t, err)

		_, err = mgr.GetDecryptedSecretForDispatcher(ctx, created.Subscription.ID)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSubscriptionDisabled)
	})

	t.Run("enabling subscription restores retrieval and matching", func(t *testing.T) {
		err := mgr.EnableSubscription(ctx, created.Subscription.ID, "admin")
		require.NoError(t, err)

		matches := mgr.FindMatchingSubscriptions(orgID, &wsID, EventAssessmentCompleted)
		require.Len(t, matches, 1)
		assert.Equal(t, created.Subscription.ID, matches[0].ID)

		// Unsubscribed event does not match
		matchesOther := mgr.FindMatchingSubscriptions(orgID, &wsID, EventRiskExceptionApproved)
		assert.Empty(t, matchesOther)
	})

	t.Run("audit logs record operations without leaking secrets", func(t *testing.T) {
		logs := mgr.GetAuditLogs(created.Subscription.ID)
		require.GreaterOrEqual(t, len(logs), 4)

		for _, l := range logs {
			assert.NotContains(t, l.Details, created.RawSecret)
		}
	})
}
