package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHTTPClient struct {
	mu           sync.Mutex
	statusCode   int
	responseBody string
	lastRequest  *http.Request
	requestBody  []byte
	networkError error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastRequest = req
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		m.requestBody = body
	}

	if m.networkError != nil {
		return nil, m.networkError
	}

	resp := &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(m.responseBody)),
		Header:     make(http.Header),
	}
	return resp, nil
}

func TestWebhookDispatcher_SuccessfulSignedDelivery(t *testing.T) {
	ctx := context.Background()
	subMgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")
	mockClient := &mockHTTPClient{
		statusCode:   200,
		responseBody: `{"received": true}`,
	}
	dispatcher := NewWebhookDispatcher(subMgr, mockClient)

	orgID := uuid.New()
	createdSub, err := subMgr.CreateSubscription(ctx, CreateSubscriptionRequest{
		OrganizationID: orgID,
		Name:           "Delivery Target",
		EndpointURL:    "https://api.external.com/events",
		EventTypes:     []string{EventFindingCreated},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	eventID := uuid.New()
	payload := map[string]any{
		"finding_id": uuid.New().String(),
		"severity":   "CRITICAL",
		"title":      "Remote Code Execution in Authentication Module",
	}

	record, err := dispatcher.Dispatch(ctx, eventID, createdSub.Subscription, EventFindingCreated, payload)
	require.NoError(t, err)
	assert.Equal(t, StatusDeliverySuccess, record.Status)
	assert.Equal(t, 1, record.Attempts)
	assert.Equal(t, 200, record.LastStatusCode)
	assert.NotNil(t, record.DeliveredAt)

	// Validate headers sent to endpoint
	require.NotNil(t, mockClient.lastRequest)
	assert.Equal(t, eventID.String(), mockClient.lastRequest.Header.Get(HeaderEventID))
	sigHeader := mockClient.lastRequest.Header.Get(HeaderSignature)
	assert.NotEmpty(t, sigHeader)

	// Verify signature using consumer helper
	payloadBytes, _ := json.Marshal(payload)
	valid, err := VerifySignature(createdSub.RawSecret, payloadBytes, sigHeader, 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestWebhookDispatcher_ReplayProtectionAndTamperDefense(t *testing.T) {
	secret := "whsec_test_secret_12345"
	payload := []byte(`{"event":"test"}`)

	t.Run("verifies valid signature within replay tolerance", func(t *testing.T) {
		now := time.Now().UTC().Unix()
		sig := CalculateSignature(secret, now, payload)

		valid, err := VerifySignature(secret, payload, sig, 5*time.Minute)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("rejects expired timestamp beyond replay window", func(t *testing.T) {
		oldTime := time.Now().UTC().Add(-10 * time.Minute).Unix()
		sig := CalculateSignature(secret, oldTime, payload)

		valid, err := VerifySignature(secret, payload, sig, 5*time.Minute)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrReplayWindowExpired)
		assert.False(t, valid)
	})

	t.Run("rejects tampered payload", func(t *testing.T) {
		now := time.Now().UTC().Unix()
		sig := CalculateSignature(secret, now, payload)

		tamperedPayload := []byte(`{"event":"tampered"}`)
		valid, err := VerifySignature(secret, tamperedPayload, sig, 5*time.Minute)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSignatureMismatch)
		assert.False(t, valid)
	})
}

func TestWebhookDispatcher_RetryAndDeadLetter(t *testing.T) {
	ctx := context.Background()
	subMgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")
	mockClient := &mockHTTPClient{
		statusCode:   503,
		responseBody: `{"error": "service unavailable"}`,
	}
	dispatcher := NewWebhookDispatcher(subMgr, mockClient)

	createdSub, err := subMgr.CreateSubscription(ctx, CreateSubscriptionRequest{
		OrganizationID: uuid.New(),
		Name:           "Failing Endpoint",
		EndpointURL:    "https://api.external.com/failing",
		EventTypes:     []string{EventAssessmentFailed},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	payload := map[string]any{"assessment_id": uuid.New().String()}

	// Attempt 1: Fails with 503 -> enters PENDING_RETRY
	record, err := dispatcher.Dispatch(ctx, uuid.New(), createdSub.Subscription, EventAssessmentFailed, payload)
	require.NoError(t, err)
	assert.Equal(t, StatusDeliveryPendingRetry, record.Status)
	assert.Equal(t, 1, record.Attempts)
	assert.NotNil(t, record.NextRetryAt)

	// Simulate failures up to max attempts (5)
	for i := 2; i <= MaxDeliveryAttempts; i++ {
		record.Attempts = i
		dispatcher.handleFailure(record, 503, "Service unavailable", "")
	}

	assert.Equal(t, MaxDeliveryAttempts, record.Attempts)
	assert.Equal(t, StatusDeliveryDeadLetter, record.Status)
	assert.Nil(t, record.NextRetryAt)
}

func TestWebhookDispatcher_Redelivery(t *testing.T) {
	ctx := context.Background()
	subMgr := NewWebhookSubscriptionManager(nil, "wh-kek-v1")
	mockClient := &mockHTTPClient{
		statusCode:   500,
		responseBody: `Internal Error`,
	}
	dispatcher := NewWebhookDispatcher(subMgr, mockClient)

	createdSub, err := subMgr.CreateSubscription(ctx, CreateSubscriptionRequest{
		OrganizationID: uuid.New(),
		Name:           "Flaky Endpoint",
		EndpointURL:    "https://api.external.com/flaky",
		EventTypes:     []string{EventWildcard},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	record, err := dispatcher.Dispatch(ctx, uuid.New(), createdSub.Subscription, EventFindingCreated, map[string]any{"test": true})
	require.NoError(t, err)
	assert.Equal(t, StatusDeliveryPendingRetry, record.Status)

	// Target recovers: mock client now returns 200 OK
	mockClient.statusCode = 200
	mockClient.responseBody = `{"ok": true}`

	redelivered, err := dispatcher.Redeliver(ctx, record.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusDeliverySuccess, redelivered.Status)
	assert.Equal(t, 2, redelivered.Attempts)
	assert.Equal(t, 200, redelivered.LastStatusCode)
}
