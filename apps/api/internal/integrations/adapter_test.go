package integrations

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// referenceMockAdapter implements IntegrationAdapter for conformance testing.
type referenceMockAdapter struct {
	provider     ProviderType
	simulatedErr error
}

func newReferenceMockAdapter(provider ProviderType) *referenceMockAdapter {
	return &referenceMockAdapter{provider: provider}
}

func (a *referenceMockAdapter) Provider() ProviderType {
	return a.provider
}

func (a *referenceMockAdapter) Version() string {
	return "1.0.0"
}

func (a *referenceMockAdapter) Capabilities() []AdapterCapability {
	return []AdapterCapability{CapabilityTicketSync, CapabilityAlertNotification}
}

func (a *referenceMockAdapter) ValidateConfig(_ context.Context, config map[string]any) error {
	if config == nil || config["project_key"] == nil {
		return errors.New("missing project_key in config")
	}
	return nil
}

func (a *referenceMockAdapter) CheckHealth(_ context.Context, conn *IntegrationConnection, _ string) (*HealthStatus, error) {
	if a.simulatedErr != nil {
		return &HealthStatus{
			State:     HealthUnreachable,
			Message:   a.simulatedErr.Error(),
			CheckedAt: time.Now().UTC(),
		}, a.simulatedErr
	}

	return &HealthStatus{
		State:     HealthHealthy,
		LatencyMs: 42,
		Message:   "Connected to " + conn.EndpointURL,
		CheckedAt: time.Now().UTC(),
	}, nil
}

func (a *referenceMockAdapter) Execute(_ context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	if a.simulatedErr != nil {
		return nil, a.simulatedErr
	}
	if execCtx.Payload == nil {
		return nil, ErrInvalidPayload
	}

	return &ExecutionResult{
		Success:     true,
		ExternalID:  "ISSUE-789",
		ExternalURL: "https://jira.company.com/browse/ISSUE-789",
		ResponseData: map[string]any{
			"status": "CREATED",
		},
	}, nil
}

func TestAdapterRegistry_RegistrationAndResolution(t *testing.T) {
	registry := NewAdapterRegistry()
	jiraAdapter := newReferenceMockAdapter(ProviderJira)

	t.Run("successful registration and discovery", func(t *testing.T) {
		err := registry.Register(jiraAdapter)
		require.NoError(t, err)

		resolved, err := registry.Get(ProviderJira)
		require.NoError(t, err)
		assert.Equal(t, ProviderJira, resolved.Provider())
		assert.Equal(t, "1.0.0", resolved.Version())
		assert.Contains(t, resolved.Capabilities(), CapabilityTicketSync)
	})

	t.Run("duplicate registration rejected", func(t *testing.T) {
		err := registry.Register(jiraAdapter)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDuplicateAdapter)
	})

	t.Run("unregistered provider returns error", func(t *testing.T) {
		_, err := registry.Get(ProviderSlack)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAdapterNotFound)
	})
}

func TestIntegrationAdapter_Conformance(t *testing.T) {
	ctx := context.Background()
	registry := NewAdapterRegistry()
	mockAdapter := newReferenceMockAdapter(ProviderJira)
	err := registry.Register(mockAdapter)
	require.NoError(t, err)

	orgID := uuid.New()
	wsID := uuid.New()

	conn := &IntegrationConnection{
		ID:             uuid.New(),
		OrganizationID: orgID,
		WorkspaceID:    &wsID,
		Provider:       ProviderJira,
		EndpointURL:    "https://company.atlassian.net",
		Status:         StatusActive,
	}

	t.Run("config validation", func(t *testing.T) {
		err := mockAdapter.ValidateConfig(ctx, map[string]any{"project_key": "SEC"})
		require.NoError(t, err)

		err = mockAdapter.ValidateConfig(ctx, map[string]any{})
		require.Error(t, err)
	})

	t.Run("health check conformance", func(t *testing.T) {
		health, err := mockAdapter.CheckHealth(ctx, conn, "test-secret")
		require.NoError(t, err)
		assert.Equal(t, HealthHealthy, health.State)
		assert.Equal(t, int64(42), health.LatencyMs)
	})

	t.Run("execution conformance and timing", func(t *testing.T) {
		execCtx := ExecutionContext{
			OrganizationID:  orgID,
			WorkspaceID:     &wsID,
			ConnectionID:    conn.ID,
			Provider:        ProviderJira,
			Action:          "CREATE_TICKET",
			Payload:         map[string]any{"summary": "Vulnerability Found"},
			DecryptedSecret: "raw-secret-token",
			EndpointURL:     conn.EndpointURL,
		}

		res, err := registry.Execute(ctx, execCtx)
		require.NoError(t, err)
		assert.True(t, res.Success)
		assert.Equal(t, "ISSUE-789", res.ExternalID)
		assert.NotEmpty(t, res.ExternalURL)
		assert.NotZero(t, res.ExecutedAt)
	})
}

func TestIntegrationAdapter_ErrorClassification(t *testing.T) {
	ctx := context.Background()
	registry := NewAdapterRegistry()
	mockAdapter := newReferenceMockAdapter(ProviderGitHub)
	err := registry.Register(mockAdapter)
	require.NoError(t, err)

	execCtx := ExecutionContext{
		OrganizationID: uuid.New(),
		Provider:       ProviderGitHub,
		Action:         "DISPATCH",
		Payload:        map[string]any{"data": "test"},
	}

	t.Run("rate limit error classification", func(t *testing.T) {
		mockAdapter.simulatedErr = ErrProviderRateLimited
		_, err := registry.Execute(ctx, execCtx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderRateLimited)
	})

	t.Run("auth failed error classification", func(t *testing.T) {
		mockAdapter.simulatedErr = ErrProviderAuthFailed
		_, err := registry.Execute(ctx, execCtx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderAuthFailed)
	})

	t.Run("service unavailable error classification", func(t *testing.T) {
		mockAdapter.simulatedErr = ErrProviderUnavailable
		_, err := registry.Execute(ctx, execCtx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderUnavailable)
	})
}
