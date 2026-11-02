package integrations

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJiraAdapter_SeverityMapping(t *testing.T) {
	assert.Equal(t, "Highest", SeverityToJiraPriority("CRITICAL"))
	assert.Equal(t, "High", SeverityToJiraPriority("HIGH"))
	assert.Equal(t, "Medium", SeverityToJiraPriority("MEDIUM"))
	assert.Equal(t, "Low", SeverityToJiraPriority("LOW"))
	assert.Equal(t, "Lowest", SeverityToJiraPriority("INFO"))
	assert.Equal(t, "Medium", SeverityToJiraPriority("UNKNOWN"))
}

func TestJiraAdapter_IssueCreationAndHealth(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockHTTPClient{
		statusCode:   201,
		responseBody: `{"id": "10001", "key": "SEC-402", "self": "https://jira.company.com/rest/api/2/issue/10001"}`,
	}
	adapter := NewJiraAdapter(mockClient)

	orgID := uuid.New()
	conn := &IntegrationConnection{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Provider:       ProviderJira,
		EndpointURL:    "https://jira.company.com",
		Config:         map[string]any{"project_key": "SEC", "issue_type": "Bug"},
	}

	t.Run("health check passes on 200 OK", func(t *testing.T) {
		mockClient.statusCode = 200
		mockClient.responseBody = `{"name": "jira-admin"}`

		health, err := adapter.CheckHealth(ctx, conn, "test-token")
		require.NoError(t, err)
		assert.Equal(t, HealthHealthy, health.State)
	})

	t.Run("issue creation constructs payload and parses response", func(t *testing.T) {
		mockClient.statusCode = 201
		mockClient.responseBody = `{"id": "10001", "key": "SEC-402", "self": "https://jira.company.com/rest/api/2/issue/10001"}`

		execCtx := ExecutionContext{
			OrganizationID:  orgID,
			Provider:        ProviderJira,
			Action:          ActionJiraCreateIssue,
			EndpointURL:     conn.EndpointURL,
			DecryptedSecret: "test-token",
			Config:          conn.Config,
			Payload: map[string]any{
				"title":       "SQL Injection in /api/v1/users",
				"description": "Sensitive query exposed with token klv_live_xyz999",
				"severity":    "CRITICAL",
			},
		}

		res, err := adapter.Execute(ctx, execCtx)
		require.NoError(t, err)
		assert.True(t, res.Success)
		assert.Equal(t, "SEC-402", res.ExternalID)
		assert.Equal(t, "https://jira.company.com/browse/SEC-402", res.ExternalURL)

		// Verify secret token was sanitized from request body
		assert.NotContains(t, string(mockClient.requestBody), "klv_live_xyz999")
		assert.Contains(t, string(mockClient.requestBody), "[REDACTED_SECRET]")
	})
}

func TestJiraService_IdempotencyAndLinking(t *testing.T) {
	ctx := context.Background()
	connMgr := NewConnectionManager(nil, "kek-v1")
	mockClient := &mockHTTPClient{
		statusCode:   201,
		responseBody: `{"id": "10002", "key": "SEC-505", "self": "https://jira.company.com/rest/api/2/issue/10002"}`,
	}
	adapter := NewJiraAdapter(mockClient)
	jiraService := NewJiraService(connMgr, adapter)

	orgID := uuid.New()
	conn, err := connMgr.CreateConnection(ctx, CreateConnectionRequest{
		OrganizationID: orgID,
		Name:           "Jira Prod",
		Provider:       ProviderJira,
		EndpointURL:    "https://jira.company.com",
		Secret:         "api-token-secret",
		Config:         map[string]any{"project_key": "SEC"},
		CreatorID:      "admin",
	})
	require.NoError(t, err)

	findingID := uuid.New()
	req := FindingExportRequest{
		OrganizationID: orgID,
		ConnectionID:   conn.ID,
		FindingID:      findingID,
		Title:          "XSS in dashboard",
		Description:    "Payload reflects in query string",
		Severity:       "HIGH",
	}

	// First export creates issue
	link1, err := jiraService.ExportFindingToJira(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "SEC-505", link1.JiraIssueKey)

	// Second export for same finding returns existing link WITHOUT duplicate HTTP request!
	mockClient.statusCode = 500 // Change to 500 to prove HTTP request is NOT called
	link2, err := jiraService.ExportFindingToJira(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, link1.ID, link2.ID)
	assert.Equal(t, "SEC-505", link2.JiraIssueKey)
}

func TestJiraAdapter_ErrorHandling(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockHTTPClient{}
	adapter := NewJiraAdapter(mockClient)

	execCtx := ExecutionContext{
		OrganizationID:  uuid.New(),
		Provider:        ProviderJira,
		Action:          ActionJiraCreateIssue,
		EndpointURL:     "https://jira.company.com",
		DecryptedSecret: "secret",
		Config:          map[string]any{"project_key": "SEC"},
		Payload:         map[string]any{"title": "Bug", "severity": "LOW"},
	}

	t.Run("rate limit 429 classified correctly", func(t *testing.T) {
		mockClient.statusCode = 429
		_, err := adapter.Execute(ctx, execCtx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderRateLimited)
	})

	t.Run("unauthorized 401 classified correctly", func(t *testing.T) {
		mockClient.statusCode = 401
		_, err := adapter.Execute(ctx, execCtx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderAuthFailed)
	})
}
