package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	ActionJiraCreateIssue = "CREATE_ISSUE"
	ActionJiraSyncStatus  = "SYNC_STATUS"
)

var (
	ErrMissingJiraProjectKey = errors.New("jira: project_key must be configured")
	ErrJiraIssueAlreadyLinked = errors.New("jira: finding already has an active linked Jira issue")
	ErrJiraLinkNotFound      = errors.New("jira: linked issue record not found")
)

// JiraIssueLink tracks persistent bidirectional binding between a Kelvin finding and external Jira issue.
type JiraIssueLink struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	WorkspaceID    *uuid.UUID `json:"workspace_id,omitempty"`
	ConnectionID   uuid.UUID `json:"connection_id"`
	FindingID      uuid.UUID `json:"finding_id"`
	RemediationID  *uuid.UUID `json:"remediation_id,omitempty"`
	JiraIssueID    string    `json:"jira_issue_id"`
	JiraIssueKey   string    `json:"jira_issue_key"` // e.g. SEC-101
	JiraProjectKey string    `json:"jira_project_key"`
	JiraIssueURL   string    `json:"jira_issue_url"`
	SyncStatus     string    `json:"sync_status"`
	LastSyncedAt   time.Time `json:"last_synced_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// JiraAdapter implements IntegrationAdapter for Jira Cloud and Server REST APIs.
type JiraAdapter struct {
	client HTTPClient
}

func NewJiraAdapter(client HTTPClient) *JiraAdapter {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &JiraAdapter{client: client}
}

func (a *JiraAdapter) Provider() ProviderType {
	return ProviderJira
}

func (a *JiraAdapter) Version() string {
	return "1.0.0"
}

func (a *JiraAdapter) Capabilities() []AdapterCapability {
	return []AdapterCapability{CapabilityTicketSync}
}

func (a *JiraAdapter) ValidateConfig(_ context.Context, config map[string]any) error {
	if config == nil {
		return errors.New("jira: configuration cannot be empty")
	}
	projectKey, ok := config["project_key"].(string)
	if !ok || strings.TrimSpace(projectKey) == "" {
		return ErrMissingJiraProjectKey
	}
	return nil
}

func (a *JiraAdapter) CheckHealth(ctx context.Context, conn *IntegrationConnection, decryptedSecret string) (*HealthStatus, error) {
	healthURL := fmt.Sprintf("%s/rest/api/2/myself", strings.TrimRight(conn.EndpointURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+decryptedSecret)

	start := time.Now()
	resp, err := a.client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return &HealthStatus{
			State:     HealthUnreachable,
			LatencyMs: latency,
			Message:   err.Error(),
			CheckedAt: time.Now().UTC(),
		}, ErrProviderUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &HealthStatus{
			State:     HealthUnreachable,
			LatencyMs: latency,
			Message:   fmt.Sprintf("Auth failed: HTTP %d", resp.StatusCode),
			CheckedAt: time.Now().UTC(),
		}, ErrProviderAuthFailed
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &HealthStatus{
			State:     HealthHealthy,
			LatencyMs: latency,
			Message:   "Authenticated successfully with Jira API",
			CheckedAt: time.Now().UTC(),
		}, nil
	}

	return &HealthStatus{
		State:     HealthDegraded,
		LatencyMs: latency,
		Message:   fmt.Sprintf("Unexpected status: HTTP %d", resp.StatusCode),
		CheckedAt: time.Now().UTC(),
	}, nil
}

func (a *JiraAdapter) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	if execCtx.Action == "" {
		execCtx.Action = ActionJiraCreateIssue
	}

	switch execCtx.Action {
	case ActionJiraCreateIssue:
		return a.executeCreateIssue(ctx, execCtx)
	default:
		return nil, fmt.Errorf("jira: unsupported action '%s'", execCtx.Action)
	}
}

func (a *JiraAdapter) executeCreateIssue(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	projectKey, _ := execCtx.Config["project_key"].(string)
	if projectKey == "" {
		projectKey = "SEC"
	}
	issueType, _ := execCtx.Config["issue_type"].(string)
	if issueType == "" {
		issueType = "Bug"
	}

	title, _ := execCtx.Payload["title"].(string)
	description, _ := execCtx.Payload["description"].(string)
	severity, _ := execCtx.Payload["severity"].(string)

	jiraPriority := SeverityToJiraPriority(severity)

	// Clean/sanitize description to prevent raw credentials from being exported
	sanitizedDesc := sanitizeForJira(description)

	jiraPayload := map[string]any{
		"fields": map[string]any{
			"project": map[string]string{
				"key": projectKey,
			},
			"summary":     title,
			"description": sanitizedDesc,
			"issuetype": map[string]string{
				"name": issueType,
			},
			"priority": map[string]string{
				"name": jiraPriority,
			},
			"labels": []string{"kelvin-vulnerability", strings.ToLower(fmt.Sprintf("severity-%s", severity))},
		},
	}

	bodyBytes, err := json.Marshal(jiraPayload)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/rest/api/2/issue", strings.TrimRight(execCtx.EndpointURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+execCtx.DecryptedSecret)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, ErrProviderRateLimited
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, ErrProviderAuthFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: HTTP %d response: %s", ErrProviderUnavailable, resp.StatusCode, string(snippet))
	}

	var jiraResp struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jiraResp); err != nil {
		return nil, fmt.Errorf("jira: failed to decode response: %w", err)
	}

	browseURL := fmt.Sprintf("%s/browse/%s", strings.TrimRight(execCtx.EndpointURL, "/"), jiraResp.Key)

	return &ExecutionResult{
		Success:     true,
		ExternalID:  jiraResp.Key,
		ExternalURL: browseURL,
		ResponseData: map[string]any{
			"jira_id":  jiraResp.ID,
			"jira_key": jiraResp.Key,
		},
	}, nil
}

// SeverityToJiraPriority maps Kelvin severity bands to Jira standard priority levels.
func SeverityToJiraPriority(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "Highest"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	case "INFO":
		return "Lowest"
	default:
		return "Medium"
	}
}

func sanitizeForJira(desc string) string {
	// Strip known token patterns
	sanitized := desc
	for _, maskTarget := range []string{"klv_live_", "whsec_", "Bearer "} {
		if strings.Contains(sanitized, maskTarget) {
			sanitized = strings.ReplaceAll(sanitized, maskTarget, "[REDACTED_SECRET]")
		}
	}
	return sanitized
}

// JiraService coordinates finding export and idempotent issue linkage.
type JiraService struct {
	mu         sync.RWMutex
	connMgr    *ConnectionManager
	adapter    *JiraAdapter
	issueLinks map[string]*JiraIssueLink // key: orgID:connID:findingID
}

func NewJiraService(connMgr *ConnectionManager, adapter *JiraAdapter) *JiraService {
	return &JiraService{
		connMgr:    connMgr,
		adapter:    adapter,
		issueLinks: make(map[string]*JiraIssueLink),
	}
}

type FindingExportRequest struct {
	OrganizationID uuid.UUID
	WorkspaceID    *uuid.UUID
	ConnectionID   uuid.UUID
	FindingID      uuid.UUID
	RemediationID  *uuid.UUID
	Title          string
	Description    string
	Severity       string
}

// ExportFindingToJira idempotently creates or retrieves the linked Jira issue.
func (s *JiraService) ExportFindingToJira(ctx context.Context, req FindingExportRequest) (*JiraIssueLink, error) {
	key := fmt.Sprintf("%s:%s:%s", req.OrganizationID, req.ConnectionID, req.FindingID)

	s.mu.RLock()
	existing, alreadyLinked := s.issueLinks[key]
	s.mu.RUnlock()

	// Idempotency check: if already linked, return existing ticket to prevent duplicates!
	if alreadyLinked {
		return existing, nil
	}

	secret, err := s.connMgr.GetDecryptedSecretForAdapter(ctx, req.ConnectionID)
	if err != nil {
		return nil, fmt.Errorf("jira: failed to get connection secret: %w", err)
	}

	s.connMgr.mu.RLock()
	conn := s.connMgr.connections[req.ConnectionID]
	s.connMgr.mu.RUnlock()

	if conn == nil {
		return nil, ErrConnectionNotFound
	}

	execCtx := ExecutionContext{
		OrganizationID:  req.OrganizationID,
		WorkspaceID:     req.WorkspaceID,
		ConnectionID:    req.ConnectionID,
		Provider:        ProviderJira,
		Action:          ActionJiraCreateIssue,
		Payload: map[string]any{
			"title":       req.Title,
			"description": req.Description,
			"severity":    req.Severity,
		},
		DecryptedSecret: secret,
		EndpointURL:     conn.EndpointURL,
		Config:          conn.Config,
	}

	res, err := s.adapter.Execute(ctx, execCtx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	jiraID, _ := res.ResponseData["jira_id"].(string)

	link := &JiraIssueLink{
		ID:             uuid.New(),
		OrganizationID: req.OrganizationID,
		WorkspaceID:    req.WorkspaceID,
		ConnectionID:   req.ConnectionID,
		FindingID:      req.FindingID,
		RemediationID:  req.RemediationID,
		JiraIssueID:    jiraID,
		JiraIssueKey:   res.ExternalID,
		JiraProjectKey: conn.Config["project_key"].(string),
		JiraIssueURL:   res.ExternalURL,
		SyncStatus:     "SYNCED",
		LastSyncedAt:   now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	s.mu.Lock()
	s.issueLinks[key] = link
	s.mu.Unlock()

	return link, nil
}

func (s *JiraService) GetLinkedIssue(orgID, connID, findingID uuid.UUID) (*JiraIssueLink, error) {
	key := fmt.Sprintf("%s:%s:%s", orgID, connID, findingID)
	s.mu.RLock()
	defer s.mu.RUnlock()

	link, exists := s.issueLinks[key]
	if !exists {
		return nil, ErrJiraLinkNotFound
	}
	return link, nil
}
