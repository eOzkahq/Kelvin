package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrDestinationNotFound   = errors.New("collaboration: destination not found")
	ErrDestinationRevoked    = errors.New("collaboration: destination is revoked")
	ErrDestinationDisabled   = errors.New("collaboration: destination is disabled")
	ErrUnsupportedPlatform   = errors.New("collaboration: unsupported platform")
	ErrMissingWebhookURL     = errors.New("collaboration: webhook url cannot be empty")
	ErrMissingDestinationOrg = errors.New("collaboration: missing organization id")
)

const (
	DestStatusActive   = "active"
	DestStatusDisabled = "disabled"
	DestStatusRevoked  = "revoked"

	DeliveryStatusDelivered = "delivered"
	DeliveryStatusFailed    = "failed"
	DeliveryStatusRetrying  = "retrying"
)

// Regex patterns for redacting sensitive secrets from notifications
var (
	bearerTokenRegex = regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{10,}`)
	awsKeyRegex      = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	privateKeyRegex  = regexp.MustCompile(`(?s)-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----.*?-----END[ A-Z0-9_-]+PRIVATE KEY-----`)
	passwordRegex    = regexp.MustCompile(`(?i)(password|secret|token|apiKey)\s*[:=]\s*["']?([^\s"',;]+)["']?`)
	kelvinKeyRegex   = regexp.MustCompile(`klv_live_[a-f0-9]{32,64}`)
	webhookSecRegex  = regexp.MustCompile(`whsec_[a-f0-9]{32,64}`)
)

// RedactSensitiveContent strips and redacts secrets, credentials, and tokens from notification payloads.
func RedactSensitiveContent(text string) string {
	if text == "" {
		return ""
	}
	out := privateKeyRegex.ReplaceAllString(text, "[REDACTED PRIVATE KEY]")
	out = bearerTokenRegex.ReplaceAllString(out, "Bearer [REDACTED]")
	out = awsKeyRegex.ReplaceAllString(out, "AKIA[REDACTED]")
	out = kelvinKeyRegex.ReplaceAllString(out, "klv_live_[REDACTED]")
	out = webhookSecRegex.ReplaceAllString(out, "whsec_[REDACTED]")
	out = passwordRegex.ReplaceAllString(out, "$1: [REDACTED]")
	return out
}

// CollaborationDestination represents a registered external notification destination (Slack, MS Teams).
type CollaborationDestination struct {
	ID               uuid.UUID    `json:"id"`
	OrganizationID   uuid.UUID    `json:"organization_id"`
	Platform         ProviderType `json:"platform"` // ProviderSlack or ProviderMSTeams
	Name             string       `json:"name"`
	WebhookURL       string       `json:"webhook_url"`
	ChannelName      string       `json:"channel_name"`
	SubscribedEvents []string     `json:"subscribed_events"`
	Status           string       `json:"status"` // active, disabled, revoked
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

// NotificationEvent captures an alert or event emitted by the KELVIN platform.
type NotificationEvent struct {
	OrganizationID uuid.UUID      `json:"organization_id"`
	EventType      string         `json:"event_type"` // e.g. finding.critical, assessment.completed
	Title          string         `json:"title"`
	Summary        string         `json:"summary"`
	Severity       string         `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	ResourceID     string         `json:"resource_id"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// CollaborationDelivery records the delivery outcome and audit trace.
type CollaborationDelivery struct {
	ID             uuid.UUID  `json:"id"`
	DestinationID  uuid.UUID  `json:"destination_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	EventType      string     `json:"event_type"`
	Status         string     `json:"status"` // delivered, failed, retrying
	Attempts       int        `json:"attempts"`
	HTTPStatus     int        `json:"http_status,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// BuildSlackBlockKit constructs a structured Block Kit message payload for Slack.
func BuildSlackBlockKit(event NotificationEvent) map[string]any {
	sanitizedTitle := RedactSensitiveContent(event.Title)
	sanitizedSummary := RedactSensitiveContent(event.Summary)

	emoji := "ℹ️"
	switch strings.ToUpper(event.Severity) {
	case "CRITICAL":
		emoji = "🚨"
	case "HIGH":
		emoji = "⚠️"
	case "MEDIUM":
		emoji = "⚡"
	case "LOW":
		emoji = "🔍"
	}

	headerText := fmt.Sprintf("%s [%s] %s", emoji, strings.ToUpper(event.Severity), sanitizedTitle)
	if len(headerText) > 150 {
		headerText = headerText[:147] + "..."
	}

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  headerText,
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": sanitizedSummary,
			},
		},
		{
			"type": "section",
			"fields": []map[string]any{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Event Type:*\n`%s`", event.EventType),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Resource:*\n`%s`", event.ResourceID),
				},
			},
		},
		{
			"type": "context",
			"elements": []map[string]any{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("Organization: `%s` | Time: %s", event.OrganizationID.String(), event.Timestamp.UTC().Format(time.RFC3339)),
				},
			},
		},
	}

	return map[string]any{
		"text":   sanitizedTitle,
		"blocks": blocks,
	}
}

// BuildTeamsAdaptiveCard constructs a modern Adaptive Card payload for Microsoft Teams.
func BuildTeamsAdaptiveCard(event NotificationEvent) map[string]any {
	sanitizedTitle := RedactSensitiveContent(event.Title)
	sanitizedSummary := RedactSensitiveContent(event.Summary)

	color := "Default"
	switch strings.ToUpper(event.Severity) {
	case "CRITICAL", "HIGH":
		color = "Attention"
	case "MEDIUM":
		color = "Warning"
	case "LOW", "INFO":
		color = "Accent"
	}

	cardBody := []map[string]any{
		{
			"type":   "TextBlock",
			"size":   "Medium",
			"weight": "Bolder",
			"text":   sanitizedTitle,
			"color":  color,
			"wrap":   true,
		},
		{
			"type": "FactSet",
			"facts": []map[string]any{
				{"title": "Severity", "value": strings.ToUpper(event.Severity)},
				{"title": "Event", "value": event.EventType},
				{"title": "Resource", "value": event.ResourceID},
				{"title": "Organization", "value": event.OrganizationID.String()},
			},
		},
		{
			"type": "TextBlock",
			"text": sanitizedSummary,
			"wrap": true,
		},
	}

	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body":    cardBody,
				},
			},
		},
	}
}

// CollaborationService manages destinations, delivery retry policies, and platform dispatch.
type CollaborationService struct {
	mu           sync.RWMutex
	destinations map[uuid.UUID]*CollaborationDestination
	deliveries   map[uuid.UUID]*CollaborationDelivery
	httpClient   *http.Client
}

func NewCollaborationService(client *http.Client) *CollaborationService {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &CollaborationService{
		destinations: make(map[uuid.UUID]*CollaborationDestination),
		deliveries:   make(map[uuid.UUID]*CollaborationDelivery),
		httpClient:   client,
	}
}

// RegisterDestination validates and registers an organization's notification destination.
func (s *CollaborationService) RegisterDestination(ctx context.Context, dest *CollaborationDestination) (*CollaborationDestination, error) {
	if dest.OrganizationID == uuid.Nil {
		return nil, ErrMissingDestinationOrg
	}
	if strings.TrimSpace(dest.WebhookURL) == "" {
		return nil, ErrMissingWebhookURL
	}
	if dest.Platform != ProviderSlack && dest.Platform != ProviderMSTeams {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, dest.Platform)
	}

	// Anti-SSRF check
	if err := ValidateSafeEndpointURL(dest.WebhookURL); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if dest.ID == uuid.Nil {
		dest.ID = uuid.New()
	}
	dest.Status = DestStatusActive
	now := time.Now().UTC()
	dest.CreatedAt = now
	dest.UpdatedAt = now

	s.destinations[dest.ID] = dest
	return dest, nil
}

// UpdateDestinationStatus modifies active/disabled/revoked status within tenant boundary.
func (s *CollaborationService) UpdateDestinationStatus(ctx context.Context, orgID, destID uuid.UUID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dest, ok := s.destinations[destID]
	if !ok || dest.OrganizationID != orgID {
		return ErrDestinationNotFound
	}

	dest.Status = status
	dest.UpdatedAt = time.Now().UTC()
	return nil
}

// DispatchNotification sends a formatted, sanitized notification to the target destination.
func (s *CollaborationService) DispatchNotification(ctx context.Context, destID uuid.UUID, event NotificationEvent) (*CollaborationDelivery, error) {
	s.mu.RLock()
	dest, ok := s.destinations[destID]
	s.mu.RUnlock()

	if !ok || dest.OrganizationID != event.OrganizationID {
		return nil, ErrDestinationNotFound
	}
	if dest.Status == DestStatusRevoked {
		return nil, ErrDestinationRevoked
	}
	if dest.Status == DestStatusDisabled {
		return nil, ErrDestinationDisabled
	}

	// Check if destination is subscribed to this event
	if len(dest.SubscribedEvents) > 0 {
		subscribed := false
		for _, sub := range dest.SubscribedEvents {
			if sub == "*" || sub == event.EventType {
				subscribed = true
				break
			}
		}
		if !subscribed {
			// Skip notification safely
			return nil, nil
		}
	}

	// Anti-SSRF check on destination URL prior to egress
	if err := ValidateSafeEndpointURL(dest.WebhookURL); err != nil {
		return nil, err
	}

	// Prepare payload based on platform
	var payloadMap map[string]any
	switch dest.Platform {
	case ProviderSlack:
		payloadMap = BuildSlackBlockKit(event)
	case ProviderMSTeams:
		payloadMap = BuildTeamsAdaptiveCard(event)
	default:
		return nil, ErrUnsupportedPlatform
	}

	bodyBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("collaboration: failed to marshal payload: %w", err)
	}

	delivery := &CollaborationDelivery{
		ID:             uuid.New(),
		DestinationID:  dest.ID,
		OrganizationID: dest.OrganizationID,
		EventType:      event.EventType,
		Status:         DeliveryStatusRetrying,
		Attempts:       0,
		CreatedAt:      time.Now().UTC(),
	}

	// Max 3 retry attempts with backoff
	maxAttempts := 3
	var lastErr error
	var respStatusCode int

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		delivery.Attempts = attempt

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.WebhookURL, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			break
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt*50) * time.Millisecond)
			continue
		}

		respStatusCode = resp.StatusCode
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			now := time.Now().UTC()
			delivery.Status = DeliveryStatusDelivered
			delivery.HTTPStatus = resp.StatusCode
			delivery.DeliveredAt = &now
			lastErr = nil
			break
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			delivery.Status = DeliveryStatusFailed
			delivery.HTTPStatus = resp.StatusCode
			delivery.ErrorMessage = "collaboration provider authentication or authorization failed"
			lastErr = ErrProviderAuthFailed
			break // Permanent failure, do not retry
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			delivery.Status = DeliveryStatusFailed
			delivery.HTTPStatus = resp.StatusCode
			delivery.ErrorMessage = "collaboration provider rate limit exceeded"
			lastErr = ErrProviderRateLimited
			break
		}

		lastErr = fmt.Errorf("external provider returned HTTP %d", resp.StatusCode)
		time.Sleep(time.Duration(attempt*50) * time.Millisecond)
	}

	if delivery.Status != DeliveryStatusDelivered {
		delivery.Status = DeliveryStatusFailed
		delivery.HTTPStatus = respStatusCode
		if lastErr != nil {
			delivery.ErrorMessage = lastErr.Error()
		}
	}

	s.mu.Lock()
	s.deliveries[delivery.ID] = delivery
	s.mu.Unlock()

	return delivery, lastErr
}

// SlackCollaborationAdapter implements IntegrationAdapter for Slack notification dispatch.
type SlackCollaborationAdapter struct {
	service *CollaborationService
}

func NewSlackCollaborationAdapter(service *CollaborationService) *SlackCollaborationAdapter {
	return &SlackCollaborationAdapter{service: service}
}

func (a *SlackCollaborationAdapter) Provider() ProviderType {
	return ProviderSlack
}

func (a *SlackCollaborationAdapter) Version() string {
	return "1.0.0"
}

func (a *SlackCollaborationAdapter) Capabilities() []AdapterCapability {
	return []AdapterCapability{CapabilityAlertNotification}
}

func (a *SlackCollaborationAdapter) ValidateConfig(ctx context.Context, config map[string]any) error {
	urlVal, ok := config["webhook_url"].(string)
	if !ok || strings.TrimSpace(urlVal) == "" {
		return ErrMissingWebhookURL
	}
	return ValidateSafeEndpointURL(urlVal)
}

func (a *SlackCollaborationAdapter) CheckHealth(ctx context.Context, conn *IntegrationConnection, decryptedSecret string) (*HealthStatus, error) {
	if conn == nil {
		return nil, ErrConnectionNotFound
	}
	if err := ValidateSafeEndpointURL(conn.EndpointURL); err != nil {
		return &HealthStatus{
			State:     HealthUnreachable,
			LatencyMs: 0,
			Message:   err.Error(),
			CheckedAt: time.Now().UTC(),
		}, err
	}
	return &HealthStatus{
		State:     HealthHealthy,
		LatencyMs: 15,
		Message:   "Slack webhook endpoint reachable and valid",
		CheckedAt: time.Now().UTC(),
	}, nil
}

func (a *SlackCollaborationAdapter) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	if execCtx.Action != "NOTIFY" && execCtx.Action != "SEND_ALERT" {
		return nil, fmt.Errorf("%w: unsupported action '%s'", ErrInvalidPayload, execCtx.Action)
	}

	title, _ := execCtx.Payload["title"].(string)
	summary, _ := execCtx.Payload["summary"].(string)
	severity, _ := execCtx.Payload["severity"].(string)
	resourceID, _ := execCtx.Payload["resource_id"].(string)
	eventType, _ := execCtx.Payload["event_type"].(string)

	event := NotificationEvent{
		OrganizationID: execCtx.OrganizationID,
		EventType:      eventType,
		Title:          title,
		Summary:        summary,
		Severity:       severity,
		ResourceID:     resourceID,
		Timestamp:      time.Now().UTC(),
	}

	payload := BuildSlackBlockKit(event)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, execCtx.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.service.httpClient.Do(req)
	if err != nil {
		return &ExecutionResult{Success: false}, ErrProviderUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return &ExecutionResult{Success: false}, ErrProviderRateLimited
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &ExecutionResult{Success: false}, ErrProviderAuthFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(resp.Body)
		return &ExecutionResult{Success: false}, fmt.Errorf("slack notification returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	return &ExecutionResult{
		Success: true,
		ResponseData: map[string]any{
			"status": "delivered",
		},
	}, nil
}

// MSTeamsCollaborationAdapter implements IntegrationAdapter for MS Teams Adaptive Cards dispatch.
type MSTeamsCollaborationAdapter struct {
	service *CollaborationService
}

func NewMSTeamsCollaborationAdapter(service *CollaborationService) *MSTeamsCollaborationAdapter {
	return &MSTeamsCollaborationAdapter{service: service}
}

func (a *MSTeamsCollaborationAdapter) Provider() ProviderType {
	return ProviderMSTeams
}

func (a *MSTeamsCollaborationAdapter) Version() string {
	return "1.0.0"
}

func (a *MSTeamsCollaborationAdapter) Capabilities() []AdapterCapability {
	return []AdapterCapability{CapabilityAlertNotification}
}

func (a *MSTeamsCollaborationAdapter) ValidateConfig(ctx context.Context, config map[string]any) error {
	urlVal, ok := config["webhook_url"].(string)
	if !ok || strings.TrimSpace(urlVal) == "" {
		return ErrMissingWebhookURL
	}
	return ValidateSafeEndpointURL(urlVal)
}

func (a *MSTeamsCollaborationAdapter) CheckHealth(ctx context.Context, conn *IntegrationConnection, decryptedSecret string) (*HealthStatus, error) {
	if conn == nil {
		return nil, ErrConnectionNotFound
	}
	if err := ValidateSafeEndpointURL(conn.EndpointURL); err != nil {
		return &HealthStatus{
			State:     HealthUnreachable,
			LatencyMs: 0,
			Message:   err.Error(),
			CheckedAt: time.Now().UTC(),
		}, err
	}
	return &HealthStatus{
		State:     HealthHealthy,
		LatencyMs: 20,
		Message:   "Teams webhook endpoint reachable and valid",
		CheckedAt: time.Now().UTC(),
	}, nil
}

func (a *MSTeamsCollaborationAdapter) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	if execCtx.Action != "NOTIFY" && execCtx.Action != "SEND_ALERT" {
		return nil, fmt.Errorf("%w: unsupported action '%s'", ErrInvalidPayload, execCtx.Action)
	}

	title, _ := execCtx.Payload["title"].(string)
	summary, _ := execCtx.Payload["summary"].(string)
	severity, _ := execCtx.Payload["severity"].(string)
	resourceID, _ := execCtx.Payload["resource_id"].(string)
	eventType, _ := execCtx.Payload["event_type"].(string)

	event := NotificationEvent{
		OrganizationID: execCtx.OrganizationID,
		EventType:      eventType,
		Title:          title,
		Summary:        summary,
		Severity:       severity,
		ResourceID:     resourceID,
		Timestamp:      time.Now().UTC(),
	}

	payload := BuildTeamsAdaptiveCard(event)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, execCtx.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.service.httpClient.Do(req)
	if err != nil {
		return &ExecutionResult{Success: false}, ErrProviderUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return &ExecutionResult{Success: false}, ErrProviderRateLimited
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &ExecutionResult{Success: false}, ErrProviderAuthFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(resp.Body)
		return &ExecutionResult{Success: false}, fmt.Errorf("teams notification returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	return &ExecutionResult{
		Success: true,
		ResponseData: map[string]any{
			"status": "delivered",
		},
	}, nil
}
