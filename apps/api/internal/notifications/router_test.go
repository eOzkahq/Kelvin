package notifications

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHandler struct {
	channel string
	fail    bool
}

func (m *mockHandler) Channel() string {
	return m.channel
}

func (m *mockHandler) Deliver(ctx context.Context, notif NotificationMessage) error {
	if m.fail {
		return errors.New("external gateway timeout (HTTP 504)")
	}
	return nil
}

func TestNotificationRouter_Redaction(t *testing.T) {
	router := NewRouter()
	orgID := uuid.New()

	event := Event{
		OrganizationID: orgID,
		EventType:      "findings.critical",
		Severity:       "CRITICAL",
		ResourceID:     "s3://secure-data",
		Title:          "Leak Authorization: Bearer secret-auth-token-12345",
		Message:        "Found compromised password=SuperSecretPassword! in AWS key AKIAIOSFODNN7EXAMPLE",
		Timestamp:      time.Now().UTC(),
	}

	logs := router.Dispatch(context.Background(), event)
	require.NotEmpty(t, logs)

	for _, logEntry := range logs {
		assert.NotContains(t, logEntry.Title, "secret-auth-token-12345")
		assert.NotContains(t, logEntry.SanitizedContent, "SuperSecretPassword!")
		assert.NotContains(t, logEntry.SanitizedContent, "AKIAIOSFODNN7EXAMPLE")
	}
}

func TestNotificationRouter_Deduplication(t *testing.T) {
	router := NewRouter()
	orgID := uuid.New()

	event := Event{
		OrganizationID: orgID,
		EventType:      "findings.critical",
		Severity:       "CRITICAL",
		ResourceID:     "asset-001",
		Title:          "SQL Injection Alert",
		Message:        "Detected pattern on endpoint",
		Timestamp:      time.Now().UTC(),
	}

	// First dispatch
	firstLogs := router.Dispatch(context.Background(), event)
	require.NotEmpty(t, firstLogs)
	assert.Equal(t, StatusDelivered, firstLogs[0].Status)

	// Immediate repeat of identical event -> must be suppressed
	secondLogs := router.Dispatch(context.Background(), event)
	require.NotEmpty(t, secondLogs)
	for _, l := range secondLogs {
		assert.Equal(t, StatusSuppressed, l.Status)
		assert.Equal(t, SuppressionDuplicate, l.SuppressionReason)
	}
}

func TestNotificationRouter_MandatoryOptOutPrevention(t *testing.T) {
	router := NewRouter()
	orgID := uuid.New()

	router.SetOrgPreferences(OrgPreferences{
		OrganizationID:  orgID,
		AllowedChannels: []string{ChannelInApp, ChannelEmail},
		MandatoryEvents: []string{"findings.critical", "policy.violation"},
		ChannelDefaults: map[string]bool{ChannelInApp: true, ChannelEmail: true},
	})

	// User attempting to opt-out of mandatory event
	err := router.SetUserPreferences(UserPreferences{
		OrganizationID: orgID,
		UserID:         "user-admin-1",
		EventOverrides: map[string]bool{
			"findings.critical": false,
		},
	})
	assert.ErrorIs(t, err, ErrMandatoryEventOptOut)

	// Opting out of non-mandatory event is permitted
	err = router.SetUserPreferences(UserPreferences{
		OrganizationID: orgID,
		UserID:         "user-admin-1",
		EventOverrides: map[string]bool{
			"assessment.scheduled": false,
		},
	})
	assert.NoError(t, err)
}

func TestNotificationRouter_OrgAllowedChannels(t *testing.T) {
	router := NewRouter()
	orgID := uuid.New()

	// Org disables external webhook & collaboration
	router.SetOrgPreferences(OrgPreferences{
		OrganizationID:  orgID,
		AllowedChannels: []string{ChannelInApp, ChannelEmail},
		MandatoryEvents: []string{"findings.critical"},
		ChannelDefaults: map[string]bool{
			ChannelInApp: true,
			ChannelEmail: true,
		},
	})

	event := Event{
		OrganizationID: orgID,
		EventType:      "findings.critical",
		Severity:       "CRITICAL",
		ResourceID:     "res-1",
		Title:          "Critical Security Alert",
		Message:        "Details",
	}

	logs := router.Dispatch(context.Background(), event)
	require.NotEmpty(t, logs)

	for _, l := range logs {
		if l.Channel == ChannelWebhook || l.Channel == ChannelCollaboration {
			assert.Equal(t, StatusSuppressed, l.Status)
			assert.Equal(t, SuppressionOrgDisabled, l.SuppressionReason)
		} else {
			assert.Equal(t, StatusDelivered, l.Status)
		}
	}
}

func TestNotificationRouter_QuietHours(t *testing.T) {
	router := NewRouter()
	orgID := uuid.New()
	currentHour := time.Now().UTC().Hour()

	// Org configures quiet hours covering current hour
	router.SetOrgPreferences(OrgPreferences{
		OrganizationID:    orgID,
		AllowedChannels:   []string{ChannelInApp},
		MandatoryEvents:   []string{},
		ChannelDefaults:   map[string]bool{ChannelInApp: true},
		QuietHoursEnabled: true,
		QuietHoursStart:   currentHour,
		QuietHoursEnd:     (currentHour + 2) % 24,
	})

	// Non-critical event should be suppressed by quiet hours
	nonCriticalEvent := Event{
		OrganizationID: orgID,
		EventType:      "assessment.completed",
		Severity:       "MEDIUM",
		ResourceID:     "res-medium",
		Title:          "Scan complete",
		Message:        "Finished scanning",
	}
	logs1 := router.Dispatch(context.Background(), nonCriticalEvent)
	require.NotEmpty(t, logs1)
	assert.Equal(t, StatusSuppressed, logs1[0].Status)
	assert.Equal(t, SuppressionQuietHours, logs1[0].SuppressionReason)

	// Critical event bypasses quiet hours
	criticalEvent := Event{
		OrganizationID: orgID,
		EventType:      "findings.critical",
		Severity:       "CRITICAL",
		ResourceID:     "res-crit",
		Title:          "Critical CVE Found",
		Message:        "Urgent fix required",
	}
	logs2 := router.Dispatch(context.Background(), criticalEvent)
	require.NotEmpty(t, logs2)
	assert.Equal(t, StatusDelivered, logs2[0].Status)
}

func TestNotificationRouter_ChannelHandlerFailureGraceful(t *testing.T) {
	router := NewRouter()
	orgID := uuid.New()

	router.RegisterHandler(&mockHandler{
		channel: ChannelEmail,
		fail:    true,
	})

	event := Event{
		OrganizationID: orgID,
		EventType:      "findings.critical",
		Severity:       "CRITICAL",
		ResourceID:     "res-fail",
		Title:          "Critical issue",
		Message:        "Message",
	}

	logs := router.Dispatch(context.Background(), event)
	require.NotEmpty(t, logs)

	for _, l := range logs {
		if l.Channel == ChannelEmail {
			assert.Equal(t, StatusFailed, l.Status)
			assert.Contains(t, l.ErrorMessage, "504")
		}
	}
}
