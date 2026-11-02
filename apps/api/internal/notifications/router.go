package notifications

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/integrations"
	"github.com/kelvin/kelvin/apps/api/internal/redaction"
)

var (
	ErrOrgNotFound          = errors.New("notifications: organization preferences not found")
	ErrMandatoryEventOptOut = errors.New("notifications: cannot opt out of mandatory enterprise security events")
)

const (
	ChannelInApp         = "in_app"
	ChannelEmail         = "email"
	ChannelWebhook       = "webhook"
	ChannelCollaboration = "collaboration"

	StatusDelivered  = "delivered"
	StatusSuppressed = "suppressed"
	StatusFailed     = "failed"
	StatusQueued     = "queued"

	SuppressionDuplicate    = "DUPLICATE_EVENT"
	SuppressionQuietHours   = "QUIET_HOURS_ACTIVE"
	SuppressionUserDisabled = "USER_OPT_OUT"
	SuppressionOrgDisabled  = "ORG_CHANNEL_DISABLED"
)

// Event describes a business event emitted within the KELVIN platform.
type Event struct {
	OrganizationID uuid.UUID      `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	EventType      string         `json:"event_type"` // e.g., findings.critical, policy.violation
	Severity       string         `json:"severity"`   // CRITICAL, HIGH, MEDIUM, LOW, INFO
	ResourceID     string         `json:"resource_id"`
	Title          string         `json:"title"`
	Message        string         `json:"message"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// NotificationMessage is the sanitized payload sent to a delivery channel.
type NotificationMessage struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	EventType      string         `json:"event_type"`
	Severity       string         `json:"severity"`
	Channel        string         `json:"channel"`
	Title          string         `json:"title"`
	Content        string         `json:"content"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// OrgPreferences defines organization-wide notification constraints.
type OrgPreferences struct {
	OrganizationID    uuid.UUID       `json:"organization_id"`
	AllowedChannels   []string        `json:"allowed_channels"` // in_app, email, webhook, collaboration
	MandatoryEvents   []string        `json:"mandatory_events"` // events users cannot opt out of
	ChannelDefaults   map[string]bool `json:"channel_defaults"`
	QuietHoursEnabled bool            `json:"quiet_hours_enabled"`
	QuietHoursStart   int             `json:"quiet_hours_start_utc"` // 0-23 UTC
	QuietHoursEnd     int             `json:"quiet_hours_end_utc"`   // 0-23 UTC
	UpdatedAt         time.Time       `json:"updated_at"`
}

// UserPreferences defines individual user overrides within organization boundaries.
type UserPreferences struct {
	OrganizationID    uuid.UUID       `json:"organization_id"`
	UserID            string          `json:"user_id"`
	ChannelOverrides  map[string]bool `json:"channel_overrides"`
	EventOverrides    map[string]bool `json:"event_overrides"` // eventType -> enabled
	QuietHoursEnabled bool            `json:"quiet_hours_enabled"`
	QuietHoursStart   int             `json:"quiet_hours_start_utc"`
	QuietHoursEnd     int             `json:"quiet_hours_end_utc"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// DeliveryLog captures the immutable history of notification delivery attempts.
type DeliveryLog struct {
	ID                uuid.UUID  `json:"id"`
	OrganizationID    uuid.UUID  `json:"organization_id"`
	UserID            string     `json:"user_id,omitempty"`
	EventType         string     `json:"event_type"`
	Channel           string     `json:"channel"`
	DeduplicationKey  string     `json:"deduplication_key"`
	Title             string     `json:"title"`
	SanitizedContent  string     `json:"sanitized_content"`
	Status            string     `json:"status"`
	SuppressionReason string     `json:"suppression_reason,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	DeliveredAt       *time.Time `json:"delivered_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// ChannelDeliveryHandler processes outbound delivery for a specific channel.
type ChannelDeliveryHandler interface {
	Channel() string
	Deliver(ctx context.Context, notif NotificationMessage) error
}

// Router orchestrates notification evaluation, preferences, deduplication, and multi-channel dispatch.
type Router struct {
	mu           sync.RWMutex
	orgPrefs     map[uuid.UUID]*OrgPreferences
	userPrefs    map[string]*UserPreferences // key: orgID:userID
	handlers     map[string]ChannelDeliveryHandler
	deliveryLogs []*DeliveryLog
	dedupCache   map[string]time.Time // key: dedupKey -> last seen time
	redactor     *redaction.Redactor
	dedupWindow  time.Duration
}

// NewRouter constructs a notification router with default redaction and a 10-minute deduplication window.
func NewRouter() *Router {
	return &Router{
		orgPrefs:     make(map[uuid.UUID]*OrgPreferences),
		userPrefs:    make(map[string]*UserPreferences),
		handlers:     make(map[string]ChannelDeliveryHandler),
		deliveryLogs: make([]*DeliveryLog, 0),
		dedupCache:   make(map[string]time.Time),
		redactor:     redaction.NewDefaultRedactor(),
		dedupWindow:  10 * time.Minute,
	}
}

// RegisterHandler registers a channel delivery provider.
func (r *Router) RegisterHandler(handler ChannelDeliveryHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[handler.Channel()] = handler
}

// SetOrgPreferences saves organization notification policy.
func (r *Router) SetOrgPreferences(pref OrgPreferences) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pref.UpdatedAt = time.Now().UTC()
	r.orgPrefs[pref.OrganizationID] = &pref
}

// GetOrgPreferences retrieves organization notification preferences or initializes sensible defaults.
func (r *Router) GetOrgPreferences(orgID uuid.UUID) *OrgPreferences {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if pref, ok := r.orgPrefs[orgID]; ok {
		return pref
	}
	return &OrgPreferences{
		OrganizationID:  orgID,
		AllowedChannels: []string{ChannelInApp, ChannelEmail, ChannelWebhook, ChannelCollaboration},
		MandatoryEvents: []string{"findings.critical", "policy.violation"},
		ChannelDefaults: map[string]bool{
			ChannelInApp:         true,
			ChannelEmail:         true,
			ChannelWebhook:       true,
			ChannelCollaboration: true,
		},
		QuietHoursEnabled: false,
		QuietHoursStart:   22,
		QuietHoursEnd:     7,
		UpdatedAt:         time.Now().UTC(),
	}
}

// SetUserPreferences saves user preferences, rejecting opt-outs of mandatory enterprise events.
func (r *Router) SetUserPreferences(pref UserPreferences) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	orgPref := r.orgPrefs[pref.OrganizationID]
	if orgPref == nil {
		orgPref = &OrgPreferences{
			MandatoryEvents: []string{"findings.critical", "policy.violation"},
		}
	}

	for _, mandatory := range orgPref.MandatoryEvents {
		if enabled, exists := pref.EventOverrides[mandatory]; exists && !enabled {
			return fmt.Errorf("%w: '%s'", ErrMandatoryEventOptOut, mandatory)
		}
	}

	pref.UpdatedAt = time.Now().UTC()
	key := fmt.Sprintf("%s:%s", pref.OrganizationID.String(), pref.UserID)
	r.userPrefs[key] = &pref
	return nil
}

// ComputeDeduplicationKey hashes event dimensions to identify redundant notification bursts.
func (r *Router) ComputeDeduplicationKey(event Event) string {
	h := sha256.New()
	h.Write([]byte(event.OrganizationID.String()))
	h.Write([]byte(event.EventType))
	h.Write([]byte(event.ResourceID))
	h.Write([]byte(event.Title))
	return hex.EncodeToString(h.Sum(nil))
}

// isQuietHours checks whether the current UTC time falls within quiet hours.
func isQuietHours(startHour, endHour int, now time.Time) bool {
	hour := now.UTC().Hour()
	if startHour == endHour {
		return false
	}
	if startHour < endHour {
		return hour >= startHour && hour < endHour
	}
	// Wraps around midnight (e.g. 22 to 7)
	return hour >= startHour || hour < endHour
}

// Dispatch evaluates preferences, sanitizes secrets, checks deduplication and quiet hours,
// and delivers across active channels. Failures are recorded safely without breaking business events.
func (r *Router) Dispatch(ctx context.Context, event Event) []*DeliveryLog {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}

	// 1. Redact sensitive credentials and evidence from notification content
	sanitizedTitle := integrations.RedactSensitiveContent(r.redactor.RedactString(event.Title))
	sanitizedMessage := integrations.RedactSensitiveContent(r.redactor.RedactString(event.Message))

	// 2. Compute Deduplication Key & Check Duplicate Burst
	dedupKey := r.ComputeDeduplicationKey(event)
	isDuplicate := false
	if lastSeen, ok := r.dedupCache[dedupKey]; ok {
		if now.Sub(lastSeen) < r.dedupWindow {
			isDuplicate = true
		}
	}
	r.dedupCache[dedupKey] = now

	// 3. Resolve Organization Preferences
	orgPref, ok := r.orgPrefs[event.OrganizationID]
	if !ok {
		orgPref = &OrgPreferences{
			OrganizationID:  event.OrganizationID,
			AllowedChannels: []string{ChannelInApp, ChannelEmail, ChannelWebhook, ChannelCollaboration},
			MandatoryEvents: []string{"findings.critical", "policy.violation"},
			ChannelDefaults: map[string]bool{
				ChannelInApp:         true,
				ChannelEmail:         true,
				ChannelWebhook:       true,
				ChannelCollaboration: true,
			},
			QuietHoursEnabled: false,
		}
	}

	// 4. Resolve User Preferences (if user specified)
	var userPref *UserPreferences
	if event.UserID != "" {
		key := fmt.Sprintf("%s:%s", event.OrganizationID.String(), event.UserID)
		userPref = r.userPrefs[key]
	}

	// Check if event is mandatory
	isMandatory := false
	for _, m := range orgPref.MandatoryEvents {
		if m == event.EventType || m == "*" {
			isMandatory = true
			break
		}
	}

	// Check quiet hours (Critical severity bypasses quiet hours)
	quietHoursActive := false
	if event.Severity != "CRITICAL" {
		if userPref != nil && userPref.QuietHoursEnabled {
			quietHoursActive = isQuietHours(userPref.QuietHoursStart, userPref.QuietHoursEnd, now)
		} else if orgPref.QuietHoursEnabled {
			quietHoursActive = isQuietHours(orgPref.QuietHoursStart, orgPref.QuietHoursEnd, now)
		}
	}

	allowedChannelsMap := make(map[string]bool)
	for _, ch := range orgPref.AllowedChannels {
		allowedChannelsMap[ch] = true
	}

	var results []*DeliveryLog
	channels := []string{ChannelInApp, ChannelEmail, ChannelWebhook, ChannelCollaboration}

	for _, ch := range channels {
		logEntry := &DeliveryLog{
			ID:               uuid.New(),
			OrganizationID:   event.OrganizationID,
			UserID:           event.UserID,
			EventType:        event.EventType,
			Channel:          ch,
			DeduplicationKey: dedupKey,
			Title:            sanitizedTitle,
			SanitizedContent: sanitizedMessage,
			CreatedAt:        now,
		}

		// A. Check if Org allows this channel
		if !allowedChannelsMap[ch] {
			logEntry.Status = StatusSuppressed
			logEntry.SuppressionReason = SuppressionOrgDisabled
			results = append(results, logEntry)
			r.deliveryLogs = append(r.deliveryLogs, logEntry)
			continue
		}

		// B. Check Deduplication
		if isDuplicate {
			logEntry.Status = StatusSuppressed
			logEntry.SuppressionReason = SuppressionDuplicate
			results = append(results, logEntry)
			r.deliveryLogs = append(r.deliveryLogs, logEntry)
			continue
		}

		// C. Check User/Org enabled state
		channelEnabled := orgPref.ChannelDefaults[ch]
		if userPref != nil {
			if override, exists := userPref.ChannelOverrides[ch]; exists {
				channelEnabled = override
			}
			if eventOverride, exists := userPref.EventOverrides[event.EventType]; exists && !isMandatory {
				if !eventOverride {
					channelEnabled = false
				}
			}
		}

		if !channelEnabled && !isMandatory {
			logEntry.Status = StatusSuppressed
			logEntry.SuppressionReason = SuppressionUserDisabled
			results = append(results, logEntry)
			r.deliveryLogs = append(r.deliveryLogs, logEntry)
			continue
		}

		// D. Check Quiet Hours
		if quietHoursActive {
			logEntry.Status = StatusSuppressed
			logEntry.SuppressionReason = SuppressionQuietHours
			results = append(results, logEntry)
			r.deliveryLogs = append(r.deliveryLogs, logEntry)
			continue
		}

		// E. Deliver via Channel Handler
		handler, hasHandler := r.handlers[ch]
		if !hasHandler {
			// In-app or default unconfigured handler records queued
			logEntry.Status = StatusDelivered
			deliveredTime := now
			logEntry.DeliveredAt = &deliveredTime
			results = append(results, logEntry)
			r.deliveryLogs = append(r.deliveryLogs, logEntry)
			continue
		}

		msg := NotificationMessage{
			ID:             logEntry.ID,
			OrganizationID: event.OrganizationID,
			UserID:         event.UserID,
			EventType:      event.EventType,
			Severity:       event.Severity,
			Channel:        ch,
			Title:          sanitizedTitle,
			Content:        sanitizedMessage,
			Metadata:       event.Metadata,
			Timestamp:      event.Timestamp,
		}

		err := handler.Deliver(ctx, msg)
		if err != nil {
			logEntry.Status = StatusFailed
			logEntry.ErrorMessage = err.Error()
		} else {
			logEntry.Status = StatusDelivered
			deliveredTime := time.Now().UTC()
			logEntry.DeliveredAt = &deliveredTime
		}

		results = append(results, logEntry)
		r.deliveryLogs = append(r.deliveryLogs, logEntry)
	}

	return results
}
