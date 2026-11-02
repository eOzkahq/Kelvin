package integrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrSubscriptionNotFound      = errors.New("webhooks: subscription not found")
	ErrInvalidWebhookEvent       = errors.New("webhooks: invalid event type not in approved catalog")
	ErrNoEventsSelected          = errors.New("webhooks: at least one event type must be selected")
	ErrMissingSubscriptionName   = errors.New("webhooks: subscription name cannot be empty")
	ErrHTTPSRequired             = errors.New("webhooks: endpoint must use https scheme")
	ErrSubscriptionDisabled      = errors.New("webhooks: subscription is disabled")
)

// Approved Webhook Event Catalog (v1)
const (
	EventAssessmentCompleted     = "assessment.completed"
	EventAssessmentFailed        = "assessment.failed"
	EventFindingCreated          = "finding.created"
	EventFindingStatusChanged    = "finding.status_changed"
	EventRiskExceptionApproved   = "risk_exception.approved"
	EventRiskExceptionExpired    = "risk_exception.expired"
	EventRemediationStateChanged = "remediation.state_changed"
	EventReportGenerated         = "report.generated"
	EventWildcard                = "*"
)

var ApprovedEventCatalog = map[string]bool{
	EventAssessmentCompleted:     true,
	EventAssessmentFailed:        true,
	EventFindingCreated:          true,
	EventFindingStatusChanged:    true,
	EventRiskExceptionApproved:   true,
	EventRiskExceptionExpired:    true,
	EventRemediationStateChanged: true,
	EventReportGenerated:         true,
	EventWildcard:                true,
}

type SubscriptionStatus string

const (
	SubActive    SubscriptionStatus = "ACTIVE"
	SubDisabled  SubscriptionStatus = "DISABLED"
	SubSuspended SubscriptionStatus = "SUSPENDED"
)

// WebhookSubscription defines the external webhook configuration.
type WebhookSubscription struct {
	ID                     uuid.UUID          `json:"id"`
	OrganizationID         uuid.UUID          `json:"organization_id"`
	WorkspaceID            *uuid.UUID         `json:"workspace_id,omitempty"`
	Name                   string             `json:"name"`
	EndpointURL            string             `json:"endpoint_url"`
	Status                 SubscriptionStatus `json:"status"`
	EventTypes             []string           `json:"event_types"`
	EncryptedSigningSecret []byte             `json:"-"` // Never exposed in JSON serialization
	EncryptionNonce        []byte             `json:"-"`
	KeyID                  string             `json:"key_id"`
	CreatorID              string             `json:"creator_id"`
	ConsecutiveFailures    int                `json:"consecutive_failures"`
	LastDispatchedAt       *time.Time         `json:"last_dispatched_at,omitempty"`
	LastDeliveryStatus     string             `json:"last_delivery_status,omitempty"`
	CreatedAt              time.Time          `json:"created_at"`
	UpdatedAt              time.Time          `json:"updated_at"`
}

func (s *WebhookSubscription) String() string {
	return fmt.Sprintf("WebhookSubscription(id=%s, name=%s, status=%s, events=%v)",
		s.ID, s.Name, s.Status, s.EventTypes)
}

// CreatedSubscriptionResponse returns the raw signing secret strictly once.
type CreatedSubscriptionResponse struct {
	Subscription *WebhookSubscription `json:"subscription"`
	RawSecret    string               `json:"raw_secret"` // Returned ONLY once
}

// SubAuditLog tracks subscription alterations.
type SubAuditLog struct {
	ID             uuid.UUID `json:"id"`
	OrgID          uuid.UUID `json:"org_id"`
	SubscriptionID uuid.UUID `json:"subscription_id"`
	ActorID        string    `json:"actor_id"`
	Action         string    `json:"action"`
	Details        string    `json:"details"`
	CreatedAt      time.Time `json:"created_at"`
}

type CreateSubscriptionRequest struct {
	OrganizationID uuid.UUID
	WorkspaceID    *uuid.UUID
	Name           string
	EndpointURL    string
	EventTypes     []string
	CreatorID      string
	AllowHTTP      bool // for local testing only
}

// WebhookSubscriptionManager coordinates subscription persistence, anti-SSRF, and signing secret encryption.
type WebhookSubscriptionManager struct {
	mu            sync.RWMutex
	kek           []byte
	keyID         string
	subscriptions map[uuid.UUID]*WebhookSubscription
	audits        []SubAuditLog
}

func NewWebhookSubscriptionManager(kek []byte, keyID string) *WebhookSubscriptionManager {
	if len(kek) != 32 {
		kek = []byte("kelvin-webhooks-aes256-key-32byt")
	}
	if keyID == "" {
		keyID = "wh-kek-v1"
	}
	return &WebhookSubscriptionManager{
		kek:           kek,
		keyID:         keyID,
		subscriptions: make(map[uuid.UUID]*WebhookSubscription),
		audits:        make([]SubAuditLog, 0),
	}
}

// CreateSubscription registers a new webhook subscription, generates a 256-bit signing secret, and encrypts it.
func (m *WebhookSubscriptionManager) CreateSubscription(
	_ context.Context,
	req CreateSubscriptionRequest,
) (*CreatedSubscriptionResponse, error) {
	if req.OrganizationID == uuid.Nil {
		return nil, errors.New("webhooks: missing organization id")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrMissingSubscriptionName
	}
	if len(req.EventTypes) == 0 {
		return nil, ErrNoEventsSelected
	}

	// Validate events against catalog
	for _, ev := range req.EventTypes {
		if !ApprovedEventCatalog[ev] {
			return nil, fmt.Errorf("%w: '%s'", ErrInvalidWebhookEvent, ev)
		}
	}

	// Validate endpoint URL
	if err := m.validateWebhookURL(req.EndpointURL, req.AllowHTTP); err != nil {
		return nil, err
	}

	// Generate 256-bit cryptographically secure shared signing secret (whsec_...)
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	rawSecret := fmt.Sprintf("whsec_%s", hex.EncodeToString(entropy))

	// Encrypt secret with AES-GCM
	ciphertext, nonce, err := m.encryptSecret([]byte(rawSecret))
	if err != nil {
		return nil, fmt.Errorf("webhooks: failed to encrypt secret: %w", err)
	}

	now := time.Now().UTC()
	sub := &WebhookSubscription{
		ID:                     uuid.New(),
		OrganizationID:         req.OrganizationID,
		WorkspaceID:            req.WorkspaceID,
		Name:                   name,
		EndpointURL:            strings.TrimSpace(req.EndpointURL),
		Status:                 SubActive,
		EventTypes:             req.EventTypes,
		EncryptedSigningSecret: ciphertext,
		EncryptionNonce:        nonce,
		KeyID:                  m.keyID,
		CreatorID:              req.CreatorID,
		ConsecutiveFailures:    0,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	m.mu.Lock()
	m.subscriptions[sub.ID] = sub
	m.recordAudit(sub.OrganizationID, sub.ID, req.CreatorID, "CREATE", fmt.Sprintf("Created subscription '%s' for events %v", sub.Name, sub.EventTypes))
	m.mu.Unlock()

	return &CreatedSubscriptionResponse{
		Subscription: sub,
		RawSecret:    rawSecret,
	}, nil
}

// RotateSigningSecret generates a new shared secret, re-encrypts it, and returns it strictly once.
func (m *WebhookSubscriptionManager) RotateSigningSecret(_ context.Context, subID uuid.UUID, actorID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sub, exists := m.subscriptions[subID]
	if !exists {
		return "", ErrSubscriptionNotFound
	}

	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	rawSecret := fmt.Sprintf("whsec_%s", hex.EncodeToString(entropy))

	ciphertext, nonce, err := m.encryptSecret([]byte(rawSecret))
	if err != nil {
		return "", err
	}

	sub.EncryptedSigningSecret = ciphertext
	sub.EncryptionNonce = nonce
	sub.UpdatedAt = time.Now().UTC()

	m.recordAudit(sub.OrganizationID, sub.ID, actorID, "ROTATE_SECRET", "Signing secret rotated")
	return rawSecret, nil
}

// GetDecryptedSecretForDispatcher retrieves plaintext secret in memory for HMAC-SHA256 event signature generation.
func (m *WebhookSubscriptionManager) GetDecryptedSecretForDispatcher(_ context.Context, subID uuid.UUID) (string, error) {
	m.mu.RLock()
	sub, exists := m.subscriptions[subID]
	m.mu.RUnlock()

	if !exists {
		return "", ErrSubscriptionNotFound
	}
	if sub.Status != SubActive {
		return "", ErrSubscriptionDisabled
	}

	plaintext, err := m.decryptSecret(sub.EncryptedSigningSecret, sub.EncryptionNonce)
	if err != nil {
		return "", fmt.Errorf("webhooks: failed to decrypt secret: %w", err)
	}

	return string(plaintext), nil
}

// DisableSubscription temporarily suspends dispatching.
func (m *WebhookSubscriptionManager) DisableSubscription(_ context.Context, subID uuid.UUID, actorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sub, exists := m.subscriptions[subID]
	if !exists {
		return ErrSubscriptionNotFound
	}
	sub.Status = SubDisabled
	sub.UpdatedAt = time.Now().UTC()

	m.recordAudit(sub.OrganizationID, sub.ID, actorID, "DISABLE", "Subscription disabled")
	return nil
}

// EnableSubscription reactivates a subscription.
func (m *WebhookSubscriptionManager) EnableSubscription(_ context.Context, subID uuid.UUID, actorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sub, exists := m.subscriptions[subID]
	if !exists {
		return ErrSubscriptionNotFound
	}
	sub.Status = SubActive
	sub.UpdatedAt = time.Now().UTC()

	m.recordAudit(sub.OrganizationID, sub.ID, actorID, "ENABLE", "Subscription enabled")
	return nil
}

// DeleteSubscription removes a webhook subscription.
func (m *WebhookSubscriptionManager) DeleteSubscription(_ context.Context, subID uuid.UUID, actorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sub, exists := m.subscriptions[subID]
	if !exists {
		return ErrSubscriptionNotFound
	}
	delete(m.subscriptions, subID)

	m.recordAudit(sub.OrganizationID, sub.ID, actorID, "DELETE", "Subscription deleted")
	return nil
}

// FindMatchingSubscriptions returns active subscriptions subscribed to eventType in the given organization & workspace.
func (m *WebhookSubscriptionManager) FindMatchingSubscriptions(orgID uuid.UUID, workspaceID *uuid.UUID, eventType string) []*WebhookSubscription {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matching []*WebhookSubscription
	for _, sub := range m.subscriptions {
		if sub.OrganizationID != orgID || sub.Status != SubActive {
			continue
		}
		// If subscription is workspace-scoped, verify match
		if sub.WorkspaceID != nil && workspaceID != nil && *sub.WorkspaceID != *workspaceID {
			continue
		}

		// Check event matching
		matched := false
		for _, e := range sub.EventTypes {
			if e == EventWildcard || e == eventType {
				matched = true
				break
			}
		}
		if matched {
			matching = append(matching, sub)
		}
	}

	return matching
}

func (m *WebhookSubscriptionManager) validateWebhookURL(rawURL string, allowHTTP bool) error {
	rawURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	scheme := strings.ToLower(parsed.Scheme)
	if !allowHTTP && scheme != "https" {
		return ErrHTTPSRequired
	}

	return ValidateSafeEndpointURL(rawURL)
}

func (m *WebhookSubscriptionManager) recordAudit(orgID, subID uuid.UUID, actorID, action, details string) {
	m.audits = append(m.audits, SubAuditLog{
		ID:             uuid.New(),
		OrgID:          orgID,
		SubscriptionID: subID,
		ActorID:        actorID,
		Action:         action,
		Details:        details,
		CreatedAt:      time.Now().UTC(),
	})
}

func (m *WebhookSubscriptionManager) GetAuditLogs(subID uuid.UUID) []SubAuditLog {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []SubAuditLog
	for _, l := range m.audits {
		if l.SubscriptionID == subID {
			res = append(res, l)
		}
	}
	return res
}

func (m *WebhookSubscriptionManager) encryptSecret(plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(m.kek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (m *WebhookSubscriptionManager) decryptSecret(ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
