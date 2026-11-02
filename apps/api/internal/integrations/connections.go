package integrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrConnectionNotFound      = errors.New("integrations: connection not found")
	ErrSSRFDestinationBlocked  = errors.New("integrations: outbound request blocked: unsafe or private IP destination (anti-SSRF)")
	ErrInvalidEndpointScheme   = errors.New("integrations: endpoint must use http or https scheme")
	ErrMissingConnectionName   = errors.New("integrations: connection name cannot be empty")
	ErrMissingProvider         = errors.New("integrations: integration provider must be specified")
	ErrMissingSecret           = errors.New("integrations: integration secret cannot be empty")
	ErrConnectionDisabled      = errors.New("integrations: connection is disabled")
)

type ConnectionStatus string

const (
	StatusActive   ConnectionStatus = "ACTIVE"
	StatusDisabled ConnectionStatus = "DISABLED"
	StatusError    ConnectionStatus = "ERROR"
)

type ProviderType string

const (
	ProviderJira           ProviderType = "JIRA"
	ProviderSlack          ProviderType = "SLACK"
	ProviderGitHub         ProviderType = "GITHUB"
	ProviderPagerDuty      ProviderType = "PAGERDUTY"
	ProviderGenericWebhook ProviderType = "GENERIC_WEBHOOK"
)

// IntegrationConnection represents an external integration configuration with encrypted credentials.
type IntegrationConnection struct {
	ID                     uuid.UUID        `json:"id"`
	OrganizationID         uuid.UUID        `json:"organization_id"`
	WorkspaceID            *uuid.UUID       `json:"workspace_id,omitempty"`
	Name                   string           `json:"name"`
	Provider               ProviderType     `json:"provider"`
	Status                 ConnectionStatus `json:"status"`
	EndpointURL            string           `json:"endpoint_url"`
	EncryptedSecretPayload []byte           `json:"-"` // Never exposed in JSON serialization
	EncryptionNonce        []byte           `json:"-"`
	KeyID                  string           `json:"key_id"`
	Config                 map[string]any   `json:"config"`
	CreatorID              string           `json:"creator_id"`
	OwnerID                string           `json:"owner_id"`
	LastSyncAt             *time.Time       `json:"last_sync_at,omitempty"`
	LastError              string           `json:"last_error,omitempty"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
}

func (c *IntegrationConnection) String() string {
	return fmt.Sprintf("IntegrationConnection(id=%s, name=%s, provider=%s, status=%s, endpoint=%s)",
		c.ID, c.Name, c.Provider, c.Status, c.EndpointURL)
}

// ConnectionAuditLog captures all lifecycle and invocation audit events.
type ConnectionAuditLog struct {
	ID           uuid.UUID `json:"id"`
	OrgID        uuid.UUID `json:"org_id"`
	ConnectionID uuid.UUID `json:"connection_id"`
	ActorID      string    `json:"actor_id"`
	Action       string    `json:"action"`
	Details      string    `json:"details"`
	CreatedAt    time.Time `json:"created_at"`
}

// CreateConnectionRequest holds parameters for establishing a connection.
type CreateConnectionRequest struct {
	OrganizationID uuid.UUID
	WorkspaceID    *uuid.UUID
	Name           string
	Provider       ProviderType
	EndpointURL    string
	Secret         string
	Config         map[string]any
	CreatorID      string
	OwnerID        string
}

// ConnectionManager manages tenant connections, envelope encryption, and anti-SSRF protections.
type ConnectionManager struct {
	mu          sync.RWMutex
	kek         []byte
	keyID       string
	connections map[uuid.UUID]*IntegrationConnection
	audits      []ConnectionAuditLog
}

func NewConnectionManager(kek []byte, keyID string) *ConnectionManager {
	if len(kek) != 32 {
		// Standard AES-256 fallback key (32 bytes) if unspecified
		kek = []byte("kelvin-integrations-aes256-32byt")
	}
	if keyID == "" {
		keyID = "kek-v1"
	}
	return &ConnectionManager{
		kek:         kek,
		keyID:       keyID,
		connections: make(map[uuid.UUID]*IntegrationConnection),
		audits:      make([]ConnectionAuditLog, 0),
	}
}

// CreateConnection registers a new external connection, validating anti-SSRF and encrypting secrets.
func (m *ConnectionManager) CreateConnection(
	ctx context.Context,
	req CreateConnectionRequest,
) (*IntegrationConnection, error) {
	if req.OrganizationID == uuid.Nil {
		return nil, errors.New("integrations: missing organization id")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrMissingConnectionName
	}
	if req.Provider == "" {
		return nil, ErrMissingProvider
	}
	secret := strings.TrimSpace(req.Secret)
	if secret == "" {
		return nil, ErrMissingSecret
	}

	// Validate endpoint anti-SSRF
	if err := ValidateSafeEndpointURL(req.EndpointURL); err != nil {
		return nil, err
	}

	// Encrypt secret with AES-GCM-256 envelope
	ciphertext, nonce, err := m.encryptSecret([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("integrations: encryption failed: %w", err)
	}

	now := time.Now().UTC()
	ownerID := strings.TrimSpace(req.OwnerID)
	if ownerID == "" {
		ownerID = req.CreatorID
	}

	conn := &IntegrationConnection{
		ID:                     uuid.New(),
		OrganizationID:         req.OrganizationID,
		WorkspaceID:            req.WorkspaceID,
		Name:                   name,
		Provider:               req.Provider,
		Status:                 StatusActive,
		EndpointURL:            strings.TrimSpace(req.EndpointURL),
		EncryptedSecretPayload: ciphertext,
		EncryptionNonce:        nonce,
		KeyID:                  m.keyID,
		Config:                 req.Config,
		CreatorID:              req.CreatorID,
		OwnerID:                ownerID,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	m.mu.Lock()
	m.connections[conn.ID] = conn
	m.recordAudit(conn.OrganizationID, conn.ID, req.CreatorID, "CREATE", fmt.Sprintf("Created %s connection '%s'", conn.Provider, conn.Name))
	m.mu.Unlock()

	return conn, nil
}

// RotateSecret re-encrypts a new secret for an active connection without altering other configurations.
func (m *ConnectionManager) RotateSecret(
	_ context.Context,
	connID uuid.UUID,
	actorID string,
	newSecret string,
) error {
	newSecret = strings.TrimSpace(newSecret)
	if newSecret == "" {
		return ErrMissingSecret
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	conn, exists := m.connections[connID]
	if !exists {
		return ErrConnectionNotFound
	}

	ciphertext, nonce, err := m.encryptSecret([]byte(newSecret))
	if err != nil {
		return fmt.Errorf("integrations: encryption failed: %w", err)
	}

	conn.EncryptedSecretPayload = ciphertext
	conn.EncryptionNonce = nonce
	conn.KeyID = m.keyID
	conn.UpdatedAt = time.Now().UTC()

	m.recordAudit(conn.OrganizationID, conn.ID, actorID, "ROTATE_SECRET", "Secret rotated successfully")
	return nil
}

// GetDecryptedSecretForAdapter retrieves plaintext secret strictly in-memory for adapter dispatch.
func (m *ConnectionManager) GetDecryptedSecretForAdapter(_ context.Context, connID uuid.UUID) (string, error) {
	m.mu.RLock()
	conn, exists := m.connections[connID]
	m.mu.RUnlock()

	if !exists {
		return "", ErrConnectionNotFound
	}
	if conn.Status != StatusActive {
		return "", ErrConnectionDisabled
	}

	plaintext, err := m.decryptSecret(conn.EncryptedSecretPayload, conn.EncryptionNonce)
	if err != nil {
		return "", fmt.Errorf("integrations: decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// DisableConnection disables an integration, blocking any outgoing requests.
func (m *ConnectionManager) DisableConnection(_ context.Context, connID uuid.UUID, actorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, exists := m.connections[connID]
	if !exists {
		return ErrConnectionNotFound
	}
	conn.Status = StatusDisabled
	conn.UpdatedAt = time.Now().UTC()

	m.recordAudit(conn.OrganizationID, conn.ID, actorID, "DISABLE", "Connection disabled")
	return nil
}

// EnableConnection reactivates a disabled connection.
func (m *ConnectionManager) EnableConnection(_ context.Context, connID uuid.UUID, actorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, exists := m.connections[connID]
	if !exists {
		return ErrConnectionNotFound
	}
	conn.Status = StatusActive
	conn.UpdatedAt = time.Now().UTC()

	m.recordAudit(conn.OrganizationID, conn.ID, actorID, "ENABLE", "Connection enabled")
	return nil
}

// DeleteConnection deletes a connection record.
func (m *ConnectionManager) DeleteConnection(_ context.Context, connID uuid.UUID, actorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, exists := m.connections[connID]
	if !exists {
		return ErrConnectionNotFound
	}
	delete(m.connections, connID)

	m.recordAudit(conn.OrganizationID, conn.ID, actorID, "DELETE", "Connection deleted")
	return nil
}

func (m *ConnectionManager) recordAudit(orgID, connID uuid.UUID, actorID, action, details string) {
	m.audits = append(m.audits, ConnectionAuditLog{
		ID:           uuid.New(),
		OrgID:        orgID,
		ConnectionID: connID,
		ActorID:      actorID,
		Action:       action,
		Details:      details,
		CreatedAt:    time.Now().UTC(),
	})
}

func (m *ConnectionManager) GetAuditLogs(connID uuid.UUID) []ConnectionAuditLog {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []ConnectionAuditLog
	for _, l := range m.audits {
		if l.ConnectionID == connID {
			res = append(res, l)
		}
	}
	return res
}

func (m *ConnectionManager) encryptSecret(plaintext []byte) (ciphertext, nonce []byte, err error) {
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

func (m *ConnectionManager) decryptSecret(ciphertext, nonce []byte) ([]byte, error) {
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

// ValidateSafeEndpointURL ensures that destination targets are valid, public, and not private/internal SSRF hazards.
func ValidateSafeEndpointURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("integrations: malformed endpoint url: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ErrInvalidEndpointScheme
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return errors.New("integrations: endpoint host cannot be empty")
	}

	// Immediate string blocks for common SSRF targets
	lowerHost := strings.ToLower(hostname)
	if lowerHost == "localhost" || lowerHost == "127.0.0.1" || lowerHost == "::1" || lowerHost == "169.254.169.254" {
		return ErrSSRFDestinationBlocked
	}

	// Parse IP directly if hostname is IP
	ip := net.ParseIP(hostname)
	if ip != nil {
		if isPrivateOrUnsafeIP(ip) {
			return ErrSSRFDestinationBlocked
		}
	}

	return nil
}

func isPrivateOrUnsafeIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	// IPv4 Private RFC 1918 + AWS metadata + CGNAT
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (Link local & cloud metadata)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 100.64.0.0/10 (CGNAT)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}

	return false
}
