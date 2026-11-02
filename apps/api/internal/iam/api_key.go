package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAPIKeyNotFound        = errors.New("api key: credential not found")
	ErrAPIKeyRevoked         = errors.New("api key: credential has been revoked")
	ErrAPIKeyExpired         = errors.New("api key: credential has expired")
	ErrAPIKeyCompromised     = errors.New("api key: credential has been marked compromised and disabled")
	ErrAPIKeyInvalidFormat   = errors.New("api key: invalid key format or prefix")
	ErrAPIKeyMissingScope    = errors.New("api key: credential lacks required authorization scope")
	ErrInvalidExpiryDuration = errors.New("api key: expiry duration must be between 1 and 365 days")
)

const (
	LiveKeyPrefix        = "klv_live_"
	TestKeyPrefix        = "klv_test_"
	DefaultKeyExpiryDays = 90
	MaxKeyExpiryDays     = 365
)

type KeyStatus string

const (
	KeyActive      KeyStatus = "ACTIVE"
	KeyRevoked     KeyStatus = "REVOKED"
	KeyExpired     KeyStatus = "EXPIRED"
	KeyCompromised KeyStatus = "COMPROMISED"
)

// APICredential stores metadata and hash of an issued API key without secret leakage.
type APICredential struct {
	ID               uuid.UUID  `json:"id"`
	OrganizationID   uuid.UUID  `json:"organization_id"`
	WorkspaceID      *uuid.UUID `json:"workspace_id,omitempty"`
	ServiceAccountID *uuid.UUID `json:"service_account_id,omitempty"`
	UserID           string     `json:"user_id,omitempty"`
	Name             string     `json:"name"`
	KeyPrefix        string     `json:"key_prefix"`
	KeyHash          string     `json:"-"` // Never exposed in JSON serialization
	Scopes           []string   `json:"scopes"`
	Status           KeyStatus  `json:"status"`
	ExpiresAt        time.Time  `json:"expires_at"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP       string     `json:"last_used_ip,omitempty"`
	UsageCount       int64      `json:"usage_count"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func (c *APICredential) String() string {
	return fmt.Sprintf("APICredential(id=%s, prefix=%s, status=%s, scopes=%v)", c.ID, c.KeyPrefix, c.Status, c.Scopes)
}

// CreatedKeyResponse contains the raw key returned strictly once upon generation.
type CreatedKeyResponse struct {
	Credential *APICredential `json:"credential"`
	RawKey     string         `json:"raw_key"` // Returned ONLY once
}

// CreateKeyRequest parameters for issuing a scoped API credential.
type CreateKeyRequest struct {
	OrganizationID   uuid.UUID
	WorkspaceID      *uuid.UUID
	ServiceAccountID *uuid.UUID
	UserID           string
	Name             string
	IsLive           bool
	Scopes           []string
	ExpiryDays       int
}

// APIKeyService coordinates lifecycle, validation, rotation, and security auditing for API keys.
type APIKeyService struct {
	mu          sync.RWMutex
	credentials map[uuid.UUID]*APICredential
	byHash      map[string]uuid.UUID
}

func NewAPIKeyService() *APIKeyService {
	return &APIKeyService{
		credentials: make(map[uuid.UUID]*APICredential),
		byHash:      make(map[string]uuid.UUID),
	}
}

// CreateKey generates a cryptographically secure 256-bit API key, returning plaintext once.
func (s *APIKeyService) CreateKey(_ context.Context, req CreateKeyRequest) (*CreatedKeyResponse, error) {
	if req.OrganizationID == uuid.Nil {
		return nil, errors.New("api key: missing organization id")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("api key: credential name required")
	}

	expiryDays := req.ExpiryDays
	if expiryDays == 0 {
		expiryDays = DefaultKeyExpiryDays
	}
	if expiryDays < 1 || expiryDays > MaxKeyExpiryDays {
		return nil, ErrInvalidExpiryDuration
	}

	prefixType := LiveKeyPrefix
	if !req.IsLive {
		prefixType = TestKeyPrefix
	}

	rawEntropy := randomBytes(32)
	hexEntropy := hex.EncodeToString(rawEntropy)
	rawKey := fmt.Sprintf("%s%s", prefixType, hexEntropy)

	displayPrefix := rawKey[:len(prefixType)+6] // e.g., klv_live_a1b2c3
	keyHash := HashAPIKey(rawKey)

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(expiryDays) * 24 * time.Hour)

	cred := &APICredential{
		ID:               uuid.New(),
		OrganizationID:   req.OrganizationID,
		WorkspaceID:      req.WorkspaceID,
		ServiceAccountID: req.ServiceAccountID,
		UserID:           strings.TrimSpace(req.UserID),
		Name:             name,
		KeyPrefix:        displayPrefix,
		KeyHash:          keyHash,
		Scopes:           req.Scopes,
		Status:           KeyActive,
		ExpiresAt:        expiresAt,
		UsageCount:       0,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	s.mu.Lock()
	s.credentials[cred.ID] = cred
	s.byHash[keyHash] = cred.ID
	s.mu.Unlock()

	return &CreatedKeyResponse{
		Credential: cred,
		RawKey:     rawKey,
	}, nil
}

// AuthenticateKey verifies incoming API key token, enforcing scope, expiry, and revocation checks.
func (s *APIKeyService) AuthenticateKey(
	_ context.Context,
	rawKey string,
	requiredScope string,
	ip string,
) (*APICredential, error) {
	rawKey = strings.TrimSpace(rawKey)
	if !strings.HasPrefix(rawKey, LiveKeyPrefix) && !strings.HasPrefix(rawKey, TestKeyPrefix) {
		return nil, ErrAPIKeyInvalidFormat
	}

	keyHash := HashAPIKey(rawKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	credID, exists := s.byHash[keyHash]
	if !exists {
		return nil, ErrAPIKeyNotFound
	}
	cred := s.credentials[credID]

	now := time.Now().UTC()

	// Check status
	switch cred.Status {
	case KeyRevoked:
		return nil, ErrAPIKeyRevoked
	case KeyCompromised:
		return nil, ErrAPIKeyCompromised
	case KeyExpired:
		return nil, ErrAPIKeyExpired
	}

	if now.After(cred.ExpiresAt) {
		cred.Status = KeyExpired
		cred.UpdatedAt = now
		return nil, ErrAPIKeyExpired
	}

	// Scope verification if specified
	if requiredScope != "" {
		hasScope := false
		for _, s := range cred.Scopes {
			if s == requiredScope || s == "*" || s == "admin" {
				hasScope = true
				break
			}
		}
		if !hasScope {
			return nil, ErrAPIKeyMissingScope
		}
	}

	// Update telemetry
	cred.LastUsedAt = &now
	cred.LastUsedIP = ip
	cred.UsageCount++
	cred.UpdatedAt = now

	return cred, nil
}

// RevokeKey immediately revokes an API credential.
func (s *APIKeyService) RevokeKey(_ context.Context, keyID uuid.UUID, actorID string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.credentials[keyID]
	if !exists {
		return ErrAPIKeyNotFound
	}

	now := time.Now().UTC()
	cred.Status = KeyRevoked
	cred.RevokedAt = &now
	cred.RevokedBy = strings.TrimSpace(actorID)
	cred.RevocationReason = strings.TrimSpace(reason)
	cred.UpdatedAt = now

	return nil
}

// ReportCompromisedKey permanently flags a credential as compromised and disables it immediately.
func (s *APIKeyService) ReportCompromisedKey(_ context.Context, keyID uuid.UUID, reporterID string, evidence string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.credentials[keyID]
	if !exists {
		return ErrAPIKeyNotFound
	}

	now := time.Now().UTC()
	cred.Status = KeyCompromised
	cred.RevokedAt = &now
	cred.RevokedBy = strings.TrimSpace(reporterID)
	cred.RevocationReason = fmt.Sprintf("SECURITY ALERT: Compromised credential reported: %s", strings.TrimSpace(evidence))
	cred.UpdatedAt = now

	return nil
}

// RotateKey creates a new API key while keeping the existing key active for an optional grace period.
func (s *APIKeyService) RotateKey(
	ctx context.Context,
	oldKeyID uuid.UUID,
	actorID string,
	overlapGracePeriod time.Duration,
) (*CreatedKeyResponse, error) {
	s.mu.Lock()
	oldCred, exists := s.credentials[oldKeyID]
	if !exists {
		s.mu.Unlock()
		return nil, ErrAPIKeyNotFound
	}
	if oldCred.Status != KeyActive {
		s.mu.Unlock()
		return nil, ErrAPIKeyRevoked
	}

	now := time.Now().UTC()
	if overlapGracePeriod > 0 {
		graceExpiry := now.Add(overlapGracePeriod)
		if graceExpiry.Before(oldCred.ExpiresAt) {
			oldCred.ExpiresAt = graceExpiry
		}
	} else {
		oldCred.Status = KeyRevoked
		oldCred.RevokedAt = &now
		oldCred.RevokedBy = actorID
		oldCred.RevocationReason = "Rotated with zero-overlap"
	}
	oldCred.UpdatedAt = now

	req := CreateKeyRequest{
		OrganizationID:   oldCred.OrganizationID,
		WorkspaceID:      oldCred.WorkspaceID,
		ServiceAccountID: oldCred.ServiceAccountID,
		UserID:           oldCred.UserID,
		Name:             fmt.Sprintf("%s (Rotated)", oldCred.Name),
		IsLive:           strings.HasPrefix(oldCred.KeyPrefix, LiveKeyPrefix),
		Scopes:           oldCred.Scopes,
		ExpiryDays:       DefaultKeyExpiryDays,
	}
	s.mu.Unlock()

	return s.CreateKey(ctx, req)
}

// HashAPIKey computes the SHA-256 hash of a raw API key.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// RedactKey masks a raw API key string for safe logging.
func RedactKey(key string) string {
	if len(key) <= 12 {
		return "[REDACTED_KEY]"
	}
	return fmt.Sprintf("%s...%s", key[:9], key[len(key)-4:])
}
