package iam

import (
	"context"
	"crypto/rand"
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
	ErrServiceAccountNotFound     = errors.New("service account: identity not found")
	ErrServiceAccountSuspended    = errors.New("service account: account is suspended; operations blocked")
	ErrServiceAccountRevoked      = errors.New("service account: account is permanently revoked")
	ErrServiceAccountExpired      = errors.New("service account: account expiration date has elapsed")
	ErrInteractiveLoginForbidden  = errors.New("service account: interactive user login forbidden for machine identities")
	ErrInvalidCredentials         = errors.New("service account: invalid client ID or secret")
	ErrCredentialRevoked          = errors.New("service account: credential has been revoked")
	ErrCredentialExpired          = errors.New("service account: credential has expired")
	ErrMissingSAName              = errors.New("service account: name cannot be empty")
)

type ServiceAccountStatus string

const (
	SAActive    ServiceAccountStatus = "ACTIVE"
	SASuspended ServiceAccountStatus = "SUSPENDED"
	SARevoked   ServiceAccountStatus = "REVOKED"
	SAExpired   ServiceAccountStatus = "EXPIRED"
)

type CredentialStatus string

const (
	CredActive  CredentialStatus = "ACTIVE"
	CredRevoked CredentialStatus = "REVOKED"
	CredExpired CredentialStatus = "EXPIRED"
)

// ServiceAccount defines an automated machine identity for non-interactive systems.
type ServiceAccount struct {
	ID             uuid.UUID            `json:"id"`
	OrganizationID uuid.UUID            `json:"organization_id"`
	WorkspaceID    *uuid.UUID           `json:"workspace_id,omitempty"`
	Name           string               `json:"name"`
	Description    string               `json:"description"`
	ClientID       string               `json:"client_id"`
	Status         ServiceAccountStatus `json:"status"`
	Roles          []string             `json:"roles"`
	Permissions    []string             `json:"permissions"`
	CreatorID      string               `json:"creator_id"`
	OwnerID        string               `json:"owner_id"`
	LastUsedAt     *time.Time           `json:"last_used_at,omitempty"`
	LastUsedIP     string               `json:"last_used_ip,omitempty"`
	ExpiresAt      *time.Time           `json:"expires_at,omitempty"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

// ServiceAccountCredential stores the hashed secret of a machine credential.
type ServiceAccountCredential struct {
	ID               uuid.UUID        `json:"id"`
	ServiceAccountID uuid.UUID        `json:"service_account_id"`
	OrganizationID   uuid.UUID        `json:"organization_id"`
	KeyPrefix        string           `json:"key_prefix"`
	SecretHash       string           `json:"-"`
	Status           CredentialStatus `json:"status"`
	ExpiresAt        *time.Time       `json:"expires_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
}

// CreatedCredential contains the plaintext secret returned once at creation or rotation.
type CreatedCredential struct {
	CredentialID uuid.UUID `json:"credential_id"`
	ClientID     string    `json:"client_id"`
	RawSecret    string    `json:"raw_secret"`
	KeyPrefix    string    `json:"key_prefix"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// SAAuditLog captures lifecycle events of service accounts.
type SAAuditLog struct {
	ID               uuid.UUID `json:"id"`
	OrganizationID   uuid.UUID `json:"organization_id"`
	ServiceAccountID uuid.UUID `json:"service_account_id"`
	ActorID          string    `json:"actor_id"`
	Action           string    `json:"action"`
	Details          string    `json:"details"`
	IPAddress        string    `json:"ip_address,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// CreateSARequest carries parameters for provisioning a machine identity.
type CreateSARequest struct {
	OrganizationID uuid.UUID
	WorkspaceID    *uuid.UUID
	Name           string
	Description    string
	Roles          []string
	Permissions    []string
	CreatorID      string
	OwnerID        string
	ExpiresInDays  int
}

// ServiceAccountService coordinates machine identity provisioning, authentication, and credential rotation.
type ServiceAccountService struct {
	mu          sync.RWMutex
	accounts    map[uuid.UUID]*ServiceAccount
	byClientID  map[string]uuid.UUID
	credentials map[uuid.UUID][]*ServiceAccountCredential
	audits      []SAAuditLog
}

func NewServiceAccountService() *ServiceAccountService {
	return &ServiceAccountService{
		accounts:    make(map[uuid.UUID]*ServiceAccount),
		byClientID:  make(map[string]uuid.UUID),
		credentials: make(map[uuid.UUID][]*ServiceAccountCredential),
		audits:      make([]SAAuditLog, 0),
	}
}

// CreateServiceAccount provisions a new service account identity and issues its initial credential.
func (s *ServiceAccountService) CreateServiceAccount(
	_ context.Context,
	req CreateSARequest,
) (*ServiceAccount, *CreatedCredential, error) {
	if req.OrganizationID == uuid.Nil {
		return nil, nil, errors.New("service account: missing organization id")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, nil, ErrMissingSAName
	}
	creatorID := strings.TrimSpace(req.CreatorID)
	if creatorID == "" {
		return nil, nil, errors.New("service account: creator id required")
	}
	ownerID := strings.TrimSpace(req.OwnerID)
	if ownerID == "" {
		ownerID = creatorID
	}

	clientID := fmt.Sprintf("sa_%s_%s", hex.EncodeToString(randomBytes(4)), hex.EncodeToString(randomBytes(4)))
	now := time.Now().UTC()

	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		exp := now.Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &exp
	}

	sa := &ServiceAccount{
		ID:             uuid.New(),
		OrganizationID: req.OrganizationID,
		WorkspaceID:    req.WorkspaceID,
		Name:           name,
		Description:    strings.TrimSpace(req.Description),
		ClientID:       clientID,
		Status:         SAActive,
		Roles:          req.Roles,
		Permissions:    req.Permissions,
		CreatorID:      creatorID,
		OwnerID:        ownerID,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	rawSecret, hash, prefix := generateCredentialSecret()
	cred := &ServiceAccountCredential{
		ID:               uuid.New(),
		ServiceAccountID: sa.ID,
		OrganizationID:   sa.OrganizationID,
		KeyPrefix:        prefix,
		SecretHash:       hash,
		Status:           CredActive,
		ExpiresAt:        expiresAt,
		CreatedAt:        now,
	}

	s.mu.Lock()
	s.accounts[sa.ID] = sa
	s.byClientID[clientID] = sa.ID
	s.credentials[sa.ID] = append(s.credentials[sa.ID], cred)
	s.recordAudit(sa.OrganizationID, sa.ID, creatorID, "CREATE", fmt.Sprintf("Created service account %s (%s)", sa.Name, sa.ClientID), "")
	s.mu.Unlock()

	createdCred := &CreatedCredential{
		CredentialID: cred.ID,
		ClientID:     sa.ClientID,
		RawSecret:    rawSecret,
		KeyPrefix:    prefix,
		ExpiresAt:    expiresAt,
	}

	return sa, createdCred, nil
}

// Authenticate validates machine credentials against active status and hashed secret.
func (s *ServiceAccountService) Authenticate(
	_ context.Context,
	clientID string,
	rawSecret string,
	ip string,
) (*ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	saID, exists := s.byClientID[strings.TrimSpace(clientID)]
	if !exists {
		return nil, ErrInvalidCredentials
	}
	sa := s.accounts[saID]

	// Check SA status
	now := time.Now().UTC()
	if sa.ExpiresAt != nil && now.After(*sa.ExpiresAt) {
		sa.Status = SAExpired
		return nil, ErrServiceAccountExpired
	}
	if sa.Status == SASuspended {
		s.recordAudit(sa.OrganizationID, sa.ID, sa.ClientID, "AUTHENTICATE_BLOCKED", "Authentication blocked: account suspended", ip)
		return nil, ErrServiceAccountSuspended
	}
	if sa.Status == SARevoked {
		return nil, ErrServiceAccountRevoked
	}
	if sa.Status != SAActive {
		return nil, ErrServiceAccountNotFound
	}

	// Validate secret hash
	hash := hashSecret(rawSecret)
	var matchedCred *ServiceAccountCredential
	for _, cred := range s.credentials[saID] {
		if cred.SecretHash == hash {
			matchedCred = cred
			break
		}
	}
	if matchedCred == nil {
		s.recordAudit(sa.OrganizationID, sa.ID, sa.ClientID, "AUTHENTICATE_FAILED", "Invalid secret provided", ip)
		return nil, ErrInvalidCredentials
	}
	if matchedCred.Status == CredRevoked {
		return nil, ErrCredentialRevoked
	}
	if matchedCred.ExpiresAt != nil && now.After(*matchedCred.ExpiresAt) {
		matchedCred.Status = CredExpired
		return nil, ErrCredentialExpired
	}

	// Successful machine authentication
	sa.LastUsedAt = &now
	sa.LastUsedIP = ip
	s.recordAudit(sa.OrganizationID, sa.ID, sa.ClientID, "AUTHENTICATE", "Machine authenticated successfully", ip)

	return sa, nil
}

// AttemptInteractiveLogin strictly rejects interactive session login attempts.
func (s *ServiceAccountService) AttemptInteractiveLogin(_ context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	saID, exists := s.byClientID[strings.TrimSpace(clientID)]
	if exists {
		sa := s.accounts[saID]
		s.recordAudit(sa.OrganizationID, sa.ID, clientID, "REJECT_INTERACTIVE_LOGIN", "Interactive login attempt blocked", "")
	}
	return ErrInteractiveLoginForbidden
}

// RotateCredentials generates a new active credential and optionally revokes older credentials.
func (s *ServiceAccountService) RotateCredentials(
	_ context.Context,
	saID uuid.UUID,
	actorID string,
	revokeOldImmediately bool,
) (*CreatedCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sa, exists := s.accounts[saID]
	if !exists {
		return nil, ErrServiceAccountNotFound
	}
	if sa.Status != SAActive {
		return nil, ErrServiceAccountSuspended
	}

	now := time.Now().UTC()
	if revokeOldImmediately {
		for _, cred := range s.credentials[saID] {
			if cred.Status == CredActive {
				cred.Status = CredRevoked
				cred.RevokedAt = &now
			}
		}
	}

	rawSecret, hash, prefix := generateCredentialSecret()
	newCred := &ServiceAccountCredential{
		ID:               uuid.New(),
		ServiceAccountID: sa.ID,
		OrganizationID:   sa.OrganizationID,
		KeyPrefix:        prefix,
		SecretHash:       hash,
		Status:           CredActive,
		ExpiresAt:        sa.ExpiresAt,
		CreatedAt:        now,
	}
	s.credentials[saID] = append(s.credentials[saID], newCred)
	s.recordAudit(sa.OrganizationID, sa.ID, actorID, "ROTATE_CREDENTIALS", fmt.Sprintf("Credentials rotated (revokeOld=%v)", revokeOldImmediately), "")

	return &CreatedCredential{
		CredentialID: newCred.ID,
		ClientID:     sa.ClientID,
		RawSecret:    rawSecret,
		KeyPrefix:    prefix,
		ExpiresAt:    sa.ExpiresAt,
	}, nil
}

// SuspendServiceAccount suspends the machine identity, immediately blocking downstream operations.
func (s *ServiceAccountService) SuspendServiceAccount(_ context.Context, saID uuid.UUID, actorID string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sa, exists := s.accounts[saID]
	if !exists {
		return ErrServiceAccountNotFound
	}
	sa.Status = SASuspended
	sa.UpdatedAt = time.Now().UTC()

	s.recordAudit(sa.OrganizationID, sa.ID, actorID, "SUSPEND", fmt.Sprintf("Suspended: %s", strings.TrimSpace(reason)), "")
	return nil
}

// ActivateServiceAccount reactivates a suspended service account.
func (s *ServiceAccountService) ActivateServiceAccount(_ context.Context, saID uuid.UUID, actorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sa, exists := s.accounts[saID]
	if !exists {
		return ErrServiceAccountNotFound
	}
	if sa.Status == SARevoked {
		return ErrServiceAccountRevoked
	}
	sa.Status = SAActive
	sa.UpdatedAt = time.Now().UTC()

	s.recordAudit(sa.OrganizationID, sa.ID, actorID, "ACTIVATE", "Service account reactivated", "")
	return nil
}

// RevokeServiceAccount permanently revokes a machine identity and all associated credentials.
func (s *ServiceAccountService) RevokeServiceAccount(_ context.Context, saID uuid.UUID, actorID string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sa, exists := s.accounts[saID]
	if !exists {
		return ErrServiceAccountNotFound
	}
	now := time.Now().UTC()
	sa.Status = SARevoked
	sa.UpdatedAt = now

	for _, cred := range s.credentials[saID] {
		cred.Status = CredRevoked
		cred.RevokedAt = &now
	}

	s.recordAudit(sa.OrganizationID, sa.ID, actorID, "REVOKE", fmt.Sprintf("Permanently revoked: %s", strings.TrimSpace(reason)), "")
	return nil
}

func (s *ServiceAccountService) recordAudit(orgID, saID uuid.UUID, actorID, action, details, ip string) {
	s.audits = append(s.audits, SAAuditLog{
		ID:               uuid.New(),
		OrganizationID:   orgID,
		ServiceAccountID: saID,
		ActorID:          actorID,
		Action:           action,
		Details:          details,
		IPAddress:        ip,
		CreatedAt:        time.Now().UTC(),
	})
}

func (s *ServiceAccountService) GetAuditLogs(saID uuid.UUID) []SAAuditLog {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var res []SAAuditLog
	for _, l := range s.audits {
		if l.ServiceAccountID == saID {
			res = append(res, l)
		}
	}
	return res
}

func generateCredentialSecret() (rawSecret, hash, prefix string) {
	bytes := randomBytes(32)
	rawSecret = hex.EncodeToString(bytes)
	prefix = rawSecret[:8]
	hash = hashSecret(rawSecret)
	return rawSecret, hash, prefix
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
