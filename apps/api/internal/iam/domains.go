package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrDomainNotFound          = errors.New("domain registration not found")
	ErrDomainAlreadyClaimed    = errors.New("domain is already claimed and verified by another organization")
	ErrInvalidDomainFormat     = errors.New("invalid domain format: must be valid fully qualified domain name")
	ErrDNSChallengeFailed      = errors.New("DNS TXT challenge verification failed: token not found in records")
	ErrJITDisabled             = errors.New("just-in-time (JIT) provisioning is disabled for this domain")
	ErrJITDomainNotVerified    = errors.New("cannot provision user: email domain is not verified or has expired")
	ErrPrivilegedJITForbidden  = errors.New("security invariant violation: JIT cannot assign privileged administrative roles")
)

const (
	ActionDomainRegistered = "domain.registered"
	ActionDomainVerified   = "domain.verified"
	ActionDomainRevoked    = "domain.revoked"
	ActionJITUserCreated   = "jit.user_provisioned"
)

type DomainStatus string

const (
	DomainStatusPendingVerification DomainStatus = "PENDING_VERIFICATION"
	DomainStatusVerified            DomainStatus = "VERIFIED"
	DomainStatusExpired             DomainStatus = "EXPIRED"
	DomainStatusRevoked             DomainStatus = "REVOKED"
)

// OrganizationDomain records a registered enterprise email domain and its verification state.
type OrganizationDomain struct {
	ID                uuid.UUID    `json:"id"`
	OrganizationID    uuid.UUID    `json:"organization_id"`
	Domain            string       `json:"domain"`
	VerificationToken string       `json:"verification_token"`
	Status            DomainStatus `json:"status"`
	JITEnabled        bool         `json:"jit_enabled"`
	DefaultRole       RoleName     `json:"default_role"`
	VerifiedAt        *time.Time   `json:"verified_at,omitempty"`
	ExpiresAt         *time.Time   `json:"expires_at,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// ProvisionedUser represents the resulting membership context after successful JIT provisioning.
type ProvisionedUser struct {
	UserID         string    `json:"user_id"`
	Email          string    `json:"email"`
	Name           string    `json:"name"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Role           RoleName  `json:"role"`
	ProvisionedAt  time.Time `json:"provisioned_at"`
}

// TXTResolver abstracts DNS lookup for TXT records to allow anti-SSRF defenses and testing.
type TXTResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// StandardTXTResolver uses the standard Go net package for DNS TXT resolution.
type StandardTXTResolver struct{}

func (r *StandardTXTResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

// DomainRepository defines storage operations for enterprise domain registrations.
type DomainRepository interface {
	Save(ctx context.Context, d *OrganizationDomain) error
	GetByID(ctx context.Context, id uuid.UUID) (*OrganizationDomain, error)
	GetByDomain(ctx context.Context, domain string) (*OrganizationDomain, error)
	ListByOrgID(ctx context.Context, orgID uuid.UUID) ([]*OrganizationDomain, error)
	Update(ctx context.Context, d *OrganizationDomain) error
}

// MemoryDomainRepository provides an in-memory implementation of DomainRepository.
type MemoryDomainRepository struct {
	mu      sync.RWMutex
	domains map[uuid.UUID]*OrganizationDomain
}

func NewMemoryDomainRepository() *MemoryDomainRepository {
	return &MemoryDomainRepository{
		domains: make(map[uuid.UUID]*OrganizationDomain),
	}
}

func (m *MemoryDomainRepository) Save(ctx context.Context, d *OrganizationDomain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domains[d.ID] = d
	return nil
}

func (m *MemoryDomainRepository) GetByID(ctx context.Context, id uuid.UUID) (*OrganizationDomain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.domains[id]
	if !ok {
		return nil, ErrDomainNotFound
	}
	return d, nil
}

func (m *MemoryDomainRepository) GetByDomain(ctx context.Context, domain string) (*OrganizationDomain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	norm := strings.ToLower(strings.TrimSpace(domain))
	for _, d := range m.domains {
		if strings.ToLower(d.Domain) == norm {
			return d, nil
		}
	}
	return nil, ErrDomainNotFound
}

func (m *MemoryDomainRepository) ListByOrgID(ctx context.Context, orgID uuid.UUID) ([]*OrganizationDomain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*OrganizationDomain
	for _, d := range m.domains {
		if d.OrganizationID == orgID {
			list = append(list, d)
		}
	}
	return list, nil
}

func (m *MemoryDomainRepository) Update(ctx context.Context, d *OrganizationDomain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.domains[d.ID]; !ok {
		return ErrDomainNotFound
	}
	m.domains[d.ID] = d
	return nil
}

// DomainService manages domain ownership lifecycle, DNS challenges, and JIT provisioning.
type DomainService struct {
	repo     DomainRepository
	resolver TXTResolver
	audit    audit.Recorder
}

func NewDomainService(repo DomainRepository, resolver TXTResolver, audit audit.Recorder) *DomainService {
	if resolver == nil {
		resolver = &StandardTXTResolver{}
	}
	return &DomainService{
		repo:     repo,
		resolver: resolver,
		audit:    audit,
	}
}

// RegisterDomain initializes a domain registration challenge.
func (s *DomainService) RegisterDomain(
	ctx context.Context,
	actorUserID string,
	orgID uuid.UUID,
	rawDomain string,
	defaultRole RoleName,
	jitEnabled bool,
) (*OrganizationDomain, error) {
	domain := strings.ToLower(strings.TrimSpace(rawDomain))
	if domain == "" || !strings.Contains(domain, ".") || strings.Contains(domain, " ") {
		return nil, ErrInvalidDomainFormat
	}

	// Least Privilege Invariant: JIT default role cannot be administrative
	if defaultRole == "" {
		defaultRole = RoleReadOnlyViewer
	}
	if defaultRole == RoleOrgOwner || defaultRole == RoleOrgAdmin || defaultRole == RoleSecurityAdmin {
		return nil, fmt.Errorf("%w: cannot use privileged role %q as JIT default", ErrPrivilegedJITForbidden, defaultRole)
	}

	// Check if already claimed and verified by another org
	existing, err := s.repo.GetByDomain(ctx, domain)
	if err == nil && existing.Status == DomainStatusVerified && existing.OrganizationID != orgID {
		return nil, ErrDomainAlreadyClaimed
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}
	verificationToken := "kelvin-domain-verification=" + hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	d := &OrganizationDomain{
		ID:                uuid.New(),
		OrganizationID:    orgID,
		Domain:            domain,
		VerificationToken: verificationToken,
		Status:            DomainStatusPendingVerification,
		JITEnabled:        jitEnabled,
		DefaultRole:       defaultRole,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.repo.Save(ctx, d); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, orgID, actorUserID, ActionDomainRegistered, d.ID)
	return d, nil
}

// VerifyDomain queries DNS TXT records to confirm domain ownership.
func (s *DomainService) VerifyDomain(ctx context.Context, actorUserID string, domainID uuid.UUID) (*OrganizationDomain, error) {
	d, err := s.repo.GetByID(ctx, domainID)
	if err != nil {
		return nil, err
	}

	records, err := s.resolver.LookupTXT(ctx, d.Domain)
	if err != nil {
		return nil, fmt.Errorf("%w: DNS lookup failed: %v", ErrDNSChallengeFailed, err)
	}

	tokenFound := false
	for _, r := range records {
		if strings.TrimSpace(r) == d.VerificationToken {
			tokenFound = true
			break
		}
	}

	if !tokenFound {
		return nil, ErrDNSChallengeFailed
	}

	now := time.Now().UTC()
	expires := now.Add(180 * 24 * time.Hour) // 180-day revalidation window
	d.Status = DomainStatusVerified
	d.VerifiedAt = &now
	d.ExpiresAt = &expires
	d.UpdatedAt = now

	if err := s.repo.Update(ctx, d); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, d.OrganizationID, actorUserID, ActionDomainVerified, d.ID)
	return d, nil
}

// ProvisionJITUser evaluates verified domain matching and assigns the organization default role.
func (s *DomainService) ProvisionJITUser(
	ctx context.Context,
	orgID uuid.UUID,
	email string,
	name string,
	idpSubject string,
) (*ProvisionedUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		return nil, ErrInvalidDomainFormat
	}
	domainPart := parts[1]

	d, err := s.repo.GetByDomain(ctx, domainPart)
	if err != nil || d.OrganizationID != orgID {
		return nil, ErrJITDomainNotVerified
	}

	now := time.Now().UTC()
	if d.Status != DomainStatusVerified || (d.ExpiresAt != nil && now.After(*d.ExpiresAt)) {
		return nil, ErrJITDomainNotVerified
	}

	if !d.JITEnabled {
		return nil, ErrJITDisabled
	}

	// Double-check role safety invariant
	if d.DefaultRole == RoleOrgOwner || d.DefaultRole == RoleOrgAdmin || d.DefaultRole == RoleSecurityAdmin {
		return nil, ErrPrivilegedJITForbidden
	}

	userID := "usr_jit_" + uuid.New().String()[:8]
	user := &ProvisionedUser{
		UserID:         userID,
		Email:          email,
		Name:           name,
		OrganizationID: orgID,
		Role:           d.DefaultRole,
		ProvisionedAt:  now,
	}

	if s.audit != nil {
		evt := audit.Event{
			ID:         uuid.New(),
			TenantID:   &orgID,
			ActorType:  audit.ActorUser,
			Action:     ActionJITUserCreated,
			EntityType: "user_membership",
			CreatedAt:  now,
		}
		_ = s.audit.Record(ctx, evt)
	}

	return user, nil
}

func (s *DomainService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID string, action string, entityID uuid.UUID) {
	if s.audit == nil {
		return
	}
	var actorUUID *uuid.UUID
	if aID, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &aID
	}
	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    &orgID,
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "organization_domain",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
