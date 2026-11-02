package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrSAMLNotConfigured     = errors.New("SAML 2.0 SSO is not configured or disabled for this organization")
	ErrSAMLAssertionReplayed = errors.New("SAML assertion ID has already been consumed (replay detected)")
	ErrSAMLIssuerMismatch    = errors.New("SAML assertion issuer does not match configured IdP entity ID")
	ErrSAMLAudienceMismatch  = errors.New("SAML assertion audience does not match configured SP entity ID")
	ErrSAMLRecipientMismatch = errors.New("SAML assertion recipient does not match configured ACS URL")
	ErrSAMLAssertionExpired  = errors.New("SAML assertion has expired (current time exceeds NotOnOrAfter)")
	ErrSAMLAssertionPremature= errors.New("SAML assertion is not yet valid (current time precedes NotBefore)")
	ErrSAMLInvalidSignature  = errors.New("SAML assertion signature verification failed or untrusted certificate")
	ErrSAMLMissingSubject    = errors.New("SAML assertion missing NameID or email attribute")
)

const (
	ActionSAMLConfigured       = "saml.configured"
	ActionSAMLCertRolledOver   = "saml.certificate_rolled_over"
	ActionSAMLLoginSuccess     = "saml.login_success"
	ActionSAMLLoginFailed      = "saml.login_failed"
)

// SAMLConfig represents an enterprise organization's SAML 2.0 federation settings.
type SAMLConfig struct {
	ID                   uuid.UUID `json:"id"`
	OrganizationID       uuid.UUID `json:"organization_id"`
	IdPEntityID          string    `json:"idp_entity_id"`
	SSOURL               string    `json:"sso_url"`
	SPEntityID           string    `json:"sp_entity_id"`
	ACSURL               string    `json:"acs_url"`
	IdPX509Cert          string    `json:"idp_x509_cert"`
	IdPX509CertSecondary string    `json:"idp_x509_cert_secondary"`
	Enabled              bool      `json:"enabled"`
	EnforceSSO           bool      `json:"enforce_sso"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// SAMLAuthnRequest represents an SP-initiated SAML authentication request.
type SAMLAuthnRequest struct {
	ID           string    `json:"id"`
	IssueInstant time.Time `json:"issue_instant"`
	Destination  string    `json:"destination"`
	Issuer       string    `json:"issuer"` // SP Entity ID
	ACSURL       string    `json:"acs_url"`
}

// SAMLAssertion represents parsed attributes and claims from a validated SAML assertion.
type SAMLAssertion struct {
	ID             string            `json:"id"`
	Issuer         string            `json:"issuer"`
	Audience       string            `json:"audience"`
	SubjectNameID  string            `json:"subject_name_id"`
	Recipient      string            `json:"recipient"`
	NotBefore      time.Time         `json:"not_before"`
	NotOnOrAfter   time.Time         `json:"not_on_or_after"`
	Attributes     map[string]string `json:"attributes"`
	SignatureValid bool              `json:"signature_valid"`
	SigningCert    string            `json:"signing_cert"`
}

// SAMLIdentity represents the verified caller identity resolved from a SAML assertion.
type SAMLIdentity struct {
	NameID          string    `json:"name_id"`
	Email           string    `json:"email"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	OrganizationID  uuid.UUID `json:"organization_id"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

// SAMLConfigRepository defines storage operations for organization SAML configurations.
type SAMLConfigRepository interface {
	Save(ctx context.Context, config *SAMLConfig) error
	GetByOrgID(ctx context.Context, orgID uuid.UUID) (*SAMLConfig, error)
	Update(ctx context.Context, config *SAMLConfig) error
}

// MemorySAMLConfigRepository provides an in-memory implementation of SAMLConfigRepository.
type MemorySAMLConfigRepository struct {
	mu      sync.RWMutex
	configs map[uuid.UUID]*SAMLConfig
}

func NewMemorySAMLConfigRepository() *MemorySAMLConfigRepository {
	return &MemorySAMLConfigRepository{
		configs: make(map[uuid.UUID]*SAMLConfig),
	}
}

func (m *MemorySAMLConfigRepository) Save(ctx context.Context, config *SAMLConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.OrganizationID] = config
	return nil
}

func (m *MemorySAMLConfigRepository) GetByOrgID(ctx context.Context, orgID uuid.UUID) (*SAMLConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[orgID]
	if !ok {
		return nil, ErrSAMLNotConfigured
	}
	return cfg, nil
}

func (m *MemorySAMLConfigRepository) Update(ctx context.Context, config *SAMLConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.OrganizationID] = config
	return nil
}

// SAMLReplayCache stores consumed assertion IDs to prevent replay attacks.
type SAMLReplayCache interface {
	CheckAndRecord(ctx context.Context, assertionID string, expiresAt time.Time) error
}

// MemorySAMLReplayCache provides an in-memory implementation of SAMLReplayCache.
type MemorySAMLReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func NewMemorySAMLReplayCache() *MemorySAMLReplayCache {
	return &MemorySAMLReplayCache{
		entries: make(map[string]time.Time),
	}
}

func (c *MemorySAMLReplayCache) CheckAndRecord(ctx context.Context, assertionID string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	// Clean up expired entries occasionally
	for id, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, id)
		}
	}

	if _, exists := c.entries[assertionID]; exists {
		return ErrSAMLAssertionReplayed
	}

	c.entries[assertionID] = expiresAt
	return nil
}

// SAMLService coordinates SP-initiated SAML 2.0 authentication and assertion verification.
type SAMLService struct {
	configRepo  SAMLConfigRepository
	replayCache SAMLReplayCache
	audit       audit.Recorder
	clockSkew   time.Duration
}

func NewSAMLService(configRepo SAMLConfigRepository, replayCache SAMLReplayCache, audit audit.Recorder) *SAMLService {
	return &SAMLService{
		configRepo:  configRepo,
		replayCache: replayCache,
		audit:       audit,
		clockSkew:   2 * time.Minute,
	}
}

// ConfigureSAML sets up or updates SAML 2.0 configuration for an organization.
func (s *SAMLService) ConfigureSAML(ctx context.Context, actorUserID string, config *SAMLConfig) error {
	if config.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	if strings.TrimSpace(config.IdPEntityID) == "" {
		return errors.New("IdP entity ID cannot be empty")
	}

	u, err := url.Parse(config.SSOURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("SSO URL must be a valid HTTPS URL")
	}

	if strings.TrimSpace(config.SPEntityID) == "" {
		return errors.New("SP entity ID cannot be empty")
	}

	if strings.TrimSpace(config.ACSURL) == "" {
		return errors.New("ACS URL cannot be empty")
	}

	if strings.TrimSpace(config.IdPX509Cert) == "" {
		return errors.New("primary IdP X.509 certificate cannot be empty")
	}

	now := time.Now().UTC()
	if config.ID == uuid.Nil {
		config.ID = uuid.New()
		config.CreatedAt = now
	}
	config.UpdatedAt = now

	if err := s.configRepo.Save(ctx, config); err != nil {
		return err
	}

	s.recordAudit(ctx, config.OrganizationID, actorUserID, ActionSAMLConfigured, config.ID)
	return nil
}

// RolloverCertificate stages a new secondary certificate or promotes secondary to primary for zero downtime.
func (s *SAMLService) RolloverCertificate(ctx context.Context, actorUserID string, orgID uuid.UUID, newCert string, promote bool) error {
	config, err := s.configRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		return err
	}

	if strings.TrimSpace(newCert) == "" {
		return errors.New("new certificate cannot be empty")
	}

	if promote {
		config.IdPX509Cert = newCert
		config.IdPX509CertSecondary = ""
	} else {
		config.IdPX509CertSecondary = newCert
	}
	config.UpdatedAt = time.Now().UTC()

	if err := s.configRepo.Update(ctx, config); err != nil {
		return err
	}

	s.recordAudit(ctx, orgID, actorUserID, ActionSAMLCertRolledOver, config.ID)
	return nil
}

// GenerateAuthnRequest constructs an SP-Initiated SAML AuthnRequest.
func (s *SAMLService) GenerateAuthnRequest(ctx context.Context, orgID uuid.UUID) (*SAMLAuthnRequest, error) {
	config, err := s.configRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return nil, ErrSAMLNotConfigured
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}
	requestID := "_" + hex.EncodeToString(randBytes)

	req := &SAMLAuthnRequest{
		ID:           requestID,
		IssueInstant: time.Now().UTC(),
		Destination:  config.SSOURL,
		Issuer:       config.SPEntityID,
		ACSURL:       config.ACSURL,
	}
	return req, nil
}

// ValidateAssertion enforces strict cryptographic, temporal, audience, and replay validation.
func (s *SAMLService) ValidateAssertion(ctx context.Context, orgID uuid.UUID, assertion SAMLAssertion) (*SAMLIdentity, error) {
	now := time.Now().UTC()

	config, err := s.configRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "SAML not configured")
		return nil, err
	}
	if !config.Enabled {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "SAML disabled")
		return nil, ErrSAMLNotConfigured
	}

	// 1. Replay Check
	if err := s.replayCache.CheckAndRecord(ctx, assertion.ID, assertion.NotOnOrAfter); err != nil {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "replay detected")
		return nil, err
	}

	// 2. Issuer Validation
	if assertion.Issuer != config.IdPEntityID {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "issuer mismatch")
		return nil, ErrSAMLIssuerMismatch
	}

	// 3. Audience Validation
	if assertion.Audience != config.SPEntityID {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "audience mismatch")
		return nil, ErrSAMLAudienceMismatch
	}

	// 4. Recipient Validation (ACS URL)
	if assertion.Recipient != config.ACSURL {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "recipient mismatch")
		return nil, ErrSAMLRecipientMismatch
	}

	// 5. Temporal Conditions (with clock skew allowance)
	if !assertion.NotOnOrAfter.IsZero() && now.After(assertion.NotOnOrAfter.Add(s.clockSkew)) {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "assertion expired")
		return nil, ErrSAMLAssertionExpired
	}

	if !assertion.NotBefore.IsZero() && now.Before(assertion.NotBefore.Add(-s.clockSkew)) {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "assertion premature")
		return nil, ErrSAMLAssertionPremature
	}

	// 6. Signature & Certificate Verification
	if !assertion.SignatureValid {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "invalid signature")
		return nil, ErrSAMLInvalidSignature
	}

	// Verify signing cert matches primary or secondary rollover cert
	normSign := normalizeCert(assertion.SigningCert)
	normPrimary := normalizeCert(config.IdPX509Cert)
	normSecondary := normalizeCert(config.IdPX509CertSecondary)

	if normSign != normPrimary && (normSecondary == "" || normSign != normSecondary) {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "untrusted cert")
		return nil, ErrSAMLInvalidSignature
	}

	// 7. Identity Attribute Extraction
	email := assertion.Attributes["email"]
	if email == "" {
		email = assertion.Attributes["urn:oid:0.9.2342.19200300.100.1.3"] // Standard LDAP email OID
	}
	if email == "" && strings.Contains(assertion.SubjectNameID, "@") {
		email = assertion.SubjectNameID
	}
	if email == "" {
		s.recordAuthAudit(ctx, orgID, ActionSAMLLoginFailed, assertion.SubjectNameID, "missing email attribute")
		return nil, ErrSAMLMissingSubject
	}

	s.recordAuthAudit(ctx, orgID, ActionSAMLLoginSuccess, email, "")

	return &SAMLIdentity{
		NameID:          assertion.SubjectNameID,
		Email:           email,
		FirstName:       assertion.Attributes["firstName"],
		LastName:        assertion.Attributes["lastName"],
		OrganizationID:  orgID,
		AuthenticatedAt: now,
	}, nil
}

func (s *SAMLService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID string, action string, entityID uuid.UUID) {
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
		EntityType:  "saml_configuration",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}

func (s *SAMLService) recordAuthAudit(ctx context.Context, orgID uuid.UUID, action, email, reason string) {
	if s.audit == nil {
		return
	}
	evt := audit.Event{
		ID:         uuid.New(),
		TenantID:   &orgID,
		ActorType:  audit.ActorUser,
		Action:     action,
		EntityType: "saml_session",
		CreatedAt:  time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}

func normalizeCert(cert string) string {
	cert = strings.ReplaceAll(cert, "-----BEGIN CERTIFICATE-----", "")
	cert = strings.ReplaceAll(cert, "-----END CERTIFICATE-----", "")
	cert = strings.ReplaceAll(cert, "\r", "")
	cert = strings.ReplaceAll(cert, "\n", "")
	cert = strings.ReplaceAll(cert, " ", "")
	return cert
}
