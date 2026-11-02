package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	ErrOIDCNotConfigured       = errors.New("OIDC SSO is not configured or disabled for this organization")
	ErrInvalidRedirectURI      = errors.New("redirect URI does not match registered OIDC configuration")
	ErrInvalidIssuerURL        = errors.New("invalid OIDC issuer URL: must be valid HTTPS URL")
	ErrSSOFlowExpired          = errors.New("OIDC authentication flow has expired")
	ErrSSOFlowReplayed         = errors.New("OIDC authentication state already consumed (replay detected)")
	ErrSSOStateNotFound        = errors.New("invalid or unknown OIDC state parameter")
	ErrSSOIssuerMismatch       = errors.New("ID token issuer does not match configured IdP issuer")
	ErrSSOAudienceMismatch     = errors.New("ID token audience does not match configured client ID")
	ErrSSONonceMismatch        = errors.New("ID token nonce does not match authentication flow nonce")
	ErrSSOTokenExpired         = errors.New("ID token has expired")
	ErrSSOUnverifiedEmail      = errors.New("ID token email claim is unverified by IdP")
)

const (
	ActionSSOConfigured  = "sso.configured"
	ActionSSOLoginSuccess = "sso.login_success"
	ActionSSOLoginFailed  = "sso.login_failed"
)

// OIDCConfig represents an organization's identity provider configuration.
type OIDCConfig struct {
	ID                    uuid.UUID `json:"id"`
	OrganizationID       uuid.UUID `json:"organization_id"`
	IssuerURL             string    `json:"issuer_url"`
	ClientID              string    `json:"client_id"`
	ClientSecretEncrypted string    `json:"client_secret_encrypted"`
	RedirectURI           string    `json:"redirect_uri"`
	Scopes                []string  `json:"scopes"`
	Enabled               bool      `json:"enabled"`
	EnforceSSO            bool      `json:"enforce_sso"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// OIDCAuthFlowState tracks an in-flight authentication transaction to prevent replay and CSRF.
type OIDCAuthFlowState struct {
	State          string    `json:"state"`
	Nonce          string    `json:"nonce"`
	CodeVerifier   string    `json:"code_verifier"`
	CodeChallenge  string    `json:"code_challenge"`
	OrganizationID uuid.UUID `json:"organization_id"`
	RedirectURI    string    `json:"redirect_uri"`
	ExpiresAt      time.Time `json:"expires_at"`
	Used           bool      `json:"used"`
}

// OIDCClaims carries the validated claims extracted from an enterprise ID token.
type OIDCClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Nonce         string `json:"nonce"`
	ExpiresAt     int64  `json:"exp"`
}

// OIDCIdentity represents the normalized identity resulting from successful SSO.
type OIDCIdentity struct {
	IdPSubject     string    `json:"idp_subject"`
	Email          string    `json:"email"`
	Name           string    `json:"name"`
	OrganizationID uuid.UUID `json:"organization_id"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

// OIDCConfigRepository defines storage operations for enterprise OIDC configurations.
type OIDCConfigRepository interface {
	Save(ctx context.Context, config *OIDCConfig) error
	GetByOrgID(ctx context.Context, orgID uuid.UUID) (*OIDCConfig, error)
	Update(ctx context.Context, config *OIDCConfig) error
}

// MemoryOIDCConfigRepository provides an in-memory implementation of OIDCConfigRepository.
type MemoryOIDCConfigRepository struct {
	mu      sync.RWMutex
	configs map[uuid.UUID]*OIDCConfig
}

func NewMemoryOIDCConfigRepository() *MemoryOIDCConfigRepository {
	return &MemoryOIDCConfigRepository{
		configs: make(map[uuid.UUID]*OIDCConfig),
	}
}

func (m *MemoryOIDCConfigRepository) Save(ctx context.Context, config *OIDCConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.OrganizationID] = config
	return nil
}

func (m *MemoryOIDCConfigRepository) GetByOrgID(ctx context.Context, orgID uuid.UUID) (*OIDCConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[orgID]
	if !ok {
		return nil, ErrOIDCNotConfigured
	}
	return cfg, nil
}

func (m *MemoryOIDCConfigRepository) Update(ctx context.Context, config *OIDCConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.OrganizationID] = config
	return nil
}

// OIDCFlowStore manages ephemeral state for active SSO flows.
type OIDCFlowStore interface {
	SaveFlow(ctx context.Context, flow *OIDCAuthFlowState) error
	ConsumeFlow(ctx context.Context, state string) (*OIDCAuthFlowState, error)
}

// MemoryOIDCFlowStore provides an in-memory thread-safe implementation of OIDCFlowStore.
type MemoryOIDCFlowStore struct {
	mu    sync.Mutex
	flows map[string]*OIDCAuthFlowState
}

func NewMemoryOIDCFlowStore() *MemoryOIDCFlowStore {
	return &MemoryOIDCFlowStore{
		flows: make(map[string]*OIDCAuthFlowState),
	}
}

func (m *MemoryOIDCFlowStore) SaveFlow(ctx context.Context, flow *OIDCAuthFlowState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[flow.State] = flow
	return nil
}

func (m *MemoryOIDCFlowStore) ConsumeFlow(ctx context.Context, state string) (*OIDCAuthFlowState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.flows[state]
	if !ok {
		return nil, ErrSSOStateNotFound
	}
	if flow.Used {
		return nil, ErrSSOFlowReplayed
	}
	flow.Used = true
	return flow, nil
}

// OIDCService orchestrates OpenID Connect SSO authentication flows.
type OIDCService struct {
	configRepo OIDCConfigRepository
	flowStore  OIDCFlowStore
	audit      audit.Recorder
}

func NewOIDCService(configRepo OIDCConfigRepository, flowStore OIDCFlowStore, audit audit.Recorder) *OIDCService {
	return &OIDCService{
		configRepo: configRepo,
		flowStore:  flowStore,
		audit:      audit,
	}
}

// ConfigureOIDC validates and stores enterprise OIDC identity provider settings.
func (s *OIDCService) ConfigureOIDC(ctx context.Context, actorUserID string, config *OIDCConfig) error {
	if config.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	u, err := url.Parse(config.IssuerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ErrInvalidIssuerURL
	}

	if strings.TrimSpace(config.ClientID) == "" {
		return errors.New("client ID cannot be empty")
	}

	if strings.TrimSpace(config.RedirectURI) == "" {
		return errors.New("redirect URI cannot be empty")
	}

	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
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

	if s.audit != nil {
		var actorUUID *uuid.UUID
		if aID, err := uuid.Parse(actorUserID); err == nil {
			actorUUID = &aID
		}
		evt := audit.Event{
			ID:          uuid.New(),
			TenantID:    &config.OrganizationID,
			ActorUserID: actorUUID,
			ActorType:   audit.ActorUser,
			Action:      ActionSSOConfigured,
			EntityType:  "oidc_configuration",
			EntityID:    &config.ID,
			CreatedAt:   now,
		}
		_ = s.audit.Record(ctx, evt)
	}

	return nil
}

// InitiateAuthFlow generates the authorization URL and ephemeral cryptographic state for PKCE authorization code flow.
func (s *OIDCService) InitiateAuthFlow(ctx context.Context, orgID uuid.UUID, redirectURI string) (authURL string, state string, err error) {
	config, err := s.configRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		return "", "", err
	}
	if !config.Enabled {
		return "", "", ErrOIDCNotConfigured
	}

	if redirectURI != config.RedirectURI {
		return "", "", ErrInvalidRedirectURI
	}

	state, err = generateEntropy(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := generateEntropy(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE credentials: %w", err)
	}

	flow := &OIDCAuthFlowState{
		State:          state,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		CodeChallenge:  codeChallenge,
		OrganizationID: orgID,
		RedirectURI:    redirectURI,
		ExpiresAt:      time.Now().UTC().Add(10 * time.Minute),
		Used:           false,
	}

	if err := s.flowStore.SaveFlow(ctx, flow); err != nil {
		return "", "", err
	}

	// Construct IdP authorization redirect URL
	authEndpoint := strings.TrimRight(config.IssuerURL, "/") + "/protocol/openid-connect/auth"
	params := url.Values{}
	params.Set("client_id", config.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(config.Scopes, " "))
	params.Set("redirect_uri", config.RedirectURI)
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	authURL = fmt.Sprintf("%s?%s", authEndpoint, params.Encode())
	return authURL, state, nil
}

// ValidateCallback processes the OIDC callback, validating state, nonce, PKCE, token claims, and issuer boundaries.
func (s *OIDCService) ValidateCallback(
	ctx context.Context,
	orgID uuid.UUID,
	code string,
	state string,
	claims OIDCClaims,
) (*OIDCIdentity, error) {
	now := time.Now().UTC()

	// 1. Consume state (atomic single-use check preventing replay)
	flow, err := s.flowStore.ConsumeFlow(ctx, state)
	if err != nil {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, err.Error())
		return nil, err
	}

	// 2. Validate expiration
	if now.After(flow.ExpiresAt) {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "flow expired")
		return nil, ErrSSOFlowExpired
	}

	// 3. Retrieve and verify org config
	config, err := s.configRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "config not found")
		return nil, err
	}

	// 4. Validate Claims
	if claims.Issuer != config.IssuerURL {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "issuer mismatch")
		return nil, ErrSSOIssuerMismatch
	}

	if claims.Audience != config.ClientID {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "audience mismatch")
		return nil, ErrSSOAudienceMismatch
	}

	if claims.Nonce != flow.Nonce {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "nonce mismatch")
		return nil, ErrSSONonceMismatch
	}

	if claims.ExpiresAt > 0 && claims.ExpiresAt < now.Unix() {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "token expired")
		return nil, ErrSSOTokenExpired
	}

	if !claims.EmailVerified {
		s.recordAuthAudit(ctx, orgID, ActionSSOLoginFailed, claims.Email, "email unverified")
		return nil, ErrSSOUnverifiedEmail
	}

	s.recordAuthAudit(ctx, orgID, ActionSSOLoginSuccess, claims.Email, "")

	return &OIDCIdentity{
		IdPSubject:      claims.Subject,
		Email:           claims.Email,
		Name:            claims.Name,
		OrganizationID:  orgID,
		AuthenticatedAt: now,
	}, nil
}

func (s *OIDCService) recordAuthAudit(ctx context.Context, orgID uuid.UUID, action, email, reason string) {
	if s.audit == nil {
		return
	}
	evt := audit.Event{
		ID:         uuid.New(),
		TenantID:   &orgID,
		ActorType:  audit.ActorUser,
		Action:     action,
		EntityType: "sso_session",
		CreatedAt:  time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}

func generateEntropy(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}
