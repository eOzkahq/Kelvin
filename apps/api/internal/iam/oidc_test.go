package iam

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOIDCService_Configure(t *testing.T) {
	ctx := context.Background()
	configRepo := NewMemoryOIDCConfigRepository()
	flowStore := NewMemoryOIDCFlowStore()
	mockAudit := &mockAuditRecorder{}
	service := NewOIDCService(configRepo, flowStore, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("successful OIDC configuration", func(t *testing.T) {
		cfg := &OIDCConfig{
			OrganizationID: orgID,
			IssuerURL:      "https://auth.enterprise.example.com",
			ClientID:       "kelvin-client-id",
			RedirectURI:    "https://app.kelvin.security/auth/oidc/callback",
			Enabled:        true,
			EnforceSSO:     false,
		}

		err := service.ConfigureOIDC(ctx, actorID, cfg)
		if err != nil {
			t.Fatalf("unexpected error configuring OIDC: %v", err)
		}

		saved, err := configRepo.GetByOrgID(ctx, orgID)
		if err != nil {
			t.Fatalf("failed to retrieve config: %v", err)
		}
		if saved.ClientID != "kelvin-client-id" {
			t.Errorf("expected client ID kelvin-client-id, got %s", saved.ClientID)
		}
		if len(mockAudit.events) != 1 || mockAudit.events[0].Action != ActionSSOConfigured {
			t.Errorf("expected audit event %s, got %+v", ActionSSOConfigured, mockAudit.events)
		}
	})

	t.Run("reject non-HTTPS issuer URL", func(t *testing.T) {
		cfg := &OIDCConfig{
			OrganizationID: uuid.New(),
			IssuerURL:      "http://insecure.example.com",
			ClientID:       "insecure-client",
			RedirectURI:    "https://app.kelvin.security/callback",
		}
		err := service.ConfigureOIDC(ctx, actorID, cfg)
		if !errors.Is(err, ErrInvalidIssuerURL) {
			t.Fatalf("expected ErrInvalidIssuerURL, got %v", err)
		}
	})

	t.Run("reject empty client ID", func(t *testing.T) {
		cfg := &OIDCConfig{
			OrganizationID: uuid.New(),
			IssuerURL:      "https://auth.example.com",
			ClientID:       "",
			RedirectURI:    "https://app.kelvin.security/callback",
		}
		err := service.ConfigureOIDC(ctx, actorID, cfg)
		if err == nil {
			t.Fatalf("expected error for empty client ID, got nil")
		}
	})
}

func TestOIDCService_AuthFlowAndValidation(t *testing.T) {
	ctx := context.Background()
	configRepo := NewMemoryOIDCConfigRepository()
	flowStore := NewMemoryOIDCFlowStore()
	mockAudit := &mockAuditRecorder{}
	service := NewOIDCService(configRepo, flowStore, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()
	issuerURL := "https://idp.okta.com/oauth2/default"
	clientID := "okta-client-123"
	redirectURI := "https://app.kelvin.security/auth/oidc/callback"

	cfg := &OIDCConfig{
		OrganizationID: orgID,
		IssuerURL:      issuerURL,
		ClientID:       clientID,
		RedirectURI:    redirectURI,
		Enabled:        true,
	}
	_ = service.ConfigureOIDC(ctx, actorID, cfg)

	t.Run("initiate auth flow with valid redirect URI generates PKCE and state", func(t *testing.T) {
		authURL, state, err := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		if err != nil {
			t.Fatalf("unexpected error initiating flow: %v", err)
		}
		if state == "" {
			t.Errorf("expected non-empty state")
		}

		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("invalid auth URL generated: %v", err)
		}

		q := u.Query()
		if q.Get("client_id") != clientID {
			t.Errorf("expected client_id %s, got %s", clientID, q.Get("client_id"))
		}
		if q.Get("response_type") != "code" {
			t.Errorf("expected response_type code")
		}
		if q.Get("code_challenge_method") != "S256" {
			t.Errorf("expected code_challenge_method S256")
		}
		if q.Get("code_challenge") == "" {
			t.Errorf("expected non-empty code_challenge")
		}
		if q.Get("nonce") == "" {
			t.Errorf("expected non-empty nonce")
		}
	})

	t.Run("reject redirect URI manipulation", func(t *testing.T) {
		manipulatedURI := "https://attacker.evil.com/callback"
		_, _, err := service.InitiateAuthFlow(ctx, orgID, manipulatedURI)
		if !errors.Is(err, ErrInvalidRedirectURI) {
			t.Fatalf("expected ErrInvalidRedirectURI, got %v", err)
		}
	})

	t.Run("successful callback validation", func(t *testing.T) {
		authURL, state, err := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		if err != nil {
			t.Fatalf("failed to initiate: %v", err)
		}
		u, _ := url.Parse(authURL)
		nonce := u.Query().Get("nonce")

		claims := OIDCClaims{
			Subject:       "sub_enterprise_usr_999",
			Email:         "analyst@enterprise.com",
			EmailVerified: true,
			Name:          "Enterprise Analyst",
			Issuer:        issuerURL,
			Audience:      clientID,
			Nonce:         nonce,
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		identity, err := service.ValidateCallback(ctx, orgID, "auth_code_xyz", state, claims)
		if err != nil {
			t.Fatalf("unexpected error on valid callback: %v", err)
		}
		if identity.Email != "analyst@enterprise.com" {
			t.Errorf("expected email analyst@enterprise.com, got %s", identity.Email)
		}
		if identity.IdPSubject != "sub_enterprise_usr_999" {
			t.Errorf("expected sub_enterprise_usr_999, got %s", identity.IdPSubject)
		}
	})

	t.Run("replay protection: consuming state twice fails", func(t *testing.T) {
		authURL, state, _ := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		u, _ := url.Parse(authURL)
		nonce := u.Query().Get("nonce")

		claims := OIDCClaims{
			Subject:       "sub_1",
			Email:         "user@corp.com",
			EmailVerified: true,
			Issuer:        issuerURL,
			Audience:      clientID,
			Nonce:         nonce,
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		// First call succeeds
		_, err := service.ValidateCallback(ctx, orgID, "code1", state, claims)
		if err != nil {
			t.Fatalf("first validation failed: %v", err)
		}

		// Replay attempt fails
		_, err = service.ValidateCallback(ctx, orgID, "code2", state, claims)
		if !errors.Is(err, ErrSSOFlowReplayed) {
			t.Fatalf("expected ErrSSOFlowReplayed on replay, got: %v", err)
		}
	})

	t.Run("reject issuer mismatch", func(t *testing.T) {
		authURL, state, _ := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		u, _ := url.Parse(authURL)
		nonce := u.Query().Get("nonce")

		claims := OIDCClaims{
			Subject:       "sub_2",
			Email:         "user@corp.com",
			EmailVerified: true,
			Issuer:        "https://rogue-idp.attacker.com",
			Audience:      clientID,
			Nonce:         nonce,
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		_, err := service.ValidateCallback(ctx, orgID, "code", state, claims)
		if !errors.Is(err, ErrSSOIssuerMismatch) {
			t.Fatalf("expected ErrSSOIssuerMismatch, got: %v", err)
		}
	})

	t.Run("reject audience mismatch", func(t *testing.T) {
		authURL, state, _ := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		u, _ := url.Parse(authURL)
		nonce := u.Query().Get("nonce")

		claims := OIDCClaims{
			Subject:       "sub_3",
			Email:         "user@corp.com",
			EmailVerified: true,
			Issuer:        issuerURL,
			Audience:      "other-app-client-id",
			Nonce:         nonce,
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		_, err := service.ValidateCallback(ctx, orgID, "code", state, claims)
		if !errors.Is(err, ErrSSOAudienceMismatch) {
			t.Fatalf("expected ErrSSOAudienceMismatch, got: %v", err)
		}
	})

	t.Run("reject nonce mismatch", func(t *testing.T) {
		_, state, _ := service.InitiateAuthFlow(ctx, orgID, redirectURI)

		claims := OIDCClaims{
			Subject:       "sub_4",
			Email:         "user@corp.com",
			EmailVerified: true,
			Issuer:        issuerURL,
			Audience:      clientID,
			Nonce:         "wrong-nonce-12345",
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		_, err := service.ValidateCallback(ctx, orgID, "code", state, claims)
		if !errors.Is(err, ErrSSONonceMismatch) {
			t.Fatalf("expected ErrSSONonceMismatch, got: %v", err)
		}
	})

	t.Run("reject unverified email claim", func(t *testing.T) {
		authURL, state, _ := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		u, _ := url.Parse(authURL)
		nonce := u.Query().Get("nonce")

		claims := OIDCClaims{
			Subject:       "sub_5",
			Email:         "unverified@corp.com",
			EmailVerified: false, // Unverified
			Issuer:        issuerURL,
			Audience:      clientID,
			Nonce:         nonce,
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		_, err := service.ValidateCallback(ctx, orgID, "code", state, claims)
		if !errors.Is(err, ErrSSOUnverifiedEmail) {
			t.Fatalf("expected ErrSSOUnverifiedEmail, got: %v", err)
		}
	})

	t.Run("reject expired token", func(t *testing.T) {
		authURL, state, _ := service.InitiateAuthFlow(ctx, orgID, redirectURI)
		u, _ := url.Parse(authURL)
		nonce := u.Query().Get("nonce")

		claims := OIDCClaims{
			Subject:       "sub_6",
			Email:         "user@corp.com",
			EmailVerified: true,
			Issuer:        issuerURL,
			Audience:      clientID,
			Nonce:         nonce,
			ExpiresAt:     time.Now().Add(-10 * time.Minute).Unix(), // Expired 10m ago
		}

		_, err := service.ValidateCallback(ctx, orgID, "code", state, claims)
		if !errors.Is(err, ErrSSOTokenExpired) {
			t.Fatalf("expected ErrSSOTokenExpired, got: %v", err)
		}
	})

	t.Run("reject expired auth flow state", func(t *testing.T) {
		expiredFlow := &OIDCAuthFlowState{
			State:          "expired-state",
			Nonce:          "some-nonce",
			OrganizationID: orgID,
			RedirectURI:    redirectURI,
			ExpiresAt:      time.Now().Add(-1 * time.Minute), // Expired
			Used:           false,
		}
		_ = flowStore.SaveFlow(ctx, expiredFlow)

		claims := OIDCClaims{
			Subject:       "sub_7",
			Email:         "user@corp.com",
			EmailVerified: true,
			Issuer:        issuerURL,
			Audience:      clientID,
			Nonce:         "some-nonce",
			ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		}

		_, err := service.ValidateCallback(ctx, orgID, "code", "expired-state", claims)
		if !errors.Is(err, ErrSSOFlowExpired) {
			t.Fatalf("expected ErrSSOFlowExpired, got: %v", err)
		}
	})
}
