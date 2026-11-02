package iam

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	GrantTypeClientCredentials  = "client_credentials"
	DefaultTokenLifetimeSeconds = 3600 // 1 hour bounded lifetime
	TokenTypeBearer             = "Bearer"
)

var (
	ErrUnsupportedGrantType   = errors.New("oauth: unsupported_grant_type: must be client_credentials")
	ErrScopeEscalationDenied  = errors.New("oauth: invalid_scope: requested scope exceeds authorized service identity permissions")
	ErrTokenRevoked           = errors.New("oauth: token has been revoked")
	ErrTokenExpired           = errors.New("oauth: token has expired")
	ErrInvalidTokenSignature  = errors.New("oauth: invalid token signature or format")
)

// TokenRequest represents the standard RFC 6749 client credentials request.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Scope        string
}

// TokenResponse represents RFC 6749 successful token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// M2MClaims represents the JWT-compatible claims payload for machine authentication.
type M2MClaims struct {
	TokenID        string     `json:"jti"`
	Subject        string     `json:"sub"` // ServiceAccount ID
	ClientID       string     `json:"client_id"`
	OrganizationID uuid.UUID  `json:"org_id"`
	WorkspaceID    *uuid.UUID `json:"workspace_id,omitempty"`
	Scopes         []string   `json:"scopes"`
	IssuedAt       int64      `json:"iat"`
	ExpiresAt      int64      `json:"exp"`
}

type IssuedTokenRecord struct {
	TokenID          string
	ServiceAccountID uuid.UUID
	OrganizationID   uuid.UUID
	ClientID         string
	Scopes           []string
	ExpiresAt        time.Time
	IsRevoked        bool
	RevokedAt        *time.Time
}

// OAuthM2MService provides RFC 6749 Client Credentials authorization for automation systems.
type OAuthM2MService struct {
	mu           sync.RWMutex
	saService    *ServiceAccountService
	signingKey   []byte
	issuedTokens map[string]*IssuedTokenRecord
}

func NewOAuthM2MService(saService *ServiceAccountService, signingKey []byte) *OAuthM2MService {
	if len(signingKey) == 0 {
		signingKey = []byte("kelvin-m2m-hmac-sha256-default-key-32b")
	}
	return &OAuthM2MService{
		saService:    saService,
		signingKey:   signingKey,
		issuedTokens: make(map[string]*IssuedTokenRecord),
	}
}

// IssueToken exchanges client credentials for a bounded, scoped access token.
func (s *OAuthM2MService) IssueToken(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	if strings.TrimSpace(req.GrantType) != GrantTypeClientCredentials {
		return nil, ErrUnsupportedGrantType
	}

	// Authenticate the machine identity
	sa, err := s.saService.Authenticate(ctx, req.ClientID, req.ClientSecret, "oauth:token_endpoint")
	if err != nil {
		return nil, err
	}

	// Evaluate scopes to prevent scope escalation
	var authorizedScopes []string
	if strings.TrimSpace(req.Scope) == "" {
		authorizedScopes = sa.Permissions
	} else {
		requested := strings.Fields(req.Scope)
		permittedMap := make(map[string]bool)
		for _, p := range sa.Permissions {
			permittedMap[p] = true
		}
		for _, r := range requested {
			if !permittedMap[r] {
				return nil, fmt.Errorf("%w: '%s'", ErrScopeEscalationDenied, r)
			}
			authorizedScopes = append(authorizedScopes, r)
		}
	}

	now := time.Now().UTC()
	tokenID := fmt.Sprintf("jti_%s", hex.EncodeToString(randomBytes(16)))
	expiresAt := now.Add(time.Duration(DefaultTokenLifetimeSeconds) * time.Second)

	claims := M2MClaims{
		TokenID:        tokenID,
		Subject:        sa.ID.String(),
		ClientID:       sa.ClientID,
		OrganizationID: sa.OrganizationID,
		WorkspaceID:    sa.WorkspaceID,
		Scopes:         authorizedScopes,
		IssuedAt:       now.Unix(),
		ExpiresAt:      expiresAt.Unix(),
	}

	signedJWT, err := s.signClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to sign token: %w", err)
	}

	record := &IssuedTokenRecord{
		TokenID:          tokenID,
		ServiceAccountID: sa.ID,
		OrganizationID:   sa.OrganizationID,
		ClientID:         sa.ClientID,
		Scopes:           authorizedScopes,
		ExpiresAt:        expiresAt,
		IsRevoked:        false,
	}

	s.mu.Lock()
	s.issuedTokens[tokenID] = record
	s.mu.Unlock()

	return &TokenResponse{
		AccessToken: signedJWT,
		TokenType:   TokenTypeBearer,
		ExpiresIn:   DefaultTokenLifetimeSeconds,
		Scope:       strings.Join(authorizedScopes, " "),
	}, nil
}

// VerifyToken verifies token signature, expiry, revocation, and required scope.
func (s *OAuthM2MService) VerifyToken(_ context.Context, rawToken string, requiredScope string) (*M2MClaims, error) {
	claims, err := s.parseAndVerifySignature(rawToken)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC().Unix()
	if now >= claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	s.mu.RLock()
	record, exists := s.issuedTokens[claims.TokenID]
	s.mu.RUnlock()

	if exists && record.IsRevoked {
		return nil, ErrTokenRevoked
	}

	// Verify required scope
	if requiredScope != "" {
		hasScope := false
		for _, sc := range claims.Scopes {
			if sc == requiredScope || sc == "*" || sc == "admin" {
				hasScope = true
				break
			}
		}
		if !hasScope {
			return nil, ErrScopeEscalationDenied
		}
	}

	return claims, nil
}

// RevokeToken marks an active token as revoked.
func (s *OAuthM2MService) RevokeToken(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.issuedTokens[tokenID]
	if !exists {
		return errors.New("oauth: token not found")
	}

	now := time.Now().UTC()
	record.IsRevoked = true
	record.RevokedAt = &now
	return nil
}

// RevokeTokensForServiceAccount immediately revokes all tokens issued to a service account.
func (s *OAuthM2MService) RevokeTokensForServiceAccount(saID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, t := range s.issuedTokens {
		if t.ServiceAccountID == saID {
			t.IsRevoked = true
			t.RevokedAt = &now
		}
	}
	return nil
}

func (s *OAuthM2MService) signClaims(claims M2MClaims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hdrBytes, _ := json.Marshal(header)
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrBytes)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := fmt.Sprintf("%s.%s", hdrB64, claimsB64)
	h := hmac.New(sha256.New, s.signingKey)
	h.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", signingInput, sigB64), nil
}

func (s *OAuthM2MService) parseAndVerifySignature(token string) (*M2MClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidTokenSignature
	}

	signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
	h := hmac.New(sha256.New, s.signingKey)
	h.Write([]byte(signingInput))
	expectedSig := h.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expectedSig, actualSig) {
		return nil, ErrInvalidTokenSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidTokenSignature
	}

	var claims M2MClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidTokenSignature
	}

	return &claims, nil
}
