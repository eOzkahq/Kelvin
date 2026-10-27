package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Standard JWT durations and token definitions.
const (
	DefaultAccessTokenDuration  = 15 * time.Minute
	DefaultRefreshTokenDuration = 30 * 24 * time.Hour // 30 days
	DefaultIssuer               = "kelvin.auth"
	DefaultAudience             = "kelvin.api"
)

// Role denotes the tenant authorization role per RBAC_MATRIX.md §2.
type Role string

const (
	RolePlatformAdmin   Role = "PLATFORM_ADMIN"
	RoleTenantAdmin     Role = "TENANT_ADMIN"
	RoleSecurityAnalyst Role = "SECURITY_ANALYST"
	RoleReadOnlyAuditor Role = "READ_ONLY_AUDITOR"
)

// Principal represents the authenticated user context extracted from verified JWT claims.
type Principal struct {
	UserID    uuid.UUID `json:"user_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	Role      Role      `json:"role"`
	SessionID uuid.UUID `json:"session_id"`
}

// Claims represents the cryptographically signed JWT payload.
type Claims struct {
	UserID    string `json:"uid"`
	TenantID  string `json:"tid"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

// TokenPair encapsulates the minted access token and refresh token.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// TokenService signs and verifies JSON Web Tokens.
type TokenService struct {
	secretKey     []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
	audience      string
}

// NewTokenService creates a new TokenService.
func NewTokenService(secretKey string) (*TokenService, error) {
	if len(secretKey) < 32 {
		return nil, errors.New("jwt secret key must be at least 32 bytes for HMAC-SHA256")
	}
	return &TokenService{
		secretKey:     []byte(secretKey),
		accessExpiry:  DefaultAccessTokenDuration,
		refreshExpiry: DefaultRefreshTokenDuration,
		issuer:        DefaultIssuer,
		audience:      DefaultAudience,
	}, nil
}

// GenerateTokenPair creates a new short-lived access JWT and opaque refresh token.
func (s *TokenService) GenerateTokenPair(p Principal) (*TokenPair, error) {
	now := time.Now().UTC()
	accessExpiryTime := now.Add(s.accessExpiry)

	claims := Claims{
		UserID:    p.UserID.String(),
		TenantID:  p.TenantID.String(),
		Email:     p.Email,
		Role:      string(p.Role),
		SessionID: p.SessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
			Subject:   p.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExpiryTime),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedAccess, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate cryptographically random 32-byte refresh token
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshToken := hex.EncodeToString(refreshBytes)

	return &TokenPair{
		AccessToken:  signedAccess,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiryTime,
		TokenType:    "Bearer",
	}, nil
}

// VerifyAccessToken validates the signature, issuer, audience, and expiration of a JWT.
func (s *TokenService) VerifyAccessToken(tokenStr string) (*Principal, error) {
	parsedToken, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secretKey, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience))

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok || !parsedToken.Valid {
		return nil, errors.New("invalid token claims")
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, errors.New("invalid user_id in claims")
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, errors.New("invalid tenant_id in claims")
	}
	sessionID, _ := uuid.Parse(claims.SessionID)

	return &Principal{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     claims.Email,
		Role:      Role(claims.Role),
		SessionID: sessionID,
	}, nil
}

