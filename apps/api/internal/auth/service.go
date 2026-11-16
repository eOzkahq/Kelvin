package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Service coordinates authentication, session lifecycle, and token generation.
type Service struct {
	repo         Repository
	tokenService *TokenService
}

// NewService constructs an authentication Service.
func NewService(repo Repository, tokenService *TokenService) *Service {
	return &Service{
		repo:         repo,
		tokenService: tokenService,
	}
}

// Login verifies user credentials and issues an initial JWT token pair and session.
func (s *Service) Login(ctx context.Context, email, password, userAgent, ipAddress string) (*TokenPair, *User, error) {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return nil, nil, errors.New("email and password are required")
	}

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrUserInactive) || errors.Is(err, ErrTenantInactive) {
			return nil, nil, ErrInvalidPassword // Generic error to prevent user enumeration
		}
		return nil, nil, err
	}

	if !CheckPassword(password, user.PasswordHash) {
		return nil, nil, ErrInvalidPassword
	}

	sessionID := uuid.New()
	tokenFamily := uuid.New()

	principal := Principal{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Role:      user.Role,
		SessionID: sessionID,
	}

	pair, err := s.tokenService.GenerateTokenPair(principal)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue tokens: %w", err)
	}

	now := time.Now().UTC()
	tokenHashBytes := sha256.Sum256([]byte(pair.RefreshToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	session := &Session{
		ID:          sessionID,
		TenantID:    user.TenantID,
		UserID:      user.ID,
		TokenFamily: tokenFamily,
		TokenHash:   tokenHash,
		IssuedAt:    now,
		LastUsedAt:  now,
		ExpiresAt:   now.Add(s.tokenService.refreshExpiry),
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, nil, fmt.Errorf("failed to record session: %w", err)
	}

	// Update last login timestamp asynchronously
	go func(uid uuid.UUID) {
		_ = s.repo.UpdateUserLastLogin(context.Background(), uid)
	}(user.ID)

	return pair, user, nil
}

// Refresh handles single-use refresh token rotation and generates a new token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (*TokenPair, *User, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, nil, errors.New("refresh token is required")
	}

	tokenHashBytes := sha256.Sum256([]byte(refreshToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	session, err := s.repo.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, nil, ErrSessionNotFound
		}
		return nil, nil, err
	}

	// Token reuse detection: If a revoked token is presented, revoke the entire token family
	if session.RevokedAt != nil {
		_ = s.repo.RevokeSessionFamily(ctx, session.TokenFamily)
		return nil, nil, ErrSessionRevoked
	}

	// Check expiration
	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, nil, ErrSessionExpired
	}

	// Fetch active user
	user, err := s.repo.GetUserByID(ctx, session.TenantID, session.UserID)
	if err != nil {
		return nil, nil, err
	}

	newSessionID := uuid.New()
	principal := Principal{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Role:      user.Role,
		SessionID: newSessionID,
	}

	newPair, err := s.tokenService.GenerateTokenPair(principal)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue rotated tokens: %w", err)
	}

	now := time.Now().UTC()
	newTokenHashBytes := sha256.Sum256([]byte(newPair.RefreshToken))
	newTokenHash := hex.EncodeToString(newTokenHashBytes[:])

	newSession := &Session{
		ID:          newSessionID,
		TenantID:    user.TenantID,
		UserID:      user.ID,
		TokenFamily: session.TokenFamily, // Keep same token family
		TokenHash:   newTokenHash,
		IssuedAt:    now,
		LastUsedAt:  now,
		ExpiresAt:   now.Add(s.tokenService.refreshExpiry),
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
	}

	if err := s.repo.RotateSession(ctx, session.ID, newSession); err != nil {
		return nil, nil, fmt.Errorf("failed to rotate session: %w", err)
	}

	return newPair, user, nil
}

// Logout terminates an active session.
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return nil
	}
	return s.repo.RevokeSession(ctx, sessionID)
}

// RevokeByRefreshToken revokes a session identified by its refresh token.
func (s *Service) RevokeByRefreshToken(ctx context.Context, refreshToken string) error {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil
	}
	tokenHashBytes := sha256.Sum256([]byte(refreshToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	session, err := s.repo.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil
	}
	return s.repo.RevokeSession(ctx, session.ID)
}

// RevokeByAccessToken revokes a session identified by an access token (even if expired).
func (s *Service) RevokeByAccessToken(ctx context.Context, tokenStr string) error {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil
	}
	principal, err := s.tokenService.VerifyAccessToken(tokenStr)
	if err != nil {
		parser := jwt.NewParser()
		var claims Claims
		_, _, parseErr := parser.ParseUnverified(tokenStr, &claims)
		if parseErr == nil && claims.SessionID != "" {
			sid, parseUUIDErr := uuid.Parse(claims.SessionID)
			if parseUUIDErr == nil && sid != uuid.Nil {
				return s.repo.RevokeSession(ctx, sid)
			}
		}
		return nil
	}
	return s.repo.RevokeSession(ctx, principal.SessionID)
}

// GetMe retrieves the profile and tenant context for the currently authenticated principal.
func (s *Service) GetMe(ctx context.Context, tenantID, userID uuid.UUID) (*User, error) {
	return s.repo.GetUserByID(ctx, tenantID, userID)
}
