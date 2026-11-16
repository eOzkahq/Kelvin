package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
)

type authServiceIface interface {
	Login(ctx context.Context, email, password, userAgent, ipAddress string) (*auth.TokenPair, *auth.User, error)
	Refresh(ctx context.Context, refreshToken, userAgent, ipAddress string) (*auth.TokenPair, *auth.User, error)
	Logout(ctx context.Context, sessionID uuid.UUID) error
	RevokeByRefreshToken(ctx context.Context, refreshToken string) error
	RevokeByAccessToken(ctx context.Context, tokenStr string) error
	GetMe(ctx context.Context, tenantID, userID uuid.UUID) (*auth.User, error)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authUserDTO struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	OrganizationID string `json:"organizationId"`
	Organization   string `json:"organization,omitempty"`
}

type authResponse struct {
	Token        string      `json:"token"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	TokenType    string      `json:"token_type"`
	ExpiresAt    time.Time   `json:"expires_at"`
	User         authUserDTO `json:"user"`
}

func toAuthUserDTO(u *auth.User) authUserDTO {
	orgName := u.TenantName
	if orgName == "" {
		orgName = u.TenantSlug
	}
	return authUserDTO{
		ID:             u.ID.String(),
		Email:          u.Email,
		Name:           u.DisplayName,
		Role:           string(u.Role),
		OrganizationID: u.TenantID.String(),
		Organization:   orgName,
	}
}

// SetAuthService configures the authentication service on the HTTP server.
func (s *Server) SetAuthService(svc authServiceIface) {
	s.authService = svc
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "authentication service is not configured",
		})
		return
	}

	// Rate limiting: 10 login requests per minute per IP
	if s.authLimiter != nil {
		ip := auth.GetClientIP(r)
		if !s.authLimiter.Allow("login:" + ip) {
			WriteProblem(w, r, kelvinerrors.NewRateLimited("Too many login attempts. Please wait before retrying."))
			return
		}
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "body",
			Code:    "invalid_json",
			Message: "request body must be valid JSON",
		}}))
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "credentials",
			Code:    "missing_credentials",
			Message: "email and password are required",
		}}))
		return
	}

	ip := auth.GetClientIP(r)
	userAgent := r.UserAgent()

	pair, user, err := s.authService.Login(r.Context(), req.Email, req.Password, userAgent, ip)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidPassword) || errors.Is(err, auth.ErrUserNotFound) || errors.Is(err, auth.ErrUserInactive) || errors.Is(err, auth.ErrTenantInactive) {
			WriteProblem(w, r, kelvinerrors.NewUnauthenticated("Invalid email or password"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	resp := authResponse{
		Token:        pair.AccessToken,
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresAt:    pair.ExpiresAt,
		User:         toAuthUserDTO(user),
	}

	WriteSuccess(w, r, http.StatusOK, resp, nil)
}

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "authentication service is not configured",
		})
		return
	}

	// Rate limiting: 30 refresh requests per minute per IP
	if s.authLimiter != nil {
		ip := auth.GetClientIP(r)
		if !s.authLimiter.Allow("refresh:" + ip) {
			WriteProblem(w, r, kelvinerrors.NewRateLimited("Too many refresh attempts. Please wait before retrying."))
			return
		}
	}

	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "body",
			Code:    "invalid_json",
			Message: "request body must be valid JSON",
		}}))
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "refresh_token",
			Code:    "required",
			Message: "refresh_token is required",
		}}))
		return
	}

	ip := auth.GetClientIP(r)
	userAgent := r.UserAgent()

	pair, user, err := s.authService.Refresh(r.Context(), req.RefreshToken, userAgent, ip)
	if err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) || errors.Is(err, auth.ErrSessionExpired) {
			WriteProblem(w, r, kelvinerrors.NewUnauthenticated("Session has expired. Please log in again."))
			return
		}
		if errors.Is(err, auth.ErrSessionRevoked) {
			WriteProblem(w, r, kelvinerrors.NewUnauthenticated("Invalid refresh token. Session was terminated."))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	resp := authResponse{
		Token:        pair.AccessToken,
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresAt:    pair.ExpiresAt,
		User:         toAuthUserDTO(user),
	}

	WriteSuccess(w, r, http.StatusOK, resp, nil)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "authentication service is not configured",
		})
		return
	}

	// 1. If principal in context, revoke by session ID
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok && principal != nil && principal.SessionID != uuid.Nil {
		_ = s.authService.Logout(r.Context(), principal.SessionID)
	}

	// 2. If Authorization header present, revoke by access token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		tokenStr := strings.TrimSpace(authHeader[7:])
		_ = s.authService.RevokeByAccessToken(r.Context(), tokenStr)
	}

	// 3. If request body has refresh_token, revoke by refresh token
	if r.Body != nil {
		var req refreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.RefreshToken != "" {
			_ = s.authService.RevokeByRefreshToken(r.Context(), req.RefreshToken)
		}
	}

	WriteSuccess(w, r, http.StatusOK, map[string]any{
		"success": true,
		"message": "logged out successfully",
	}, nil)
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || principal == nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authentication required"))
		return
	}

	if s.authService == nil {
		// Fallback to principal claims if service not wired
		WriteSuccess(w, r, http.StatusOK, authUserDTO{
			ID:             principal.UserID.String(),
			Email:          principal.Email,
			Name:           strings.Split(principal.Email, "@")[0],
			Role:           string(principal.Role),
			OrganizationID: principal.TenantID.String(),
			Organization:   "Kelvin Security",
		}, nil)
		return
	}

	user, err := s.authService.GetMe(r.Context(), principal.TenantID, principal.UserID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("user not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, toAuthUserDTO(user), nil)
}
