package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"go.uber.org/zap"
)

func setupTestServerWithAuth(t *testing.T) (*Server, *auth.Service, *auth.User) {
	t.Helper()
	cfg := config.Config{
		APIVersion:     "1.0.0-test",
		Development:    true,
		BodyLimitBytes: 1048576,
	}
	server := New(cfg, zap.NewNop())

	repo := auth.NewMemoryRepository()
	tokenService, err := auth.NewTokenService("testSecretKeyMustBeAtLeast32BytesLong12345!")
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	tenantID := uuid.New()
	userID := uuid.New()
	hash, err := auth.HashPassword("TestPass12345!")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	tenant := &auth.Tenant{
		ID:     tenantID,
		Name:   "Kelvin Security Corp",
		Slug:   "kelvin-sec",
		Status: "ACTIVE",
	}

	user := &auth.User{
		ID:           userID,
		TenantID:     tenantID,
		Email:        "admin@kelvin.corp",
		DisplayName:  "Test Admin",
		PasswordHash: hash,
		Role:         auth.RoleTenantAdmin,
		IsActive:     true,
	}

	if err := repo.CreateTenantAndAdmin(context.Background(), tenant, user); err != nil {
		t.Fatalf("failed to create test tenant and user: %v", err)
	}

	authService := auth.NewService(repo, tokenService)
	server.SetAuthService(authService)

	server.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		roles := auth.RequireRole(auth.RolePlatformAdmin, auth.RoleTenantAdmin, auth.RoleSecurityAnalyst, auth.RoleReadOnlyAuditor)(next)
		return auth.Middleware(tokenService)(roles)
	})

	return server, authService, user
}

func TestHTTP_AuthLogin_Success(t *testing.T) {
	server, _, user := setupTestServerWithAuth(t)

	body, _ := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "TestPass12345!",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool         `json:"success"`
		Data    authResponse `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}

	if !resp.Success {
		t.Fatal("expected success true")
	}
	if resp.Data.Token == "" || resp.Data.RefreshToken == "" {
		t.Fatal("expected non-empty token and refresh_token")
	}
	if resp.Data.User.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, resp.Data.User.Email)
	}
	if resp.Data.User.Organization != "Kelvin Security Corp" {
		t.Errorf("expected organization 'Kelvin Security Corp', got '%s'", resp.Data.User.Organization)
	}
}

func TestHTTP_AuthLogin_InvalidCredentials(t *testing.T) {
	server, _, user := setupTestServerWithAuth(t)

	body, _ := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "WrongPassword!",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestHTTP_AuthRefresh_SuccessAndRotation(t *testing.T) {
	server, _, user := setupTestServerWithAuth(t)

	// Step 1: Login to acquire refresh token
	loginBody, _ := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "TestPass12345!",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(loginRec, loginReq)

	var loginResp struct {
		Data authResponse `json:"data"`
	}
	_ = json.NewDecoder(loginRec.Body).Decode(&loginResp)
	origRefreshToken := loginResp.Data.RefreshToken

	// Step 2: Call refresh endpoint
	refreshBody, _ := json.Marshal(map[string]string{
		"refresh_token": origRefreshToken,
	})
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(refreshRec, refreshReq)

	if refreshRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on refresh, got %d: %s", refreshRec.Code, refreshRec.Body.String())
	}

	var refreshResp struct {
		Data authResponse `json:"data"`
	}
	_ = json.NewDecoder(refreshRec.Body).Decode(&refreshResp)

	if refreshResp.Data.RefreshToken == origRefreshToken {
		t.Fatal("expected refresh token to be rotated")
	}

	// Step 3: Reuse of original refresh token should fail (401)
	reuseReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBody))
	reuseReq.Header.Set("Content-Type", "application/json")
	reuseRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(reuseRec, reuseReq)

	if reuseRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 on refresh token reuse, got %d", reuseRec.Code)
	}
}

func TestHTTP_AuthMe_Protected(t *testing.T) {
	server, _, user := setupTestServerWithAuth(t)

	// Unauthenticated request to /auth/me should return 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	unauthRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthRec, unauthReq)

	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for unauthenticated /auth/me, got %d", unauthRec.Code)
	}

	// Authenticated request
	loginBody, _ := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "TestPass12345!",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(loginRec, loginReq)

	var loginResp struct {
		Data authResponse `json:"data"`
	}
	_ = json.NewDecoder(loginRec.Body).Decode(&loginResp)

	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	authReq.Header.Set("Authorization", "Bearer "+loginResp.Data.Token)
	authRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for authenticated /auth/me, got %d: %s", authRec.Code, authRec.Body.String())
	}

	var meResp struct {
		Data authUserDTO `json:"data"`
	}
	_ = json.NewDecoder(authRec.Body).Decode(&meResp)

	if meResp.Data.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, meResp.Data.Email)
	}
	if meResp.Data.Organization != "Kelvin Security Corp" {
		t.Errorf("expected organization 'Kelvin Security Corp', got '%s'", meResp.Data.Organization)
	}
}

func TestHTTP_AuthLogout_Success(t *testing.T) {
	server, _, user := setupTestServerWithAuth(t)

	loginBody, _ := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "TestPass12345!",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(loginRec, loginReq)

	var loginResp struct {
		Data authResponse `json:"data"`
	}
	_ = json.NewDecoder(loginRec.Body).Decode(&loginResp)

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResp.Data.Token)
	logoutRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on logout, got %d", logoutRec.Code)
	}

	// Token refresh should now fail
	refreshBody, _ := json.Marshal(map[string]string{
		"refresh_token": loginResp.Data.RefreshToken,
	})
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(refreshRec, refreshReq)

	if refreshRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 on refresh after logout, got %d", refreshRec.Code)
	}
}
