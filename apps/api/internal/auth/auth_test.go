package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestPasswordHashing(t *testing.T) {
	password := "superSecretPassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("expected successful hash, got: %v", err)
	}

	if hash == password {
		t.Fatal("hash should not equal plaintext password")
	}

	if !CheckPassword(password, hash) {
		t.Fatal("CheckPassword should return true for valid password")
	}

	if CheckPassword("wrongPassword", hash) {
		t.Fatal("CheckPassword should return false for invalid password")
	}

	// Empty password should fail
	_, err = HashPassword("")
	if err == nil {
		t.Fatal("expected error on empty password, got nil")
	}
}

func TestJWTGenerationAndVerification(t *testing.T) {
	secretKey := "01234567890123456789012345678901" // 32 bytes
	service, err := NewTokenService(secretKey)
	if err != nil {
		t.Fatalf("failed to create TokenService: %v", err)
	}

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	principal := Principal{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     "analyst@example.com",
		Role:      RoleSecurityAnalyst,
		SessionID: sessionID,
	}

	pair, err := service.GenerateTokenPair(principal)
	if err != nil {
		t.Fatalf("GenerateTokenPair failed: %v", err)
	}

	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected non-empty tokens in pair")
	}

	// Verify valid token
	verified, err := service.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed on valid token: %v", err)
	}

	if verified.UserID != userID {
		t.Errorf("expected UserID %v, got %v", userID, verified.UserID)
	}
	if verified.TenantID != tenantID {
		t.Errorf("expected TenantID %v, got %v", tenantID, verified.TenantID)
	}
	if verified.Role != RoleSecurityAnalyst {
		t.Errorf("expected Role %v, got %v", RoleSecurityAnalyst, verified.Role)
	}
}

func TestJWTNegativeSecurityVectors(t *testing.T) {
	secretKey := "01234567890123456789012345678901"
	service, _ := NewTokenService(secretKey)

	// Vector 1: Tampered token signature
	tamperedService, _ := NewTokenService("differentSecretKeyMustBe32BytesLong!")
	p := Principal{
		UserID:   uuid.New(),
		TenantID: uuid.New(),
		Role:     RoleTenantAdmin,
	}
	forgedPair, _ := tamperedService.GenerateTokenPair(p)

	_, err := service.VerifyAccessToken(forgedPair.AccessToken)
	if err == nil {
		t.Fatal("expected signature verification failure for forged token, got nil")
	}

	// Vector 2: Expired token
	now := time.Now().UTC()
	expiredClaims := Claims{
		UserID:   uuid.New().String(),
		TenantID: uuid.New().String(),
		Role:     string(RoleSecurityAnalyst),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    DefaultIssuer,
			Audience:  jwt.ClaimStrings{DefaultAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Minute)), // Expired in past
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	signedExpired, _ := expiredToken.SignedString([]byte(secretKey))

	_, err = service.VerifyAccessToken(signedExpired)
	if err == nil {
		t.Fatal("expected error on expired token, got nil")
	}
}

func TestAuthMiddlewareAndTenantGuard(t *testing.T) {
	secretKey := "01234567890123456789012345678901"
	service, _ := NewTokenService(secretKey)

	tenantA := uuid.New()
	tenantB := uuid.New()
	userA := uuid.New()

	principalA := Principal{
		UserID:   userA,
		TenantID: tenantA,
		Role:     RoleSecurityAnalyst,
	}
	pairA, _ := service.GenerateTokenPair(principalA)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	protectedHandler := Middleware(service)(
		TenantGuard(tenantA)(
			RequireRole(RoleSecurityAnalyst)(handler),
		),
	)

	// Case 1: Unauthenticated -> 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	recUnauth := httptest.NewRecorder()
	protectedHandler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated request, got %d", recUnauth.Code)
	}

	// Case 2: Authenticated for Tenant A -> 200 OK
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+pairA.AccessToken)
	recAuth := httptest.NewRecorder()
	protectedHandler.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid auth, got %d", recAuth.Code)
	}

	// Case 3: Cross-tenant attack (Principal belongs to Tenant A, resource belongs to Tenant B) -> 403 Forbidden
	crossTenantHandler := Middleware(service)(
		TenantGuard(tenantB)(handler),
	)
	recCross := httptest.NewRecorder()
	crossTenantHandler.ServeHTTP(recCross, reqAuth)
	if recCross.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on cross-tenant IDOR attempt, got %d", recCross.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewMemoryRateLimiter(3, 1*time.Minute)
	clientIP := "192.168.1.50"

	if !limiter.Allow(clientIP) {
		t.Fatal("expected request 1 to be allowed")
	}
	if !limiter.Allow(clientIP) {
		t.Fatal("expected request 2 to be allowed")
	}
	if !limiter.Allow(clientIP) {
		t.Fatal("expected request 3 to be allowed")
	}

	// 4th request should exceed the limit
	if limiter.Allow(clientIP) {
		t.Fatal("expected request 4 to be rejected by rate limiter")
	}

	// Distinct client IP should still be allowed
	if !limiter.Allow("192.168.1.99") {
		t.Fatal("expected different IP to be allowed")
	}
}

