package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func setupTestService(t *testing.T) (*Service, *MemoryRepository, *User) {
	t.Helper()
	repo := NewMemoryRepository()
	tokenService, err := NewTokenService("testSecretKeyMustBeAtLeast32BytesLong12345!")
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	tenantID := uuid.New()
	userID := uuid.New()
	hash, err := HashPassword("SuperSecret123!")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	tenant := &Tenant{
		ID:     tenantID,
		Name:   "Acme Security Corp",
		Slug:   "acme-sec",
		Status: "ACTIVE",
	}

	user := &User{
		ID:           userID,
		TenantID:     tenantID,
		Email:        "admin@acme.com",
		DisplayName:  "Alice Admin",
		PasswordHash: hash,
		Role:         RoleTenantAdmin,
		IsActive:     true,
	}

	if err := repo.CreateTenantAndAdmin(context.Background(), tenant, user); err != nil {
		t.Fatalf("failed to create test tenant and user: %v", err)
	}

	service := NewService(repo, tokenService)
	return service, repo, user
}

func TestService_Login_Success(t *testing.T) {
	service, _, user := setupTestService(t)

	pair, loggedInUser, err := service.Login(context.Background(), "admin@acme.com", "SuperSecret123!", "Mozilla/5.0", "127.0.0.1")
	if err != nil {
		t.Fatalf("expected successful login, got: %v", err)
	}

	if pair == nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected non-empty token pair")
	}

	if loggedInUser.ID != user.ID {
		t.Errorf("expected user ID %v, got %v", user.ID, loggedInUser.ID)
	}

	if loggedInUser.Role != RoleTenantAdmin {
		t.Errorf("expected role %v, got %v", RoleTenantAdmin, loggedInUser.Role)
	}

	if loggedInUser.TenantName != "Acme Security Corp" {
		t.Errorf("expected tenant name 'Acme Security Corp', got '%s'", loggedInUser.TenantName)
	}
}

func TestService_Login_InvalidPassword(t *testing.T) {
	service, _, _ := setupTestService(t)

	_, _, err := service.Login(context.Background(), "admin@acme.com", "WrongPassword!", "Mozilla/5.0", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error on invalid password, got nil")
	}
}

func TestService_Login_UnknownUser(t *testing.T) {
	service, _, _ := setupTestService(t)

	_, _, err := service.Login(context.Background(), "unknown@example.com", "SomePassword123!", "Mozilla/5.0", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error on unknown user, got nil")
	}
}

func TestService_Refresh_SuccessAndRotation(t *testing.T) {
	service, _, user := setupTestService(t)

	pair1, _, err := service.Login(context.Background(), "admin@acme.com", "SuperSecret123!", "Mozilla/5.0", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	pair2, refreshedUser, err := service.Refresh(context.Background(), pair1.RefreshToken, "Mozilla/5.0", "127.0.0.1")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	if pair2.AccessToken == "" || pair2.RefreshToken == "" {
		t.Fatal("expected non-empty tokens in refreshed pair")
	}
	if pair2.RefreshToken == pair1.RefreshToken {
		t.Fatal("expected rotated refresh token to be different from original")
	}
	if refreshedUser.ID != user.ID {
		t.Errorf("expected user ID %v, got %v", user.ID, refreshedUser.ID)
	}
}

func TestService_Refresh_TokenReuseDetection(t *testing.T) {
	service, _, _ := setupTestService(t)

	pair1, _, err := service.Login(context.Background(), "admin@acme.com", "SuperSecret123!", "Mozilla/5.0", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// 1st refresh with pair1 -> succeeds and rotates to pair2
	pair2, _, err := service.Refresh(context.Background(), pair1.RefreshToken, "Mozilla/5.0", "127.0.0.1")
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}

	// 2nd refresh with the ALREADY USED pair1 -> should detect reuse and fail
	_, _, err = service.Refresh(context.Background(), pair1.RefreshToken, "Mozilla/5.0", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error on reused refresh token, got nil")
	}

	// Attempting to refresh with pair2 should ALSO now fail because the entire token family was revoked!
	_, _, err = service.Refresh(context.Background(), pair2.RefreshToken, "Mozilla/5.0", "127.0.0.1")
	if err == nil {
		t.Fatal("expected compromised token family to be completely revoked, but refresh succeeded")
	}
}

func TestService_Logout(t *testing.T) {
	service, _, _ := setupTestService(t)

	pair, _, err := service.Login(context.Background(), "admin@acme.com", "SuperSecret123!", "Mozilla/5.0", "127.0.0.1")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	verified, err := service.tokenService.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("verify access token failed: %v", err)
	}

	// Logout using session ID
	if err := service.Logout(context.Background(), verified.SessionID); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	// Attempting to refresh after logout should fail
	_, _, err = service.Refresh(context.Background(), pair.RefreshToken, "Mozilla/5.0", "127.0.0.1")
	if err == nil {
		t.Fatal("expected refresh to fail after logout, but it succeeded")
	}
}

func TestService_GetMe(t *testing.T) {
	service, _, user := setupTestService(t)

	me, err := service.GetMe(context.Background(), user.TenantID, user.ID)
	if err != nil {
		t.Fatalf("GetMe failed: %v", err)
	}

	if me.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, me.Email)
	}
	if me.TenantName != "Acme Security Corp" {
		t.Errorf("expected tenant name 'Acme Security Corp', got '%s'", me.TenantName)
	}
}
