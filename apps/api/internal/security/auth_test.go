package security_test

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
)

// TestAuthenticationMissingHeader covers AC-TOKEN: missing credentials -> 401.
func TestAuthenticationMissingHeader(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", "", nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationMalformedHeader covers malformed Authorization headers.
func TestAuthenticationMalformedHeader(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	cases := []struct {
		name    string
		authVal string
	}{
		{"wrong scheme (Basic)", "Basic notabearertoken"},
		{"bearer with no token", "Bearer"},
		{"empty bearer token", "Bearer "},
		{"whitespace only", " "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := srv.request(t, http.MethodGet, "/api/v1/assessments",
				map[string]string{"Authorization": tc.authVal}, nil)
			_, _ = assertProblem(t, resp, http.StatusUnauthorized)
		})
	}
}

// TestAuthenticationGarbageToken covers a non-JWT bearer value.
func TestAuthenticationGarbageToken(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", "not-a-jwt-at-all", nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationExpiredToken covers AC-TOKEN-03: expired access token -> 401.
func TestAuthenticationExpiredToken(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	claims := auth.Claims{
		UserID:    uuid.New().String(),
		TenantID:  TenantA.String(),
		Role:      string(RoleAnalyst),
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    auth.DefaultIssuer,
			Audience:  jwt.ClaimStrings{auth.DefaultAudience},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(TestSecret))
	if err != nil {
		t.Fatalf("signing expired token: %v", err)
	}

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", signed, nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationTamperedSignature covers AC-TOKEN-02: token re-signed with
// an attacker-controlled key -> 401.
func TestAuthenticationTamperedSignature(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	attackerSvc, err := auth.NewTokenService("differentSecretKeyMustBe32BytesLong!")
	if err != nil {
		t.Fatalf("attacker TokenService: %v", err)
	}
	forged := principal(RoleTenantAdmin, TenantA, UserTenantA, SessionTenantA)
	pair, err := attackerSvc.GenerateTokenPair(forged)
	if err != nil {
		t.Fatalf("attacker GenerateTokenPair: %v", err)
	}

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", pair.AccessToken, nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationAlgNone covers AC-TOKEN-01: alg:none token -> 401.
// jwt/v5 refuses to sign 'none' tokens, so we craft a raw compact-serialized
// 'none' JWT and rely on the middleware's signing-method allow-list to reject it.
func TestAuthenticationAlgNone(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"uid":"11111111-1111-1111-1111-111111111111",
		"tid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"role":"SECURITY_ANALYST",
		"sid":"22222222-2222-2222-2222-222222222222",
		"iss":"kelvin.auth",
		"aud":"kelvin.api",
		"sub":"11111111-1111-1111-1111-111111111111"
	}`))
	signed := header + "." + payload + "."

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", signed, nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationWrongAudience covers AC-TOKEN-05: wrong aud -> 401.
func TestAuthenticationWrongAudience(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	claims := auth.Claims{
		UserID:    uuid.New().String(),
		TenantID:  TenantA.String(),
		Role:      string(RoleAnalyst),
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    auth.DefaultIssuer,
			Audience:  jwt.ClaimStrings{"not-kelvin-api"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(TestSecret))
	if err != nil {
		t.Fatalf("signing wrong-aud token: %v", err)
	}

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", signed, nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationWrongIssuer covers AC-TOKEN-05: wrong iss -> 401.
func TestAuthenticationWrongIssuer(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	claims := auth.Claims{
		UserID:    uuid.New().String(),
		TenantID:  TenantA.String(),
		Role:      string(RoleAnalyst),
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "not-kelvin-auth",
			Audience:  jwt.ClaimStrings{auth.DefaultAudience},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(TestSecret))
	if err != nil {
		t.Fatalf("signing wrong-iss token: %v", err)
	}

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", signed, nil)
	_, _ = assertProblem(t, resp, http.StatusUnauthorized)
}

// TestAuthenticationValidTokenSucceeds is the positive control: a well-formed
// token for an authorized role yields 2xx.
func TestAuthenticationValidTokenSucceeds(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])
	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", token, nil)
	assertSuccess(t, resp)
}
