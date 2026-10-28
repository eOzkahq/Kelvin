package security_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
)

// TestErrorEnvelopeConformance drives every error-producing path and asserts
// each response conforms to api-error.schema.json: required fields, problem URN,
// status range, UUID correlation_id, problem+json content-type, and that
// errors[] appears only on validation_failed (422).
func TestErrorEnvelopeConformance(t *testing.T) {
	loadErrorSchema(t) // proves the canonical schema is readable & valid JSON

	srv := newTestServer(t)
	defer srv.Close()

	tokenAnalyst := srv.tokenFor(t, principalsA()[RoleAnalyst])
	tokenViewer := srv.tokenFor(t, principalsA()[RoleViewer])

	type probe struct {
		name   string
		method string
		path   string
		token  string
		body   any
		want   int
	}

	probes := []probe{
		{"401 missing header", http.MethodGet, "/api/v1/assessments", "", nil, http.StatusUnauthorized},
		{"401 expired", http.MethodGet, "/api/v1/assessments", expiredTokenString(t), nil, http.StatusUnauthorized},
		{"403 role", http.MethodPost, "/api/v1/assessments", tokenViewer, createBody(), http.StatusForbidden},
		{"404 cross-tenant", http.MethodGet, "/api/v1/assessments/" + AssessmentTenantB.String(), tokenAnalyst, nil, http.StatusNotFound},
		{"404 unknown", http.MethodGet, "/api/v1/assessments/" + uuid.New().String(), tokenAnalyst, nil, http.StatusNotFound},
		{"422 malformed id", http.MethodGet, "/api/v1/assessments/not-a-uuid", tokenAnalyst, nil, http.StatusUnprocessableEntity},
		{"422 mass assignment", http.MethodPost, "/api/v1/assessments", tokenAnalyst, massAssignmentBody(), http.StatusUnprocessableEntity},
		{"404 route", http.MethodGet, "/api/v1/no-such-route", "", nil, http.StatusNotFound},
	}

	for _, pp := range probes {
		t.Run(pp.name, func(t *testing.T) {
			resp := srv.do(t, pp.method, pp.path, pp.token, pp.body)
			p, body := assertProblem(t, resp, pp.want)

			var raw map[string]any
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			_, hasErrors := raw["errors"]
			if pp.want == http.StatusUnprocessableEntity {
				if !hasErrors {
					t.Error("validation_failed must include errors[]")
				}
			} else {
				if hasErrors {
					t.Error("errors[] must be absent on non-validation_failed problems")
				}
			}

			// correlation_id must be echoed on the X-Correlation-ID header.
			if cid := resp.Header.Get("X-Correlation-ID"); cid != p.CorrelationID {
				t.Errorf("X-Correlation-ID header %q != body correlation_id %q", cid, p.CorrelationID)
			}
			_ = raw
		})
	}
}

// TestNoStackTraceOnPanic covers recover middleware: a panicking handler yields
// a sanitized 500 problem, never the panic value or a stack trace.
func TestNoStackTraceOnPanic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/trigger-boom", func(w http.ResponseWriter, r *http.Request) {
		panic("secret internal detail 10.0.0.1 /stacktrace")
	})
	var h http.Handler = mux
	h = httpapi.Recover()(h)
	h = middleware.AccessLog()(h)
	h = middleware.Correlation(h)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/trigger-boom")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	body := readBody(t, resp)
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "10.0.0.1") {
		t.Errorf("panic detail leaked to client: %s", body)
	}
	var p problemBody
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("invalid problem JSON: %v", err)
	}
	if p.Type != "urn:kelvin:problem:internal_error" {
		t.Errorf("problem type = %q", p.Type)
	}
	if p.Status != http.StatusInternalServerError {
		t.Errorf("problem status = %d, want 500", p.Status)
	}
	if p.CorrelationID == "" {
		t.Error("correlation_id missing on recovered panic")
	}
	assertNoInternalLeakage(t, body)
}

// expiredTokenString returns an expired JWT string for the conformance probe.
func expiredTokenString(t *testing.T) string {
	t.Helper()
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
	return signed
}

// massAssignmentBody returns a creation body containing privileged fields that
// must be rejected as unknown fields.
func massAssignmentBody() any {
	return map[string]any{
		"name":      "evil",
		"profileId": "3f1c9a72-5d84-4e0b-9c6a-1b7e2d4f8a55",
		"targets": []any{
			map[string]any{"host": "shop.example.com"},
		},
		"role":      string(RoleTenantAdmin),
		"tenant_id": TenantB.String(),
	}
}
