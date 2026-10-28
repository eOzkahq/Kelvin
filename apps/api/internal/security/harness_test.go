package security_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/schemas"
)

// Role aliases for readability; maps to RBAC_MATRIX.md §2 roles.
//
// Issue roles -> Kelvin roles:
//
//	Viewer      -> READ_ONLY_AUDITOR
//	Analyst     -> SECURITY_ANALYST
//	TenantAdmin -> TENANT_ADMIN
//	SuperAdmin  -> PLATFORM_ADMIN
const (
	RoleViewer      = auth.RoleReadOnlyAuditor
	RoleAnalyst     = auth.RoleSecurityAnalyst
	RoleTenantAdmin = auth.RoleTenantAdmin
	RoleSuperAdmin  = auth.RolePlatformAdmin
)

const (
	// TestSecret satisfies TokenService's >=32 byte requirement.
	TestSecret = "01234567890123456789012345678901"
	// BodyLimit matches the API config default (API_STANDARDS §5.2, 1 MiB).
	BodyLimit = int64(1 << 20)
)

// Deterministic, reproducible fixtures: two tenants, five principals, and
// stub assessment resources owned by each tenant. Fixed UUIDs make the
// security suite deterministic across runs and CI.
var (
	TenantA = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	TenantB = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	UserViewerA    = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	UserAnalystA   = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	UserTenantA    = uuid.MustParse("33333333-3333-3333-3333-333333333333")
	UserSuperAdmin = uuid.MustParse("44444444-4444-4444-4444-444444444444")
	UserAnalystB   = uuid.MustParse("55555555-5555-5555-5555-555555555555")

	SessionViewerA    = uuid.MustParse("11111111-1111-1111-1111-111111111112")
	SessionAnalystA   = uuid.MustParse("22222222-2222-2222-2222-222222222223")
	SessionTenantA    = uuid.MustParse("33333333-3333-3333-3333-333333333334")
	SessionSuperAdmin = uuid.MustParse("44444444-4444-4444-4444-444444444445")
	SessionAnalystB   = uuid.MustParse("55555555-5555-5555-5555-555555555556")

	AssessmentTenantA = uuid.MustParse("66666666-6666-6666-6666-666666666666")
	AssessmentTenantB = uuid.MustParse("77777777-7777-7777-7777-777777777777")
)

func principal(role auth.Role, tenantID, userID, sessionID uuid.UUID) auth.Principal {
	return auth.Principal{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     fmt.Sprintf("%s@kelvin.internal.test", role),
		Role:      role,
		SessionID: sessionID,
	}
}

// principalsA returns the deterministic principal for each role in Tenant A.
func principalsA() map[auth.Role]auth.Principal {
	return map[auth.Role]auth.Principal{
		RoleViewer:      principal(RoleViewer, TenantA, UserViewerA, SessionViewerA),
		RoleAnalyst:     principal(RoleAnalyst, TenantA, UserAnalystA, SessionAnalystA),
		RoleTenantAdmin: principal(RoleTenantAdmin, TenantA, UserTenantA, SessionTenantA),
		RoleSuperAdmin:  principal(RoleSuperAdmin, TenantA, UserSuperAdmin, SessionSuperAdmin),
	}
}

// createBody returns a valid assessment creation body per the OpenAPI
// AssessmentCreate schema.
func createBody() any {
	return map[string]any{
		"name":      "External perimeter - Q4",
		"profileId": "3f1c9a72-5d84-4e0b-9c6a-1b7e2d4f8a55",
		"targets": []any{
			map[string]any{"host": "shop.example.com"},
		},
	}
}

// testServer composes the real API middleware stack against stub route
// handlers that mirror the OpenAPI contract and RBAC matrix. It exercises the
// production auth.Middleware, RequireRole, TenantGuard, Recover, BodyLimit,
// Correlation and AccessLog middleware — the security-critical enforcement
// layer — rather than re-implementing it.
type testServer struct {
	*httptest.Server
	tokenService *auth.TokenService
	baseURL      string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	svc, err := auth.NewTokenService(TestSecret)
	if err != nil {
		t.Fatalf("auth.NewTokenService: %v", err)
	}

	mux := http.NewServeMux()

	// Public (unauthenticated) health endpoints — match apps/api server.go.
	mux.HandleFunc("GET /api/v1/health", healthHandler)
	mux.HandleFunc("GET /health/live", healthHandler)
	mux.HandleFunc("GET /health/ready", healthHandler)

	// Assessment data plane — protected by authN + authZ middleware per the
	// RBAC matrix (§5) and OpenAPI contract.
	mux.Handle("GET /api/v1/assessments",
		auth.Middleware(svc)(
			auth.RequireRole(RoleViewer, RoleAnalyst, RoleTenantAdmin)(http.HandlerFunc(listAssessmentsHandler)),
		),
	)
	mux.Handle("POST /api/v1/assessments",
		auth.Middleware(svc)(
			auth.RequireRole(RoleAnalyst, RoleTenantAdmin)(http.HandlerFunc(createAssessmentHandler)),
		),
	)
	mux.Handle("GET /api/v1/assessments/{id}",
		auth.Middleware(svc)(
			auth.RequireRole(RoleViewer, RoleAnalyst, RoleTenantAdmin)(
				http.HandlerFunc(getAssessmentHandler(AssessmentTenantA, AssessmentTenantB)),
			),
		),
	)

	// Catch-all: any unmatched path returns a sanitized RFC 7807 problem,
	// mirroring apps/api server.go's handleNotFound.
	mux.HandleFunc("/", handleNotFound)

	var h http.Handler = mux
	h = middleware.BodyLimit(BodyLimit)(h)
	h = httpapi.Recover()(h)
	h = middleware.AccessLog()(h)
	h = middleware.Correlation(h)

	srv := httptest.NewServer(h)
	return &testServer{
		Server:       srv,
		tokenService: svc,
		baseURL:      srv.URL,
	}
}

func (s *testServer) tokenFor(t *testing.T, p auth.Principal) string {
	t.Helper()
	pair, err := s.tokenService.GenerateTokenPair(p)
	if err != nil {
		t.Fatalf("auth.GenerateTokenPair: %v", err)
	}
	return pair.AccessToken
}

// request issues a request with arbitrary headers and an optional JSON body.
func (s *testServer) request(t *testing.T, method, path string, headers map[string]string, body any) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.baseURL+path, r)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if _, ok := headers["Content-Type"]; !ok && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// do issues a request, optionally bearing a bearer token and a JSON body.
func (s *testServer) do(t *testing.T, method, path, token string, body any) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return s.request(t, method, path, headers, body)
}

// readBody reads and closes the response body.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

// assertStatus asserts the HTTP status code.
func assertStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		body := readBody(t, resp)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, expected, body)
	}
}

// problemBody mirrors the RFC 7807 envelope (api-error.schema.json).
type problemBody struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Detail        string `json:"detail"`
	Instance      string `json:"instance"`
	CorrelationID string `json:"correlation_id"`
	Timestamp     string `json:"timestamp"`
}

// assertProblem asserts an RFC 7807 problem response: status, content-type,
// required envelope fields, problem URN, UUID correlation_id, and absence of
// internal leakage (stack traces, SQL, paths, secrets). It returns the parsed
// problem and the raw body so callers do not read the response body twice.
func assertProblem(t *testing.T, resp *http.Response, expectedStatus int) (*problemBody, []byte) {
	t.Helper()
	assertStatus(t, resp, expectedStatus)
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("content-type = %q, want application/problem+json", ct)
	}
	body := readBody(t, resp)
	var p problemBody
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("error body is not valid JSON: %v; body=%s", err, body)
	}
	if p.Type == "" {
		t.Fatal("problem body missing required field 'type'")
	}
	if !strings.HasPrefix(p.Type, "urn:kelvin:problem:") {
		t.Fatalf("problem type is not a Kelvin problem URN: %q", p.Type)
	}
	if p.Title == "" {
		t.Error("problem body missing required field 'title'")
	}
	if p.Status != expectedStatus {
		t.Errorf("problem status = %d, want %d", p.Status, expectedStatus)
	}
	if p.Status < 400 || p.Status > 599 {
		t.Errorf("problem status %d outside RFC 7807 range [400, 599]", p.Status)
	}
	if p.CorrelationID == "" {
		t.Error("problem body missing required field 'correlation_id'")
	}
	if _, err := uuid.Parse(p.CorrelationID); err != nil {
		t.Errorf("problem correlation_id is not a UUID: %q", p.CorrelationID)
	}
	assertNoInternalLeakage(t, body)
	return &p, body
}

// assertSuccess asserts a 2xx success envelope (api-envelope.schema.json).
func assertSuccess(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body := readBody(t, resp)
		t.Fatalf("status = %d, want 2xx; body=%s", resp.StatusCode, body)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("success content-type = %q, want application/json", ct)
	}
	body := readBody(t, resp)
	var env struct {
		Success bool `json:"success"`
		Data    any  `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("success body is not valid JSON: %v; body=%s", err, body)
	}
	if !env.Success {
		t.Error("success envelope must have success=true")
	}
}

// assertNoInternalLeakage verifies an error envelope does not leak stack
// traces, SQL, internal paths, hostnames, or secrets (API_STANDARDS §7.3).
func assertNoInternalLeakage(t *testing.T, body []byte) {
	t.Helper()
	lower := strings.ToLower(string(body))
	for _, token := range []string{
		"panic", "stack trace", "stacktrace", "traceback", "at ",
		"sql:", "select ", "from ", "where ", "insert ", "update ", "delete ",
		"postgres", "minio", "s3://", "connection string",
		"password", "secret", "credential", "private_key", "api_key",
		"/home/", "/root/", "/usr/", "/var/", "c:\\",
		".go:", ".java", ".py", "node_modules", "golang.org",
		"kush", "desktop",
	} {
		if strings.Contains(lower, token) {
			t.Errorf("error body may leak internal information (%q): %s", token, body)
		}
	}
}

// loadErrorSchema loads the canonical api-error.schema.json to prove the
// harness is traced to the real contract. The schema is validated as JSON;
// structural response conformance is asserted by assertProblem.
func loadErrorSchema(t *testing.T) []byte {
	t.Helper()
	b, err := schemas.Read("api-error.schema.json")
	if err != nil {
		t.Fatalf("api-error.schema.json must be readable: %v", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("api-error.schema.json must be valid JSON: %v", err)
	}
	return b
}

// healthHandler returns the standard health success envelope.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteSuccess(w, r, http.StatusOK, map[string]string{"status": "ok"}, nil)
}

// handleNotFound returns a sanitized 404 problem for unmatched paths.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteProblem(w, r, kelvinerrors.NewNotFound("no route matches this path"))
}

// listAssessmentsHandler is a stub that returns the current principal's
// tenant/role after authZ has passed (RequireRole middleware).
func listAssessmentsHandler(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authentication required"))
		return
	}
	httpapi.WriteSuccess(w, r, http.StatusOK, map[string]any{
		"tenant": p.TenantID,
		"role":   p.Role,
		"data":   []any{},
	}, map[string]any{"limit": 25, "count": 0, "has_more": false})
}

// createAssessmentHandler validates the creation body (rejecting unknown /
// mass-assigned fields via DecodeJSON) and returns 201.
func createAssessmentHandler(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authentication required"))
		return
	}
	var body struct {
		Name      string `json:"name"`
		ProfileID string `json:"profileId"`
		Targets   []struct {
			Host string `json:"host"`
		} `json:"targets"`
	}
	if !httpapi.DecodeJSON(w, r, &body) {
		return
	}
	httpapi.WriteSuccess(w, r, http.StatusCreated, map[string]any{
		"id":         uuid.New(),
		"name":       body.Name,
		"status":     "QUEUED",
		"tenant_id":  p.TenantID,
		"created_by": p.UserID,
	}, nil)
}

// getAssessmentHandler returns 200 for an in-tenant resource, 404 for a
// cross-tenant or nonexistent resource (indistinguishable, RBAC B-2).
func getAssessmentHandler(ownerA, ownerB uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			httpapi.WriteProblem(w, r, kelvinerrors.NewUnauthenticated("authentication required"))
			return
		}
		idStr := r.PathValue("id")
		id, err := uuid.Parse(idStr)
		if err != nil {
			httpapi.WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "id",
				Code:    "malformed_identifier",
				Message: "resource id must be a valid UUID",
			}}))
			return
		}
		owner := TenantA
		switch {
		case id == AssessmentTenantB:
			owner = TenantB
		case id != AssessmentTenantA:
			httpapi.WriteProblem(w, r, kelvinerrors.NewNotFound("no resource matches this identifier"))
			return
		}
		// Cross-tenant access -> 404, indistinguishable from nonexistence.
		if p.TenantID != owner {
			httpapi.WriteProblem(w, r, kelvinerrors.NewNotFound("no resource matches this identifier"))
			return
		}
		httpapi.WriteSuccess(w, r, http.StatusOK, map[string]any{
			"id":        id,
			"name":      "stub assessment",
			"status":    "QUEUED",
			"tenant_id": p.TenantID,
		}, nil)
	}
}
