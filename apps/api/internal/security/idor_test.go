package security_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/api/internal/auth"
)

// TestCrossTenantReadIs404 covers AC-BOLA-01: Tenant A analyst reading a
// Tenant B resource returns 404 indistinguishable from nonexistence (zero
// leakage — no resource fields, no echoed resource id).
func TestCrossTenantReadIs404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tokenA := srv.tokenFor(t, principalsA()[RoleAnalyst])

	resp := srv.do(t, http.MethodGet, "/api/v1/assessments/"+AssessmentTenantB.String(), tokenA, nil)
	p, body := assertProblem(t, resp, http.StatusNotFound)

	// Zero leakage: the response must be indistinguishable from a
	// nonexistent-resource 404 (RBAC B-2 / API_STANDARDS §7.2). The `instance`
	// field echoes the client's own request path, so the requested id appearing
	// there is client-supplied data, not a server leak. What must NOT appear is
	// any server-side resource data or a 403 that would confirm existence.
	if strings.Contains(string(body), "tenant_b") {
		t.Errorf("404 body must not leak the target tenant label")
	}
	// The problem type must be not_found, not forbidden (existence must not be
	// disclosed — RBAC B-2 / API_STANDARDS §7.2).
	if p.Type != "urn:kelvin:problem:not_found" {
		t.Errorf("cross-tenant read must be not_found, got %q", p.Type)
	}
	// The detail must be generic, never confirming the resource exists.
	if strings.Contains(p.Detail, AssessmentTenantB.String()) || strings.Contains(p.Detail, TenantB.String()) {
		t.Errorf("404 detail must not confirm the requested resource: %q", p.Detail)
	}
}

// TestCrossTenantTenantGuardDirect exercises TenantGuard middleware directly:
// a principal whose tenant != expected tenant receives 403 (RBAC B-2 §4.4:
// 403 is reserved for same-tenant insufficient role; the guard itself returns
// 403, handlers convert cross-tenant data reads to 404).
func TestCrossTenantTenantGuardDirect(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tokenA := srv.tokenFor(t, principalsA()[RoleAnalyst])

	// Direct TenantGuard check: principal TenantA, guard expects TenantB -> 403.
	guardHandler := auth.Middleware(srv.tokenService)(
		auth.TenantGuard(TenantB)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)
	req, _ := http.NewRequest(http.MethodGet, srv.baseURL+"/api/v1/assessments/x", nil)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	rec := &statusRecorder{header: make(http.Header), code: 0}
	guardHandler.ServeHTTP(rec, req)
	if rec.code != http.StatusForbidden {
		t.Fatalf("TenantGuard cross-tenant status = %d, want 403", rec.code)
	}
}

// TestPlatformAdminNoTenantData covers RBAC B-6: a PLATFORM_ADMIN (SuperAdmin)
// session must not read tenant data-plane resources.
func TestPlatformAdminNoTenantData(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tokenSuper := srv.tokenFor(t, principalsA()[RoleSuperAdmin])

	// List assessments: SuperAdmin not in require-role list -> 403.
	resp := srv.do(t, http.MethodGet, "/api/v1/assessments", tokenSuper, nil)
	assertProblem(t, resp, http.StatusForbidden)

	// Get a Tenant A resource: SuperAdmin denied by role guard -> 403.
	resp = srv.do(t, http.MethodGet, "/api/v1/assessments/"+AssessmentTenantA.String(), tokenSuper, nil)
	assertProblem(t, resp, http.StatusForbidden)
}

// statusRecorder captures status for direct middleware invocation.
type statusRecorder struct {
	header http.Header
	code   int
}

func (r *statusRecorder) Header() http.Header         { return r.header }
func (r *statusRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *statusRecorder) WriteHeader(code int)        { r.code = code }
