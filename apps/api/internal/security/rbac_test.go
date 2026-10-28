package security_test

import (
	"net/http"
	"testing"

	"github.com/kelvin/kelvin/apps/api/internal/auth"
)

// TestRBACMatrix exercises the authorization matrix (RBAC_MATRIX.md §5) across
// all exposed API endpoints and every role. Deny-by-default: any role not
// explicitly granted receives 403; unauthenticated requests receive 401.
func TestRBACMatrix(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	principals := principalsA()

	type matrixCase struct {
		name   string
		method string
		path   string
		body   any
		role   auth.Role // "" = unauthenticated
		want   int
	}

	cases := []matrixCase{
		// --- Public health (no auth) ---
		{"health unauthenticated", http.MethodGet, "/api/v1/health", nil, "", http.StatusOK},
		{"health analyst", http.MethodGet, "/api/v1/health", nil, RoleAnalyst, http.StatusOK},

		// --- GET /api/v1/assessments (list) ---
		// Matrix: assessment:read granted to TENANT_ADMIN, SECURITY_ANALYST,
		// READ_ONLY_AUDITOR. PLATFORM_ADMIN has no standing tenant data-plane.
		{"list unauthenticated", http.MethodGet, "/api/v1/assessments", nil, "", http.StatusUnauthorized},
		{"list viewer", http.MethodGet, "/api/v1/assessments", nil, RoleViewer, http.StatusOK},
		{"list analyst", http.MethodGet, "/api/v1/assessments", nil, RoleAnalyst, http.StatusOK},
		{"list tenant admin", http.MethodGet, "/api/v1/assessments", nil, RoleTenantAdmin, http.StatusOK},
		{"list super admin denied", http.MethodGet, "/api/v1/assessments", nil, RoleSuperAdmin, http.StatusForbidden},

		// --- POST /api/v1/assessments (create) ---
		// Matrix: assessment:create granted to TENANT_ADMIN, SECURITY_ANALYST.
		{"create unauthenticated", http.MethodPost, "/api/v1/assessments", createBody(), "", http.StatusUnauthorized},
		{"create viewer denied", http.MethodPost, "/api/v1/assessments", createBody(), RoleViewer, http.StatusForbidden},
		{"create analyst", http.MethodPost, "/api/v1/assessments", createBody(), RoleAnalyst, http.StatusCreated},
		{"create tenant admin", http.MethodPost, "/api/v1/assessments", createBody(), RoleTenantAdmin, http.StatusCreated},
		{"create super admin denied", http.MethodPost, "/api/v1/assessments", createBody(), RoleSuperAdmin, http.StatusForbidden},

		// --- GET /api/v1/assessments/{id} (read one, Tenant A resource) ---
		{"get A unauthenticated", http.MethodGet, assessmentPathA(), nil, "", http.StatusUnauthorized},
		{"get A viewer", http.MethodGet, assessmentPathA(), nil, RoleViewer, http.StatusOK},
		{"get A analyst", http.MethodGet, assessmentPathA(), nil, RoleAnalyst, http.StatusOK},
		{"get A tenant admin", http.MethodGet, assessmentPathA(), nil, RoleTenantAdmin, http.StatusOK},
		{"get A super admin denied", http.MethodGet, assessmentPathA(), nil, RoleSuperAdmin, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var token string
			if tc.role != "" {
				token = srv.tokenFor(t, principals[tc.role])
			}
			resp := srv.do(t, tc.method, tc.path, token, tc.body)
			if tc.want >= http.StatusBadRequest {
				_, _ = assertProblem(t, resp, tc.want)
				return
			}
			assertStatus(t, resp, tc.want)
			// On success, the success envelope must be emitted (never a problem).
			assertSuccess(t, resp)
		})
	}
}

func assessmentPathA() string {
	return "/api/v1/assessments/" + AssessmentTenantA.String()
}

// TestRBACRoleImmutability covers AC-PRIV-01: a non-principal may not elevate
// their own role via a mass-assigned role field on a self-update style path.
func TestRBACRoleImmutability(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])
	body := map[string]any{
		"name":  "renamed",
		"role":  string(RoleTenantAdmin), // privilege escalation attempt
		"email": "analyst@example.com",
	}
	// POST /assessments rejects unknown fields incl. role -> 422, not elevation.
	resp := srv.do(t, http.MethodPost, "/api/v1/assessments", token, body)
	assertProblem(t, resp, http.StatusUnprocessableEntity)
}
