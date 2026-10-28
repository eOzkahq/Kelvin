package security_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestMassAssignmentRejected covers mass-assignment: unexpected / privileged
// properties (role, tenant_id, status) must be rejected with 422 rather than
// silently bound. DecodeJSON's DisallowUnknownFields enforces this.
func TestMassAssignmentRejected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])

	body := map[string]any{
		"name":      "evil",
		"profileId": "3f1c9a72-5d84-4e0b-9c6a-1b7e2d4f8a55",
		"targets": []any{
			map[string]any{"host": "shop.example.com"},
		},
		// Privileged / unexpected fields a malicious client may inject:
		"role":       string(RoleTenantAdmin),
		"tenant_id":  TenantB.String(),
		"status":     "COMPLETED",
		"created_by": "00000000-0000-0000-0000-000000000000",
	}
	resp := srv.do(t, http.MethodPost, "/api/v1/assessments", token, body)
	_, pbody := assertProblem(t, resp, http.StatusUnprocessableEntity)

	// errors[] MUST be present on validation_failed and the body must name the
	// offending field(s), never silently accept them.
	if !strings.Contains(string(pbody), "unknown_field") {
		t.Errorf("422 body should identify unknown field(s): %s", pbody)
	}
}

// TestUnexpectedRootFieldRejected covers an unexpected top-level property.
func TestUnexpectedRootFieldRejected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])
	body := map[string]any{
		"name":    "evil",
		"isAdmin": true, // unexpected root field
	}
	resp := srv.do(t, http.MethodPost, "/api/v1/assessments", token, body)
	_, _ = assertProblem(t, resp, http.StatusUnprocessableEntity)
}

// TestOversizedPayloadRejected covers oversized request bodies -> 413, and the
// response must remain a sanitized problem envelope (no stack traces).
func TestOversizedPayloadRejected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])

	// JSON body exceeding the 1 MiB gateway cap.
	big := strings.Repeat("a", int(BodyLimit)+1)
	body := map[string]any{
		"name":      big,
		"profileId": "3f1c9a72-5d84-4e0b-9c6a-1b7e2d4f8a55",
		"targets": []any{
			map[string]any{"host": "shop.example.com"},
		},
	}
	resp := srv.do(t, http.MethodPost, "/api/v1/assessments", token, body)
	_, _ = assertProblem(t, resp, http.StatusRequestEntityTooLarge)
}

// TestMalformedIdentifierRejected covers malformed / non-UUID resource ids.
func TestMalformedIdentifierRejected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])

	cases := []string{"not-a-uuid", "12345", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			resp := srv.do(t, http.MethodGet, "/api/v1/assessments/"+id, token, nil)
			_, _ = assertProblem(t, resp, http.StatusUnprocessableEntity)
		})
	}
}

// TestUnknownResourceReturns404 covers a well-formed UUID that maps to nothing.
func TestUnknownResourceReturns404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])
	resp := srv.do(t, http.MethodGet, "/api/v1/assessments/"+uuid.New().String(), token, nil)
	_, _ = assertProblem(t, resp, http.StatusNotFound)
}

// TestUnexpectedContentTypeRejected covers non-JSON bodies -> 415.
func TestUnexpectedContentTypeRejected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])
	resp := srv.request(t, http.MethodPost, "/api/v1/assessments",
		map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "text/plain",
		}, "plain text body")
	_, _ = assertProblem(t, resp, http.StatusUnsupportedMediaType)
}

// TestEmptyBodyRejected covers a POST with an empty JSON body -> 400.
func TestEmptyBodyRejected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := srv.tokenFor(t, principalsA()[RoleAnalyst])
	resp := srv.request(t, http.MethodPost, "/api/v1/assessments",
		map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
		}, nil)
	_, _ = assertProblem(t, resp, http.StatusBadRequest)
}

// TestNonexistentRouteReturnsProblem covers the catch-all not-found -> 404 problem.
func TestNonexistentRouteReturnsProblem(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := srv.do(t, http.MethodGet, "/api/v1/does-not-exist", "", nil)
	_, _ = assertProblem(t, resp, http.StatusNotFound)
}
