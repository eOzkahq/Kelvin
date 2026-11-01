package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
	"github.com/kelvin/kelvin/apps/api/pkg/job"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	schemas "github.com/kelvin/kelvin/packages/schemas"
	"go.uber.org/zap"
)

func newHandler() http.Handler {
	return New(config.Config{
		APIVersion:     "1.0.0-alpha",
		BodyLimitBytes: 1 << 20,
	}, zap.NewNop()).Handler()
}

func TestHealthReturnsStandardEnvelope(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	if rec.Header().Get(middleware.CorrelationHeader) == "" {
		t.Fatal("correlation header missing on success response")
	}
	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Status     string `json:"status"`
			APIVersion string `json:"apiVersion"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !body.Success || body.Data.Status != "ok" || body.Data.APIVersion != "1.0.0-alpha" {
		t.Fatalf("unexpected envelope: %s", rec.Body.String())
	}
}

func TestValidCorrelationIDEchoed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set(middleware.CorrelationHeader, "test-abc.123")
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)
	if got := rec.Header().Get(middleware.CorrelationHeader); got != "test-abc.123" {
		t.Fatalf("correlation = %q, want echoed client value", got)
	}
}

func TestInvalidCorrelationIDRegenerated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set(middleware.CorrelationHeader, "not a valid id!")
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)
	got := rec.Header().Get(middleware.CorrelationHeader)
	if got == "" || got == "not a valid id!" || len(got) != 36 {
		t.Fatalf("expected fresh UUID, got %q", got)
	}
}

func TestUnknownPathReturnsProblemNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil)
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("content-type = %q, want problem+json", ct)
	}
	var problem struct {
		Type          string `json:"type"`
		Status        int    `json:"status"`
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("invalid problem JSON: %v", err)
	}
	if problem.Type != "urn:kelvin:problem:not_found" || problem.Status != 404 {
		t.Fatalf("unexpected problem: %+v", problem)
	}
	if problem.CorrelationID != rec.Header().Get(middleware.CorrelationHeader) {
		t.Fatal("problem correlation_id must match the X-Correlation-ID header")
	}
}

func TestWrongMethodReturns405WithAllow(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET" {
		t.Fatalf("Allow = %q, want GET", allow)
	}
	var problem struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &problem)
	if problem.Type != "urn:kelvin:problem:method_not_allowed" {
		t.Fatalf("problem type = %q", problem.Type)
	}
}

func TestPanicYieldsSanitized500Problem(t *testing.T) {
	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("secret internal detail 10.0.0.1")
	})
	var h http.Handler = boom
	h = Recover()(h)
	h = middleware.AccessLog()(h)
	h = middleware.Correlation(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.1") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("panic value leaked to client: %s", rec.Body.String())
	}
	var problem struct {
		Type          string `json:"type"`
		CorrelationID string `json:"correlation_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &problem)
	if problem.Type != "urn:kelvin:problem:internal_error" {
		t.Fatalf("problem type = %q", problem.Type)
	}
	if problem.CorrelationID == "" {
		t.Fatal("correlation_id missing on recovered panic")
	}
}

func TestSharedContractsImportableFromAPI(t *testing.T) {
	for _, name := range []string{"finding.v1.json", "api-envelope.schema.json", "api-error.schema.json"} {
		if _, err := schemas.Read(name); err != nil {
			t.Errorf("api cannot read shared contract %s: %v", name, err)
		}
	}
}

// mockJobStore is a test double for jobStoreIface.
type mockJobStore struct {
	transitionErr error
	transitionID  string
	transitionTo  job.State
}

func (m *mockJobStore) Transition(ctx context.Context, id string, to job.State, workerID string) error {
	m.transitionID = id
	m.transitionTo = to
	return m.transitionErr
}

func newHandlerWithStore(store jobStoreIface) http.Handler {
	s := New(config.Config{
		APIVersion:     "1.0.0-alpha",
		BodyLimitBytes: 1 << 20,
	}, zap.NewNop())
	s.SetJobStore(store)
	s.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler { return next })
	return s.Handler()
}

func TestCancelAssessmentWithoutStoreReturns503(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+uuid.New().String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestProtectedCancelRouteFailsClosedWithoutSecurityMiddleware(t *testing.T) {
	store := &mockJobStore{}
	s := New(config.Config{APIVersion: "1.0.0-alpha", BodyLimitBytes: 1 << 20}, zap.NewNop())
	s.SetJobStore(store)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+uuid.NewString()+"/cancel", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when authentication is not configured", rec.Code)
	}
	if store.transitionID != "" {
		t.Fatal("protected route reached job store without security middleware")
	}
}

func TestCancelAssessmentSuccess(t *testing.T) {
	store := &mockJobStore{}
	id := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	newHandlerWithStore(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if store.transitionID != id.String() {
		t.Errorf("transition id = %q, want %q", store.transitionID, id.String())
	}
	if store.transitionTo != job.Cancelled {
		t.Errorf("transition to = %q, want %q", store.transitionTo, job.Cancelled)
	}
}

func TestCancelAssessmentInvalidUUID(t *testing.T) {
	store := &mockJobStore{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/not-a-uuid/cancel", nil)
	rec := httptest.NewRecorder()
	newHandlerWithStore(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if store.transitionErr != nil {
		t.Errorf("transition should not be called for invalid UUID, got err=%v", store.transitionErr)
	}
}

func TestCancelAssessmentTerminalStateReturns409(t *testing.T) {
	store := &mockJobStore{transitionErr: job.ErrInvalidTransition}
	id := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	newHandlerWithStore(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestCancelAssessmentNotFoundReturns404(t *testing.T) {
	store := &mockJobStore{transitionErr: job.ErrNotFound}
	id := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	newHandlerWithStore(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestCancelAssessmentInternalErrorReturns500(t *testing.T) {
	store := &mockJobStore{transitionErr: errors.New("db connection lost")}
	id := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	newHandlerWithStore(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

var _ = kelvinerrors.NewNotFound
