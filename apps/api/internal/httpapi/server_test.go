package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
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
