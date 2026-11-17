package readiness

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestReadinessHTTPHandler(t *testing.T) {
	checker := NewChecker(zap.NewNop())
	handler := HTTPHandler(checker)

	t.Run("GET /healthz returns 200 OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for /healthz, got %d", rec.Code)
		}

		var summary PublicHealthSummary
		if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
			t.Fatalf("failed to decode health summary: %v", err)
		}
		if summary.Status == "" {
			t.Errorf("expected non-empty status in health summary")
		}
	})

	t.Run("GET /readyz returns 200 OK when ready", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for /readyz, got %d", rec.Code)
		}
	})
}
