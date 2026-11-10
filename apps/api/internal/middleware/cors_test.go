package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	allowed := []string{"https://eozka.com", "https://staging.eozka.com"}
	corsMiddleware := CORS(allowed)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := corsMiddleware(dummyHandler)

	t.Run("Allowed origin preflight OPTIONS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/findings", nil)
		req.Header.Set("Origin", "https://eozka.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content for preflight, got %d", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "https://eozka.com" {
			t.Errorf("expected Access-Control-Allow-Origin: https://eozka.com, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
		}
		if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Errorf("expected Access-Control-Allow-Credentials: true")
		}
	})

	t.Run("Allowed origin GET request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
		req.Header.Set("Origin", "https://eozka.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "https://eozka.com" {
			t.Errorf("expected Access-Control-Allow-Origin: https://eozka.com, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("Disallowed origin preflight OPTIONS returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/findings", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for unauthorized origin preflight, got %d", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("expected empty Access-Control-Allow-Origin for unauthorized origin")
		}
	})

	t.Run("Disallowed origin GET does not set CORS header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for standard endpoint, got %d", rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("expected empty Access-Control-Allow-Origin, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("Wildcard in allowlist is ignored", func(t *testing.T) {
		wildcardMiddleware := CORS([]string{"*"})
		wildcardHandler := wildcardMiddleware(dummyHandler)

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/findings", nil)
		req.Header.Set("Origin", "https://anywhere.com")
		rec := httptest.NewRecorder()

		wildcardHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden when wildcard origin attempted, got %d", rec.Code)
		}
	})
}
