package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestCORSMiddlewareProductionAssessmentPreflight(t *testing.T) {
	const frontendOrigin = "https://kelvin-orpin.vercel.app"
	cors := CORS([]string{frontendOrigin})
	authenticatedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := cors(authenticatedHandler)

	t.Run("allowed origin preflight includes required headers and bypasses authentication", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/assessments", nil)
		req.Header.Set("Origin", frontendOrigin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type, x-idempotency-key")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 preflight, got %d", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != frontendOrigin {
			t.Fatalf("expected exact allow origin %q, got %q", frontendOrigin, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Fatalf("expected credentials policy to remain true, got %q", got)
		}
		allowed := make(map[string]bool)
		for _, header := range strings.Split(rec.Header().Get("Access-Control-Allow-Headers"), ",") {
			allowed[strings.ToLower(strings.TrimSpace(header))] = true
		}
		for _, header := range []string{"Authorization", "Content-Type", "Accept", "X-Idempotency-Key", "X-Request-ID", "X-Correlation-ID"} {
			if !allowed[strings.ToLower(header)] {
				t.Errorf("Access-Control-Allow-Headers missing %q: %q", header, rec.Header().Get("Access-Control-Allow-Headers"))
			}
		}
	})

	t.Run("unapproved origin is not granted access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/assessments", nil)
		req.Header.Set("Origin", "https://unapproved.example")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for unapproved origin, got %d", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("unapproved origin received Access-Control-Allow-Origin %q", got)
		}
	})
}
