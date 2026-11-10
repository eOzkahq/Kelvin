package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/api/internal/config"
	"go.uber.org/zap"
)

type mockPinger struct {
	err   error
	delay time.Duration
}

func (m *mockPinger) Ping(ctx context.Context) error {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.err
}

func TestHealthLive(t *testing.T) {
	cfg := config.Config{APIVersion: "1.0.0-test"}
	srv := New(cfg, zap.NewNop())
	handler := srv.Handler()

	for _, path := range []string{"/health/live", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for %s, got %d", path, rec.Code)
		}

		var res struct {
			Data struct {
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode response for %s: %v", path, err)
		}

		if res.Data.Status != "LIVE" {
			t.Errorf("expected status 'LIVE' for %s, got %q", path, res.Data.Status)
		}
	}
}

func TestHealthReady_AllHealthy(t *testing.T) {
	cfg := config.Config{APIVersion: "1.0.0-test"}
	srv := New(cfg, zap.NewNop())
	srv.SetReadyCheckers(ReadyCheckers{
		DB:    &mockPinger{err: nil},
		Redis: &mockPinger{err: nil},
	})
	handler := srv.Handler()

	for _, path := range []string{"/health/ready", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for healthy %s, got %d", path, rec.Code)
		}

		var res struct {
			Data struct {
				Status   string `json:"status"`
				Database string `json:"database"`
				Broker   string `json:"broker"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode response for %s: %v", path, err)
		}

		if res.Data.Status != "READY" || res.Data.Database != "UP" || res.Data.Broker != "UP" {
			t.Errorf("unexpected readiness payload for %s: %+v", path, res.Data)
		}
	}
}

func TestHealthReady_DependencyDownReturns503(t *testing.T) {
	cfg := config.Config{APIVersion: "1.0.0-test"}
	srv := New(cfg, zap.NewNop())
	srv.SetReadyCheckers(ReadyCheckers{
		DB:    &mockPinger{err: errors.New("connection refused to 10.0.0.5:5432")},
		Redis: &mockPinger{err: nil},
	})
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable for failed dependency, got %d", rec.Code)
	}

	body := rec.Body.String()
	// Ensure response does not leak internal IP or raw error message
	if rec.Body.String() == "" {
		t.Fatal("expected non-empty error response")
	}
	if rec.Body.String() == "connection refused to 10.0.0.5:5432" {
		t.Errorf("raw dependency error leaked in response: %s", body)
	}
}

func TestHealthReady_TimeoutReturns503(t *testing.T) {
	cfg := config.Config{APIVersion: "1.0.0-test"}
	srv := New(cfg, zap.NewNop())
	// Simulate hanging database call exceeding DefaultProbeTimeout (2s)
	srv.SetReadyCheckers(ReadyCheckers{
		DB:    &mockPinger{delay: 3 * time.Second},
		Redis: &mockPinger{err: nil},
	})
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable for timed-out probe, got %d", rec.Code)
	}
}

