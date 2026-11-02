package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

func TestCreateSuppressionSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	now := time.Now().UTC()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:        findingID,
				TenantID:  tenantID,
				Status:    findings.StatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	futureTime := now.Add(48 * time.Hour).Format(time.RFC3339)
	body := []byte(`{"reason":"Pending maintenance window on staging backend.","expires_at":"` + futureTime + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/suppress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSuppressionMissingReason(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	now := time.Now().UTC()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Status:   findings.StatusOpen,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	futureTime := now.Add(48 * time.Hour).Format(time.RFC3339)
	body := []byte(`{"reason":"   ","expires_at":"` + futureTime + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/suppress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSuppressionPastExpiry(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	now := time.Now().UTC()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Status:   findings.StatusOpen,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	pastTime := now.Add(-24 * time.Hour).Format(time.RFC3339)
	body := []byte(`{"reason":"Pending maintenance window","expires_at":"` + pastTime + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/suppress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity for past expiry, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSuppressionCrossTenant404(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	findingID := uuid.New()
	now := time.Now().UTC()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantA,
				Status:   findings.StatusOpen,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantB)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	futureTime := now.Add(48 * time.Hour).Format(time.RFC3339)
	body := []byte(`{"reason":"Cross tenant check","expires_at":"` + futureTime + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/suppress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on cross-tenant suppression, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeSuppressionSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Status:   findings.StatusOpen,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	body := []byte(`{"reason":"Maintenance completed early; resuming review."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/unsuppress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on unsuppress, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetSuppressionsSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Status:   findings.StatusOpen,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/suppressions", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get suppressions, got %d: %s", rec.Code, rec.Body.String())
	}
}
