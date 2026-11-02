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

func TestTriageFindingSuccess(t *testing.T) {
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

	body := []byte(`{"disposition":"CONFIRMED","justification":"Verified exploit payload in lab environment"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	if store.findings[findingID].Status != findings.StatusConfirmed {
		t.Errorf("expected status CONFIRMED, got %s", store.findings[findingID].Status)
	}
}

func TestTriageFindingValidationFailure(t *testing.T) {
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

	body := []byte(`{"disposition":"CONFIRMED","justification":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTriageFindingCrossTenant404(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	findingID := uuid.New()

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

	body := []byte(`{"disposition":"CONFIRMED","justification":"Cross tenant check"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on cross-tenant triage, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTriageFindingUnconfiguredStore(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	body := []byte(`{"disposition":"CONFIRMED","justification":"Service unconfigured check"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+uuid.New().String()+"/triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when store unconfigured, got %d", rec.Code)
	}
}
