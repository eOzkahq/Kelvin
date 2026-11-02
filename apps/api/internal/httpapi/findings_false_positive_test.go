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

func TestMarkFalsePositiveSuccess(t *testing.T) {
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

	body := []byte(`{"justification":"Payload is strictly sanitised by input sanitiser; confirmed non-vulnerable.","evidence_rebuttal":"Tested with SQLMap, returns standard error page."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/false-positive", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	if store.findings[findingID].Status != findings.StatusFalsePositive {
		t.Errorf("expected status FALSE_POSITIVE, got %s", store.findings[findingID].Status)
	}
}

func TestMarkFalsePositiveShortRationaleFails(t *testing.T) {
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

	// Under 20 characters
	body := []byte(`{"justification":"Not vulnerable"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/false-positive", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMarkFalsePositiveAlreadyFalsePositiveConflict(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Status:   findings.StatusFalsePositive,
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

	body := []byte(`{"justification":"Payload is strictly sanitised by input sanitiser; confirmed non-vulnerable."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/false-positive", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict when already marked false positive, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMarkFalsePositiveCrossTenant404(t *testing.T) {
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

	body := []byte(`{"justification":"Payload is strictly sanitised by input sanitiser; confirmed non-vulnerable."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/false-positive", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on cross-tenant false positive, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestReverseFalsePositiveSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Status:   findings.StatusFalsePositive,
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

	body := []byte(`{"target_status":"NEW","justification":"New scanner observation confirmed bypass vector; reopening review."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/false-positive/reverse", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	if store.findings[findingID].Status != findings.StatusNew {
		t.Errorf("expected status NEW after reversal, got %s", store.findings[findingID].Status)
	}
}

func TestReverseFalsePositiveNotFalsePositiveConflict(t *testing.T) {
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

	body := []byte(`{"target_status":"NEW","justification":"New scanner observation confirmed bypass vector; reopening review."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/false-positive/reverse", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict when finding is not FALSE_POSITIVE, got %d: %s", rec.Code, rec.Body.String())
	}
}
