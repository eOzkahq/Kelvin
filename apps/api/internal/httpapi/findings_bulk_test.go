package httpapi

import (
	"bytes"
	"encoding/json"
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

func TestBulkTriageMixedSuccessAndFailures(t *testing.T) {
	tenantID := uuid.New()
	finding1 := uuid.New()
	finding2 := uuid.New() // Will not exist in store
	finding3 := uuid.New() // Already resolved, illegal transition to false positive

	now := time.Now().UTC()
	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			finding1: {
				ID:        finding1,
				TenantID:  tenantID,
				Status:    findings.StatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			},
			finding3: {
				ID:        finding3,
				TenantID:  tenantID,
				Status:    findings.StatusResolved,
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

	body := []byte(`{
		"finding_ids": ["` + finding1.String() + `", "` + finding2.String() + `", "` + finding3.String() + `"],
		"action": "TRANSITION",
		"target_status": "FALSE_POSITIVE",
		"reason": "Substantive reason provided for bulk testing."
	}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/bulk-triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for multi-status bulk triage, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data findings.BulkTriageResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Data.SucceededCount != 1 {
		t.Errorf("expected 1 succeeded, got %d", resp.Data.SucceededCount)
	}
	if resp.Data.FailedCount != 2 {
		t.Errorf("expected 2 failed, got %d", resp.Data.FailedCount)
	}
	if store.findings[finding1].Status != findings.StatusFalsePositive {
		t.Errorf("expected finding1 to be FALSE_POSITIVE, got %s", store.findings[finding1].Status)
	}
}

func TestBulkTriageEmptyBatchRejected(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(&mockFindingStore{})
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	body := []byte(`{"finding_ids":[],"action":"TRANSITION","target_status":"CONFIRMED"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/bulk-triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity on empty batch, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBulkTriageLimitExceededRejected(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(&mockFindingStore{})
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	ids := make([]string, 101)
	for i := range ids {
		ids[i] = `"` + uuid.New().String() + `"`
	}
	idsJSON := "[" + string(bytes.Join([][]byte{}, []byte(",")))
	for i, id := range ids {
		if i > 0 {
			idsJSON += ","
		}
		idsJSON += id
	}
	idsJSON += "]"

	body := []byte(`{"finding_ids":` + idsJSON + `,"action":"TRANSITION","target_status":"CONFIRMED"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/bulk-triage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity when batch exceeds 100, got %d: %s", rec.Code, rec.Body.String())
	}
}
