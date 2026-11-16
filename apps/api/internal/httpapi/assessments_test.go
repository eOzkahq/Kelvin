package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

func setupAssessmentTestServer(t *testing.T) (*httpapi.Server, *assessments.Service, assessments.Repository) {
	t.Helper()
	cfg := config.Config{
		Development:          true,
		BodyLimitBytes:       1 << 20,
		CanaryOnly:           true,
		CanaryAllowedTargets: []string{"mock-target.kelvin.internal"},
	}
	log := zap.NewNop()
	srv := httpapi.New(cfg, log)

	repo := assessments.NewMemoryRepository()
	asmtSvc := assessments.NewService(repo, nil, true, []string{"mock-target.kelvin.internal"}, log)
	srv.SetAssessmentService(asmtSvc)

	// Bypass auth for test harness by passing through with dummy tenant if not set
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if _, err := tenant.ID(ctx); err != nil {
				tenantID := uuid.New()
				ctx, _ = tenant.WithID(ctx, tenantID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	return srv, asmtSvc, repo
}

func TestHTTP_CreateAssessment(t *testing.T) {
	srv, _, _ := setupAssessmentTestServer(t)

	tenantID := uuid.New()
	handler := srv.Handler()

	// 1. Authorized canary target creation
	body := map[string]any{
		"name":                     "Canary HTTP Assessment",
		"targetAddress":            "http://127.0.0.1:8080",
		"profileId":                "standard",
		"authorizedScopeConfirmed": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	ctx, _ := tenant.WithID(req.Context(), tenantID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Success bool `json:"success"`
		Data    struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !res.Success || res.Data.ID == "" {
		t.Fatalf("expected success with ID, got %v", res)
	}

	// 2. Reject target outside canary allowlist
	extBody := map[string]any{
		"name":                     "External Target Scan",
		"targetAddress":            "https://evil.external.org",
		"profileId":                "standard",
		"authorizedScopeConfirmed": true,
	}
	extBytes, _ := json.Marshal(extBody)
	extReq := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(extBytes))
	extReq.Header.Set("Content-Type", "application/json")
	extReq = extReq.WithContext(ctx)

	extRec := httptest.NewRecorder()
	handler.ServeHTTP(extRec, extReq)

	if extRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for canary violation, got %d: %s", extRec.Code, extRec.Body.String())
	}

	// 3. Reject unconfirmed scope
	noScopeBody := map[string]any{
		"name":                     "No Scope",
		"targetAddress":            "http://127.0.0.1:8080",
		"profileId":                "standard",
		"authorizedScopeConfirmed": false,
	}
	nsBytes, _ := json.Marshal(noScopeBody)
	nsReq := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(nsBytes))
	nsReq.Header.Set("Content-Type", "application/json")
	nsReq = nsReq.WithContext(ctx)

	nsRec := httptest.NewRecorder()
	handler.ServeHTTP(nsRec, nsReq)

	if nsRec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity for unconfirmed scope, got %d: %s", nsRec.Code, nsRec.Body.String())
	}
}

func TestHTTP_ListAndGetAssessment(t *testing.T) {
	srv, svc, _ := setupAssessmentTestServer(t)

	tenantA := uuid.New()
	tenantB := uuid.New()
	handler := srv.Handler()

	asmtA, err := svc.CreateAssessment(context.Background(), tenantA.String(), "userA", assessments.CreateAssessmentInput{
		Name:                     "Tenant A Assessment",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	})
	if err != nil {
		t.Fatalf("create assessment failed: %v", err)
	}

	// Tenant A gets own assessment detail
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+asmtA.ID, nil)
	ctxA, _ := tenant.WithID(req.Context(), tenantA)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req.WithContext(ctxA))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Tenant B gets 404 (IDOR cross-tenant defense)
	recB := httptest.NewRecorder()
	ctxB, _ := tenant.WithID(req.Context(), tenantB)
	handler.ServeHTTP(recB, req.WithContext(ctxB))

	if recB.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant access, got %d: %s", recB.Code, recB.Body.String())
	}

	// List assessments for Tenant A
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq.WithContext(ctxA))

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on list, got %d: %s", listRec.Code, listRec.Body.String())
	}

	var listRes struct {
		Success bool                           `json:"success"`
		Data    []assessments.AssessmentRecord `json:"data"`
		Meta    map[string]any                 `json:"meta"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listRes); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listRes.Data) != 1 || listRes.Data[0].ID != asmtA.ID {
		t.Errorf("expected 1 assessment matching ID %s, got %v", asmtA.ID, listRes.Data)
	}
}

func TestHTTP_ProfilesAndTargets(t *testing.T) {
	srv, _, _ := setupAssessmentTestServer(t)
	handler := srv.Handler()

	// 1. GET /api/v1/assessments/profiles
	pReq := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/profiles", nil)
	pRec := httptest.NewRecorder()
	handler.ServeHTTP(pRec, pReq)

	if pRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for profiles, got %d: %s", pRec.Code, pRec.Body.String())
	}

	var pRes struct {
		Success bool                      `json:"success"`
		Data    []assessments.ScanProfile `json:"data"`
	}
	if err := json.Unmarshal(pRec.Body.Bytes(), &pRes); err != nil {
		t.Fatalf("failed to decode profiles: %v", err)
	}
	if len(pRes.Data) < 3 {
		t.Errorf("expected at least 3 profiles, got %d", len(pRes.Data))
	}

	// 2. GET /api/v1/targets
	tReq := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	tRec := httptest.NewRecorder()
	handler.ServeHTTP(tRec, tReq)

	if tRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for targets, got %d: %s", tRec.Code, tRec.Body.String())
	}

	var tRes struct {
		Success bool                       `json:"success"`
		Data    []assessments.TargetOption `json:"data"`
	}
	if err := json.Unmarshal(tRec.Body.Bytes(), &tRes); err != nil {
		t.Fatalf("failed to decode targets: %v", err)
	}
	if len(tRes.Data) < 2 {
		t.Errorf("expected at least 2 canary targets, got %d", len(tRes.Data))
	}
}

func TestHTTP_CancelAssessment(t *testing.T) {
	srv, svc, _ := setupAssessmentTestServer(t)

	tenantID := uuid.New()
	handler := srv.Handler()

	asmt, err := svc.CreateAssessment(context.Background(), tenantID.String(), "user1", assessments.CreateAssessmentInput{
		Name:                     "Assessment to Cancel",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	})
	if err != nil {
		t.Fatalf("create assessment failed: %v", err)
	}

	cancelReq := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+asmt.ID+"/cancel", nil)
	ctx, _ := tenant.WithID(cancelReq.Context(), tenantID)
	cancelRec := httptest.NewRecorder()
	handler.ServeHTTP(cancelRec, cancelReq.WithContext(ctx))

	if cancelRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cancel, got %d: %s", cancelRec.Code, cancelRec.Body.String())
	}

	// Cancelling again yields 409 Conflict
	cancelAgainRec := httptest.NewRecorder()
	handler.ServeHTTP(cancelAgainRec, cancelReq.WithContext(ctx))

	if cancelAgainRec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict on double cancel, got %d: %s", cancelAgainRec.Code, cancelAgainRec.Body.String())
	}
}
