package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

func TestUpsertTargetRiskContextHTTP(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	store := &mockFindingStore{
		targetContexts: make(map[string]*findings.TargetRiskContext),
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

	// 1. Valid context upsert
	reqBody := UpsertTargetRiskContextRequest{
		TargetAsset:         "api.production.internal",
		Environment:         findings.EnvProduction,
		InternetFacing:      true,
		ContainsPII:         true,
		BusinessCriticality: findings.CritMissionCritical,
		Source:              "MANUAL_SECURITY_AUDIT",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/api/v1/projects/%s/targets/context", projectID),
		bytes.NewReader(bodyBytes),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Missing target_asset returns 422 Unprocessable Entity
	invalidBody := UpsertTargetRiskContextRequest{
		TargetAsset: "",
		Environment: findings.EnvProduction,
	}
	invBytes, _ := json.Marshal(invalidBody)
	invReq := httptest.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/api/v1/projects/%s/targets/context", projectID),
		bytes.NewReader(invBytes),
	)
	invReq.Header.Set("Content-Type", "application/json")

	invRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(invRec, invReq)

	if invRec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422 for empty target_asset, got %d", invRec.Code)
	}
}

func TestGetTargetRiskContextHTTP(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	targetAsset := "db.internal.vpc"

	store := &mockFindingStore{
		targetContexts: make(map[string]*findings.TargetRiskContext),
	}

	// Pre-populate target context
	_ = store.UpsertTargetRiskContext(context.Background(), &findings.TargetRiskContext{
		TenantID:            tenantID,
		ProjectID:           projectID,
		TargetAsset:         targetAsset,
		Environment:         findings.EnvStaging,
		InternetFacing:      false,
		ContainsPII:         true,
		BusinessCriticality: findings.CritBusinessOperational,
	})

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// 1. Successful retrieval
	req := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%s/targets/context?target_asset=%s", projectID, targetAsset),
		nil,
	)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Non-existent asset returns 404
	req404 := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%s/targets/context?target_asset=unknown.asset.com", projectID),
		nil,
	)

	rec404 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for missing target context, got %d", rec404.Code)
	}

	// 3. Missing query parameter returns 422
	req400 := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%s/targets/context", projectID),
		nil,
	)

	rec400 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec400, req400)

	if rec400.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422 for omitted target_asset query param, got %d", rec400.Code)
	}
}
