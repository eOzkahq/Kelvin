package httpapi

import (
	"encoding/json"
	"fmt"
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

func TestGetRiskExplanationHTTP(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	projectID := uuid.New()
	score := 8.2
	cvss := 8.0

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:               findingID,
				TenantID:         tenantID,
				ProjectID:        projectID,
				Title:            "Remote Code Execution",
				Severity:         "HIGH",
				Confidence:       0.95,
				CVSSScore:        &cvss,
				Status:           findings.StatusOpen,
				RiskScore:        &score,
				RiskPriorityBand: findings.RiskBandHigh,
				ScannerData: map[string]any{
					"exposure":    "PUBLIC_INTERNET",
					"criticality": "TIER_1_CRITICAL",
				},
				UpdatedAt: time.Now().UTC(),
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

	// 1. Success case
	req := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/findings/%s/risk-explanation", findingID),
		nil,
	)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Data findings.RiskExplanation `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to decode response envelope: %v", err)
	}

	if env.Data.FindingID != findingID {
		t.Errorf("expected finding ID %v, got %v", findingID, env.Data.FindingID)
	}
	if env.Data.RiskScore != score {
		t.Errorf("expected score %v, got %v", score, env.Data.RiskScore)
	}
	if env.Data.ModelVersion != findings.RiskModelVersion {
		t.Errorf("expected model version %q, got %q", findings.RiskModelVersion, env.Data.ModelVersion)
	}
	if len(env.Data.Factors) == 0 {
		t.Errorf("expected non-empty factors list")
	}

	// 2. Finding not found returns 404
	req404 := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/findings/%s/risk-explanation", uuid.New()),
		nil,
	)
	rec404 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for unknown finding, got %d", rec404.Code)
	}

	// 3. Malformed finding ID returns 422
	req422 := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/findings/invalid-uuid/risk-explanation",
		nil,
	)
	rec422 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec422, req422)

	if rec422.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422 for invalid UUID, got %d", rec422.Code)
	}
}
