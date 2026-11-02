package httpapi

import (
	"bytes"
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

func TestRecalculateRiskHTTP(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	projectID := uuid.New()
	initialScore := 7.5

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:               findingID,
				TenantID:         tenantID,
				ProjectID:        projectID,
				Title:            "Stored XSS in Comment Box",
				Severity:         "HIGH",
				Confidence:       0.85,
				Status:           findings.StatusInProgress,
				RiskScore:        &initialScore,
				RiskPriorityBand: findings.RiskBandHigh,
				UpdatedAt:        time.Now().UTC().Add(-24 * time.Hour),
			},
		},
		riskHistory: make(map[uuid.UUID][]*findings.FindingRiskHistoryEntry),
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

	// 1. Valid recalculate risk command
	reqPayload := RecalculateRiskPayload{
		Reason: findings.TriggerManualRequest,
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/v1/findings/%s/recalculate-risk", findingID),
		bytes.NewReader(bodyBytes),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Data findings.RecalculateRiskResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to decode response envelope: %v", err)
	}

	if env.Data.FindingID != findingID {
		t.Errorf("expected finding ID %v, got %v", findingID, env.Data.FindingID)
	}
	if env.Data.PreviousScore == nil || *env.Data.PreviousScore != initialScore {
		t.Errorf("expected previous score %v, got %v", initialScore, env.Data.PreviousScore)
	}
	if env.Data.CurrentScore != 9.0 {
		t.Errorf("expected new score 9.0, got %v", env.Data.CurrentScore)
	}

	// 2. Finding not found returns 404
	req404 := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/v1/findings/%s/recalculate-risk", uuid.New()),
		nil,
	)
	rec404 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for unknown finding, got %d", rec404.Code)
	}

	// 3. Invalid UUID returns 422
	req422 := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/findings/invalid-uuid/recalculate-risk",
		nil,
	)
	rec422 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec422, req422)

	if rec422.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422 for invalid UUID, got %d", rec422.Code)
	}
}

func TestGetRiskHistoryHTTP(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	projectID := uuid.New()

	historyEntry := &findings.FindingRiskHistoryEntry{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		ModelVersion:  findings.RiskModelVersion,
		RiskScore:     6.5,
		PriorityBand:  findings.RiskBandMedium,
		TriggerReason: findings.TriggerInitialIngestion,
		CalculatedAt:  time.Now().UTC().Add(-48 * time.Hour),
		SupersededAt:  time.Now().UTC().Add(-24 * time.Hour),
	}

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:        findingID,
				TenantID:  tenantID,
				ProjectID: projectID,
			},
		},
		riskHistory: map[uuid.UUID][]*findings.FindingRiskHistoryEntry{
			findingID: {historyEntry},
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

	// 1. Valid retrieval
	req := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/findings/%s/risk-history", findingID),
		nil,
	)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Data []*findings.FindingRiskHistoryEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to decode response envelope: %v", err)
	}

	if len(env.Data) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(env.Data))
	}
	if env.Data[0].RiskScore != 6.5 {
		t.Errorf("expected historical risk score 6.5, got %v", env.Data[0].RiskScore)
	}
}
