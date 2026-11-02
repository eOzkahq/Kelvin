package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

func TestHandleCompareAssessments_Success(t *testing.T) {
	cfg := config.Config{}
	srv := New(cfg, zap.NewNop())
	tenantID := uuid.New()

	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	baseID := uuid.New()
	targetID := uuid.New()

	baseObs := []*findings.FindingObservation{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: baseID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC().AddDate(0, 0, -3),
			RawMetadata: map[string]any{
				"fingerprint": "fp-1",
				"title":       "Cross-Site Scripting",
				"severity":    "HIGH",
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: baseID,
			ScannerID:    "nuclei",
			ObservedAt:   time.Now().UTC().AddDate(0, 0, -3),
			RawMetadata: map[string]any{
				"fingerprint": "fp-2",
				"title":       "Open Redirect",
				"severity":    "MEDIUM",
			},
		},
	}

	targetObs := []*findings.FindingObservation{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: targetID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC(),
			RawMetadata: map[string]any{
				"fingerprint": "fp-1",
				"title":       "Cross-Site Scripting",
				"severity":    "HIGH",
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: targetID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC(),
			RawMetadata: map[string]any{
				"fingerprint": "fp-3",
				"title":       "Insecure Direct Object Reference",
				"severity":    "CRITICAL",
			},
		},
	}

	store := &mockFindingStore{
		asmtObservations: map[uuid.UUID][]*findings.FindingObservation{
			baseID:   baseObs,
			targetID: targetObs,
		},
		asmtScanners: map[uuid.UUID][]string{
			baseID:   {"zap", "nuclei"},
			targetID: {"zap"},
		},
	}
	srv.SetFindingStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+baseID.String()+"/compare/"+targetID.String(), nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data findings.AssessmentComparisonResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	assert.Equal(t, baseID, resp.Data.BaseAssessmentID)
	assert.Equal(t, targetID, resp.Data.TargetAssessmentID)
	assert.Equal(t, 2, resp.Data.TotalBaseFindings)
	assert.Equal(t, 2, resp.Data.TotalTargetFindings)
	assert.Equal(t, 1, resp.Data.PersistentCount) // fp-1
	assert.Equal(t, 1, resp.Data.NewCount)        // fp-3
	assert.Equal(t, 1, resp.Data.CoverageGapCount) // fp-2 (nuclei omitted)
	assert.Equal(t, 0.5, resp.Data.Coverage.CoverageRatio)
}

func TestHandleCompareAssessments_NotFound(t *testing.T) {
	cfg := config.Config{}
	srv := New(cfg, zap.NewNop())
	tenantID := uuid.New()

	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	store := &mockFindingStore{
		asmtObservations: make(map[uuid.UUID][]*findings.FindingObservation),
		asmtScanners:     make(map[uuid.UUID][]string),
	}
	srv.SetFindingStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+uuid.New().String()+"/compare/"+uuid.New().String(), nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
