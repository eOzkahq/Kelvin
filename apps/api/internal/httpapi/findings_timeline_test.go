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

func TestHandleGetFindingObservationsTimeline_Success(t *testing.T) {
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
		findings:     make(map[uuid.UUID]*findings.PersistentFinding),
		observations: make(map[uuid.UUID][]*findings.FindingObservation),
	}
	srv.SetFindingStore(store)

	findingID := uuid.New()
	t0 := time.Now().UTC().AddDate(0, 0, -10)
	t1 := time.Now().UTC()

	store.findings[findingID] = &findings.PersistentFinding{
		ID:          findingID,
		TenantID:    tenantID,
		Title:       "CORS Wildcard Allowed",
		Severity:    "HIGH",
		Status:      findings.StatusConfirmed,
		FirstSeenAt: t0,
		LastSeenAt:  t1,
	}

	obs1 := &findings.FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: uuid.New(),
		JobID:        uuid.New(),
		ScannerID:    "zap",
		ObservedAt:   t0,
		EvidenceRefs: []string{"ref-1"},
	}

	obs2 := &findings.FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: uuid.New(),
		JobID:        uuid.New(),
		ScannerID:    "nuclei",
		ObservedAt:   t1,
		EvidenceRefs: []string{"ref-2"},
		RawMetadata: map[string]any{
			"partial_scan": true,
		},
	}

	store.observations[findingID] = []*findings.FindingObservation{obs1, obs2}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/observations?limit=10&offset=0", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data findings.FindingObservationTimeline `json:"data"`
		Meta map[string]any                      `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	assert.Equal(t, findingID, resp.Data.FindingID)
	assert.Equal(t, 2, resp.Data.TotalObservations)
	assert.Len(t, resp.Data.Timeline, 2)

	assert.Equal(t, obs1.ID, resp.Data.Timeline[0].ObservationID)
	assert.Equal(t, findings.PresenceInitialDiscovery, resp.Data.Timeline[0].PresenceState)
	assert.False(t, resp.Data.Timeline[0].IsPartialAssessment)

	assert.Equal(t, obs2.ID, resp.Data.Timeline[1].ObservationID)
	assert.Equal(t, findings.PresenceStillPresent, resp.Data.Timeline[1].PresenceState)
	assert.True(t, resp.Data.Timeline[1].IsPartialAssessment)
}

func TestHandleGetFindingObservationsTimeline_NotFoundAndTenantIsolation(t *testing.T) {
	cfg := config.Config{}
	srv := New(cfg, zap.NewNop())
	tenantA := uuid.New()
	tenantB := uuid.New()

	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantA)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	store := &mockFindingStore{
		findings: make(map[uuid.UUID]*findings.PersistentFinding),
	}
	srv.SetFindingStore(store)

	findingID := uuid.New()
	// Stored under tenantB
	store.findings[findingID] = &findings.PersistentFinding{
		ID:       findingID,
		TenantID: tenantB,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/observations", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
