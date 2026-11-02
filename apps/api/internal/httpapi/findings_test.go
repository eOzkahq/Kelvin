package httpapi

import (
	"context"
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

type mockFindingStore struct {
	findings     map[uuid.UUID]*findings.PersistentFinding
	observations map[uuid.UUID][]*findings.FindingObservation
}

func (m *mockFindingStore) GetFindingByID(ctx context.Context, tenantID, findingID uuid.UUID) (*findings.PersistentFinding, error) {
	f, exists := m.findings[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, findings.ErrFindingNotFound
	}
	return f, nil
}

func (m *mockFindingStore) GetObservationsByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*findings.FindingObservation, error) {
	all, exists := m.observations[findingID]
	if !exists {
		return []*findings.FindingObservation{}, nil
	}
	if offset >= len(all) {
		return []*findings.FindingObservation{}, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

func TestGetFindingSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	projectID := uuid.New()
	now := time.Now().UTC()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:               findingID,
				TenantID:         tenantID,
				ProjectID:        projectID,
				Title:            "Remote Code Execution via Template Injection",
				Severity:         "CRITICAL",
				Confidence:       0.99,
				Status:           findings.StatusOpen,
				AffectedEndpoint: "https://api.example.com/render",
				FirstSeenAt:      now,
				LastSeenAt:       now,
				OccurrenceCount:  1,
			},
		},
		observations: map[uuid.UUID][]*findings.FindingObservation{
			findingID: {
				{
					ID:           uuid.New(),
					TenantID:     tenantID,
					FindingID:    findingID,
					AssessmentID: uuid.New(),
					ScannerID:    "nuclei",
					ObservedAt:   now,
				},
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set tenant context
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String(), nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Finding      findings.PersistentFinding      `json:"finding"`
			Observations []findings.FindingObservation `json:"observations"`
		} `json:"data"`
		Meta map[string]any `json:"meta"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success = true")
	}
	if resp.Data.Finding.ID != findingID {
		t.Errorf("expected finding ID %s, got %s", findingID, resp.Data.Finding.ID)
	}
	if len(resp.Data.Observations) != 1 {
		t.Errorf("expected 1 observation, got %d", len(resp.Data.Observations))
	}
	if resp.Meta["count"] != float64(1) {
		t.Errorf("expected meta count 1, got %v", resp.Meta["count"])
	}
}

func TestGetFindingNotFoundAndCrossTenantIDOR(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	findingA := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingA: {
				ID:       findingA,
				TenantID: tenantA,
				Title:    "Tenant A Secret Finding",
				Status:   findings.StatusOpen,
			},
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)

	// User authenticated as Tenant B
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantB)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Tenant B attempts to read Tenant A's finding ID -> must return 404 (IDOR safe)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingA.String(), nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on cross-tenant IDOR, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetFindingInvalidUUID(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/not-a-valid-uuid", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity for invalid UUID, got %d", rec.Code)
	}
}

func TestGetFindingUnconfiguredStore(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	// No finding store configured
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+uuid.New().String(), nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when store unconfigured, got %d", rec.Code)
	}
}
