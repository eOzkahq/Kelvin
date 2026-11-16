package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

func setupDashboardTestServer(t *testing.T, store *mockFindingStore) (*Server, *assessments.Service) {
	t.Helper()
	cfg := config.Config{
		Development:    true,
		BodyLimitBytes: 1 << 20,
	}
	log := zap.NewNop()
	srv := New(cfg, log)

	asmtRepo := assessments.NewMemoryRepository()
	asmtSvc := assessments.NewService(asmtRepo, nil, true, nil, log)
	srv.SetAssessmentService(asmtSvc)
	srv.SetFindingStore(store)

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

	return srv, asmtSvc
}

func TestHTTP_DashboardStats(t *testing.T) {
	tenantID := uuid.New()
	asmtID := uuid.New()

	f1 := &findings.PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-vuln-1",
		Title:            "Critical Remote Code Execution",
		Severity:         "CRITICAL",
		Status:           findings.StatusConfirmed,
		AffectedEndpoint: "http://127.0.0.1:8080/api",
		ScannerData:      map[string]any{"scanner": "nuclei"},
		FirstSeenAt:      time.Now().UTC(),
		LastSeenAt:       time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	f2 := &findings.PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-vuln-2",
		Title:            "High SQL Injection",
		Severity:         "HIGH",
		Status:           findings.StatusConfirmed,
		AffectedEndpoint: "http://127.0.0.1:8080/search",
		ScannerData:      map[string]any{"scanner": "zap"},
		FirstSeenAt:      time.Now().UTC(),
		LastSeenAt:       time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			f1.ID: f1,
			f2.ID: f2,
		},
	}

	srv, asmtSvc := setupDashboardTestServer(t, store)
	handler := srv.Handler()

	// 1. Create an active assessment for this tenant
	asmt, err := asmtSvc.CreateAssessment(context.Background(), tenantID.String(), "user1", assessments.CreateAssessmentInput{
		Name:                     "Active Assessment for Dashboard",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	})
	if err != nil {
		t.Fatalf("create assessment failed: %v", err)
	}

	// 2. GET /api/v1/dashboard/stats
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	ctx, _ := tenant.WithID(req.Context(), tenantID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for dashboard stats, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Success bool                 `json:"success"`
		Data    DashboardResponseDTO `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode dashboard response: %v", err)
	}

	metrics := res.Data.Metrics
	if metrics.TotalAssessments != 1 {
		t.Errorf("expected 1 assessment, got %d", metrics.TotalAssessments)
	}
	if metrics.ActiveJobs != 1 {
		t.Errorf("expected 1 active job, got %d", metrics.ActiveJobs)
	}
	if metrics.TotalFindings != 2 {
		t.Errorf("expected 2 total findings, got %d", metrics.TotalFindings)
	}
	if metrics.SeverityDistribution.Critical != 1 {
		t.Errorf("expected 1 critical finding, got %d", metrics.SeverityDistribution.Critical)
	}
	if metrics.SeverityDistribution.High != 1 {
		t.Errorf("expected 1 high finding, got %d", metrics.SeverityDistribution.High)
	}

	if !metrics.ScannerReadiness.Nuclei || !metrics.ScannerReadiness.Zap {
		t.Errorf("expected certified scanners ready, got Nuclei=%v, ZAP=%v",
			metrics.ScannerReadiness.Nuclei, metrics.ScannerReadiness.Zap)
	}

	if len(res.Data.ActiveJobs) != 1 || res.Data.ActiveJobs[0].ID != asmt.ID {
		t.Errorf("expected active job ID %s, got %v", asmt.ID, res.Data.ActiveJobs)
	}

	if len(res.Data.RecentFindings) != 2 {
		t.Errorf("expected 2 recent findings, got %d", len(res.Data.RecentFindings))
	}
}
