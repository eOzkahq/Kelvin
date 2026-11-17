package httpapi

import (
	"bytes"
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
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

type recordQueue struct {
	enqueued []commonqueue.Message
	canceled []string
}

func (q *recordQueue) Enqueue(_ context.Context, msg commonqueue.Message) error {
	q.enqueued = append(q.enqueued, msg)
	return nil
}
func (q *recordQueue) Consume(_ context.Context, _ string) (commonqueue.Delivery, error) {
	return commonqueue.Delivery{}, nil
}
func (q *recordQueue) Complete(_ context.Context, _ commonqueue.Delivery) error { return nil }
func (q *recordQueue) Fail(_ context.Context, _ commonqueue.Delivery, _ error) error { return nil }
func (q *recordQueue) Cancel(_ context.Context, id string) error {
	q.canceled = append(q.canceled, id)
	return nil
}
func (q *recordQueue) GetStatus(_ context.Context, _ string) (commonqueue.Status, error) {
	return commonqueue.Status{}, nil
}
func (q *recordQueue) Heartbeat(_ context.Context, _, _ string, _ time.Duration) error { return nil }
func (q *recordQueue) AcquireLease(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
	return true, nil
}
func (q *recordQueue) RenewLease(_ context.Context, _, _ string, _ time.Duration) error {
	return nil
}
func (q *recordQueue) ReleaseLease(_ context.Context, _, _ string) error {
	return nil
}
func (q *recordQueue) IsLeaseActive(_ context.Context, _ string) (bool, string, error) {
	return false, "", nil
}

type testHarness struct {
	server       *Server
	asmtRepo     assessments.Repository
	queue        *recordQueue
	findingStore *mockFindingStore
	signingKey   []byte
}

func newM7TestHarness(t *testing.T) *testHarness {
	t.Helper()

	cfg := config.Config{
		Development:    true,
		BodyLimitBytes: 1 << 20,
		CanaryOnly:     true,
		CanaryAllowedTargets: []string{
			"scanner-mock.kelvin.internal",
			"mock-target.kelvin.internal",
			"127.0.0.1",
			"localhost",
		},
	}
	log := zap.NewNop()
	srv := New(cfg, log)

	asmtRepo := assessments.NewMemoryRepository()
	q := &recordQueue{}
	asmtSvc := assessments.NewService(asmtRepo, q, true, cfg.CanaryAllowedTargets, log)
	srv.SetAssessmentService(asmtSvc)

	signingKey := []byte("test-signing-key-at-least-32-bytes-long")
	repSvc := NewBuiltinReportService(asmtRepo, signingKey)
	srv.SetReportService(repSvc)

	fStore := &mockFindingStore{
		findings: make(map[uuid.UUID]*findings.PersistentFinding),
	}
	srv.SetFindingStore(fStore)

	// Auth middleware passthrough inspecting context
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})

	return &testHarness{
		server:       srv,
		asmtRepo:     asmtRepo,
		queue:        q,
		findingStore: fStore,
		signingKey:   signingKey,
	}
}

func TestMilestone7_25Scenarios(t *testing.T) {
	h := newM7TestHarness(t)
	handler := h.server.Handler()

	tenantA := uuid.New()
	tenantB := uuid.New()

	ctxA, _ := tenant.WithID(context.Background(), tenantA)
	ctxB, _ := tenant.WithID(context.Background(), tenantB)

	var asmtA_ID string
	var reportA_ID string

	// --------------------------------------------------------------------------
	// Scenario 01: Unauthenticated request rejected when protected route configured without token
	// --------------------------------------------------------------------------
	t.Run("Scenario 01: Missing authentication / tenant context rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req) // no tenant in context

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for missing tenant context, got %d", rec.Code)
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 02: Assessment creation without authorized scope confirmation rejected
	// --------------------------------------------------------------------------
	t.Run("Scenario 02: Unconfirmed scope rejected with 422", func(t *testing.T) {
		body := map[string]any{
			"name":                     "Unconfirmed Scope Scan",
			"targetAddress":            "http://127.0.0.1:8080",
			"profileId":                "standard",
			"authorizedScopeConfirmed": false,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("expected 422 for unconfirmed scope, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 03: Assessment creation with empty target address rejected
	// --------------------------------------------------------------------------
	t.Run("Scenario 03: Empty target address rejected with 422", func(t *testing.T) {
		body := map[string]any{
			"name":                     "Empty Target Scan",
			"targetAddress":            "",
			"profileId":                "standard",
			"authorizedScopeConfirmed": true,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("expected 422 for empty target, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 04: Assessment creation with invalid profile rejected
	// --------------------------------------------------------------------------
	t.Run("Scenario 04: Invalid profile ID rejected with 422", func(t *testing.T) {
		body := map[string]any{
			"name":                     "Invalid Profile Scan",
			"targetAddress":            "http://127.0.0.1:8080",
			"profileId":                "non-existent-profile-xyz",
			"authorizedScopeConfirmed": true,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("expected 422 for invalid profile, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 05: Assessment targeting external host rejected by canary-only policy (403)
	// --------------------------------------------------------------------------
	t.Run("Scenario 05: External target rejected by canary policy with 403", func(t *testing.T) {
		body := map[string]any{
			"name":                     "External Scan",
			"targetAddress":            "https://evil.external-target.org",
			"profileId":                "standard",
			"authorizedScopeConfirmed": true,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for canary violation, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 06: Assessment targeting IMDS (169.254.169.254) rejected by anti-SSRF (403)
	// --------------------------------------------------------------------------
	t.Run("Scenario 06: Cloud IMDS SSRF rejected by canary policy with 403", func(t *testing.T) {
		body := map[string]any{
			"name":                     "IMDS SSRF Attack",
			"targetAddress":            "http://169.254.169.254/latest/meta-data",
			"profileId":                "standard",
			"authorizedScopeConfirmed": true,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for IMDS target, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 07: Assessment creation with valid canary target succeeds (201)
	// --------------------------------------------------------------------------
	t.Run("Scenario 07: Canary target creation succeeds with 201", func(t *testing.T) {
		body := map[string]any{
			"name":                     "Canary Mock Scan 1",
			"targetAddress":            "http://127.0.0.1:8080",
			"profileId":                "standard",
			"authorizedScopeConfirmed": true,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
		}

		var res struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		asmtA_ID = res.Data.ID
		if asmtA_ID == "" {
			t.Fatalf("expected generated assessment ID")
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 08: Assessment creation with internal hostname canary succeeds (201)
	// --------------------------------------------------------------------------
	t.Run("Scenario 08: Internal mock-target canary hostname succeeds with 201", func(t *testing.T) {
		body := map[string]any{
			"name":                     "Canary Mock Scan 2",
			"targetAddress":            "http://scanner-mock.kelvin.internal:8080",
			"profileId":                "safe_web",
			"authorizedScopeConfirmed": true,
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created for internal hostname, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 09: Queue dispatch verified with valid message contract
	// --------------------------------------------------------------------------
	t.Run("Scenario 09: Message enqueued to Redis queue with valid contract", func(t *testing.T) {
		if len(h.queue.enqueued) < 2 {
			t.Fatalf("expected at least 2 enqueued messages, got %d", len(h.queue.enqueued))
		}
		msg := h.queue.enqueued[0]
		if msg.Version != 1 && msg.Version != 2 {
			t.Errorf("expected message version 1 or 2, got %d", msg.Version)
		}
		if msg.AssessmentID != asmtA_ID {
			t.Errorf("expected assessment ID %s, got %s", asmtA_ID, msg.AssessmentID)
		}
		if msg.TenantID != tenantA.String() {
			t.Errorf("expected tenant ID %s, got %s", tenantA.String(), msg.TenantID)
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 10: GET /api/v1/assessments lists Tenant A's assessments
	// --------------------------------------------------------------------------
	t.Run("Scenario 10: List assessments returns Tenant A's records", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Data []assessments.AssessmentRecord `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Data) < 2 {
			t.Errorf("expected at least 2 assessments for Tenant A, got %d", len(res.Data))
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 11: GET /api/v1/assessments/{id} returns assessment detail
	// --------------------------------------------------------------------------
	t.Run("Scenario 11: Assessment detail retrieved successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+asmtA_ID, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Data assessments.AssessmentDetail `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if res.Data.ID != asmtA_ID {
			t.Errorf("expected ID %s, got %s", asmtA_ID, res.Data.ID)
		}
		if res.Data.CurrentStage != assessments.StageQueued {
			t.Errorf("expected initial stage QUEUED, got %s", res.Data.CurrentStage)
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 12: IDOR Defense — Tenant B cannot retrieve Tenant A's assessment
	// --------------------------------------------------------------------------
	t.Run("Scenario 12: Cross-tenant assessment access yields 404 Not Found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+asmtA_ID, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxB))

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for cross-tenant IDOR, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 13: IDOR Defense — Tenant B listing sees zero Tenant A assessments
	// --------------------------------------------------------------------------
	t.Run("Scenario 13: Tenant B listing isolates Tenant A data", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxB))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Data []assessments.AssessmentRecord `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Data) != 0 {
			t.Errorf("tenant B unexpectedly saw assessments: %v", res.Data)
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 14: GET /api/v1/assessments/profiles returns certified profiles
	// --------------------------------------------------------------------------
	t.Run("Scenario 14: Profiles catalog returns certified scan profiles", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/profiles", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		var res struct {
			Data []assessments.ScanProfile `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Data) < 3 {
			t.Errorf("expected standard, safe_web, deep profiles, got %d", len(res.Data))
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 15: GET /api/v1/targets returns authorized target options
	// --------------------------------------------------------------------------
	t.Run("Scenario 15: Targets catalog returns authorized canary target options", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		var res struct {
			Data []assessments.TargetOption `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Data) < 2 {
			t.Errorf("expected authorized target options, got %d", len(res.Data))
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 16: IDOR Defense — Tenant B cannot cancel Tenant A's assessment
	// --------------------------------------------------------------------------
	t.Run("Scenario 16: Cross-tenant assessment cancellation rejected with 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+asmtA_ID+"/cancel", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxB))

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for cross-tenant cancel, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 17: Tenant A can cancel own active assessment
	// --------------------------------------------------------------------------
	t.Run("Scenario 17: Assessment cancellation succeeds with 200 OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+asmtA_ID+"/cancel", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for cancel, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 18: Queue cancellation emitted
	// --------------------------------------------------------------------------
	t.Run("Scenario 18: Queue cancellation event emitted", func(t *testing.T) {
		if len(h.queue.canceled) != 1 || h.queue.canceled[0] != asmtA_ID {
			t.Errorf("expected cancellation emitted for %s, got %v", asmtA_ID, h.queue.canceled)
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 19: Double cancellation returns 409 Conflict
	// --------------------------------------------------------------------------
	t.Run("Scenario 19: Double cancel returns 409 Conflict", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments/"+asmtA_ID+"/cancel", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusConflict {
			t.Errorf("expected 409 Conflict for double cancel, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 20: POST /api/v1/reports/generate creates HTML report
	// --------------------------------------------------------------------------
	t.Run("Scenario 20: HTML report generation succeeds with 201", func(t *testing.T) {
		body := map[string]any{
			"assessmentId": asmtA_ID,
			"targetHost":   "http://127.0.0.1:8080",
			"templateType": "EXECUTIVE_SUMMARY",
			"format":       "HTML",
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/reports/generate", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created for HTML report, got %d: %s", rec.Code, rec.Body.String())
		}

		var res struct {
			Data ReportItemDTO `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		reportA_ID = res.Data.ID
		if reportA_ID == "" || res.Data.DownloadURL == "" {
			t.Fatalf("expected generated report ID and download URL")
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 21: POST /api/v1/reports/generate creates PDF report
	// --------------------------------------------------------------------------
	t.Run("Scenario 21: PDF report generation succeeds with 201", func(t *testing.T) {
		body := map[string]any{
			"assessmentId": asmtA_ID,
			"targetHost":   "http://127.0.0.1:8080",
			"templateType": "TECHNICAL_FINDINGS",
			"format":       "PDF",
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/reports/generate", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created for PDF report, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 22: GET /api/v1/reports/{id}/download serves HTML content
	// --------------------------------------------------------------------------
	t.Run("Scenario 22: Report download serves HTML stream", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/"+reportA_ID+"/download?format=HTML", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for report download, got %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("expected text/html, got %s", rec.Header().Get("Content-Type"))
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("<!DOCTYPE html>")) {
			t.Errorf("expected valid HTML content")
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 23: IDOR Defense — Tenant B cannot download Tenant A's report
	// --------------------------------------------------------------------------
	t.Run("Scenario 23: Cross-tenant report download yields 404 Not Found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/"+reportA_ID+"/download", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxB))

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for cross-tenant report download, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 24: GET /api/v1/reports lists Tenant A's generated reports
	// --------------------------------------------------------------------------
	t.Run("Scenario 24: Report listing returns Tenant A's reports", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reports", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		var res struct {
			Data []ReportItemDTO `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Data) < 2 {
			t.Errorf("expected at least 2 reports, got %d", len(res.Data))
		}
	})

	// --------------------------------------------------------------------------
	// Scenario 25: GET /api/v1/dashboard/stats provides unified metrics & scanner readiness
	// --------------------------------------------------------------------------
	t.Run("Scenario 25: Dashboard stats aggregates truthful metrics and readiness", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(ctxA))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Data DashboardResponseDTO `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if res.Data.Metrics.TotalAssessments < 2 {
			t.Errorf("expected at least 2 total assessments, got %d", res.Data.Metrics.TotalAssessments)
		}
		if !res.Data.Metrics.ScannerReadiness.Nuclei || !res.Data.Metrics.ScannerReadiness.Zap {
			t.Errorf("expected verified scanner readiness")
		}
	})
}
