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
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

type mockFindingStore struct {
	findings     map[uuid.UUID]*findings.PersistentFinding
	observations map[uuid.UUID][]*findings.FindingObservation
	timeline     map[uuid.UUID][]*findings.TimelineEntry
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

func (m *mockFindingStore) GetTimelineByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*findings.TimelineEntry, error) {
	f, exists := m.findings[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, findings.ErrFindingNotFound
	}
	all, exists := m.timeline[findingID]
	if !exists {
		return []*findings.TimelineEntry{}, nil
	}
	if offset >= len(all) {
		return []*findings.TimelineEntry{}, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

func (m *mockFindingStore) SaveTriageDecision(ctx context.Context, decision *findings.TriageDecision) error {
	f, exists := m.findings[decision.FindingID]
	if !exists || f.TenantID != decision.TenantID {
		return findings.ErrFindingNotFound
	}
	if err := findings.ValidateTriageDecision(decision); err != nil {
		return err
	}
	var targetStatus findings.FindingStatus
	switch decision.Disposition {
	case findings.DispositionConfirmed:
		targetStatus = findings.StatusConfirmed
	case findings.DispositionInvestigating:
		targetStatus = findings.StatusInProgress
	case findings.DispositionFalsePositive:
		targetStatus = findings.StatusFalsePositive
	case findings.DispositionAcceptedRisk:
		targetStatus = findings.StatusAcceptedRisk
	case findings.DispositionDuplicate:
		targetStatus = findings.StatusResolved
	}
	if findings.CanonicalStatus(f.Status) != findings.CanonicalStatus(targetStatus) {
		if err := findings.ValidateTransition(f.Status, targetStatus); err != nil {
			return err
		}
		f.Status = targetStatus
		f.UpdatedAt = time.Now().UTC()
	}
	return nil
}

func (m *mockFindingStore) MarkFindingFalsePositive(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	actorID uuid.UUID,
	justification, rebuttal string,
	corrID uuid.UUID,
) (*findings.FalsePositiveReview, error) {
	f, exists := m.findings[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, findings.ErrFindingNotFound
	}
	if findings.CanonicalStatus(f.Status) == findings.StatusFalsePositive {
		return nil, findings.ErrAlreadyFalsePositive
	}
	review := &findings.FalsePositiveReview{
		ID:               uuid.New(),
		TenantID:         tenantID,
		FindingID:        findingID,
		ActorID:          &actorID,
		Action:           findings.ActionMarkedFalsePositive,
		Justification:    justification,
		EvidenceRebuttal: rebuttal,
		CreatedAt:        time.Now().UTC(),
	}
	if err := findings.ValidateFalsePositiveDecision(review); err != nil {
		return nil, err
	}
	f.Status = findings.StatusFalsePositive
	f.UpdatedAt = review.CreatedAt
	return review, nil
}

func (m *mockFindingStore) ReverseFalsePositive(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	actorID uuid.UUID,
	targetStatus findings.FindingStatus,
	justification string,
	corrID uuid.UUID,
) (*findings.FalsePositiveReview, error) {
	f, exists := m.findings[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, findings.ErrFindingNotFound
	}
	if findings.CanonicalStatus(f.Status) != findings.StatusFalsePositive {
		return nil, findings.ErrNotFalsePositive
	}
	if err := findings.ValidateTransition(f.Status, targetStatus); err != nil {
		return nil, err
	}
	review := &findings.FalsePositiveReview{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		ActorID:       &actorID,
		Action:        findings.ActionReversed,
		Justification: justification,
		CreatedAt:     time.Now().UTC(),
	}
	if err := findings.ValidateFalsePositiveDecision(review); err != nil {
		return nil, err
	}
	f.Status = targetStatus
	f.UpdatedAt = review.CreatedAt
	return review, nil
}

func (m *mockFindingStore) GetFalsePositiveReviewsByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) ([]*findings.FalsePositiveReview, error) {
	return nil, nil
}

func (m *mockFindingStore) UpdateFindingStatus(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	newStatus findings.FindingStatus,
	actorUserID *uuid.UUID,
	note string,
	correlationID uuid.UUID,
) (*findings.PersistentFinding, *findings.FindingEvent, error) {
	f, exists := m.findings[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, nil, findings.ErrFindingNotFound
	}
	if err := findings.ValidateTransition(f.Status, newStatus); err != nil {
		return nil, nil, err
	}
	fromStatus := f.Status
	f.Status = newStatus
	f.UpdatedAt = time.Now().UTC()
	event := &findings.FindingEvent{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		FromStatus:    &fromStatus,
		ToStatus:      newStatus,
		EventType:     findings.EventTriage,
		ActorUserID:   actorUserID,
		Note:          note,
		CorrelationID: correlationID,
		CreatedAt:     f.UpdatedAt,
	}
	return f, event, nil
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

func TestGetFindingTimelineSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	entryID := uuid.New()
	now := time.Now().UTC()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Title:    "SQL Injection",
				Status:   findings.StatusOpen,
			},
		},
		timeline: map[uuid.UUID][]*findings.TimelineEntry{
			findingID: {
				{
					ID:            entryID,
					TenantID:      tenantID,
					FindingID:     findingID,
					EventType:     findings.TimelineEventFindingCreated,
					Payload:       map[string]any{"severity": "HIGH"},
					CorrelationID: uuid.New(),
					CreatedAt:     now,
				},
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/timeline", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool                      `json:"success"`
		Data    []*findings.TimelineEntry `json:"data"`
		Meta    map[string]any            `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success true")
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 timeline entry, got %d", len(resp.Data))
	}
	if resp.Data[0].ID != entryID {
		t.Errorf("expected entry ID %s, got %s", entryID, resp.Data[0].ID)
	}
	if resp.Meta["count"] != float64(1) {
		t.Errorf("expected meta count 1, got %v", resp.Meta["count"])
	}
}

func TestGetFindingTimelineNotFoundAndCrossTenantIDOR(t *testing.T) {
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
		timeline: map[uuid.UUID][]*findings.TimelineEntry{
			findingA: {
				{
					ID:        uuid.New(),
					TenantID:  tenantA,
					FindingID: findingA,
					EventType: findings.TimelineEventFindingCreated,
				},
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

	// Tenant B attempts to read Tenant A's timeline -> 404 (IDOR safe)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingA.String()+"/timeline", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on cross-tenant IDOR, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetFindingTimelineUnconfiguredStore(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+uuid.New().String()+"/timeline", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when store unconfigured, got %d", rec.Code)
	}
}

func TestTransitionFindingSuccess(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Title:    "SQL Injection in /api/login",
				Status:   findings.StatusNew,
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

	body := []byte(`{"target_status":"CONFIRMED","reason":"Validated in staging"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/transition", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool                      `json:"success"`
		Data    TransitionFindingResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success true")
	}
	if resp.Data.Finding.Status != findings.StatusConfirmed {
		t.Errorf("expected status CONFIRMED, got %s", resp.Data.Finding.Status)
	}
	if resp.Data.Event == nil || resp.Data.Event.ToStatus != findings.StatusConfirmed {
		t.Errorf("expected event with ToStatus CONFIRMED")
	}
}

func TestTransitionFindingSensitiveReasonRequired(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Title:    "False Alarm",
				Status:   findings.StatusNew,
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

	// Missing reason on FALSE_POSITIVE transition -> 422
	bodyNoReason := []byte(`{"target_status":"FALSE_POSITIVE"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/transition", bytes.NewReader(bodyNoReason))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity when reason missing, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// With reason -> 200 OK
	bodyWithReason := []byte(`{"target_status":"FALSE_POSITIVE","reason":"Verified scanner rule hallucination"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/transition", bytes.NewReader(bodyWithReason))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK when reason provided, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestTransitionFindingIllegalTransition(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingID: {
				ID:       findingID,
				TenantID: tenantID,
				Title:    "False Alarm",
				Status:   findings.StatusFalsePositive,
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

	// FALSE_POSITIVE -> IN_PROGRESS is illegal -> 409 Conflict
	body := []byte(`{"target_status":"IN_PROGRESS"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID.String()+"/transition", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for illegal transition, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTransitionFindingCrossTenantIDOR(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	findingA := uuid.New()

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			findingA: {
				ID:       findingA,
				TenantID: tenantA,
				Title:    "Tenant A Secret Finding",
				Status:   findings.StatusNew,
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

	// Tenant B attempts to transition Tenant A's finding -> must return 404 (IDOR safe)
	body := []byte(`{"target_status":"CONFIRMED"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingA.String()+"/transition", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on cross-tenant transition, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTransitionFindingUnconfiguredStore(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	body := []byte(`{"target_status":"CONFIRMED"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+uuid.New().String()+"/transition", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when store unconfigured, got %d", rec.Code)
	}
}

