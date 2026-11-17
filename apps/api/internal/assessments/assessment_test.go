package assessments_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"go.uber.org/zap"
)

type mockQueue struct {
	enqueued []commonqueue.Message
	canceled []string
}

func (m *mockQueue) Enqueue(_ context.Context, msg commonqueue.Message) error {
	m.enqueued = append(m.enqueued, msg)
	return nil
}
func (m *mockQueue) Consume(_ context.Context, _ string) (commonqueue.Delivery, error) {
	return commonqueue.Delivery{}, nil
}
func (m *mockQueue) Complete(_ context.Context, _ commonqueue.Delivery) error { return nil }
func (m *mockQueue) Fail(_ context.Context, _ commonqueue.Delivery, _ error) error { return nil }
func (m *mockQueue) Cancel(_ context.Context, id string) error {
	m.canceled = append(m.canceled, id)
	return nil
}
func (m *mockQueue) GetStatus(_ context.Context, _ string) (commonqueue.Status, error) {
	return commonqueue.Status{}, nil
}
func (m *mockQueue) Heartbeat(_ context.Context, _, _ string, _ time.Duration) error { return nil }
func (m *mockQueue) AcquireLease(_ context.Context, _ string, _ string, _ time.Duration) (bool, error) {
	return true, nil
}
func (m *mockQueue) RenewLease(_ context.Context, _ string, _ string, _ time.Duration) error {
	return nil
}
func (m *mockQueue) ReleaseLease(_ context.Context, _ string, _ string) error {
	return nil
}
func (m *mockQueue) IsLeaseActive(_ context.Context, _ string) (bool, string, error) {
	return false, "", nil
}

func TestAssessmentCreation_CanaryEnforcement(t *testing.T) {
	repo := assessments.NewMemoryRepository()
	q := &mockQueue{}
	svc := assessments.NewService(repo, q, true, []string{"mock-target.kelvin.internal"}, zap.NewNop())

	tenantID := uuid.New().String()
	userID := uuid.New().String()

	// 1. Authorized canary target should succeed
	input := assessments.CreateAssessmentInput{
		Name:                     "Canary Qualification Scan",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	}

	record, err := svc.CreateAssessment(context.Background(), tenantID, userID, input)
	if err != nil {
		t.Fatalf("expected successful creation with canary target, got err: %v", err)
	}
	if record.ID == "" {
		t.Errorf("expected generated assessment ID")
	}
	if record.Status != assessments.StatusQueued {
		t.Errorf("expected status QUEUED, got %s", record.Status)
	}
	if len(q.enqueued) != 1 {
		t.Fatalf("expected 1 enqueued job, got %d", len(q.enqueued))
	}
	if q.enqueued[0].AssessmentID != record.ID {
		t.Errorf("expected enqueued message assessment ID %s, got %s", record.ID, q.enqueued[0].AssessmentID)
	}

	// 2. Target outside canary allowlist should be rejected
	externalInput := assessments.CreateAssessmentInput{
		Name:                     "External Unauthorized Scan",
		TargetAddress:            "https://target.external.com",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	}

	_, err = svc.CreateAssessment(context.Background(), tenantID, userID, externalInput)
	if err == nil {
		t.Fatalf("expected canary policy rejection for external target, got nil")
	}

	// 3. Target without scope confirmation should be rejected
	noScopeInput := assessments.CreateAssessmentInput{
		Name:                     "Unconfirmed Scope Scan",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: false,
	}

	_, err = svc.CreateAssessment(context.Background(), tenantID, userID, noScopeInput)
	if err == nil {
		t.Fatalf("expected rejection for unconfirmed scope, got nil")
	}

	// 4. Empty target should be rejected
	emptyTargetInput := assessments.CreateAssessmentInput{
		Name:                     "Empty Target Scan",
		TargetAddress:            "",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	}

	_, err = svc.CreateAssessment(context.Background(), tenantID, userID, emptyTargetInput)
	if err == nil {
		t.Fatalf("expected rejection for empty target, got nil")
	}
}

func TestAssessmentLifecycle_TenantBoundary(t *testing.T) {
	repo := assessments.NewMemoryRepository()
	svc := assessments.NewService(repo, nil, false, nil, zap.NewNop())

	tenantA := uuid.New().String()
	tenantB := uuid.New().String()

	asmtA, err := svc.CreateAssessment(context.Background(), tenantA, "userA", assessments.CreateAssessmentInput{
		Name:                     "Tenant A Assessment",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	})
	if err != nil {
		t.Fatalf("create assessment A failed: %v", err)
	}

	// Tenant A can retrieve assessment A
	detailA, err := svc.GetAssessment(context.Background(), tenantA, asmtA.ID)
	if err != nil {
		t.Fatalf("tenant A failed to retrieve own assessment: %v", err)
	}
	if detailA.ID != asmtA.ID {
		t.Errorf("expected assessment ID %s, got %s", asmtA.ID, detailA.ID)
	}

	// Tenant B CANNOT retrieve assessment A (cross-tenant isolation)
	_, err = svc.GetAssessment(context.Background(), tenantB, asmtA.ID)
	if err == nil {
		t.Fatalf("tenant B unexpectedly retrieved Tenant A's assessment!")
	}

	// Tenant B cannot see assessment A in list
	listB, totalB, err := svc.ListAssessments(context.Background(), tenantB, assessments.AssessmentFilter{})
	if err != nil {
		t.Fatalf("list assessments failed: %v", err)
	}
	if totalB != 0 || len(listB) != 0 {
		t.Errorf("tenant B unexpectedly saw assessments: %v", listB)
	}

	// Tenant A can see assessment A in list
	listA, totalA, err := svc.ListAssessments(context.Background(), tenantA, assessments.AssessmentFilter{})
	if err != nil {
		t.Fatalf("list assessments failed: %v", err)
	}
	if totalA != 1 || len(listA) != 1 {
		t.Errorf("tenant A expected 1 assessment, got %d", totalA)
	}
}

func TestAssessmentCancellation(t *testing.T) {
	repo := assessments.NewMemoryRepository()
	q := &mockQueue{}
	svc := assessments.NewService(repo, q, true, nil, zap.NewNop())

	tenantID := uuid.New().String()
	asmt, err := svc.CreateAssessment(context.Background(), tenantID, "user1", assessments.CreateAssessmentInput{
		Name:                     "Active Assessment",
		TargetAddress:            "http://127.0.0.1:8080",
		ProfileID:                "standard",
		AuthorizedScopeConfirmed: true,
	})
	if err != nil {
		t.Fatalf("create assessment failed: %v", err)
	}

	// Cancel active assessment
	err = svc.CancelAssessment(context.Background(), tenantID, asmt.ID)
	if err != nil {
		t.Fatalf("cancel active assessment failed: %v", err)
	}

	detail, err := svc.GetAssessment(context.Background(), tenantID, asmt.ID)
	if err != nil {
		t.Fatalf("get cancelled assessment failed: %v", err)
	}
	if detail.Status != assessments.StatusCancelled {
		t.Errorf("expected status CANCELLED, got %s", detail.Status)
	}
	if len(q.canceled) != 1 || q.canceled[0] != asmt.ID {
		t.Errorf("expected queue cancellation for assessment %s, got %v", asmt.ID, q.canceled)
	}

	// Cancelling again should fail (terminal state)
	err = svc.CancelAssessment(context.Background(), tenantID, asmt.ID)
	if err == nil {
		t.Fatalf("expected error cancelling already cancelled assessment, got nil")
	}
}

func TestProfilesAndTargetsCatalog(t *testing.T) {
	repo := assessments.NewMemoryRepository()
	svc := assessments.NewService(repo, nil, true, nil, zap.NewNop())

	tenantID := uuid.New().String()

	profiles, err := svc.GetProfiles(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get profiles failed: %v", err)
	}
	if len(profiles) < 3 {
		t.Errorf("expected at least 3 profiles (standard, safe_web, deep), got %d", len(profiles))
	}

	targets, err := svc.GetTargets(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get targets failed: %v", err)
	}
	if len(targets) < 2 {
		t.Errorf("expected at least 2 canary targets, got %d", len(targets))
	}
}
