package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAssessmentGovernance_ConfigurePolicy(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryAssessmentGovernanceRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewAssessmentGovernanceService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("configure governance policy increments version", func(t *testing.T) {
		p := &AssessmentGovernancePolicy{
			OrganizationID:          orgID,
			AllowedScanners:         []string{"zap", "nuclei"},
			AllowedAssessmentTypes: []string{"DAST", "NETWORK"},
			MaxConcurrency:          10,
			ProhibitIntrusiveOnProd:  true,
		}

		err := service.ConfigurePolicy(ctx, actorID, p)
		if err != nil {
			t.Fatalf("unexpected error configuring policy: %v", err)
		}
		if p.Version != 1 {
			t.Errorf("expected version 1, got %d", p.Version)
		}

		// Update policy
		p.MaxConcurrency = 8
		_ = service.ConfigurePolicy(ctx, actorID, p)
		if p.Version != 2 {
			t.Errorf("expected version 2 after second update, got %d", p.Version)
		}
	})

	t.Run("reject policy exceeding platform concurrency ceiling", func(t *testing.T) {
		p := &AssessmentGovernancePolicy{
			OrganizationID:  orgID,
			AllowedScanners: []string{"zap"},
			MaxConcurrency:  30, // Exceeds platform limit of 20
		}
		err := service.ConfigurePolicy(ctx, actorID, p)
		if !errors.Is(err, ErrExceedsPlatformLimit) {
			t.Fatalf("expected ErrExceedsPlatformLimit, got %v", err)
		}
	})
}

func TestAssessmentGovernance_EvaluateSubmission(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryAssessmentGovernanceRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewAssessmentGovernanceService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	policy := &AssessmentGovernancePolicy{
		OrganizationID:             orgID,
		AllowedScanners:            []string{"zap", "nuclei", "http"},
		AllowedAssessmentTypes:     []string{"DAST", "NETWORK"},
		MaxConcurrency:             3,
		ProhibitIntrusiveOnProd:    true,
		EnforceMaintenanceWindows:  true,
		MaintenanceWindowStart:     "01:00",
		MaintenanceWindowEnd:       "05:00",
	}
	_ = service.ConfigurePolicy(ctx, actorID, policy)

	baseSubmission := AssessmentSubmission{
		OrganizationID:           orgID,
		WorkspaceID:              uuid.New(),
		AssessmentType:           "DAST",
		TargetEnvironment:        "STAGING",
		RequestedScanners:        []string{"zap", "nuclei"},
		IntrusiveScan:            false,
		CurrentActiveAssessments: 1,
		ScheduledTime:            time.Date(2027, 3, 15, 2, 30, 0, 0, time.UTC), // 02:30 UTC within window
	}

	t.Run("compliant submission succeeds", func(t *testing.T) {
		eval, err := service.EvaluateSubmission(ctx, baseSubmission)
		if err != nil {
			t.Fatalf("unexpected rejection for compliant submission: %v", err)
		}
		if !eval.Allowed || len(eval.Violations) != 0 {
			t.Errorf("expected Allowed=true, got violations: %v", eval.Violations)
		}
		if eval.PolicyVersion != policy.Version {
			t.Errorf("expected policy version %d, got %d", policy.Version, eval.PolicyVersion)
		}
	})

	t.Run("reject unauthorized scanner", func(t *testing.T) {
		sub := baseSubmission
		sub.RequestedScanners = []string{"zap", "unapproved_custom_scanner"}

		eval, err := service.EvaluateSubmission(ctx, sub)
		if !errors.Is(err, ErrGovernanceViolation) {
			t.Fatalf("expected ErrGovernanceViolation, got %v", err)
		}
		if eval.Allowed {
			t.Errorf("expected Allowed=false")
		}
	})

	t.Run("reject unauthorized assessment type", func(t *testing.T) {
		sub := baseSubmission
		sub.AssessmentType = "FULL_RED_TEAM"

		eval, err := service.EvaluateSubmission(ctx, sub)
		if !errors.Is(err, ErrGovernanceViolation) {
			t.Fatalf("expected ErrGovernanceViolation, got %v", err)
		}
		if eval.Allowed {
			t.Errorf("expected Allowed=false")
		}
	})

	t.Run("reject when concurrency ceiling is reached", func(t *testing.T) {
		sub := baseSubmission
		sub.CurrentActiveAssessments = 3 // Limit is 3

		eval, err := service.EvaluateSubmission(ctx, sub)
		if !errors.Is(err, ErrGovernanceViolation) {
			t.Fatalf("expected ErrGovernanceViolation, got %v", err)
		}
		if eval.Allowed {
			t.Errorf("expected Allowed=false on concurrency limit")
		}
	})

	t.Run("reject intrusive scanning on production targets", func(t *testing.T) {
		sub := baseSubmission
		sub.TargetEnvironment = "PRODUCTION"
		sub.IntrusiveScan = true

		eval, err := service.EvaluateSubmission(ctx, sub)
		if !errors.Is(err, ErrGovernanceViolation) {
			t.Fatalf("expected ErrGovernanceViolation, got %v", err)
		}
		if eval.Allowed {
			t.Errorf("expected intrusive prod scan to be rejected")
		}
	})

	t.Run("reject scan scheduled outside maintenance window", func(t *testing.T) {
		sub := baseSubmission
		sub.ScheduledTime = time.Date(2027, 3, 15, 14, 0, 0, 0, time.UTC) // 14:00 UTC outside 01:00-05:00 window

		eval, err := service.EvaluateSubmission(ctx, sub)
		if !errors.Is(err, ErrGovernanceViolation) {
			t.Fatalf("expected ErrGovernanceViolation, got %v", err)
		}
		if eval.Allowed {
			t.Errorf("expected outside-window scan to be rejected")
		}
	})
}
