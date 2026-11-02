package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSLAService_PolicyConfiguration(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySLARepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSLAService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("configure valid SLA policy", func(t *testing.T) {
		p := &SLAPolicy{
			OrganizationID:          orgID,
			Name:                    "Fintech SLA Policy",
			CriticalRemediationDays: 3,
			HighRemediationDays:     14,
			MediumRemediationDays:   45,
			LowRemediationDays:      90,
			CriticalTriageHours:     12,
			HighTriageHours:         48,
		}

		err := service.ConfigurePolicy(ctx, actorID, p)
		if err != nil {
			t.Fatalf("unexpected error configuring policy: %v", err)
		}
		if p.Version != 1 {
			t.Errorf("expected version 1, got %d", p.Version)
		}
	})

	t.Run("reject non-positive durations", func(t *testing.T) {
		p := &SLAPolicy{
			OrganizationID:          orgID,
			CriticalRemediationDays: 0, // Invalid
			HighRemediationDays:     14,
			MediumRemediationDays:   45,
			LowRemediationDays:      90,
		}
		err := service.ConfigurePolicy(ctx, actorID, p)
		if !errors.Is(err, ErrInvalidSLADuration) {
			t.Fatalf("expected ErrInvalidSLADuration, got %v", err)
		}
	})
}

func TestSLAService_CalculationAndEvaluation(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySLARepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSLAService(repo, mockAudit)

	orgID := uuid.New()
	findingID := uuid.New()
	firstSeen := time.Date(2027, 5, 1, 10, 0, 0, 0, time.UTC)

	policy := &SLAPolicy{
		OrganizationID:          orgID,
		CriticalRemediationDays: 7,
		HighRemediationDays:     30,
		MediumRemediationDays:   90,
		LowRemediationDays:      180,
		CriticalTriageHours:     24,
		HighTriageHours:         72,
	}
	_ = service.ConfigurePolicy(ctx, "admin", policy)

	t.Run("calculate SLA for Critical finding", func(t *testing.T) {
		tracker, err := service.CalculateSLA(ctx, orgID, findingID, "CRITICAL", firstSeen)
		if err != nil {
			t.Fatalf("unexpected error calculating SLA: %v", err)
		}
		expectedRemDue := firstSeen.Add(7 * 24 * time.Hour)
		expectedTriageDue := firstSeen.Add(24 * time.Hour)

		if !tracker.RemediationDueAt.Equal(expectedRemDue) {
			t.Errorf("expected remediation due %v, got %v", expectedRemDue, tracker.RemediationDueAt)
		}
		if !tracker.TriageDueAt.Equal(expectedTriageDue) {
			t.Errorf("expected triage due %v, got %v", expectedTriageDue, tracker.TriageDueAt)
		}
		if tracker.PolicyVersion != policy.Version {
			t.Errorf("expected tracker policy version %d, got %d", policy.Version, tracker.PolicyVersion)
		}
	})

	t.Run("on track evaluation before due date", func(t *testing.T) {
		checkTime := firstSeen.Add(2 * 24 * time.Hour) // Day 2 of 7
		dec, err := service.EvaluateFindingSLAStatus(ctx, findingID, "OPEN", checkTime)
		if err != nil {
			t.Fatalf("unexpected error evaluating SLA: %v", err)
		}
		if dec.IsBreached || dec.RemediationStatus != SLAStatusOnTrack {
			t.Errorf("expected ON_TRACK, got %s", dec.RemediationStatus)
		}
		if dec.HoursRemaining <= 0 {
			t.Errorf("expected positive hours remaining")
		}
	})

	t.Run("breached evaluation after due date", func(t *testing.T) {
		checkTime := firstSeen.Add(8 * 24 * time.Hour) // Day 8 of 7 (Overdue)
		dec, err := service.EvaluateFindingSLAStatus(ctx, findingID, "OPEN", checkTime)
		if err != nil {
			t.Fatalf("unexpected error evaluating SLA: %v", err)
		}
		if !dec.IsBreached || dec.RemediationStatus != SLAStatusBreached {
			t.Errorf("expected BREACHED, got %s", dec.RemediationStatus)
		}
		if dec.HoursRemaining >= 0 {
			t.Errorf("expected negative hours remaining for overdue finding")
		}
	})

	t.Run("pause and resume SLA extends deadline", func(t *testing.T) {
		newFindingID := uuid.New()
		tracker, _ := service.CalculateSLA(ctx, orgID, newFindingID, "HIGH", firstSeen)
		originalDue := tracker.RemediationDueAt

		// Pause
		err := service.PauseSLA(ctx, newFindingID, "exception requested")
		if err != nil {
			t.Fatalf("unexpected error pausing SLA: %v", err)
		}

		// Double pause rejected
		err = service.PauseSLA(ctx, newFindingID, "again")
		if !errors.Is(err, ErrSLAAlreadyPaused) {
			t.Fatalf("expected ErrSLAAlreadyPaused, got %v", err)
		}

		// Fast forward paused duration by modifying pausedAt in repository
		tReloaded, _ := repo.GetTracker(ctx, newFindingID)
		pastPaused := time.Now().UTC().Add(-48 * time.Hour) // Paused for 48 hours
		tReloaded.PausedAt = &pastPaused
		_ = repo.UpdateTracker(ctx, tReloaded)

		// Resume
		err = service.ResumeSLA(ctx, newFindingID)
		if err != nil {
			t.Fatalf("unexpected error resuming SLA: %v", err)
		}

		tResumed, _ := repo.GetTracker(ctx, newFindingID)
		if tResumed.PausedAt != nil {
			t.Errorf("expected PausedAt to be nil after resume")
		}
		if !tResumed.RemediationDueAt.After(originalDue) {
			t.Errorf("expected RemediationDueAt extended beyond original due date")
		}
	})

	t.Run("resolved finding marks SLA as MET", func(t *testing.T) {
		dec, err := service.EvaluateFindingSLAStatus(ctx, findingID, "RESOLVED", time.Now().UTC())
		if err != nil {
			t.Fatalf("unexpected error evaluating resolved: %v", err)
		}
		if dec.RemediationStatus != SLAStatusMet || dec.IsBreached {
			t.Errorf("expected SLA MET for resolved finding")
		}
	})
}
