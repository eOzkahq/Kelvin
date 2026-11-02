package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSchedulingService_Configuration(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySchedulingWindowRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSchedulingService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("configure valid scheduling window", func(t *testing.T) {
		w := &SchedulingWindow{
			OrganizationID:     orgID,
			Name:               "Business Hours Blackout",
			WindowType:         WindowTypeBlackout,
			TimeZone:           "America/New_York",
			DaysOfWeek:         []int{1, 2, 3, 4, 5}, // Mon-Fri
			StartTime:          "09:00",
			EndTime:            "17:00",
			BlackoutAction:     BlackoutActionHold,
			AppliesToManual:    true,
			AppliesToScheduled: true,
		}

		err := service.ConfigureWindow(ctx, actorID, w)
		if err != nil {
			t.Fatalf("unexpected error configuring window: %v", err)
		}
		if w.ID == uuid.Nil {
			t.Errorf("expected non-nil UUID")
		}
	})

	t.Run("reject invalid IANA timezone", func(t *testing.T) {
		w := &SchedulingWindow{
			OrganizationID: orgID,
			Name:           "Invalid TZ Window",
			WindowType:     WindowTypeBlackout,
			TimeZone:       "Invalid/City_Name",
			DaysOfWeek:     []int{1},
			StartTime:      "09:00",
			EndTime:        "17:00",
		}
		err := service.ConfigureWindow(ctx, actorID, w)
		if !errors.Is(err, ErrInvalidTimeZone) {
			t.Fatalf("expected ErrInvalidTimeZone, got %v", err)
		}
	})

	t.Run("reject invalid time format", func(t *testing.T) {
		w := &SchedulingWindow{
			OrganizationID: orgID,
			Name:           "Invalid Time",
			WindowType:     WindowTypeBlackout,
			TimeZone:       "UTC",
			DaysOfWeek:     []int{1},
			StartTime:      "25:00", // Invalid hour
			EndTime:        "17:00",
		}
		err := service.ConfigureWindow(ctx, actorID, w)
		if !errors.Is(err, ErrInvalidTimeFormat) {
			t.Fatalf("expected ErrInvalidTimeFormat, got %v", err)
		}
	})

	t.Run("reject invalid days of week", func(t *testing.T) {
		w := &SchedulingWindow{
			OrganizationID: orgID,
			Name:           "Invalid Day",
			WindowType:     WindowTypeBlackout,
			TimeZone:       "UTC",
			DaysOfWeek:     []int{0, 8}, // 0 and 8 are invalid
			StartTime:      "09:00",
			EndTime:        "17:00",
		}
		err := service.ConfigureWindow(ctx, actorID, w)
		if !errors.Is(err, ErrInvalidDaysOfWeek) {
			t.Fatalf("expected ErrInvalidDaysOfWeek, got %v", err)
		}
	})
}

func TestSchedulingService_Evaluation(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySchedulingWindowRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSchedulingService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	// Blackout window: Monday-Friday, 09:00 - 17:00 in America/New_York (HOLD)
	nyBlackout := &SchedulingWindow{
		OrganizationID:     orgID,
		Name:               "NY Business Hours Blackout",
		WindowType:         WindowTypeBlackout,
		TimeZone:           "America/New_York",
		DaysOfWeek:         []int{1, 2, 3, 4, 5},
		StartTime:          "09:00",
		EndTime:            "17:00",
		BlackoutAction:     BlackoutActionHold,
		AppliesToManual:    false, // Manual scans allowed!
		AppliesToScheduled: true,  // Scheduled scans held
	}
	_ = service.ConfigureWindow(ctx, actorID, nyBlackout)

	// In EDT (UTC-4):
	// 14:00 UTC on Wednesday = 10:00 AM EDT (Inside blackout 09:00-17:00)
	wednesdayDuringBlackout := time.Date(2027, 4, 14, 14, 0, 0, 0, time.UTC)

	// 23:00 UTC on Wednesday = 19:00 EDT (Outside blackout)
	wednesdayOutsideBlackout := time.Date(2027, 4, 14, 23, 0, 0, 0, time.UTC)

	t.Run("scheduled scan inside blackout is HELD with next available time", func(t *testing.T) {
		res, err := service.EvaluateExecution(ctx, orgID, wednesdayDuringBlackout, false)
		if err != nil {
			t.Fatalf("unexpected error evaluating execution: %v", err)
		}
		if res.CanExecuteNow {
			t.Errorf("expected CanExecuteNow=false during blackout")
		}
		if res.Verdict != VerdictHold {
			t.Errorf("expected VerdictHold, got %s", res.Verdict)
		}
		if res.NextAvailableTime == nil {
			t.Fatalf("expected non-nil NextAvailableTime")
		}
		// In America/New_York (EDT, UTC-4), 17:00 EDT is 21:00 UTC
		expectedEndUTC := time.Date(2027, 4, 14, 21, 0, 0, 0, time.UTC)
		if !res.NextAvailableTime.Equal(expectedEndUTC) {
			t.Errorf("expected NextAvailableTime %v, got %v", expectedEndUTC, *res.NextAvailableTime)
		}
	})

	t.Run("manual scan bypasses blackout when applies_to_manual is false", func(t *testing.T) {
		res, err := service.EvaluateExecution(ctx, orgID, wednesdayDuringBlackout, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.CanExecuteNow || res.Verdict != VerdictDispatch {
			t.Errorf("expected manual scan to dispatch immediately")
		}
	})

	t.Run("scheduled scan outside blackout dispatches immediately", func(t *testing.T) {
		res, err := service.EvaluateExecution(ctx, orgID, wednesdayOutsideBlackout, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.CanExecuteNow || res.Verdict != VerdictDispatch {
			t.Errorf("expected scan outside blackout to dispatch immediately")
		}
	})

	t.Run("blackout window with CANCEL action terminates scan", func(t *testing.T) {
		cancelWindow := &SchedulingWindow{
			OrganizationID:     orgID,
			Name:               "Weekend Maintenance Blackout",
			WindowType:         WindowTypeBlackout,
			TimeZone:           "UTC",
			DaysOfWeek:         []int{6, 7}, // Saturday & Sunday
			StartTime:          "00:00",
			EndTime:            "23:59",
			BlackoutAction:     BlackoutActionCancel,
			AppliesToManual:    true,
			AppliesToScheduled: true,
		}
		_ = service.ConfigureWindow(ctx, actorID, cancelWindow)

		saturdayTime := time.Date(2027, 4, 17, 12, 0, 0, 0, time.UTC) // Saturday
		res, err := service.EvaluateExecution(ctx, orgID, saturdayTime, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Verdict != VerdictCancel {
			t.Errorf("expected VerdictCancel, got %s", res.Verdict)
		}
		if res.CanExecuteNow {
			t.Errorf("expected CanExecuteNow=false")
		}
	})
}
