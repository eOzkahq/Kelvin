package progress

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestStageValidation(t *testing.T) {
	validStages := []Stage{
		StagePreflight,
		StageScannerInitialization,
		StageScannerExecution,
		StageOutputCollection,
		StageResultNormalization,
		StageCompletion,
	}
	for _, s := range validStages {
		if !s.Valid() {
			t.Errorf("expected stage %q to be valid", s)
		}
	}

	if Stage("INVALID_STAGE").Valid() {
		t.Error("expected INVALID_STAGE to be invalid")
	}
}

func TestStageTrackerNormalProgression(t *testing.T) {
	mem := NewMemoryPublisher()
	tracker := NewTracker("assessment-1", "job-1", "tenant-1", "nuclei", mem, zap.NewNop())

	ctx := context.Background()

	// 1. Preflight
	if err := tracker.TransitionTo(ctx, StagePreflight, "running scope checks"); err != nil {
		t.Fatalf("TransitionTo Preflight error: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	// 2. Scanner Initialization
	if err := tracker.TransitionTo(ctx, StageScannerInitialization, "generating OCI config"); err != nil {
		t.Fatalf("TransitionTo ScannerInitialization error: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	// 3. Scanner Execution
	if err := tracker.TransitionTo(ctx, StageScannerExecution, "running nuclei container"); err != nil {
		t.Fatalf("TransitionTo ScannerExecution error: %v", err)
	}

	// Report determinate progress during execution
	prog := NewDeterminateProgress(25, 100, "templates", "testing target")
	if err := tracker.ReportProgress(ctx, prog); err != nil {
		t.Fatalf("ReportProgress error: %v", err)
	}

	// 4. Output Collection
	if err := tracker.TransitionTo(ctx, StageOutputCollection, "extracting report.json"); err != nil {
		t.Fatalf("TransitionTo OutputCollection error: %v", err)
	}

	// 5. Result Normalization
	if err := tracker.TransitionTo(ctx, StageResultNormalization, "validating finding schema"); err != nil {
		t.Fatalf("TransitionTo ResultNormalization error: %v", err)
	}

	// 6. Completion
	if err := tracker.CompleteStage(ctx, "scan finished cleanly"); err != nil {
		t.Fatalf("CompleteStage error: %v", err)
	}

	if tracker.CurrentStage() != StageCompletion {
		t.Errorf("got current stage %q, want %q", tracker.CurrentStage(), StageCompletion)
	}
	if tracker.CurrentStatus() != StageStatusCompleted {
		t.Errorf("got current status %q, want %q", tracker.CurrentStatus(), StageStatusCompleted)
	}

	transitions := tracker.Transitions()
	if len(transitions) != 6 {
		t.Fatalf("expected 6 transitions, got %d", len(transitions))
	}

	if transitions[0].ToStage != StagePreflight {
		t.Errorf("transition 0 ToStage = %q, want %q", transitions[0].ToStage, StagePreflight)
	}
	if transitions[1].FromStage != StagePreflight || transitions[1].ToStage != StageScannerInitialization {
		t.Errorf("transition 1 mismatch: %+v", transitions[1])
	}
	if transitions[1].Duration <= 0 {
		t.Errorf("expected transition 1 duration > 0, got %v", transitions[1].Duration)
	}

	events := mem.Events()
	if len(events) != 7 { // 6 stage transitions + 1 progress update
		t.Fatalf("expected 7 published events, got %d", len(events))
	}

	// Verify progress event has percentage
	foundProgress := false
	for _, ev := range events {
		if ev.Progress != nil && ev.Progress.HasPercentage() {
			foundProgress = true
			if *ev.Progress.Percentage != 25.0 {
				t.Errorf("expected 25%% progress, got %.2f%%", *ev.Progress.Percentage)
			}
			if ev.Progress.ItemsCompleted != 25 || ev.Progress.ItemsTotal != 100 {
				t.Errorf("items mismatch: completed=%d, total=%d", ev.Progress.ItemsCompleted, ev.Progress.ItemsTotal)
			}
		}
	}
	if !foundProgress {
		t.Error("determinate progress event was not published")
	}
}

func TestStageTrackerInterruptedExecution(t *testing.T) {
	mem := NewMemoryPublisher()
	tracker := NewTracker("assessment-2", "job-2", "tenant-1", "zap", mem, zap.NewNop())
	ctx := context.Background()

	_ = tracker.TransitionTo(ctx, StagePreflight, "init")
	_ = tracker.TransitionTo(ctx, StageScannerExecution, "executing")

	// Fail stage due to cancellation
	if err := tracker.FailStage(ctx, StageStatusCancelled, "operator cancelled assessment"); err != nil {
		t.Fatalf("FailStage error: %v", err)
	}

	if tracker.CurrentStatus() != StageStatusCancelled {
		t.Errorf("expected status CANCELLED, got %q", tracker.CurrentStatus())
	}

	events := mem.EventsForJob("job-2")
	if len(events) != 3 {
		t.Fatalf("expected 3 events for job-2, got %d", len(events))
	}
	lastEvent := events[len(events)-1]
	if lastEvent.StageStatus != StageStatusCancelled {
		t.Errorf("last event status = %q, want %q", lastEvent.StageStatus, StageStatusCancelled)
	}
}

func TestHonestIndeterminateProgress(t *testing.T) {
	prog := NewIndeterminateProgress("evaluating targets")
	if prog.HasPercentage() {
		t.Fatal("expected HasPercentage() = false for indeterminate progress")
	}
	if prog.Percentage != nil {
		t.Fatalf("expected Percentage == nil, got %v", *prog.Percentage)
	}
	if prog.Message != "evaluating targets" {
		t.Errorf("got message %q, want %q", prog.Message, "evaluating targets")
	}
}

func TestDeterminateProgressBounds(t *testing.T) {
	// Normal
	p1 := NewDeterminateProgress(50, 200, "requests", "running")
	if !p1.HasPercentage() || *p1.Percentage != 25.0 {
		t.Fatalf("expected 25%%, got %v", p1.Percentage)
	}

	// Division by zero or negative total must be indeterminate
	p2 := NewDeterminateProgress(10, 0, "requests", "running")
	if p2.HasPercentage() {
		t.Fatalf("expected indeterminate progress when total is 0")
	}

	// Clamping over 100%
	p3 := NewDeterminateProgress(150, 100, "requests", "running")
	if *p3.Percentage != 100.0 {
		t.Fatalf("expected clamped 100%%, got %v", *p3.Percentage)
	}
}

func TestSanitizeMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Basic Auth URL",
			input:    "Connecting to https://admin:SuperSecret123@example.com/api",
			expected: "Connecting to https://admin:[REDACTED]@example.com/api",
		},
		{
			name:     "Query param token",
			input:    "Request failed for https://example.com/scan?token=abc12345&mode=fast",
			expected: "Request failed for https://example.com/scan?token=[REDACTED]&mode=fast",
		},
		{
			name:     "Query param password",
			input:    "Target URL: https://example.com/login?user=alice&password=mypassword",
			expected: "Target URL: https://example.com/login?user=alice&password=[REDACTED]",
		},
		{
			name:     "Bearer token",
			input:    "Header set: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expected: "Header set: Authorization: [REDACTED]",
		},
		{
			name:     "ANSI escape sequences",
			input:    "\x1b[32mScanning target\x1b[0m completed",
			expected: "Scanning target completed",
		},
		{
			name:     "Long message truncation",
			input:    strings.Repeat("A", 300),
			expected: strings.Repeat("A", maxMessageLength-15) + "... [truncated]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeMessage(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeMessage(%q)\ngot:  %q\nwant: %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestContextReporter(t *testing.T) {
	mem := NewMemoryPublisher()
	tracker := NewTracker("a", "j", "t", "s", mem, nil)

	ctx := context.Background()
	if _, ok := ReporterFromContext(ctx); ok {
		t.Fatal("expected no reporter in empty context")
	}

	ctx = WithReporter(ctx, tracker)
	rep, ok := ReporterFromContext(ctx)
	if !ok || rep == nil {
		t.Fatal("expected reporter in context")
	}

	if err := rep.ReportProgress(ctx, NewIndeterminateProgress("in context")); err != nil {
		t.Fatalf("ReportProgress error: %v", err)
	}

	events := mem.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Progress.Message != "in context" {
		t.Errorf("message = %q, want %q", events[0].Progress.Message, "in context")
	}
}
