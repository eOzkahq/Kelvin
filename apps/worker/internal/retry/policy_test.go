package retry

import (
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/classification"
)

func TestPolicyRetriesTransientFailures(t *testing.T) {
	pol := DefaultPolicy()
	pol.JitterEnabled = false

	failure := classification.ClassifiedFailure{
		Category:  classification.CategoryTargetUnreachable,
		Code:      "ERR_TARGET_UNREACHABLE",
		Retryable: true,
	}

	// Attempt 0: retryable with initial backoff
	should, backoff := pol.ShouldRetry(0, failure, time.Time{})
	if !should {
		t.Fatalf("expected attempt 0 to be retryable")
	}
	if backoff != 1*time.Second {
		t.Fatalf("expected backoff of 1s, got %v", backoff)
	}

	// Attempt 1: retryable with exponential backoff 2s
	should, backoff = pol.ShouldRetry(1, failure, time.Time{})
	if !should {
		t.Fatalf("expected attempt 1 to be retryable")
	}
	if backoff != 2*time.Second {
		t.Fatalf("expected backoff of 2s, got %v", backoff)
	}

	// Attempt 2: exceeds MaxRetries (2) -> terminal
	should, _ = pol.ShouldRetry(2, failure, time.Time{})
	if should {
		t.Fatalf("expected attempt 2 to be rejected due to MaxRetries")
	}
}

func TestPolicyRejectsTerminalFailures(t *testing.T) {
	pol := DefaultPolicy()

	terminalCategories := []classification.FailureCategory{
		classification.CategoryInvalidConfig,
		classification.CategoryScopeViolation,
		classification.CategoryResourceExhaustion,
		classification.CategoryOutputParseError,
		classification.CategoryUnsupportedVersion,
		classification.CategoryProcessCrash,
		classification.CategoryUnknown,
	}

	for _, cat := range terminalCategories {
		t.Run(string(cat), func(t *testing.T) {
			failure := classification.ClassifiedFailure{
				Category:  cat,
				Retryable: cat.IsRetryable(),
			}
			should, _ := pol.ShouldRetry(0, failure, time.Time{})
			if should {
				t.Fatalf("category %s should never be retried", cat)
			}
		})
	}
}

func TestPolicyRespectsAssessmentDeadline(t *testing.T) {
	pol := DefaultPolicy()
	pol.InitialBackoff = 2 * time.Second
	pol.JitterEnabled = false

	failure := classification.ClassifiedFailure{
		Category:  classification.CategoryTargetUnreachable,
		Retryable: true,
	}

	// Case 1: Deadline allows backoff (deadline 10s from now, backoff 2s)
	validDeadline := time.Now().Add(10 * time.Second)
	should, backoff := pol.ShouldRetry(0, failure, validDeadline)
	if !should || backoff != 2*time.Second {
		t.Fatalf("expected retry permitted within deadline, got should=%t backoff=%v", should, backoff)
	}

	// Case 2: Deadline is only 1s away, but backoff requires 2s -> abort retry
	shortDeadline := time.Now().Add(1 * time.Second)
	should, _ = pol.ShouldRetry(0, failure, shortDeadline)
	if should {
		t.Fatalf("expected retry to be rejected when backoff exceeds remaining deadline")
	}
}

func TestScannerTailoredPolicies(t *testing.T) {
	nucleiPol := ScannerPolicy("nuclei")
	if nucleiPol.MaxRetries != 1 {
		t.Fatalf("expected Nuclei to have MaxRetries=1, got %d", nucleiPol.MaxRetries)
	}

	preflightPol := ScannerPolicy("http_preflight")
	if preflightPol.MaxRetries != 2 {
		t.Fatalf("expected preflight to have MaxRetries=2, got %d", preflightPol.MaxRetries)
	}
}

func TestRecorderEventsAndFiltering(t *testing.T) {
	rec := NewRecorder()

	var received []RetryEvent
	var mu sync.Mutex
	rec.AddListener(func(ev RetryEvent) {
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
	})

	ev1 := RetryEvent{
		JobID:           "job-1",
		Scanner:         "nuclei",
		Target:          "test.com",
		Attempt:         1,
		BackoffDuration: 2 * time.Second,
	}
	ev2 := RetryEvent{
		JobID:           "job-2",
		Scanner:         "zap",
		Target:          "app.test",
		Attempt:         1,
		BackoffDuration: 2 * time.Second,
	}

	rec.Record(ev1)
	rec.Record(ev2)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count != 2 {
		t.Fatalf("expected 2 received events via listener, got %d", count)
	}

	job1Events := rec.EventsForJob("job-1")
	if len(job1Events) != 1 || job1Events[0].Scanner != "nuclei" {
		t.Fatalf("unexpected events for job-1: %+v", job1Events)
	}
}
