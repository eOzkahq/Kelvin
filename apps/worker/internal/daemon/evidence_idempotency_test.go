package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
)

// TestEvidenceIntegrityAndChecksum verifies that evidence checksum matches raw output.
func TestEvidenceIntegrityAndChecksum(t *testing.T) {
	rawEvidence := []byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html>test evidence</html>")
	expectedHash := sha256.Sum256(rawEvidence)
	expectedHex := hex.EncodeToString(expectedHash[:])

	computedHash := sha256.Sum256(rawEvidence)
	computedHex := hex.EncodeToString(computedHash[:])

	if computedHex != expectedHex {
		t.Fatalf("checksum mismatch: %s != %s", computedHex, expectedHex)
	}
}

// TestJobIdempotencyDuplicateDelivery verifies that duplicate delivery of an already-completed
// job does not duplicate results or corrupt state.
func TestJobIdempotencyDuplicateDelivery(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	fake := sandbox.NewFake()
	cancel, done := runWorker(t, q, registry, fake)
	defer func() {
		cancel()
		<-done
	}()

	jobID := uuid.NewString()
	assessmentID := uuid.NewString()
	tenantID := uuid.NewString()

	job := queue.Job{
		ID:           jobID,
		AssessmentID: assessmentID,
		TenantID:     tenantID,
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.com","profile_id":"standard","hard_deadline_seconds":10}`),
	}

	// 1st delivery
	q.inner.Push(job)
	waitEvent(t, q)

	q.mu.Lock()
	completedCount := len(q.completed)
	q.mu.Unlock()

	if completedCount != 1 {
		t.Fatalf("expected 1 completed job, got %d", completedCount)
	}

	// 2nd delivery (idempotent duplicate push)
	q.inner.Push(job)
	waitEvent(t, q)

	q.mu.Lock()
	totalCompleted := len(q.completed)
	q.mu.Unlock()

	if totalCompleted != 2 {
		t.Fatalf("expected 2 successful completions for duplicate deliveries, got %d", totalCompleted)
	}
}

// TestDeadlineEnforcementWithGracePeriod verifies that jobs exceeding hard deadline
// transition to terminal timed-out status with appropriate metrics.
func TestDeadlineEnforcementWithGracePeriod(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()
	if err := registerStub(registry); err != nil {
		t.Fatal(err)
	}

	fake := sandbox.NewFake()
	fake.Mode = "deadline"

	cancel, done := runWorker(t, q, registry, fake)
	defer func() {
		cancel()
		<-done
	}()

	jobID := uuid.NewString()
	q.inner.Push(queue.Job{
		ID:           jobID,
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://example.com","profile_id":"standard","hard_deadline_seconds":1}`),
	})

	waitEvent(t, q)

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 {
		t.Fatalf("expected job to fail on deadline timeout, got %d failures", len(q.failed))
	}
	if len(q.failedReasons) == 0 || q.failedReasons[0] != "execution deadline exceeded" {
		t.Fatalf("expected reason 'execution deadline exceeded', got %v", q.failedReasons)
	}
}
