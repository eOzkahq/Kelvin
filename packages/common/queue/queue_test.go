package queue

import (
	"context"
	"errors"
	"testing"
	"time"
)

var validMessage = Message{Version: 1, ID: "123e4567-e89b-12d3-a456-426614174000", AssessmentID: "123e4567-e89b-12d3-a456-426614174001", TenantID: "123e4567-e89b-12d3-a456-426614174002", CorrelationID: "trace-24", Type: "NUCLEI", Payload: []byte(`{"target":"https://example.test"}`), MaxAttempts: 2}

func TestMessageValidation(t *testing.T) {
	if err := validMessage.Validate(); err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}
	tests := []Message{func() Message { m := validMessage; m.TenantID = "bad"; return m }(), func() Message { m := validMessage; m.Type = "lowercase"; return m }(), func() Message { m := validMessage; m.Payload = []byte(`[]`); return m }(), func() Message { m := validMessage; m.MaxAttempts = 21; return m }()}
	for _, m := range tests {
		if !errors.Is(m.Validate(), ErrInvalidMessage) {
			t.Errorf("invalid message accepted: %+v", m)
		}
	}
}

func TestMemoryQueueLifecycleAndRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := NewMemory()
	if err := q.Enqueue(ctx, validMessage); err != nil {
		t.Fatal(err)
	}
	d, err := q.Consume(ctx, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if d.Attempts != 1 {
		t.Fatalf("attempts=%d", d.Attempts)
	}
	if err := q.Fail(ctx, d, errors.New("temporary")); err != nil {
		t.Fatal(err)
	}
	d, err = q.Consume(ctx, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if d.Attempts != 2 {
		t.Fatalf("retry attempts=%d", d.Attempts)
	}
	if err := q.Fail(ctx, d, errors.New("permanent")); err != nil {
		t.Fatal(err)
	}
	s, err := q.GetStatus(ctx, validMessage.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "DEAD_LETTER" {
		t.Fatalf("state=%s", s.State)
	}
}

func TestWorkerTokenScopeExpiryAndSignature(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	tokens := WorkerTokens{Secret: []byte("01234567890123456789012345678901"), TTL: time.Minute, Now: func() time.Time { return now }}
	token, err := tokens.Issue("job-1", "tenant-1", "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tokens.Verify(token, "job-1", "tenant-1", "worker-1"); err != nil {
		t.Fatal(err)
	}
	if err := tokens.Verify(token, "job-2", "tenant-1", "worker-1"); err == nil {
		t.Fatal("wrong job scope accepted")
	}
	if err := tokens.Verify(token, "job-1", "tenant-1", "worker-2"); err == nil {
		t.Fatal("wrong worker scope accepted")
	}
	if err := tokens.Verify(token, "job-1", "tenant-2", "worker-1"); err == nil {
		t.Fatal("wrong tenant scope accepted")
	}
	tokens.Now = func() time.Time { return now.Add(time.Minute) }
	if err := tokens.Verify(token, "job-1", "tenant-1", "worker-1"); err == nil {
		t.Fatal("expired token accepted")
	}
	if err := tokens.Verify(token+"x", "job-1", "tenant-1", "worker-1"); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestMemoryQueueDistributedLease(t *testing.T) {
	ctx := context.Background()
	q := NewMemory()
	jobID := "job-lease-test-1"

	// 1. Initial acquisition by worker-1
	acquired, err := q.AcquireLease(ctx, jobID, "worker-1", 500*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("expected initial lease acquisition to succeed, got %v, err=%v", acquired, err)
	}

	// 2. Active lease query
	active, owner, err := q.IsLeaseActive(ctx, jobID)
	if err != nil || !active || owner != "worker-1" {
		t.Fatalf("expected lease active with owner worker-1, got active=%v, owner=%s, err=%v", active, owner, err)
	}

	// 3. Competing acquisition by worker-2 should fail
	acquired, err = q.AcquireLease(ctx, jobID, "worker-2", 500*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error during competing acquisition: %v", err)
	}
	if acquired {
		t.Fatal("competing worker acquired active lease")
	}

	// 4. Renewal by wrong worker fails
	if err := q.RenewLease(ctx, jobID, "worker-2", time.Second); err == nil {
		t.Fatal("unauthorized worker successfully renewed lease")
	}

	// 5. Renewal by owner succeeds
	if err := q.RenewLease(ctx, jobID, "worker-1", time.Second); err != nil {
		t.Fatalf("owner failed to renew lease: %v", err)
	}

	// 6. Release by owner
	if err := q.ReleaseLease(ctx, jobID, "worker-1"); err != nil {
		t.Fatalf("failed to release lease: %v", err)
	}

	active, _, _ = q.IsLeaseActive(ctx, jobID)
	if active {
		t.Fatal("lease still active after release")
	}

	// 7. worker-2 can now acquire
	acquired, err = q.AcquireLease(ctx, jobID, "worker-2", 50*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("worker-2 failed to acquire released lease: %v", err)
	}

	// 8. Lease expiration allows acquisition
	time.Sleep(70 * time.Millisecond)
	acquired, err = q.AcquireLease(ctx, jobID, "worker-3", 100*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("worker-3 failed to acquire expired lease: %v", err)
	}
}
