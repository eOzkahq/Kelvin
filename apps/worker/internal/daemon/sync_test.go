package daemon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"go.uber.org/zap"
)

func TestStateSyncer_TransitionsRecorded(t *testing.T) {
	ctx := context.Background()
	syncer := NewMemoryStateSyncer()

	tenantID := uuid.New().String()
	asmtID := uuid.New().String()
	jobID := uuid.New().String()

	if err := syncer.SyncJobState(ctx, tenantID, asmtID, jobID, "RUNNING", ""); err != nil {
		t.Fatalf("sync RUNNING failed: %v", err)
	}
	if err := syncer.SyncJobState(ctx, tenantID, asmtID, jobID, "COMPLETED", ""); err != nil {
		t.Fatalf("sync COMPLETED failed: %v", err)
	}

	transitions := syncer.GetTransitions()
	if len(transitions) != 2 {
		t.Fatalf("expected 2 transitions, got %d", len(transitions))
	}
	if transitions[0].Status != "RUNNING" {
		t.Errorf("expected transition 0 RUNNING, got %s", transitions[0].Status)
	}
	if transitions[1].Status != "COMPLETED" {
		t.Errorf("expected transition 1 COMPLETED, got %s", transitions[1].Status)
	}
}

func TestDaemon_StateSynchronizationOnFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := adapters.NewRegistry()
	q := newRecordingQueue()
	syncer := NewMemoryStateSyncer()

	jobID := uuid.New().String()
	asmtID := uuid.New().String()
	tenantID := uuid.New().String()

	// An invalid job envelope that fails validation
	invalidEnv := commonqueue.JobEnvelope{
		SchemaVersion: 2,
		JobID:         jobID,
		AssessmentID:  asmtID,
		TenantID:      tenantID,
		TargetAddress: "", // missing target triggers validation error
	}
	raw, _ := json.Marshal(invalidEnv)

	job := queue.Job{
		Version:       2,
		ID:            jobID,
		AssessmentID:  asmtID,
		TenantID:      tenantID,
		CorrelationID: "corr-sync-test",
		Type:          adapters.ScannerNuclei,
		Payload:       raw,
	}

	cfg := Config{
		WorkerID:    "worker-sync-test",
		StateSyncer: syncer,
	}

	process(ctx, zap.NewNop(), q, reg, job, cfg)

	transitions := syncer.GetTransitions()
	if len(transitions) != 1 {
		t.Fatalf("expected 1 transition recorded for failure, got %d", len(transitions))
	}
	if transitions[0].Status != "FAILED" {
		t.Errorf("expected status FAILED, got %s", transitions[0].Status)
	}
	if transitions[0].JobID != jobID {
		t.Errorf("expected job ID %s, got %s", jobID, transitions[0].JobID)
	}
}

func TestDaemon_GracefulShutdownCleanupContext(t *testing.T) {
	// Simulate already-cancelled context (as occurs on SIGINT / SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	syncer := NewMemoryStateSyncer()
	q := newRecordingQueue()

	jobID := uuid.New().String()
	asmtID := uuid.New().String()
	tenantID := uuid.New().String()

	job := queue.Job{
		Version:       1,
		ID:            jobID,
		AssessmentID:  asmtID,
		TenantID:      tenantID,
		CorrelationID: "corr-shutdown-test",
		Type:          adapters.ScannerNuclei,
		Payload:       []byte(`{"target":"https://example.test","profile_id":"standard"}`),
	}

	cfg := Config{
		WorkerID:    "worker-shutdown-test",
		StateSyncer: syncer,
	}

	// Calling fail directly with a cancelled context must still succeed using cleanup fallback
	fail(zap.NewNop(), q, ctx, job, "daemon shutting down", cfg)

	transitions := syncer.GetTransitions()
	if len(transitions) != 1 {
		t.Fatalf("expected 1 transition recorded via cleanup context, got %d", len(transitions))
	}
	if transitions[0].Status != "FAILED" {
		t.Errorf("expected status FAILED, got %s", transitions[0].Status)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 {
		t.Fatalf("expected 1 failed job recorded in queue via cleanup context, got %d", len(q.failed))
	}
}
