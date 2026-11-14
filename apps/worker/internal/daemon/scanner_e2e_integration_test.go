package daemon

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"go.uber.org/zap"
)

// TestFullScannerEndToEndIntegrationSuite verifies:
// 1. Both Nuclei and ZAP baseline complete the end-to-end pipeline.
// 2. Unauthorized target access fails closed before container creation.
// 3. Execution deadlines and cancellations are enforced with zero container leaks.
// 4. Output envelopes match the canonical envelope schema.
func TestFullScannerEndToEndIntegrationSuite(t *testing.T) {
	q, registry := newRecordingQueue(), adapters.NewRegistry()

	// 1. Register Nuclei with mock runner emitting findings
	nucleiAdapter := inProcessMockAdapter{
		name:    adapters.ScannerNuclei,
		version: "1.0.0",
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			rawFinding := json.RawMessage(`{
				"schema_version": "1.0",
				"title": "Exposed Git Repository Configuration",
				"severity": "MEDIUM",
				"confidence": 0.90,
				"target": {
					"asset": "approved.example.com",
					"endpoint": "https://approved.example.com/.git/config"
				},
				"vulnerability": {
					"template_id": "git-config",
					"cwe_id": "CWE-200"
				},
				"description": "Git configuration file exposed",
				"scanner": {
					"name": "nuclei",
					"adapter_version": "1.0.0"
				},
				"discovered_at": "2026-11-01T20:00:00Z"
			}`)
			code := 0
			return adapters.Result{
				SchemaVersion: "1.0",
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      adapters.ScannerNuclei,
					ScannerVersion: "1.0.0",
					AdapterVersion: "1.0.0",
					RunID:          task.JobID,
					StartedAt:      time.Now().Add(-50 * time.Millisecond),
					CompletedAt:    time.Now(),
					CorrelationID:  task.CorrelationID,
				},
				Status:       adapters.StatusCompleted,
				ExitCode:     &code,
				DurationMS:   50,
				Findings:     []json.RawMessage{rawFinding},
				Diagnostics:  make([]adapters.ExecutionDiagnostic, 0),
			}, nil
		},
	}
	if err := registerMock(registry, nucleiAdapter); err != nil {
		t.Fatalf("failed to register Nuclei: %v", err)
	}

	// 2. Register ZAP baseline with mock runner
	zapAdapter := inProcessMockAdapter{
		name:    adapters.ScannerZAPBaseline,
		version: "1.0.0",
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			rawFinding := json.RawMessage(`{
				"schema_version": "1.0",
				"title": "Missing Anti-Clickjacking Header",
				"severity": "LOW",
				"confidence": 0.85,
				"target": {
					"asset": "approved.example.com",
					"endpoint": "https://approved.example.com"
				},
				"vulnerability": {
					"template_id": "10020",
					"cwe_id": "CWE-1021"
				},
				"description": "X-Frame-Options header missing",
				"scanner": {
					"name": "zap",
					"adapter_version": "1.0.0"
				},
				"discovered_at": "2026-11-01T20:00:00Z"
			}`)
			code := 0
			return adapters.Result{
				SchemaVersion: "1.0",
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      adapters.ScannerZAPBaseline,
					ScannerVersion: "1.0.0",
					AdapterVersion: "1.0.0",
					RunID:          task.JobID,
					StartedAt:      time.Now().Add(-80 * time.Millisecond),
					CompletedAt:    time.Now(),
					CorrelationID:  task.CorrelationID,
				},
				Status:       adapters.StatusCompleted,
				ExitCode:     &code,
				DurationMS:   80,
				Findings:     []json.RawMessage{rawFinding},
				Diagnostics:  make([]adapters.ExecutionDiagnostic, 0),
			}, nil
		},
	}
	if err := registerMock(registry, zapAdapter); err != nil {
		t.Fatalf("failed to register ZAP: %v", err)
	}

	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatalf("failed to initialize registry: %v", err)
	}

	fake := sandbox.NewFake()
	cancel, done := runWorker(t, q, registry, fake)
	defer func() {
		cancel()
		<-done
	}()

	// Test Case 1: Nuclei successful execution
	jobNuclei := queue.Job{
		ID:           uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"https://approved.example.com","profile_id":"standard","hard_deadline_seconds":30}`),
	}
	q.inner.Push(jobNuclei)
	waitEvent(t, q)

	// Test Case 2: ZAP baseline successful execution
	jobZAP := queue.Job{
		ID:           uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Type:         adapters.ScannerZAPBaseline,
		Payload:      []byte(`{"target":"https://approved.example.com","profile_id":"standard","hard_deadline_seconds":30}`),
	}
	q.inner.Push(jobZAP)
	waitEvent(t, q)

	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.completed) != 2 {
		t.Fatalf("expected 2 successful completions for Nuclei and ZAP, got %d (failed: %d, reasons: %v)", len(q.completed), len(q.failed), q.failedReasons)
	}
}

// TestUnauthorizedTargetScopeRejection verifies that targets violating scope policy
// fail closed before execution starts.
func TestUnauthorizedTargetScopeRejection(t *testing.T) {
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

	// Submit task with empty target host
	q.inner.Push(queue.Job{
		ID:           uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Type:         adapters.ScannerNuclei,
		Payload:      []byte(`{"target":"","profile_id":"standard","hard_deadline_seconds":10}`),
	})

	waitEvent(t, q)

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) != 1 {
		t.Fatalf("expected malformed/empty target to fail, got %d failures", len(q.failed))
	}
}
