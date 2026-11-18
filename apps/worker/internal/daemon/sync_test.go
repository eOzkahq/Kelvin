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

func TestStateSyncer_FindingPersistenceAndSeverityAggregation(t *testing.T) {
	ctx := context.Background()
	syncer := NewMemoryStateSyncer()

	tenantID := uuid.New().String()
	asmtID := uuid.New().String()
	jobID := uuid.New().String()

	findings := []json.RawMessage{
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Remote Code Execution (Log4j)",
			"severity": "CRITICAL",
			"confidence": 0.95,
			"target": {"asset": "target.test", "endpoint": "https://target.test/api"},
			"vulnerability": {"template_id": "cve-2021-44228", "cve_ids": ["CVE-2021-44228"]},
			"scanner": {"name": "nuclei", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-01T20:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "SQL Injection in User Endpoint",
			"severity": "HIGH",
			"confidence": 0.90,
			"target": {"asset": "target.test", "endpoint": "https://target.test/users"},
			"vulnerability": {"cwe_id": "CWE-89", "template_id": "sqli-user"},
			"scanner": {"name": "nuclei", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-01T20:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Command Injection in Upload",
			"severity": "HIGH",
			"confidence": 0.85,
			"target": {"asset": "target.test", "endpoint": "https://target.test/upload"},
			"vulnerability": {"cwe_id": "CWE-78", "template_id": "cmdi-upload"},
			"scanner": {"name": "zap", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-01T20:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Reflected Cross-Site Scripting",
			"severity": "MEDIUM",
			"confidence": 0.80,
			"target": {"asset": "target.test", "endpoint": "https://target.test/search"},
			"vulnerability": {"cwe_id": "CWE-79", "template_id": "xss-search"},
			"scanner": {"name": "zap", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-01T20:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Missing Strict-Transport-Security Header",
			"severity": "LOW",
			"confidence": 0.70,
			"target": {"asset": "target.test", "endpoint": "https://target.test/"},
			"vulnerability": {"template_id": "missing-hsts"},
			"scanner": {"name": "http_security_headers", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-01T20:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Open Port 80 (HTTP)",
			"severity": "INFORMATIONAL",
			"confidence": 0.99,
			"target": {"asset": "target.test", "endpoint": "http://target.test:80"},
			"vulnerability": {"template_id": "port-80-open"},
			"scanner": {"name": "nmap", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-01T20:00:00Z"
		}`),
	}

	if err := syncer.SyncJobResults(ctx, tenantID, asmtID, jobID, findings, "corr-test-1"); err != nil {
		t.Fatalf("SyncJobResults failed: %v", err)
	}

	stored := syncer.GetStoredFindings()
	if len(stored) != 6 {
		t.Fatalf("expected 6 stored findings, got %d", len(stored))
	}

	counts := syncer.GetSeverityCounts(asmtID)
	if counts["CRITICAL"] != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", counts["CRITICAL"])
	}
	if counts["HIGH"] != 2 {
		t.Errorf("expected 2 HIGH, got %d", counts["HIGH"])
	}
	if counts["MEDIUM"] != 1 {
		t.Errorf("expected 1 MEDIUM, got %d", counts["MEDIUM"])
	}
	if counts["LOW"] != 1 {
		t.Errorf("expected 1 LOW, got %d", counts["LOW"])
	}
	if counts["INFORMATIONAL"] != 1 {
		t.Errorf("expected 1 INFORMATIONAL, got %d", counts["INFORMATIONAL"])
	}
	if counts["TOTAL"] != 6 {
		t.Errorf("expected 6 TOTAL, got %d", counts["TOTAL"])
	}

	// Repeated scan execution updates occurrences without duplicate entries
	asmt2ID := uuid.New().String()
	job2ID := uuid.New().String()
	if err := syncer.SyncJobResults(ctx, tenantID, asmt2ID, job2ID, findings[:2], "corr-test-2"); err != nil {
		t.Fatalf("SyncJobResults for repeated scan failed: %v", err)
	}

	storedAfter := syncer.GetStoredFindings()
	if len(storedAfter) != 6 {
		t.Fatalf("repeated scan must not create duplicate findings, got %d", len(storedAfter))
	}

	occurrencesChecked := 0
	for _, f := range storedAfter {
		if f.Title == "Remote Code Execution (Log4j)" || f.Title == "SQL Injection in User Endpoint" {
			if f.Occurrences != 2 {
				t.Errorf("expected 2 occurrences for repeated finding %s, got %d", f.Title, f.Occurrences)
			}
			occurrencesChecked++
		}
	}
	if occurrencesChecked != 2 {
		t.Errorf("expected to check 2 repeated findings, checked %d", occurrencesChecked)
	}
}
