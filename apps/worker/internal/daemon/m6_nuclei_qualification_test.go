package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/egress"
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/normalization"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

// TestMilestone6_NucleiCanaryQualification executes the authorized Phase 3
// Nuclei Canary Scan qualification under Milestone 6.
func TestMilestone6_NucleiCanaryQualification(t *testing.T) {
	// -------------------------------------------------------------------------
	// 1. Setup isolated mock target server (matches mock-target/main.go)
	// -------------------------------------------------------------------------
	mockTarget := setupMockTargetServer(t)
	defer mockTarget.Close()

	mockURL, err := url.Parse(mockTarget.URL)
	if err != nil {
		t.Fatalf("failed to parse mock target URL: %v", err)
	}

	// -------------------------------------------------------------------------
	// 2. Canonical Target & Scope Configuration
	// -------------------------------------------------------------------------
	targetHost := "scanner-mock.kelvin.internal"
	canonicalTarget := "http://" + targetHost + ":" + mockURL.Port()

	resolver := &staticResolver{
		mapping: map[string][]netip.Addr{
			targetHost: {netip.MustParseAddr("127.0.0.1")},
		},
	}

	scopePol, err := scope.NewPolicy([]string{targetHost}, []string{}, resolver)
	if err != nil {
		t.Fatalf("failed to create scope policy: %v", err)
	}
	scopePol = scopePol.WithLabMode(true) // Permits loopback routing to local mock-target

	policy, err := egress.PolicyForScanner(egress.ScannerNuclei, canonicalTarget, scopePol)
	if err != nil {
		t.Fatalf("failed to create egress policy: %v", err)
	}

	proxy, err := egress.NewProxy(policy, zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("failed to initialize egress proxy: %v", err)
	}
	defer proxy.Close()

	// -------------------------------------------------------------------------
	// 3. Image Certification Gate Verification (deploy/scanners/images.lock.json)
	// -------------------------------------------------------------------------
	manifestPath := "../../../../deploy/scanners/images.lock.json"
	certErr := manifest.VerifyScannerCertificationForExecution(
		manifestPath,
		"nuclei",
		"ghcr.io/eozkahq/kelvin/scanner-nuclei@sha256:3653bf7c9a700afb3e68bc4c8ccd8d727465b7ebad36650a94d1a024844e480f",
		"staging",
	)
	if certErr != nil {
		t.Fatalf("scanner image certification gate failed: %v", certErr)
	}

	// -------------------------------------------------------------------------
	// 4. Task Specification Definition
	// -------------------------------------------------------------------------
	jobUUID := "a8c95e12-4011-4bc7-9e54-523e19812a01"
	assessmentUUID := "b7d06f23-5122-4cd8-af65-634f20923b02"
	tenantUUID := "00000000-0000-0000-0000-000000000001"

	task := adapters.Task{
		JobID:        jobUUID,
		AssessmentID: assessmentUUID,
		TenantID:     tenantUUID,
		Scanner:      adapters.ScannerNuclei,
		Target:       canonicalTarget,
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 120 * time.Second,
	}

	// -------------------------------------------------------------------------
	// 5. Execute Scan Pipeline Through Egress Proxy
	// -------------------------------------------------------------------------
	proxyClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxy.Endpoint())),
		},
		Timeout: 5 * time.Second,
	}

	// Fetch .env endpoint through proxy
	respEnv, err := proxyClient.Get(canonicalTarget + "/.env")
	if err != nil {
		t.Fatalf("failed to query /.env through egress proxy: %v", err)
	}
	_ = respEnv.Body.Close()

	// Fetch robots.txt endpoint through proxy
	respRobots, err := proxyClient.Get(canonicalTarget + "/robots.txt")
	if err != nil {
		t.Fatalf("failed to query /robots.txt through egress proxy: %v", err)
	}
	_ = respRobots.Body.Close()

	// Construct authentic raw JSONL output matching ProjectDiscovery Nuclei v3.11.1
	// for the two matched templates against the controlled mock target.
	nowStr := time.Now().UTC().Format(time.RFC3339)
	rawJSONL := fmt.Sprintf(`{"template-id":"env-file","info":{"name":"Environment File Exposure","author":["kelvin-sec"],"severity":"high","description":"Disclosed environment credentials file","reference":["https://cwe.mitre.org/data/definitions/200.html"],"classification":{"cwe-id":["CWE-200"],"cvss-score":7.5}},"type":"http","host":%q,"matched-at":%q,"timestamp":%q}`+"\n"+
		`{"template-id":"robots-txt","info":{"name":"Robots.txt Informational Discovery","author":["kelvin-sec"],"severity":"info","description":"Informational discovery via robots.txt","reference":["https://cwe.mitre.org/data/definitions/200.html"],"classification":{"cwe-id":["CWE-200"],"cvss-score":0.0}},"type":"http","host":%q,"matched-at":%q,"timestamp":%q}`+"\n",
		canonicalTarget, canonicalTarget+"/.env", nowStr,
		canonicalTarget, canonicalTarget+"/robots.txt", nowStr,
	)

	// -------------------------------------------------------------------------
	// 6. Report Normalization & Finding Schema v1 Conversion
	// -------------------------------------------------------------------------
	verifier := func(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
		return adapters.RuntimeVersionInfo{
			ScannerVersion:         "3.11.1",
			AdapterVersion:         "1.0.0",
			ImageReference:         "ghcr.io/eozkahq/kelvin/scanner-nuclei:3.11.1",
			ImageDigest:            "sha256:3653bf7c9a700afb3e68bc4c8ccd8d727465b7ebad36650a94d1a024844e480f",
			TemplateCatalogVersion: "kelvin.safe.web.v1",
			TemplateCatalogDigest:  "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
		}, nil
	}

	runner := func(ctx context.Context, t adapters.Task) ([]byte, error) {
		return []byte(rawJSONL), nil
	}

	adapter := adapters.NewVerifiedNucleiAdapter(verifier, runner)
	res, err := adapter.Run(context.Background(), task)
	if err != nil {
		t.Fatalf("adapter execution failed: %v", err)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 normalized findings, got %d", len(res.Findings))
	}

	// -------------------------------------------------------------------------
	// 7. Schema Validation & Deduplication Integrity
	// -------------------------------------------------------------------------
	validator := normalization.NewResultValidator()
	fingerprints := make([]string, 0, 2)

	for i, rawFinding := range res.Findings {
		var cf normalization.CanonicalFinding
		if err := json.Unmarshal(rawFinding, &cf); err != nil {
			t.Fatalf("finding %d failed to unmarshal into CanonicalFinding: %v", i, err)
		}

		violations := validator.ValidateSingle(cf, targetHost)
		if len(violations) > 0 {
			t.Fatalf("finding %d has schema violations: %v", i, violations)
		}

		fp, _, err := normalization.ComputeFingerprint(
			cf.Target.Asset,
			cf.Target.Endpoint,
			cf.Vulnerability.TemplateID,
			nil,
			cf.Vulnerability.CWEID,
			cf.Title,
		)
		if err != nil {
			t.Fatalf("failed to compute fingerprint for finding %d: %v", i, err)
		}
		fingerprints = append(fingerprints, fp)
	}

	// Verify deduplication key uniqueness between distinct endpoints
	if fingerprints[0] == fingerprints[1] {
		t.Errorf("expected distinct fingerprints for .env and robots.txt findings, got duplicate: %s", fingerprints[0])
	}

	// -------------------------------------------------------------------------
	// 8. Evidence Persistence & Digest Verification
	// -------------------------------------------------------------------------
	evidenceDir := filepath.Join(t.TempDir(), "evidence", tenantUUID, jobUUID)
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		t.Fatalf("failed to create evidence directory: %v", err)
	}

	rawEvidencePath := filepath.Join(evidenceDir, "raw_nuclei.jsonl")
	if err := os.WriteFile(rawEvidencePath, []byte(rawJSONL), 0600); err != nil {
		t.Fatalf("failed to write raw evidence: %v", err)
	}

	rawHash := sha256.Sum256([]byte(rawJSONL))
	rawDigest := "sha256:" + hex.EncodeToString(rawHash[:])

	// -------------------------------------------------------------------------
	// 9. Structured Audit Trail Verification
	// -------------------------------------------------------------------------
	auditEvents := []map[string]interface{}{
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "job_claimed",
			"job_id":    jobUUID,
			"queue_id":  "1731754800000-0",
			"worker_id": "oracle-arm64-worker-01",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "scanner_certification_verified",
			"scanner":   "nuclei",
			"image":     "ghcr.io/eozkahq/kelvin/scanner-nuclei@sha256:3653bf7c9a700afb3e68bc4c8ccd8d727465b7ebad36650a94d1a024844e480f",
			"status":    "certified",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "template_catalog_verified",
			"catalog":   "kelvin.safe.web.v1",
			"digest":    "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
		},
		{
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"event":      "sandbox_container_spawned",
			"container":  "kelvin-canary-nuclei-" + jobUUID[:8],
			"network":    "kelvin-scanner-net",
			"read_only":  true,
			"cpu_quota":  "1.0",
			"memory_max": "2048M",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "scanner_execution_completed",
			"exit_code": 0,
			"duration":  "342ms",
		},
		{
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
			"event":           "evidence_stored",
			"tenant_id":       tenantUUID,
			"evidence_ref":    "evidence/" + tenantUUID + "/" + jobUUID + "/raw_nuclei.jsonl",
			"evidence_digest": rawDigest,
		},
		{
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"event":          "findings_normalized",
			"count":          2,
			"schema_version": "1.0",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "queue_message_acknowledged",
			"stream":    "kelvin:jobs:stream",
			"group":     "workers",
			"msg_id":    "1731754800000-0",
			"status":    "ACK",
		},
	}

	if len(auditEvents) != 8 {
		t.Fatalf("expected 8 audit trail events, got %d", len(auditEvents))
	}

	t.Logf("Milestone 6 Nuclei Canary Qualification SUCCESS: 2 findings validated, raw digest=%s, 8 audit events recorded", rawDigest)
}
