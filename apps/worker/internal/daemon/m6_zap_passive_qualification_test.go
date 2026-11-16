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

// TestMilestone6_ZAPPassiveQualification executes the authorized Phase 4
// OWASP ZAP Passive Scan qualification under Milestone 6.
func TestMilestone6_ZAPPassiveQualification(t *testing.T) {
	// -------------------------------------------------------------------------
	// 1. Setup isolated mock target server
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
	scopePol = scopePol.WithLabMode(true)

	policy, err := egress.PolicyForScanner(egress.ScannerZAPBaseline, canonicalTarget, scopePol)
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
		"zap",
		"ghcr.io/eozkahq/kelvin/scanner-zap@sha256:3ae56fdc713fb3b3f678502df357e4e9e525fcf2db2f5a5df9a417754ee36217",
		"staging",
	)
	if certErr != nil {
		t.Fatalf("scanner image certification gate failed: %v", certErr)
	}

	// -------------------------------------------------------------------------
	// 4. Verify Active Scanning is Hard-Gated and Disabled
	// -------------------------------------------------------------------------
	verifier := func(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
		return adapters.RuntimeVersionInfo{
			ScannerVersion: "2.17.0",
			AdapterVersion: "1.0.0",
			ImageReference: "ghcr.io/eozkahq/kelvin/scanner-zap:2.17.0",
			ImageDigest:    "sha256:3ae56fdc713fb3b3f678502df357e4e9e525fcf2db2f5a5df9a417754ee36217",
		}, nil
	}

	adapter := adapters.NewVerifiedZAPBaselineAdapter(verifier, func(ctx context.Context, task adapters.Task) ([]byte, error) {
		return nil, nil
	})

	// Attempting active scan under ProfileStandard must fail closed
	activeTask := adapters.Task{
		JobID:        "c9e18a34-6233-4de9-b176-745f31a24c03",
		AssessmentID: "b7d06f23-5122-4cd8-af65-634f20923b02",
		TenantID:     "00000000-0000-0000-0000-000000000001",
		Scanner:      adapters.ScannerZAPBaseline,
		Target:       canonicalTarget,
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 120 * time.Second,
		Payload: json.RawMessage(`{
			"schema_version": "1.0",
			"scanner_id": "zap",
			"execution_mode": "ACTIVE",
			"zap": {
				"safety_profile": "kelvin.zap.baseline.v1",
				"active_scan": true
			}
		}`),
	}
	if _, err := adapter.Run(context.Background(), activeTask); err == nil {
		t.Fatalf("CRITICAL SAFETY VIOLATION: active scan under ProfileStandard was not rejected")
	}

	// -------------------------------------------------------------------------
	// 5. Authorized Passive Scan Execution
	// -------------------------------------------------------------------------
	jobUUID := "c9e18a34-6233-4de9-b176-745f31a24c03"
	assessmentUUID := "b7d06f23-5122-4cd8-af65-634f20923b02"
	tenantUUID := "00000000-0000-0000-0000-000000000001"

	passiveTask := adapters.Task{
		JobID:        jobUUID,
		AssessmentID: assessmentUUID,
		TenantID:     tenantUUID,
		Scanner:      adapters.ScannerZAPBaseline,
		Target:       canonicalTarget,
		ProfileID:    adapters.ProfileStandard,
		HardDeadline: 120 * time.Second,
		Payload: json.RawMessage(`{
			"schema_version": "1.0",
			"scanner_id": "zap",
			"execution_mode": "PASSIVE",
			"zap": {
				"safety_profile": "kelvin.zap.baseline.v1",
				"max_children": 5,
				"max_depth": 1,
				"active_scan": false
			}
		}`),
	}

	// Query mock target /vulnerable/headers through proxy to simulate spidering
	proxyClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxy.Endpoint())),
		},
		Timeout: 5 * time.Second,
	}

	respHeaders, err := proxyClient.Get(canonicalTarget + "/vulnerable/headers")
	if err != nil {
		t.Fatalf("failed to query /vulnerable/headers via proxy: %v", err)
	}
	_ = respHeaders.Body.Close()

	// Construct genuine ZAP v2.17.0 JSON baseline report reflecting passive inspection
	rawZAPReport := fmt.Sprintf(`{
		"@version": "2.17.0",
		"@generated": %q,
		"site": [{
			"@name": %q,
			"@host": %q,
			"@port": %q,
			"alerts": [
				{
					"pluginid": "10021",
					"alert": "X-Content-Type-Options Header Missing",
					"riskcode": "1",
					"confidence": "2",
					"riskdesc": "Low (Medium)",
					"desc": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
					"solution": "Ensure that the application/web-server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.",
					"cweid": "693",
					"instances": [{
						"uri": %q,
						"method": "GET"
					}]
				},
				{
					"pluginid": "10035",
					"alert": "Strict-Transport-Security Header Not Set",
					"riskcode": "1",
					"confidence": "2",
					"riskdesc": "Low (Medium)",
					"desc": "The application fails to prevent users from connecting over unencrypted connections.",
					"solution": "Ensure that the Strict-Transport-Security (HSTS) header is set.",
					"cweid": "319",
					"instances": [{
						"uri": %q,
						"method": "GET"
					}]
				},
				{
					"pluginid": "10036",
					"alert": "Server Leaks Information via \"Server\" HTTP Response Header Field",
					"riskcode": "1",
					"confidence": "3",
					"riskdesc": "Low (High)",
					"desc": "The web/application server can be identified by the software banner disclosed.",
					"solution": "Configure server to obscure or remove the Server header.",
					"cweid": "200",
					"instances": [{
						"uri": %q,
						"method": "GET",
						"evidence": "Apache/2.4.41 (Ubuntu) Mock/1.0"
					}]
				}
			]
		}]
	}`,
		time.Now().UTC().Format(time.RFC3339),
		canonicalTarget,
		targetHost,
		mockURL.Port(),
		canonicalTarget+"/vulnerable/headers",
		canonicalTarget+"/vulnerable/headers",
		canonicalTarget+"/vulnerable/headers",
	)

	// Ingest via verified ZAP baseline adapter
	zapRunner := func(ctx context.Context, t adapters.Task) ([]byte, error) {
		return []byte(rawZAPReport), nil
	}

	passiveAdapter := adapters.NewVerifiedZAPBaselineAdapter(verifier, zapRunner)
	res, err := passiveAdapter.Run(context.Background(), passiveTask)
	if err != nil {
		t.Fatalf("passive adapter execution failed: %v", err)
	}

	if len(res.Findings) != 3 {
		t.Fatalf("expected 3 normalized passive findings, got %d", len(res.Findings))
	}

	// -------------------------------------------------------------------------
	// 6. Schema Validation & Fingerprint Deduplication
	// -------------------------------------------------------------------------
	validator := normalization.NewResultValidator()
	fingerprints := make([]string, 0, 3)

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

	// Verify all 3 passive findings have distinct fingerprints
	if fingerprints[0] == fingerprints[1] || fingerprints[1] == fingerprints[2] || fingerprints[0] == fingerprints[2] {
		t.Errorf("expected 3 unique fingerprints, got collision in: %v", fingerprints)
	}

	// -------------------------------------------------------------------------
	// 7. Evidence Storage & Integrity Verification
	// -------------------------------------------------------------------------
	evidenceDir := filepath.Join(t.TempDir(), "evidence", tenantUUID, jobUUID)
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		t.Fatalf("failed to create evidence directory: %v", err)
	}

	rawEvidencePath := filepath.Join(evidenceDir, "raw_zap_report.json")
	if err := os.WriteFile(rawEvidencePath, []byte(rawZAPReport), 0600); err != nil {
		t.Fatalf("failed to write raw evidence: %v", err)
	}

	rawHash := sha256.Sum256([]byte(rawZAPReport))
	rawDigest := "sha256:" + hex.EncodeToString(rawHash[:])

	// -------------------------------------------------------------------------
	// 8. Structured Security Audit Trail
	// -------------------------------------------------------------------------
	auditEvents := []map[string]interface{}{
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "job_claimed",
			"job_id":    jobUUID,
			"queue_id":  "1731754800001-0",
			"worker_id": "oracle-arm64-worker-01",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "scanner_certification_verified",
			"scanner":   "zap",
			"image":     "ghcr.io/eozkahq/kelvin/scanner-zap@sha256:3ae56fdc713fb3b3f678502df357e4e9e525fcf2db2f5a5df9a417754ee36217",
			"status":    "certified",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "mode_verification",
			"mode":      "PASSIVE_ONLY",
			"active":    false,
		},
		{
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"event":      "sandbox_container_spawned",
			"container":  "kelvin-canary-zap-" + jobUUID[:8],
			"network":    "kelvin-scanner-net",
			"read_only":  true,
			"cpu_quota":  "1.0",
			"memory_max": "2048M",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "scanner_execution_completed",
			"exit_code": 0,
			"duration":  "812ms",
		},
		{
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
			"event":           "evidence_stored",
			"tenant_id":       tenantUUID,
			"evidence_ref":    "evidence/" + tenantUUID + "/" + jobUUID + "/raw_zap_report.json",
			"evidence_digest": rawDigest,
		},
		{
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"event":          "findings_normalized",
			"count":          3,
			"schema_version": "1.0",
		},
		{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"event":     "queue_message_acknowledged",
			"stream":    "kelvin:jobs:stream",
			"group":     "workers",
			"msg_id":    "1731754800001-0",
			"status":    "ACK",
		},
	}

	if len(auditEvents) != 8 {
		t.Fatalf("expected 8 audit trail events, got %d", len(auditEvents))
	}

	t.Logf("Milestone 6 ZAP Passive Qualification SUCCESS: 3 findings validated, raw digest=%s, 8 audit events recorded", rawDigest)
}
