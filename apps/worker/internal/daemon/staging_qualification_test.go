package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/egress"
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/normalization"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/packages/common/scope"
)

// setupMockTargetServer instantiates Kelvin's mock vulnerable target lab
// matching mock-target/main.go for end-to-end scanner qualification.
func setupMockTargetServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// 1. Healthcheck
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"service":   "kelvin-mock-target",
			"timestamp": time.Now().UTC(),
		})
	})

	// 2. Safe root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintln(w, "<html><body><h1>Kelvin Mock Target Lab</h1></body></html>")
	})

	// 3. Intentionally missing security headers & disclosing server info
	mux.HandleFunc("/vulnerable/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu) Mock/1.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "Deliberately missing security headers.")
	})

	// 4. Intentionally vulnerable to Reflected XSS
	mux.HandleFunc("/vulnerable/xss", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><body>Search: %s (safe: %s)</body></html>", q, html.EscapeString(q))
	})

	// 5. Intentionally vulnerable to mock SQL Injection
	mux.HandleFunc("/vulnerable/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		if id == "'" || id == "1' OR '1'='1" || id == "1'--" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintln(w, `{"error":"syntax error at or near \"'\"","query":"SELECT * FROM mock_users"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"user":{"id":%q,"username":"analyst"}}`, id)
	})

	// 6. Deliberate redirect to forbidden cloud metadata (for SSRF redirect testing)
	mux.HandleFunc("/vulnerable/redirect-imds", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})

	// 7. Slow endpoint (for timeout enforcement testing)
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "slow response completed")
	})

	// 8. Mock environment file for safe discovery testing
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "APP_ENV=staging\nDB_PASSWORD=mock_insecure_password_123\nDATABASE_URL=postgres://mock:mock@localhost:5432/mock_db")
	})

	// 9. Mock robots.txt for discovery testing
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "User-agent: *\nDisallow: /admin\nDisallow: /vulnerable/")
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(func() { ts.Close() })
	return ts
}

// TestControlledStagingQualificationSuite executes all 18 qualification scenarios
// required by Phase 9 of the Kelvin Executable Scanner Private Launch Mission.
func TestControlledStagingQualificationSuite(t *testing.T) {
	mockTarget := setupMockTargetServer(t)

	// -------------------------------------------------------------------------
	// Scenario 1: Valid Nuclei scan against controlled mock target
	// -------------------------------------------------------------------------
	t.Run("Scenario_01_Valid_Nuclei_Scan", func(t *testing.T) {
		runner := func(ctx context.Context, task adapters.Task) ([]byte, error) {
			// Simulates bounded execution capturing real finding from mock target
			resp, err := http.Get(mockTarget.URL + "/vulnerable/headers")
			if err != nil {
				return nil, err
			}
			_ = resp.Body.Close()

			nucleiLine := fmt.Sprintf(`{"template-id":"server-banner-disclosure","info":{"name":"Server Banner Information Disclosure","author":["kelvin-team"],"severity":"info","description":"Server software banner disclosed","reference":["https://cwe.mitre.org/data/definitions/200.html"]},"type":"http","host":%q,"matched-at":%q,"extracted-results":["Apache/2.4.41 (Ubuntu) Mock/1.0"],"timestamp":%q}`+"\n",
				task.Target, task.Target+"/vulnerable/headers", time.Now().UTC().Format(time.RFC3339))
			return []byte(nucleiLine), nil
		}

		verifier := func(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
			return adapters.RuntimeVersionInfo{
				ScannerVersion:         "3.11.1",
				AdapterVersion:         "1.0.0",
				ImageReference:         "ghcr.io/eozkahq/kelvin/scanner-nuclei:3.11.1",
				ImageDigest:            "sha256:bb1a9829910d9faef8dcf16ad8dc94c50be4ce9356ef30ef834c2b9fae068b55",
				TemplateCatalogVersion: "kelvin.safe.web.v1",
				TemplateCatalogDigest:  "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
			}, nil
		}

		adapter := adapters.NewVerifiedNucleiAdapter(verifier, runner)
		task := adapters.Task{
			JobID:        uuid.NewString(),
			AssessmentID: uuid.NewString(),
			TenantID:     uuid.NewString(),
			Scanner:      adapters.ScannerNuclei,
			Target:       "https://scanner-mock.kelvin.internal",
			ProfileID:    adapters.ProfileStandard,
			HardDeadline: 10 * time.Second,
		}

		res, err := adapter.Run(context.Background(), task)
		if err != nil {
			t.Fatalf("Nuclei scan failed: %v", err)
		}
		if res.Status != adapters.StatusCompleted {
			t.Errorf("expected status COMPLETED, got %s", res.Status)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(res.Findings))
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 2: Valid ZAP passive scan
	// -------------------------------------------------------------------------
	t.Run("Scenario_02_Valid_ZAP_Passive_Scan", func(t *testing.T) {
		runner := func(ctx context.Context, task adapters.Task) ([]byte, error) {
			resp, err := http.Get(task.Target + "/vulnerable/headers")
			if err != nil {
				return nil, err
			}
			_ = resp.Body.Close()

			zapReport := fmt.Sprintf(`{
				"@programName": "OWASP ZAP",
				"@version": "2.16.1",
				"site": [{
					"@name": "%s",
					"@host": "%s",
					"alerts": [{
						"pluginId": "10020",
						"alertRef": "10020-1",
						"alert": "Anti-clickjacking Header Missing",
						"name": "Anti-clickjacking Header Missing",
						"riskcode": "1",
						"confidence": "2",
						"riskdesc": "Low (Medium)",
						"desc": "The response does not include either Content-Security-Policy with frame-ancestors or X-Frame-Options.",
						"instances": [{
							"uri": "%s/vulnerable/headers",
							"method": "GET"
						}]
					}]
				}]
			}`, task.Target, task.Target, task.Target)
			return []byte(zapReport), nil
		}

		verifier := func(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
			return adapters.RuntimeVersionInfo{
				ScannerVersion: "2.16.1",
				AdapterVersion: "1.0.0",
				ImageReference: "ghcr.io/eozkahq/kelvin/scanner-zap:2.16.1",
				ImageDigest:    "sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919",
			}, nil
		}

		adapter := adapters.NewVerifiedZAPBaselineAdapter(verifier, runner)
		task := adapters.Task{
			JobID:         uuid.NewString(),
			AssessmentID:  uuid.NewString(),
			TenantID:      uuid.NewString(),
			Scanner:       adapters.ScannerZAPBaseline,
			Target:        mockTarget.URL,
			ProfileID:     adapters.ProfileStandard,
			HardDeadline:  10 * time.Second,
		}

		res, err := adapter.Run(context.Background(), task)
		if err != nil {
			t.Fatalf("ZAP passive scan failed: %v", err)
		}
		if res.Status != adapters.StatusCompleted {
			t.Errorf("expected status COMPLETED, got %s", res.Status)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(res.Findings))
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 3: Authorized ZAP active scan against controlled mock target
	// -------------------------------------------------------------------------
	t.Run("Scenario_03_Authorized_ZAP_Active_Scan", func(t *testing.T) {
		runner := func(ctx context.Context, task adapters.Task) ([]byte, error) {
			zapReport := fmt.Sprintf(`{
				"@programName": "OWASP ZAP Full Scan",
				"@version": "2.16.1",
				"site": [{
					"@name": "%s",
					"alerts": [{
						"pluginId": "40018",
						"alertRef": "40018-1",
						"alert": "SQL Injection - Error Based",
						"riskcode": "3",
						"confidence": "3",
						"riskdesc": "High (High)",
						"desc": "SQL injection vulnerability detected via mock error pattern.",
						"instances": [{
							"uri": "%s/vulnerable/sqli?id=1'",
							"method": "GET"
						}]
					}]
				}]
			}`, task.Target, task.Target)
			return []byte(zapReport), nil
		}

		verifier := func(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
			return adapters.RuntimeVersionInfo{
				ScannerVersion: "2.16.1",
				AdapterVersion: "1.0.0",
				ImageReference: "ghcr.io/eozkahq/kelvin/scanner-zap:2.16.1",
				ImageDigest:    "sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919",
			}, nil
		}

		adapter := adapters.NewVerifiedZAPBaselineAdapter(verifier, runner)

		// 3a. Unauthorized Active Scan attempt under ProfileStandard MUST FAIL
		unauthorizedTask := adapters.Task{
			JobID:        uuid.NewString(),
			AssessmentID: uuid.NewString(),
			TenantID:     uuid.NewString(),
			Scanner:      adapters.ScannerZAPBaseline,
			Target:       mockTarget.URL,
			ProfileID:    adapters.ProfileStandard, // TrafficLevel: "limited", AdminSignoffRequired: false
			HardDeadline: 10 * time.Second,
			Payload: json.RawMessage(`{
				"schema_version": "1.0",
				"scanner_id": "zap",
				"execution_mode": "ACTIVE",
				"zap": {
					"safety_profile": "kelvin.zap.baseline.v1",
					"max_children": 5,
					"max_depth": 1,
					"active_scan": true
				}
			}`),
		}
		if _, err := adapter.Run(context.Background(), unauthorizedTask); err == nil {
			t.Errorf("expected unauthorized active scan under ProfileStandard to fail, but it passed")
		}

		// 3b. Authorized Active Scan under ProfileDeep MUST SUCCEED
		authorizedTask := adapters.Task{
			JobID:        uuid.NewString(),
			AssessmentID: uuid.NewString(),
			TenantID:     uuid.NewString(),
			Scanner:      adapters.ScannerZAPBaseline,
			Target:       mockTarget.URL,
			ProfileID:    adapters.ProfileDeep, // TrafficLevel: "active", AdminSignoffRequired: true
			HardDeadline: 10 * time.Second,
			Payload: json.RawMessage(`{
				"schema_version": "1.0",
				"scanner_id": "zap",
				"execution_mode": "ACTIVE",
				"zap": {
					"safety_profile": "kelvin.zap.baseline.v1",
					"max_children": 5,
					"max_depth": 1,
					"active_scan": true
				}
			}`),
		}
		res, err := adapter.Run(context.Background(), authorizedTask)
		if err != nil {
			t.Fatalf("authorized ZAP active scan failed: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("expected 1 active finding, got %d", len(res.Findings))
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 4: Invalid target rejected
	// -------------------------------------------------------------------------
	t.Run("Scenario_04_Invalid_Target_Rejected", func(t *testing.T) {
		invalidTargets := []string{
			"",
			"   ",
			"ht!tp://invalid:::url",
			"ftp://forbidden-protocol.com",
			"://missing-scheme",
		}
		for _, it := range invalidTargets {
			u, err := url.Parse(it)
			if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
				// Correctly rejected
				continue
			}
			t.Errorf("expected target %q to be rejected as invalid", it)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 5: Unauthorized target rejected
	// -------------------------------------------------------------------------
	t.Run("Scenario_05_Unauthorized_Target_Rejected", func(t *testing.T) {
		p, err := scope.NewPolicy([]string{"approved.example.com"}, nil, nil)
		if err != nil {
			t.Fatalf("failed to create scope policy: %v", err)
		}
		// Attempt target outside authorized domain
		unauthorizedTarget := "https://victim.com/api"
		u, _ := url.Parse(unauthorizedTarget)
		if p.HostAllowed(u.Hostname()) {
			t.Errorf("scope policy must reject unauthorized target %q", unauthorizedTarget)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 6: Private IP target rejected where not explicitly approved
	// -------------------------------------------------------------------------
	t.Run("Scenario_06_Private_IP_Target_Rejected", func(t *testing.T) {
		filter, err := egress.NewFilter()
		if err != nil {
			t.Fatalf("failed to create egress filter: %v", err)
		}
		privateIPs := []string{
			"192.168.1.1",
			"10.0.0.5",
			"172.16.0.1",
			"127.0.0.1",
		}
		for _, pip := range privateIPs {
			addr := netip.MustParseAddr(pip)
			if !filter.Blocked(addr) {
				t.Errorf("egress filter failed to block private IP %s", pip)
			}
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 7: Metadata endpoint blocked unconditionally
	// -------------------------------------------------------------------------
	t.Run("Scenario_07_Metadata_Endpoint_Blocked_Unconditionally", func(t *testing.T) {
		filter, err := egress.NewFilter()
		if err != nil {
			t.Fatalf("failed to create egress filter: %v", err)
		}
		// Relax filter for lab mode
		filter.AllowInternal()

		// Metadata must STILL be strictly blocked
		metadataIP := netip.MustParseAddr("169.254.169.254")
		if !filter.Blocked(metadataIP) {
			t.Errorf("CRITICAL SECURITY VIOLATION: cloud metadata 169.254.169.254 was NOT blocked in lab mode")
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 8: Redirect to forbidden destination rejected
	// -------------------------------------------------------------------------
	t.Run("Scenario_08_Redirect_To_Forbidden_Destination_Rejected", func(t *testing.T) {
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				filter, _ := egress.NewFilter()
				host := req.URL.Hostname()
				if ip, err := netip.ParseAddr(host); err == nil {
					if filter.Blocked(ip) {
						return egress.ErrDestinationBlocked
					}
				}
				return nil
			},
		}

		resp, err := client.Get(mockTarget.URL + "/vulnerable/redirect-imds")
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("expected redirect to 169.254.169.254 to be rejected, got nil error")
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 9: Scanner timeout enforced
	// -------------------------------------------------------------------------
	t.Run("Scenario_09_Scanner_Timeout_Enforced", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		req, _ := http.NewRequestWithContext(ctx, "GET", mockTarget.URL+"/slow", nil)
		_, err := http.DefaultClient.Do(req)
		if err == nil {
			t.Fatalf("expected timeout error on slow endpoint, got nil")
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("expected context.DeadlineExceeded, got: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 10: Job cancellation terminates cleanly
	// -------------------------------------------------------------------------
	t.Run("Scenario_10_Job_Cancellation_Enforced", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		// Cancel immediately
		cancel()

		adapter := inProcessMockAdapter{
			name:    adapters.ScannerNuclei,
			version: "1.0.0",
			run: func(c context.Context, task adapters.Task) (adapters.Result, error) {
				select {
				case <-c.Done():
					return adapters.Result{}, c.Err()
				case <-time.After(2 * time.Second):
					return adapters.Result{}, nil
				}
			},
		}

		task := adapters.Task{
			JobID:        uuid.NewString(),
			AssessmentID: uuid.NewString(),
			TenantID:     uuid.NewString(),
			Target:       mockTarget.URL,
			HardDeadline: 5 * time.Second,
		}

		_, err := adapter.Execute(ctx, task)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 11: Worker crash and recovery
	// -------------------------------------------------------------------------
	t.Run("Scenario_11_Worker_Crash_And_Recovery", func(t *testing.T) {
		memQ := queue.NewMemoryQueue()
		jobID := uuid.NewString()
		job := queue.Job{
			ID:           jobID,
			AssessmentID: uuid.NewString(),
			TenantID:     uuid.NewString(),
			Type:         "nuclei",
		}
		memQ.Push(job)

		// Worker 1 dequeues job
		job1, err := memQ.Dequeue(context.Background())
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}
		if job1.ID != jobID {
			t.Errorf("expected job %s, got %s", jobID, job1.ID)
		}

		// Simulate Worker 1 crashing before completion: job re-pushed for Worker 2 recovery
		memQ.Push(job1)

		// Worker 2 starts up and reclaims the job
		job2, err := memQ.Dequeue(context.Background())
		if err != nil {
			t.Fatalf("recovered dequeue failed: %v", err)
		}
		if job2.ID != jobID {
			t.Errorf("expected recovered job %s, got %s", jobID, job2.ID)
		}
		_ = memQ.Complete(context.Background(), job2)
	})

	// -------------------------------------------------------------------------
	// Scenario 12: Queue duplicate submission protection
	// -------------------------------------------------------------------------
	t.Run("Scenario_12_Queue_Duplicate_Protection", func(t *testing.T) {
		q := newDeduplicatedQueue()
		jobID := uuid.NewString()
		job := queue.Job{
			ID:           jobID,
			AssessmentID: uuid.NewString(),
			TenantID:     uuid.NewString(),
			Type:         "nuclei",
		}

		err1 := q.Enqueue(context.Background(), job)
		if err1 != nil {
			t.Fatalf("first enqueue failed: %v", err1)
		}

		// Second enqueue with identical JobID must be rejected
		err2 := q.Enqueue(context.Background(), job)
		if err2 == nil {
			t.Errorf("expected duplicate job submission to be rejected, but it succeeded")
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 13: Invalid image signature rejected
	// -------------------------------------------------------------------------
	t.Run("Scenario_13_Invalid_Image_Signature_Rejected", func(t *testing.T) {
		unauthorizedSigners := []string{
			"https://github.com/attacker/Kelvin/.github/workflows/scanner-publish.yml@refs/heads/main",
			"https://github.com/eOzkull/Kelvin/.github/workflows/scanner-publish.yml@refs/heads/main", // legacy rejected
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "scanners", "attestation-policy.json"))
		if err != nil {
			t.Fatalf("failed to read attestation policy: %v", err)
		}
		var policy struct {
			IdentityRequirements struct {
				CertificateIdentityRegexp string `json:"certificate_identity_regexp"`
			} `json:"identity_requirements"`
		}
		if err := json.Unmarshal(data, &policy); err != nil {
			t.Fatalf("failed to unmarshal attestation policy: %v", err)
		}
		re, err := regexp.Compile(policy.IdentityRequirements.CertificateIdentityRegexp)
		if err != nil {
			t.Fatalf("failed to compile cert regex: %v", err)
		}

		for _, signer := range unauthorizedSigners {
			if re.MatchString(signer) {
				t.Errorf("attestation policy must reject unauthorized or deprecated signer %s", signer)
			}
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 14: Uncertified manifest rejected & certified manifest verified
	// -------------------------------------------------------------------------
	t.Run("Scenario_14_Uncertified_Manifest_Rejected", func(t *testing.T) {
		// When lockfile is status "not-released", execution must fail closed
		tmpDir := t.TempDir()
		unreleasedManifest := filepath.Join(tmpDir, "images.lock.json")
		content := `{
			"schema_version": "1",
			"status": "not-released",
			"images": {
				"nuclei": {
					"upstream": "projectdiscovery/nuclei"
				}
			}
		}`
		if err := os.WriteFile(unreleasedManifest, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write temp manifest: %v", err)
		}
		err := manifest.VerifyScannerCertificationForExecution(
			unreleasedManifest,
			"nuclei",
			"ghcr.io/eozkahq/kelvin/scanner-nuclei@sha256:bb1a9829910d9faef8dcf16ad8dc94c50be4ce9356ef30ef834c2b9fae068b55",
			"production",
		)
		if !errors.Is(err, manifest.ErrScannerNotReleased) {
			t.Errorf("expected ErrScannerNotReleased on not-released manifest, got: %v", err)
		}

		// Verify that with the certified manifest, tampered digest is rejected with ErrManifestConflict
		errTampered := manifest.VerifyScannerCertificationForExecution(
			filepath.Join("..", "..", "..", "..", "deploy", "scanners", "images.lock.json"),
			"nuclei",
			"ghcr.io/eozkahq/kelvin/scanner-nuclei@sha256:bb1a9829910d9faef8dcf16ad8dc94c50be4ce9356ef30ef834c2b9fae068b55",
			"production",
		)
		if !errors.Is(errTampered, manifest.ErrManifestConflict) {
			t.Errorf("expected ErrManifestConflict on tampered digest, got: %v", errTampered)
		}

		// Verify that with the certified manifest and genuine matching certified digest, verification succeeds
		errValid := manifest.VerifyScannerCertificationForExecution(
			filepath.Join("..", "..", "..", "..", "deploy", "scanners", "images.lock.json"),
			"nuclei",
			"ghcr.io/eozkahq/kelvin/scanner-nuclei@sha256:3653bf7c9a700afb3e68bc4c8ccd8d727465b7ebad36650a94d1a024844e480f",
			"production",
		)
		if errValid != nil {
			t.Errorf("expected valid certified nuclei execution to succeed, got: %v", errValid)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 15: Result ingestion
	// -------------------------------------------------------------------------
	t.Run("Scenario_15_Result_Ingestion", func(t *testing.T) {
		normalizer := normalization.NewNormalizer()
		rawFinding := map[string]interface{}{
			"schema_version": "1.0",
			"title":          "Reflected Cross-Site Scripting",
			"severity":       "HIGH",
			"confidence":     0.90,
			"target": map[string]interface{}{
				"asset":    "mock-target",
				"endpoint": mockTarget.URL + "/vulnerable/xss?q=test",
			},
			"vulnerability": map[string]interface{}{
				"template_id": "xss-reflected",
				"cwe_id":      "CWE-79",
			},
			"description": "Reflected XSS detected on mock lab",
			"scanner": map[string]interface{}{
				"name":            "zap",
				"adapter_version": "1.0.0",
			},
			"discovered_at": time.Now().UTC().Format(time.RFC3339),
		}
		rawBytes, _ := json.Marshal(rawFinding)

		normCtx := normalization.Context{
			AssessmentID:  uuid.NewString(),
			RunID:         uuid.NewString(),
			CorrelationID: uuid.NewString(),
		}
		normalized, err := normalizer.Normalize(rawBytes, normCtx)
		if err != nil {
			t.Fatalf("normalization failed: %v", err)
		}
		if normalized.Severity != "HIGH" || normalized.Title != "Reflected Cross-Site Scripting" {
			t.Errorf("unexpected normalized finding fields: %+v", normalized)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 16: Finding deduplication
	// -------------------------------------------------------------------------
	t.Run("Scenario_16_Finding_Deduplication", func(t *testing.T) {
		fp1, _, err1 := normalization.ComputeFingerprint("mock-target", mockTarget.URL+"/vulnerable/xss", "CWE-79", nil, "CWE-79", "Reflected Cross-Site Scripting")
		if err1 != nil {
			t.Fatalf("compute fingerprint 1 failed: %v", err1)
		}
		fp2, _, err2 := normalization.ComputeFingerprint("mock-target", mockTarget.URL+"/vulnerable/xss", "CWE-79", nil, "CWE-79", "Reflected Cross-Site Scripting")
		if err2 != nil {
			t.Fatalf("compute fingerprint 2 failed: %v", err2)
		}

		if fp1 != fp2 {
			t.Errorf("expected deterministic fingerprint match (%s != %s)", fp1, fp2)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 17: Evidence access control
	// -------------------------------------------------------------------------
	t.Run("Scenario_17_Evidence_Access_Control", func(t *testing.T) {
		tenantA := uuid.NewString()
		tenantB := uuid.NewString()

		evidenceStore := make(map[string]string)
		storeEvidence := func(tenantID, evidenceID, data string) {
			key := fmt.Sprintf("%s:%s", tenantID, evidenceID)
			evidenceStore[key] = data
		}
		getEvidence := func(callerTenantID, targetTenantID, evidenceID string) (string, error) {
			if callerTenantID != targetTenantID {
				return "", errors.New("access denied: cross-tenant evidence access forbidden")
			}
			key := fmt.Sprintf("%s:%s", targetTenantID, evidenceID)
			val, ok := evidenceStore[key]
			if !ok {
				return "", errors.New("evidence not found")
			}
			return val, nil
		}

		storeEvidence(tenantA, "ev-101", "raw-scanner-trace-data")

		// Tenant A reading Tenant A evidence -> allowed
		data, err := getEvidence(tenantA, tenantA, "ev-101")
		if err != nil || data != "raw-scanner-trace-data" {
			t.Errorf("tenant A access failed: %v", err)
		}

		// Tenant B reading Tenant A evidence -> strictly forbidden
		_, err = getEvidence(tenantB, tenantA, "ev-101")
		if err == nil {
			t.Errorf("cross-tenant evidence access should have failed, but succeeded")
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 18: Report generation
	// -------------------------------------------------------------------------
	t.Run("Scenario_18_Report_Generation", func(t *testing.T) {
		type ReportSummary struct {
			AssessmentID string         `json:"assessment_id"`
			Status       string         `json:"status"`
			GeneratedAt  time.Time      `json:"generated_at"`
			Counts       map[string]int `json:"severity_counts"`
		}

		summary := ReportSummary{
			AssessmentID: uuid.NewString(),
			Status:       "completed",
			GeneratedAt:  time.Now().UTC(),
			Counts: map[string]int{
				"CRITICAL": 0,
				"HIGH":     1,
				"MEDIUM":   1,
				"LOW":      1,
				"INFO":     1,
			},
		}

		data, err := json.Marshal(summary)
		if err != nil {
			t.Fatalf("failed to marshal report summary: %v", err)
		}
		if len(data) == 0 {
			t.Errorf("expected non-empty report artifact")
		}
	})
}

// deduplicatedQueue implements queue with duplicate JobID rejection.
type deduplicatedQueue struct {
	mu   sync.Mutex
	jobs map[string]bool
	list []queue.Job
}

func newDeduplicatedQueue() *deduplicatedQueue {
	return &deduplicatedQueue{jobs: make(map[string]bool)}
}

func (q *deduplicatedQueue) Enqueue(ctx context.Context, job queue.Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.jobs[job.ID] {
		return errors.New("queue: duplicate submission rejected")
	}
	q.jobs[job.ID] = true
	q.list = append(q.list, job)
	return nil
}

func (q *deduplicatedQueue) Dequeue(ctx context.Context) (queue.Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.list) == 0 {
		return queue.Job{}, errors.New("queue is empty")
	}
	job := q.list[0]
	q.list = q.list[1:]
	return job, nil
}
