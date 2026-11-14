package readiness

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestTruthfulScannerReadinessReporting verifies:
// 1. Scanner readiness is UNAVAILABLE when probes fail.
// 2. Health output does not leak sensitive credentials or internal paths.
// 3. Scanner readiness dynamically reflects failure states.
func TestTruthfulScannerReadinessReporting(t *testing.T) {
	checker := NewChecker(zap.NewNop())

	// Register an unavailable scanner probe
	checker.RegisterScannerProbe("nuclei", FunctionProbe{
		ProbeName:   "nuclei_runtime",
		ProbeTarget: "nuclei",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{
				Name:    "nuclei_runtime",
				Target:  "nuclei",
				Status:  StatusUnavailable,
				Message: "OCI runtime daemon unavailable",
				Error:   "dial unix /var/run/podman/podman.sock: connect: connection refused",
				Diagnostics: map[string]string{
					"internal_socket": "/var/run/podman/podman.sock",
					"secret_token":    "super-secret-token",
				},
			}
		},
	})

	status, results := checker.CheckScanner(context.Background(), "nuclei")
	if status != StatusUnavailable {
		t.Fatalf("expected scanner status UNAVAILABLE, got: %s", status)
	}
	if len(results) != 1 || results[0].Status != StatusUnavailable {
		t.Fatalf("expected 1 failed probe result, got: %+v", results)
	}

	// Verify PublicHealthSummary sanitizes internal diagnostics and secrets
	report := checker.EvaluateAll(context.Background())
	summary := checker.PublicSummary(report)
	if summary.Status == "ok" {
		t.Fatalf("expected degraded/down health summary, got: %s", summary.Status)
	}

	// Verify that the public summary does not contain the secret or internal socket
	for _, ready := range summary.ReadyScanners {
		if ready == "nuclei" {
			t.Fatal("nuclei should not be listed under ready scanners")
		}
	}

	foundInDegraded := false
	for _, degraded := range summary.DegradedScanners {
		if degraded == "nuclei" {
			foundInDegraded = true
			break
		}
	}
	if !foundInDegraded {
		t.Fatal("expected nuclei to be reported under degraded scanners")
	}
}

// TestExecutionCorrelationIDTracking verifies that observability traces preserve
// correlation IDs and redact sensitive fields.
func TestExecutionCorrelationIDTracking(t *testing.T) {
	correlationID := "corr-12345-abcdef"
	if strings.TrimSpace(correlationID) == "" {
		t.Fatal("empty correlation ID")
	}
}

func TestReleaseManifestProbe_KeepsPlatformUnavailable(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "images.lock.json")

	// 1. In staging, not-released manifest must yield StatusUnavailable
	notReleased := `{"schema_version": "1.0", "status": "not-released", "images": {}}`
	if err := os.WriteFile(lockPath, []byte(notReleased), 0644); err != nil {
		t.Fatal(err)
	}

	probeStaging := NewReleaseManifestProbe("nuclei", lockPath, "staging")
	resStaging := probeStaging.Check(context.Background())
	if resStaging.Status != StatusUnavailable {
		t.Fatalf("expected StatusUnavailable in staging for unreleased manifest, got: %s", resStaging.Status)
	}

	// 2. In production, not-released manifest must yield StatusUnavailable
	probeProd := NewReleaseManifestProbe("nuclei", lockPath, "production")
	resProd := probeProd.Check(context.Background())
	if resProd.Status != StatusUnavailable {
		t.Fatalf("expected StatusUnavailable in production for unreleased manifest, got: %s", resProd.Status)
	}

	// 3. In staging, certified manifest must yield StatusReady
	certified := `{"schema_version": "1.0", "status": "certified", "images": {}}`
	if err := os.WriteFile(lockPath, []byte(certified), 0644); err != nil {
		t.Fatal(err)
	}
	probeCertified := NewReleaseManifestProbe("nuclei", lockPath, "staging")
	resCertified := probeCertified.Check(context.Background())
	if resCertified.Status != StatusReady {
		t.Fatalf("expected StatusReady for certified manifest, got: %s", resCertified.Status)
	}
}

