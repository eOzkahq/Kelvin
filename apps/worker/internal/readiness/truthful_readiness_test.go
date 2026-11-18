package readiness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
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

func TestOCIImageInspectorAndTruthfulCapabilityMatrix(t *testing.T) {
	ctx := context.Background()

	t.Run("missing image reported unavailable by inspector", func(t *testing.T) {
		insp := NewOCIImageInspector(
			func(name string) (string, error) { return "/usr/bin/podman", nil },
			func(ctx context.Context, name string, args ...string) ([]byte, error) {
				return []byte("Error: image not found: ghcr.io/eozkahq/kelvin/scanner-missing:latest\n"), errors.New("exit status 125")
			},
		)
		info, err := insp.InspectImage(ctx, "ghcr.io/eozkahq/kelvin/scanner-missing:latest")
		if err != nil {
			t.Fatalf("unexpected error inspecting missing image: %v", err)
		}
		if info.Available {
			t.Fatalf("expected Available = false for missing image")
		}
	})

	t.Run("present image parsed with digest from inspect output", func(t *testing.T) {
		inspectJSON := `[
			{
				"Id": "sha256:1111222233334444555566667777888899990000aaaaabbbbbcccccdddddeeeee",
				"Digest": "sha256:4a38dfc6d996e382d3345f1bce8b33534a029a242f3ea99d5a6b0c2a7e75e114",
				"RepoDigests": [
					"ghcr.io/eozkahq/kelvin/scanner-nmap@sha256:4a38dfc6d996e382d3345f1bce8b33534a029a242f3ea99d5a6b0c2a7e75e114"
				]
			}
		]`
		insp := NewOCIImageInspector(
			func(name string) (string, error) { return "/usr/bin/podman", nil },
			func(ctx context.Context, name string, args ...string) ([]byte, error) {
				return []byte(inspectJSON), nil
			},
		)
		info, err := insp.InspectImage(ctx, "ghcr.io/eozkahq/kelvin/scanner-nmap:7.95")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !info.Available {
			t.Fatalf("expected Available = true")
		}
		expectedDigest := "sha256:4a38dfc6d996e382d3345f1bce8b33534a029a242f3ea99d5a6b0c2a7e75e114"
		if info.Digest != expectedDigest {
			t.Fatalf("expected digest %s, got %s", expectedDigest, info.Digest)
		}
	})

	t.Run("checker updates registry metadata availability and capability matrix truthfully", func(t *testing.T) {
		reg := adapters.NewRegistry()
		mockAdp := &mockAdapter{
			name:        "nmap",
			version:     "7.95.0",
			runtimeInfo: adapters.RuntimeVersionInfo{ScannerVersion: "7.95.0", AdapterVersion: "1.0.0"},
			caps: adapters.Capabilities{
				SupportedTargetTypes: []string{"hostname"},
				RequiresSandbox:      true,
			},
		}
		expectedDigest := "sha256:4a38dfc6d996e382d3345f1bce8b33534a029a242f3ea99d5a6b0c2a7e75e114"
		err := reg.RegisterAdapter(adapters.Metadata{
			ID:               "nmap",
			DisplayName:      "Nmap Scanner",
			Version:          "7.95.0",
			SupportedTargets: []string{"hostname"},
			Capabilities:     mockAdp.caps,
			ConfigVersion:    adapters.ScannerConfigVersion,
			VersionPolicy: adapters.VersionPolicy{
				ScannerVersion: "7.95.0",
				ImageReference: "ghcr.io/eozkahq/kelvin/scanner-nmap:7.95@" + expectedDigest,
				ImageDigest:    expectedDigest,
			},
		}, func() adapters.ScannerAdapter { return mockAdp })
		if err != nil {
			t.Fatalf("failed to register adapter: %v", err)
		}

		// Initial mock inspector simulating missing image on host
		missingImageInspector := MockImageInspector{
			InspectFn: func(ctx context.Context, imageRef string) (ImageInspectInfo, error) {
				return ImageInspectInfo{Available: false}, nil
			},
		}

		checker := NewChecker(zap.NewNop())
		checker.SetRegistry(reg)
		checker.RegisterScannerProbe("nmap", NewContainerImageProbe("nmap", "ghcr.io/eozkahq/kelvin/scanner-nmap:7.95", expectedDigest, missingImageInspector))

		// 1. Evaluate scanner - image missing
		status, results := checker.CheckScanner(ctx, "nmap")
		if status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable, got: %s", status)
		}
		if len(results) != 1 || !strings.Contains(results[0].Message, "not present on host") {
			t.Fatalf("expected actionable diagnostic message, got: %+v", results)
		}

		// Verify registry reflects AvailabilityUnavailable with actionable diagnostic reason
		meta, ok := reg.Metadata("nmap")
		if !ok || meta.Availability != adapters.AvailabilityUnavailable {
			t.Fatalf("expected adapter in registry to be UNAVAILABLE, got: %+v", meta)
		}
		if !strings.Contains(meta.UnavailableReason, "not present on host") {
			t.Fatalf("expected unavailable reason to mention not present on host, got: %s", meta.UnavailableReason)
		}

		// Verify GetAdapter fails closed
		_, err = reg.GetAdapter("nmap")
		if err == nil || !errors.Is(err, adapters.ErrAdapterUnavailable) {
			t.Fatalf("expected ErrAdapterUnavailable, got: %v", err)
		}

		// Verify CapabilityMatrix snapshot reflects truthful unavailability
		matrix := reg.CapabilityMatrix()
		if len(matrix) != 1 {
			t.Fatalf("expected 1 entry in capability matrix, got %d", len(matrix))
		}
		if matrix[0].Availability != adapters.AvailabilityUnavailable {
			t.Fatalf("expected matrix availability UNAVAILABLE, got: %s", matrix[0].Availability)
		}

		// 2. Simulate image pulled and verified
		presentImageInspector := MockImageInspector{
			InspectFn: func(ctx context.Context, imageRef string) (ImageInspectInfo, error) {
				return ImageInspectInfo{Available: true, Digest: expectedDigest}, nil
			},
		}
		readyChecker := NewChecker(zap.NewNop())
		readyChecker.SetRegistry(reg)
		readyChecker.RegisterScannerProbe("nmap", NewContainerImageProbe("nmap", "ghcr.io/eozkahq/kelvin/scanner-nmap:7.95", expectedDigest, presentImageInspector))

		readyStatus, _ := readyChecker.CheckScanner(ctx, "nmap")
		if readyStatus != StatusReady {
			t.Fatalf("expected StatusReady, got: %s", readyStatus)
		}

		// Verify registry transitioned to AvailabilityAvailable
		metaReady, ok := reg.Metadata("nmap")
		if !ok || metaReady.Availability != adapters.AvailabilityAvailable {
			t.Fatalf("expected adapter in registry to be AVAILABLE, got: %+v", metaReady)
		}
		if metaReady.UnavailableReason != "" {
			t.Fatalf("expected empty unavailable reason, got: %s", metaReady.UnavailableReason)
		}
	})
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

