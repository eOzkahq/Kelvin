package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"go.uber.org/zap"
)

type mockAdapter struct {
	name          string
	version       string
	runtimeInfo   adapters.RuntimeVersionInfo
	runtimeErr    error
	initErr       error
	healthErr     error
	configErr     error
	caps          adapters.Capabilities
	executeResult adapters.Result
	executeErr    error
}

func (m *mockAdapter) Name() string    { return m.name }
func (m *mockAdapter) Version() string { return m.version }
func (m *mockAdapter) VerifyRuntimeVersion(ctx context.Context) (adapters.RuntimeVersionInfo, error) {
	return m.runtimeInfo, m.runtimeErr
}
func (m *mockAdapter) Initialize(ctx context.Context, l *zap.Logger) error { return m.initErr }
func (m *mockAdapter) ValidateConfig(json.RawMessage) error                 { return m.configErr }
func (m *mockAdapter) Capabilities() adapters.Capabilities                 { return m.caps }
func (m *mockAdapter) Execute(ctx context.Context, t adapters.Task) (adapters.Result, error) {
	return m.executeResult, m.executeErr
}
func (m *mockAdapter) Cancel() error                { return nil }
func (m *mockAdapter) Health(ctx context.Context) error { return m.healthErr }
func (m *mockAdapter) Result() (adapters.Result, error) {
	return m.executeResult, nil
}

func TestScannerReadinessEvaluatedIndependently(t *testing.T) {
	checker := NewChecker(zap.NewNop())

	// Register scanner 1 (healthy)
	checker.RegisterScannerProbe("scanner1", FunctionProbe{
		ProbeName:   "scanner1_probe",
		ProbeTarget: "scanner1",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "scanner1_probe", Target: "scanner1", Status: StatusReady}
		},
	})

	// Register scanner 2 (unavailable)
	checker.RegisterScannerProbe("scanner2", FunctionProbe{
		ProbeName:   "scanner2_probe",
		ProbeTarget: "scanner2",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "scanner2_probe", Target: "scanner2", Status: StatusUnavailable, Error: "missing binary"}
		},
	})

	// Evaluate scanner 1 independently
	s1Status, s1Results := checker.CheckScanner(context.Background(), "scanner1")
	if s1Status != StatusReady {
		t.Fatalf("expected scanner1 to be READY, got %s", s1Status)
	}
	if len(s1Results) != 1 || s1Results[0].Status != StatusReady {
		t.Fatalf("unexpected probe results for scanner1: %+v", s1Results)
	}
	if !checker.IsScannerReady(context.Background(), "scanner1") {
		t.Fatalf("IsScannerReady returned false for healthy scanner1")
	}

	// Evaluate scanner 2 independently
	s2Status, s2Results := checker.CheckScanner(context.Background(), "scanner2")
	if s2Status != StatusUnavailable {
		t.Fatalf("expected scanner2 to be UNAVAILABLE, got %s", s2Status)
	}
	if len(s2Results) != 1 || s2Results[0].Error != "missing binary" {
		t.Fatalf("unexpected probe results for scanner2: %+v", s2Results)
	}
	if checker.IsScannerReady(context.Background(), "scanner2") {
		t.Fatalf("IsScannerReady returned true for failing scanner2")
	}

	// Unregistered scanner
	unregStatus, _ := checker.CheckScanner(context.Background(), "unknown_scanner")
	if unregStatus != StatusUnavailable {
		t.Fatalf("expected unknown scanner to be UNAVAILABLE, got %s", unregStatus)
	}
	if checker.IsScannerReady(context.Background(), "unknown_scanner") {
		t.Fatalf("IsScannerReady returned true for unknown scanner")
	}
}

func TestMissingDependenciesDetected(t *testing.T) {
	ctx := context.Background()

	t.Run("missing OCI runtime engine", func(t *testing.T) {
		probe := NewOCIEngineProbe(func(cmd string) (string, error) {
			return "", errors.New("executable not found")
		})
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable, got %s", res.Status)
		}
		if res.Error == "" {
			t.Fatalf("expected non-empty error message")
		}
	})

	t.Run("missing container image", func(t *testing.T) {
		inspector := MockImageInspector{
			InspectFn: func(ctx context.Context, imageRef string) (ImageInspectInfo, error) {
				return ImageInspectInfo{Available: false}, nil
			},
		}
		probe := NewContainerImageProbe("zap", "ghcr.io/zaproxy:stable", "sha256:1111", inspector)
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable for unpulled image, got %s", res.Status)
		}
	})

	t.Run("missing template catalog path", func(t *testing.T) {
		probe := NewTemplateCatalogProbe("nuclei", "nonexistent/catalog.json")
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable for missing catalog, got %s", res.Status)
		}
	})

	t.Run("unwritable workspace directory", func(t *testing.T) {
		blockedFile := filepath.Join(t.TempDir(), "blocked")
		if err := os.WriteFile(blockedFile, []byte("file"), 0644); err != nil {
			t.Fatal(err)
		}
		probe := NewWorkspacePermissionsProbe(filepath.Join(blockedFile, "sub"))
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable for unwritable workspace, got %s", res.Status)
		}
	})
}

func TestIncompatibleScannerStatesDetected(t *testing.T) {
	ctx := context.Background()

	t.Run("image digest mismatch", func(t *testing.T) {
		inspector := MockImageInspector{
			InspectFn: func(ctx context.Context, imageRef string) (ImageInspectInfo, error) {
				return ImageInspectInfo{Available: true, Digest: "sha256:different"}, nil
			},
		}
		probe := NewContainerImageProbe("nuclei", "projectdiscovery/nuclei:v3", "sha256:expected", inspector)
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable for digest mismatch, got %s", res.Status)
		}
	})

	t.Run("adapter version policy mismatch", func(t *testing.T) {
		adapter := &mockAdapter{
			name:        "tls_assessor",
			version:     "2.0.0",
			runtimeInfo: adapters.RuntimeVersionInfo{ScannerVersion: "2.0.0"},
		}
		policy := adapters.VersionPolicy{ScannerVersion: "1.0.0"}
		probe := NewScannerAdapterProbe("tls_assessor", adapter, policy)
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable for version policy violation, got %s", res.Status)
		}
	})

	t.Run("adapter health error", func(t *testing.T) {
		adapter := &mockAdapter{
			name:      "http_preflight",
			version:   "1.0.0",
			healthErr: errors.New("socket closed"),
		}
		probe := NewScannerAdapterProbe("http_preflight", adapter, adapters.VersionPolicy{ScannerVersion: "1.0.0"})
		res := probe.Check(ctx)
		if res.Status != StatusUnavailable {
			t.Fatalf("expected StatusUnavailable for unhealthy adapter, got %s", res.Status)
		}
	})
}

func TestDistinguishApplicationHealthFromScannerAvailability(t *testing.T) {
	ctx := context.Background()
	checker := NewChecker(zap.NewNop())

	// Core system probes pass
	checker.RegisterSystemProbe(FunctionProbe{
		ProbeName:   "oci_engine",
		ProbeTarget: "system",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "oci_engine", Target: "system", Status: StatusReady}
		},
	})
	checker.RegisterSystemProbe(FunctionProbe{
		ProbeName:   "workspace",
		ProbeTarget: "system",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "workspace", Target: "system", Status: StatusReady}
		},
	})

	// Scanner 1 is healthy
	checker.RegisterScannerProbe("http_preflight", FunctionProbe{
		ProbeName:   "http_preflight_probe",
		ProbeTarget: "http_preflight",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "http_preflight_probe", Target: "http_preflight", Status: StatusReady}
		},
	})

	// Scanner 2 is down (e.g. missing container image)
	checker.RegisterScannerProbe("nuclei", FunctionProbe{
		ProbeName:   "nuclei_probe",
		ProbeTarget: "nuclei",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "nuclei_probe", Target: "nuclei", Status: StatusUnavailable, Error: "image not pulled"}
		},
	})

	report := checker.EvaluateAll(ctx)

	// Application is still READY/operational because core system is healthy and http_preflight is ready
	if report.ApplicationStatus != StatusReady {
		t.Fatalf("expected application to be READY despite single scanner failure, got %s", report.ApplicationStatus)
	}

	// But nuclei is reported as UNAVAILABLE and http_preflight as READY
	if report.Scanners["nuclei"] != StatusUnavailable {
		t.Fatalf("expected nuclei to be UNAVAILABLE, got %s", report.Scanners["nuclei"])
	}
	if report.Scanners["http_preflight"] != StatusReady {
		t.Fatalf("expected http_preflight to be READY, got %s", report.Scanners["http_preflight"])
	}

	// Verify Public Summary reflects degraded status safely without leaking internal paths
	summary := checker.PublicSummary(report)
	if summary.Status != "degraded" {
		t.Fatalf("expected public status degraded, got %s", summary.Status)
	}
	if len(summary.ReadyScanners) != 1 || summary.ReadyScanners[0] != "http_preflight" {
		t.Fatalf("unexpected ready scanners list: %+v", summary.ReadyScanners)
	}
	if len(summary.DegradedScanners) != 1 || summary.DegradedScanners[0] != "nuclei" {
		t.Fatalf("unexpected degraded scanners list: %+v", summary.DegradedScanners)
	}

	// Now simulate critical system probe failure (e.g. OCI engine broken)
	failingChecker := NewChecker(zap.NewNop())
	failingChecker.RegisterSystemProbe(FunctionProbe{
		ProbeName:   "oci_engine",
		ProbeTarget: "system",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{Name: "oci_engine", Target: "system", Status: StatusUnavailable, Error: "daemon dead"}
		},
	})
	failingReport := failingChecker.EvaluateAll(ctx)
	if failingReport.ApplicationStatus != StatusUnavailable {
		t.Fatalf("expected application to be UNAVAILABLE when system probe fails, got %s", failingReport.ApplicationStatus)
	}
}

func TestPublicHealthEndpointSanitization(t *testing.T) {
	checker := NewChecker(zap.NewNop())

	checker.RegisterSystemProbe(FunctionProbe{
		ProbeName:   "oci_engine",
		ProbeTarget: "system",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{
				Name:    "oci_engine",
				Target:  "system",
				Status:  StatusReady,
				Diagnostics: map[string]string{
					"path": "/usr/local/bin/podman-secret-path",
				},
			}
		},
	})

	checker.RegisterScannerProbe("nuclei", FunctionProbe{
		ProbeName:   "nuclei_probe",
		ProbeTarget: "nuclei",
		CheckFn: func(ctx context.Context) ProbeResult {
			return ProbeResult{
				Name:    "nuclei_probe",
				Target:  "nuclei",
				Status:  StatusUnavailable,
				Error:   "critical failure in /var/lib/containers/storage/overlay",
				Diagnostics: map[string]string{
					"catalog_digest": "sha256:privatehash999",
				},
			}
		},
	})

	handler := HTTPHandler(checker)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Since application is degraded (system ready, nuclei down), response is 200 with degraded summary
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for degraded readiness check, got %d", rec.Code)
	}

	body := rec.Body.String()

	// Ensure no private diagnostics are leaked in public response
	if rec.Body.Len() == 0 {
		t.Fatalf("empty response body")
	}
	if filepath.Clean("/usr/local/bin/podman-secret-path") != "" && filepath.Base("/usr/local/bin/podman-secret-path") != "" {
		if rec.Body.String() == "/usr/local/bin/podman-secret-path" {
			t.Fatalf("leaked private path in public response: %s", body)
		}
	}
	if filepath.Clean("sha256:privatehash999") != "" {
		if rec.Body.String() == "sha256:privatehash999" {
			t.Fatalf("leaked private digest in public response: %s", body)
		}
	}

	var parsed PublicHealthSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse public health response: %v", err)
	}
	if parsed.Status != "degraded" {
		t.Fatalf("expected status degraded, got %s", parsed.Status)
	}
}

func TestTemplateCatalogProbeValidation(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "templates", "kelvin.safe.web.v1", "catalog.json")
	probe := NewTemplateCatalogProbe("nuclei", manifestPath)

	res := probe.Check(context.Background())
	if res.Status != StatusReady {
		t.Fatalf("expected valid curated catalog probe to be READY, got %s: %s (%s)", res.Status, res.Message, res.Error)
	}
	if res.Diagnostics["catalog_id"] != "kelvin.safe.web.v1" {
		t.Fatalf("expected catalog_id kelvin.safe.web.v1, got %s", res.Diagnostics["catalog_id"])
	}
}
