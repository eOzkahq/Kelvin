package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"go.uber.org/zap"
)

type mockExecutor struct {
	executeCalled bool
	lastSpec      sandbox.Spec
	returnResult  *sandbox.Result
	returnErr     error
}

func (m *mockExecutor) Execute(ctx context.Context, spec sandbox.Spec) (*sandbox.Result, error) {
	m.executeCalled = true
	m.lastSpec = spec
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	if m.returnResult != nil {
		return m.returnResult, nil
	}
	return &sandbox.Result{
		ContainerName:  "test-container",
		ExitCode:       0,
		LifecycleState: sandbox.StateCleaned,
	}, nil
}

func TestPodmanRunner_RejectionOfNotReleasedManifest(t *testing.T) {
	dir := t.TempDir()
	manifestFile := filepath.Join(dir, "images.lock.json")
	notReleasedJSON := `{
		"schema_version": "1",
		"status": "not-released",
		"images": {
			"zap": {
				"upstream": "ghcr.io/zaproxy/zaproxy:stable",
				"kelvin_image": "ghcr.io/eozkull/kelvin/scanner-zap",
				"kelvin_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
			}
		}
	}`
	if err := os.WriteFile(manifestFile, []byte(notReleasedJSON), 0644); err != nil {
		t.Fatal(err)
	}

	mockExec := &mockExecutor{}
	runner := NewPodmanRunner(manifestFile, "staging", mockExec, zap.NewNop())

	spec := sandbox.Spec{
		Scanner: "zap",
		Image:   "ghcr.io/eozkull/kelvin/scanner-zap@sha256:1111111111111111111111111111111111111111111111111111111111111111",
	}

	// Staging must fail closed
	_, err := runner.Execute(context.Background(), spec, nil)
	if err == nil || !errors.Is(err, ErrCertificationFailed) || !errors.Is(err, manifest.ErrScannerNotReleased) {
		t.Fatalf("expected ErrCertificationFailed / ErrScannerNotReleased in staging, got: %v", err)
	}
	if mockExec.executeCalled {
		t.Fatal("executor should never be invoked when manifest is not certified")
	}

	// Production must fail closed
	prodRunner := NewPodmanRunner(manifestFile, "production", mockExec, zap.NewNop())
	_, err = prodRunner.Execute(context.Background(), spec, nil)
	if err == nil || !errors.Is(err, ErrCertificationFailed) {
		t.Fatalf("expected certification failure in production, got: %v", err)
	}

	// Development allows execution
	devRunner := NewPodmanRunner(manifestFile, "development", mockExec, zap.NewNop())
	res, err := devRunner.Execute(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("expected development execution to be permitted, got: %v", err)
	}
	if res == nil || res.ContainerName != "test-container" {
		t.Fatalf("unexpected result: %v", res)
	}
}

func TestPodmanRunner_DigestTamperingDetection(t *testing.T) {
	dir := t.TempDir()
	manifestFile := filepath.Join(dir, "images.lock.json")
	certifiedJSON := `{
		"schema_version": "1",
		"status": "certified",
		"images": {
			"nuclei": {
				"upstream": "projectdiscovery/nuclei",
				"upstream_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
				"version": "3.11.1",
				"kelvin_image": "ghcr.io/eozkull/kelvin/scanner-nuclei",
				"kelvin_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"scorecard_status": "ELIGIBLE"
			}
		}
	}`
	if err := os.WriteFile(manifestFile, []byte(certifiedJSON), 0644); err != nil {
		t.Fatal(err)
	}

	mockExec := &mockExecutor{}
	runner := NewPodmanRunner(manifestFile, "production", mockExec, zap.NewNop())

	// Attacker tries to run a modified/tampered image with different digest
	tamperedSpec := sandbox.Spec{
		Scanner: "nuclei",
		Image:   "ghcr.io/eozkull/kelvin/scanner-nuclei@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	_, err := runner.Execute(context.Background(), tamperedSpec, nil)
	if err == nil || !errors.Is(err, ErrCertificationFailed) || !errors.Is(err, manifest.ErrManifestConflict) {
		t.Fatalf("expected ErrManifestConflict tampering detection, got: %v", err)
	}
	if mockExec.executeCalled {
		t.Fatal("executor must not run when digest tampering is detected")
	}

	// Compliant image with matching certified digest passes
	validSpec := sandbox.Spec{
		Scanner: "nuclei",
		Image:   "ghcr.io/eozkull/kelvin/scanner-nuclei@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	res, err := runner.Execute(context.Background(), validSpec, nil)
	if err != nil {
		t.Fatalf("expected valid certified image to pass, got: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got: %d", res.ExitCode)
	}
}

func TestPodmanRunner_DockerSocketAccessForbidden(t *testing.T) {
	dir := t.TempDir()
	manifestFile := filepath.Join(dir, "images.lock.json")
	certifiedJSON := `{
		"schema_version": "1",
		"status": "certified",
		"images": {
			"zap": {
				"upstream": "ghcr.io/zaproxy/zaproxy:stable",
				"version": "2.15.0",
				"kelvin_image": "ghcr.io/eozkull/kelvin/scanner-zap",
				"kelvin_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
			}
		}
	}`
	if err := os.WriteFile(manifestFile, []byte(certifiedJSON), 0644); err != nil {
		t.Fatal(err)
	}

	mockExec := &mockExecutor{}
	runner := NewPodmanRunner(manifestFile, "production", mockExec, zap.NewNop())

	spec := sandbox.Spec{
		Scanner: "zap",
		Image:   "ghcr.io/eozkull/kelvin/scanner-zap@sha256:1111111111111111111111111111111111111111111111111111111111111111",
	}

	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")

	_, err := runner.Execute(context.Background(), spec, nil)
	if err == nil || !errors.Is(err, ErrDockerSocketForbidden) {
		t.Fatalf("expected ErrDockerSocketForbidden when DOCKER_HOST is set, got: %v", err)
	}
}
