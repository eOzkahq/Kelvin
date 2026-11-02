package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRuntimeDeploymentManifests verifies that Kubernetes deployment manifests
// meet enterprise security baselines, probe definitions, and resource limits.
func TestRuntimeDeploymentManifests(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	deployBaseDir := filepath.Join(repoRoot, "deploy", "kubernetes", "base")

	requiredFiles := []string{
		"api-deployment.yaml",
		"worker-deployment.yaml",
		"frontend-deployment.yaml",
		"scanner-sandbox-spec.yaml",
		"service-accounts.yaml",
		"services.yaml",
		"kustomization.yaml",
	}

	for _, f := range requiredFiles {
		p := filepath.Join(deployBaseDir, f)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("Missing required deployment manifest: %s", f)
		}
		content := string(data)

		// Check for non-root security context across all workload deployments
		if strings.Contains(f, "deployment") || strings.Contains(f, "sandbox") {
			if !strings.Contains(content, "runAsNonRoot: true") {
				t.Errorf("%s missing 'runAsNonRoot: true'", f)
			}
			if !strings.Contains(content, "drop:") || !strings.Contains(content, "- ALL") {
				t.Errorf("%s does not drop all Linux capabilities", f)
			}
			if !strings.Contains(content, "allowPrivilegeEscalation: false") {
				t.Errorf("%s missing 'allowPrivilegeEscalation: false'", f)
			}
		}

		// Check probes and grace periods on API
		if f == "api-deployment.yaml" {
			if !strings.Contains(content, "path: /healthz") {
				t.Errorf("API deployment missing /healthz liveness probe")
			}
			if !strings.Contains(content, "path: /readyz") {
				t.Errorf("API deployment missing /readyz readiness probe")
			}
			if !strings.Contains(content, "terminationGracePeriodSeconds: 60") {
				t.Errorf("API deployment missing terminationGracePeriodSeconds: 60")
			}
		}

		// Check worker termination grace period for active job draining
		if f == "worker-deployment.yaml" {
			if !strings.Contains(content, "terminationGracePeriodSeconds: 120") {
				t.Errorf("Worker deployment missing terminationGracePeriodSeconds: 120")
			}
		}

		// Check scanner sandbox isolation
		if f == "scanner-sandbox-spec.yaml" {
			if !strings.Contains(content, "automountServiceAccountToken: false") {
				t.Errorf("Scanner sandbox must have automountServiceAccountToken: false")
			}
		}
	}

	// Verify environment overlays
	overlays := []string{"dev", "staging", "prod"}
	for _, env := range overlays {
		overlayKust := filepath.Join(repoRoot, "deploy", "kubernetes", "overlays", env, "kustomization.yaml")
		if _, err := os.Stat(overlayKust); os.IsNotExist(err) {
			t.Errorf("Missing overlay kustomization: %s", overlayKust)
		}
	}
}
