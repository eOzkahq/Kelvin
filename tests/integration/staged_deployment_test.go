package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStagedDeploymentAndPromotion verifies the promotion workflow, smoke test script,
// and operational release specifications.
func TestStagedDeploymentAndPromotion(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify Deployment Promotion Workflow
	wfPath := filepath.Join(repoRoot, ".github", "workflows", "deploy-promotion.yml")
	data, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("Missing .github/workflows/deploy-promotion.yml: %v", err)
	}
	wf := string(data)

	if !strings.Contains(wf, "name: staging") {
		t.Errorf("deploy-promotion.yml missing staging environment definition")
	}

	if !strings.Contains(wf, "name: production") {
		t.Errorf("deploy-promotion.yml missing production environment definition")
	}

	if !strings.Contains(wf, "needs: [deploy-staging]") {
		t.Errorf("deploy-production must depend on deploy-staging")
	}

	// 2. Verify Smoke Test Script
	smokePath := filepath.Join(repoRoot, "scripts", "release", "smoke-test.sh")
	data, err = os.ReadFile(smokePath)
	if err != nil {
		t.Fatalf("Missing scripts/release/smoke-test.sh: %v", err)
	}
	smoke := string(data)

	for _, check := range []string{"/healthz", "/readyz", "Strict-Transport-Security"} {
		if !strings.Contains(smoke, check) {
			t.Errorf("smoke-test.sh missing test check: %s", check)
		}
	}

	// 3. Verify Operational Documentation
	docPath := filepath.Join(repoRoot, "docs", "release", "STAGED_DEPLOYMENT_AND_ENVIRONMENT_PROMOTION.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing STAGED_DEPLOYMENT_AND_ENVIRONMENT_PROMOTION.md documentation")
	}
}
