package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCIGatesWorkflow verifies that the production-gates.yml workflow contains
// all mandatory quality gates, test verification suites, and security scans.
func TestCIGatesWorkflow(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	wfPath := filepath.Join(repoRoot, ".github", "workflows", "production-gates.yml")

	data, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("Missing .github/workflows/production-gates.yml: %v", err)
	}
	content := string(data)

	// Verify required jobs exist
	requiredJobs := []string{
		"code-quality:",
		"test-verification:",
		"security-contracts:",
		"release-gate:",
	}
	for _, job := range requiredJobs {
		if !strings.Contains(content, job) {
			t.Errorf("production-gates.yml missing required job: %s", job)
		}
	}

	// Verify quality checks
	qualityChecks := []string{
		"gofmt -l",
		"go vet",
		"npm run lint",
		"npm run build:web",
		"go test -race",
		"validate-iac.sh",
	}
	for _, check := range qualityChecks {
		if !strings.Contains(content, check) {
			t.Errorf("production-gates.yml missing verification check: %s", check)
		}
	}

	// Verify release gate depends on all upstream jobs
	if !strings.Contains(content, "needs: [code-quality, test-verification, security-contracts]") {
		t.Errorf("release-gate must depend on code-quality, test-verification, and security-contracts")
	}

	// Verify documentation exists
	docPath := filepath.Join(repoRoot, "docs", "release", "CI_QUALITY_AND_VERIFICATION_GATES.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing CI_QUALITY_AND_VERIFICATION_GATES.md documentation")
	}
}
