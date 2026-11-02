package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSupplyChainVerification verifies the existence and completeness of SBOM generation,
// artifact provenance scripts, and supply-chain policies.
func TestSupplyChainVerification(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify SBOM script
	sbomScript := filepath.Join(repoRoot, "scripts", "release", "generate-sbom.sh")
	data, err := os.ReadFile(sbomScript)
	if err != nil {
		t.Fatalf("Missing scripts/release/generate-sbom.sh: %v", err)
	}
	sbomContent := string(data)
	if !strings.Contains(sbomContent, "cyclonedx") {
		t.Errorf("generate-sbom.sh must generate CycloneDX format")
	}

	// 2. Verify Provenance verification script
	provScript := filepath.Join(repoRoot, "scripts", "release", "verify-artifact-provenance.sh")
	data, err = os.ReadFile(provScript)
	if err != nil {
		t.Fatalf("Missing scripts/release/verify-artifact-provenance.sh: %v", err)
	}
	provContent := string(data)
	if !strings.Contains(provContent, "@sha256:") {
		t.Errorf("verify-artifact-provenance.sh must enforce @sha256 digest validation")
	}

	// 3. Verify GitHub Workflow
	wfPath := filepath.Join(repoRoot, ".github", "workflows", "artifact-security.yml")
	data, err = os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("Missing .github/workflows/artifact-security.yml: %v", err)
	}
	wfContent := string(data)
	if !strings.Contains(wfContent, "cosign") {
		t.Errorf("artifact-security.yml must include cosign verification")
	}

	// 4. Verify Documentation
	docPath := filepath.Join(repoRoot, "docs", "release", "SOFTWARE_SUPPLY_CHAIN_AND_ARTIFACT_VERIFICATION.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing SOFTWARE_SUPPLY_CHAIN_AND_ARTIFACT_VERIFICATION.md documentation")
	}
}
