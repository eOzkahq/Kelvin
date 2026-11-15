package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerPublishWorkflow_PermissionsAndEnvironmentGate(t *testing.T) {
	workflowPath := filepath.Join("..", "..", "..", "..", ".github", "workflows", "scanner-publish.yml")
	contentBytes, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("failed to read workflow file: %v", err)
	}
	content := string(contentBytes)

	// 1. Top-level least privilege: contents: read
	if !strings.Contains(content, "permissions:\n  contents: read") && !strings.Contains(content, "permissions:\r\n  contents: read") {
		t.Errorf("scanner-publish.yml must declare top-level least privilege 'contents: read'")
	}

	// 2. Must contain two jobs: verify-readiness and publish-and-certify
	if !strings.Contains(content, "verify-readiness:") {
		t.Errorf("scanner-publish.yml missing 'verify-readiness' job")
	}
	if !strings.Contains(content, "publish-and-certify:") {
		t.Errorf("scanner-publish.yml missing 'publish-and-certify' job")
	}

	// 3. publish-and-certify must depend on verify-readiness
	if !strings.Contains(content, "needs: [verify-readiness]") && !strings.Contains(content, "needs: verify-readiness") {
		t.Errorf("publish-and-certify job must depend on verify-readiness")
	}

	// 4. publish-and-certify must require explicit environment approval
	if !strings.Contains(content, "environment: scanner-release") && !strings.Contains(content, "environment: production-release") {
		t.Errorf("publish-and-certify job must require manual environment approval gate")
	}

	// 5. publish-and-certify must hold required permissions for GHCR and Cosign
	for _, reqPerm := range []string{"packages: write", "id-token: write", "contents: write"} {
		if !strings.Contains(content, reqPerm) {
			t.Errorf("publish-and-certify job must explicitly specify %q", reqPerm)
		}
	}
}

func TestScannerPublishScript_PreflightAndSigningContracts(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "..", "scripts", "scanners", "publish-images.sh")
	contentBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read publish-images.sh script: %v", err)
	}
	content := string(contentBytes)

	// 1. Must enforce preflight checks
	if !strings.Contains(content, "release-readiness-check.sh") && !strings.Contains(content, "verify-release-manifest.sh") {
		t.Errorf("publish-images.sh must enforce pre-flight readiness or manifest verification")
	}

	// 2. Must use Cosign keyless signing
	if !strings.Contains(content, "cosign sign") {
		t.Errorf("publish-images.sh must execute cosign sign")
	}

	// 3. Must attach SLSA provenance and CycloneDX SBOM attestations
	if !strings.Contains(content, "cosign attest") || !strings.Contains(content, "slsaprovenance") || !strings.Contains(content, "cyclonedx") {
		t.Errorf("publish-images.sh must attach both slsaprovenance and cyclonedx attestations")
	}

	// 4. Must immediately verify signatures and attestations
	if !strings.Contains(content, "cosign verify") || !strings.Contains(content, "cosign verify-attestation") {
		t.Errorf("publish-images.sh must verify signatures and attestations post-publication")
	}
}
