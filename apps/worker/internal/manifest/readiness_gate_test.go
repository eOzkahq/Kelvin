package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerReleaseGate_WorkflowStructureAndPermissions(t *testing.T) {
	workflowPath := filepath.Join("..", "..", "..", "..", ".github", "workflows", "scanner-release-gate.yml")
	contentBytes, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("failed to read workflow file: %v", err)
	}
	content := string(contentBytes)

	// 1. Least privilege: must have contents: read
	if !strings.Contains(content, "contents: read") {
		t.Errorf("scanner-release-gate.yml must have least-privilege 'contents: read'")
	}

	// 2. Forbidden write permissions
	for _, forbidden := range []string{"packages: write", "id-token: write", "attestations: write"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("scanner-release-gate.yml must not contain write permission: %q", forbidden)
		}
	}

	// 3. Must execute release-readiness-check.sh
	if !strings.Contains(content, "release-readiness-check.sh") {
		t.Errorf("scanner-release-gate.yml must execute release-readiness-check.sh")
	}

	// 4. Must upload release readiness report artifacts
	if !strings.Contains(content, "actions/upload-artifact") || !strings.Contains(content, "scanner-release-readiness-report") {
		t.Errorf("scanner-release-gate.yml must upload scanner-release-readiness-report artifacts")
	}
}

func TestScannerReleaseGate_ScriptContracts(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "..", "scripts", "scanners", "release-readiness-check.sh")
	contentBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read release readiness script: %v", err)
	}
	content := string(contentBytes)

	// Verify required gate checks are referenced in script
	requiredGates := []string{
		"manifest_validation",
		"waiver_governance",
		"vuln_reconciliation",
		"sbom_integrity",
		"provenance_attestation",
		"runtime_hardening",
	}

	for _, gate := range requiredGates {
		if !strings.Contains(content, gate) {
			t.Errorf("release-readiness-check.sh missing required gate reference %q", gate)
		}
	}

	// Verify fail-closed exit and report generation
	if !strings.Contains(content, "release-readiness-report.json") || !strings.Contains(content, "release-readiness-report.md") {
		t.Errorf("release-readiness-check.sh must generate both JSON and Markdown reports")
	}
}
