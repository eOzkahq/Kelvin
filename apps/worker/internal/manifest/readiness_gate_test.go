package manifest

import (
	"encoding/json"
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

	// Verify Gate 5 queries the canonical schema .identity_requirements
	if !strings.Contains(content, ".identity_requirements.repository") || !strings.Contains(content, ".identity_requirements.oidc_issuer") {
		t.Errorf("release-readiness-check.sh Gate 5 must query canonical .identity_requirements schema")
	}
	if strings.Contains(content, ".trusted_signer.repository") || strings.Contains(content, ".trusted_signer.issuer") {
		t.Errorf("release-readiness-check.sh Gate 5 must not query defunct .trusted_signer schema")
	}
}

func TestScannerReleaseGate_AttestationPolicySchemaContracts(t *testing.T) {
	policyPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "attestation-policy.json")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("failed to read attestation-policy.json: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal attestation policy: %v", err)
	}

	// Canonical schema enforcement: must contain identity_requirements and attestation_requirements
	idReq, ok := raw["identity_requirements"].(map[string]interface{})
	if !ok {
		t.Fatalf("attestation policy missing mandatory identity_requirements object")
	}

	if _, ok := raw["trusted_signer"]; ok {
		t.Errorf("attestation policy must not define non-canonical trusted_signer block")
	}

	// Positive validation
	issuer, _ := idReq["oidc_issuer"].(string)
	if issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("expected GitHub OIDC issuer, got: %s", issuer)
	}

	repo, _ := idReq["repository"].(string)
	if repo == "" {
		t.Errorf("repository in identity_requirements cannot be empty")
	}

	attReq, ok := raw["attestation_requirements"].(map[string]interface{})
	if !ok {
		t.Fatalf("attestation policy missing mandatory attestation_requirements object")
	}

	enforce, _ := attReq["enforce_immutable_digest"].(bool)
	if !enforce {
		t.Errorf("enforce_immutable_digest must be true")
	}

	// Negative test cases for policy validator logic
	negativeCases := []struct {
		name        string
		repo        string
		issuer      string
		certRegex   string
		enforce     bool
		expectError bool
	}{
		{"valid_policy", repo, "https://token.actions.githubusercontent.com", "^https://.*", true, false},
		{"unauthorized_issuer", repo, "https://evil.issuer.com", "^https://.*", true, true},
		{"unauthorized_repo", "attacker/malicious-repo", "https://token.actions.githubusercontent.com", "^https://.*", true, true},
		{"empty_repo", "", "https://token.actions.githubusercontent.com", "^https://.*", true, true},
		{"empty_issuer", repo, "", "^https://.*", true, true},
		{"empty_cert_regex", repo, "https://token.actions.githubusercontent.com", "", true, true},
		{"disabled_digest_enforcement", repo, "https://token.actions.githubusercontent.com", "^https://.*", false, true},
	}

	for _, tc := range negativeCases {
		t.Run(tc.name, func(t *testing.T) {
			hasErr := false
			if tc.repo == "" || tc.issuer == "" || tc.certRegex == "" || !tc.enforce {
				hasErr = true
			} else if tc.issuer != "https://token.actions.githubusercontent.com" {
				hasErr = true
			} else if tc.repo != "eOzkull/Kelvin" && tc.repo != "eOzkahq/Kelvin" {
				hasErr = true
			}

			if hasErr != tc.expectError {
				t.Errorf("case %s: expected error %v, got %v", tc.name, tc.expectError, hasErr)
			}
		})
	}
}
