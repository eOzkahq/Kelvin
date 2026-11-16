package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

type AttestationPolicy struct {
	SchemaVersion        string `json:"schema_version"`
	Policy               string `json:"policy"`
	IdentityRequirements struct {
		OIDCIssuer                string   `json:"oidc_issuer"`
		Repository                string   `json:"repository"`
		CertificateIdentityRegexp string   `json:"certificate_identity_regexp"`
		AllowedWorkflows          []string `json:"allowed_workflows"`
	} `json:"identity_requirements"`
	AttestationRequirements struct {
		Type                   string `json:"type"`
		PredicateType          string `json:"predicate_type"`
		EnforceImmutableDigest bool   `json:"enforce_immutable_digest"`
	} `json:"attestation_requirements"`
}

func TestScannerAttestation_PolicyInvariants(t *testing.T) {
	policyPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "attestation-policy.json")

	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("failed to read attestation-policy.json: %v", err)
	}

	var policy AttestationPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("failed to parse attestation-policy.json: %v", err)
	}

	if policy.IdentityRequirements.Repository != "eOzkahq/Kelvin" {
		t.Errorf("expected canonical repository eOzkahq/Kelvin, got: %s", policy.IdentityRequirements.Repository)
	}

	if policy.IdentityRequirements.OIDCIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("expected GitHub OIDC token issuer, got: %s", policy.IdentityRequirements.OIDCIssuer)
	}

	if !policy.AttestationRequirements.EnforceImmutableDigest {
		t.Errorf("enforce_immutable_digest must be true")
	}

	// Verify certificate identity regexp matches expected workflow
	re, err := regexp.Compile(policy.IdentityRequirements.CertificateIdentityRegexp)
	if err != nil {
		t.Fatalf("invalid certificate identity regex: %v", err)
	}

	validID := "https://github.com/eOzkahq/Kelvin/.github/workflows/scanner-publish.yml@refs/heads/main"
	if !re.MatchString(validID) {
		t.Errorf("expected regex to match valid workflow identity %s", validID)
	}

	// Legacy eOzkull identity must be rejected under active trust policy
	legacyID := "https://github.com/eOzkull/Kelvin/.github/workflows/scanner-publish.yml@refs/heads/main"
	if re.MatchString(legacyID) {
		t.Errorf("expected regex to reject deprecated legacy repository identity %s", legacyID)
	}

	// Attacker identity must fail
	attackerID := "https://github.com/attacker/Kelvin/.github/workflows/scanner-publish.yml@refs/heads/main"
	if re.MatchString(attackerID) {
		t.Errorf("expected regex to reject attacker workflow identity %s", attackerID)
	}
}

func TestScannerAttestation_RejectMutableTags(t *testing.T) {
	mutableRefs := []string{
		"ghcr.io/eozkull/kelvin/scanner-nuclei:latest",
		"ghcr.io/eozkull/kelvin/scanner-nuclei:v3.11.1",
		"ghcr.io/eozkull/kelvin/scanner-zap:stable",
	}

	digestReg := regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
	for _, ref := range mutableRefs {
		if digestReg.MatchString(ref) {
			t.Errorf("mutable reference %s should not match digest regex", ref)
		}
	}

	validRef := "ghcr.io/eozkull/kelvin/scanner-nuclei@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	if !digestReg.MatchString(validRef) {
		t.Errorf("valid reference %s must match digest regex", validRef)
	}
}
