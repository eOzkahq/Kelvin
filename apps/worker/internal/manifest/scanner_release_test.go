package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Condition 1: Invalid upstream image references
func TestScannerReleaseGate_InvalidUpstreamReference(t *testing.T) {
	validZAP := "ghcr.io/zaproxy/zaproxy:stable@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919"
	if err := ValidateUpstreamReference(validZAP, "ghcr.io/zaproxy/zaproxy:stable"); err != nil {
		t.Fatalf("expected valid ZAP reference to pass, got: %v", err)
	}

	invalidRepos := []string{
		"docker.io/malicious/zaproxy@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919",
		"evil.com/zaproxy:stable@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919",
		"ghcr.io/attacker/zaproxy@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919",
	}
	for _, repo := range invalidRepos {
		err := ValidateUpstreamReference(repo, "ghcr.io/zaproxy/zaproxy:stable")
		if err == nil || !errors.Is(err, ErrInvalidUpstreamReference) {
			t.Errorf("expected ErrInvalidUpstreamReference for %q, got: %v", repo, err)
		}
	}
}

// Condition 2: Mutable image tags
func TestScannerReleaseGate_MutableImageTags(t *testing.T) {
	mutableRefs := []string{
		"ghcr.io/zaproxy/zaproxy:stable",
		"ghcr.io/zaproxy/zaproxy:latest",
		"projectdiscovery/nuclei:v3.3.7",
		"gcr.io/distroless/static-debian12:nonroot",
	}
	for _, ref := range mutableRefs {
		err := ValidateUpstreamReference(ref, "")
		if err == nil || !errors.Is(err, ErrMutableTagProhibited) {
			t.Errorf("expected ErrMutableTagProhibited for mutable tag %q, got: %v", ref, err)
		}
	}
}

// Condition 3: Invalid digest formats
func TestScannerReleaseGate_InvalidDigestFormats(t *testing.T) {
	validDigest := "sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919"
	if err := ValidateDigestFormat(validDigest); err != nil {
		t.Fatalf("expected valid digest to pass, got: %v", err)
	}

	invalidDigests := []struct {
		digest string
		err    error
	}{
		{"sha256:short", ErrInvalidDigestFormat},
		{"md5:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919", ErrInvalidDigestFormat},
		{"sha256:zzzz3b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919", ErrInvalidDigestFormat},
		{"sha256:D9B23B169527BE63660FB1E57C6B9EB97CF1E2C9EF806DC5E7E3E7F53CFC0919", ErrInvalidDigestFormat}, // must be lowercase
		{EmptySHA256Digest, ErrPlaceholderEmptyHash},
		{"", ErrInvalidDigestFormat},
	}
	for _, tc := range invalidDigests {
		err := ValidateDigestFormat(tc.digest)
		if err == nil || !errors.Is(err, tc.err) {
			t.Errorf("digest %q expected %v, got: %v", tc.digest, tc.err, err)
		}
	}
}

// Condition 4: Invalid versions
func TestScannerReleaseGate_InvalidVersions(t *testing.T) {
	validVersions := []string{"2.15.0", "3.3.7", "1.0.0-rc1"}
	for _, v := range validVersions {
		if err := ValidateSemanticVersion(v); err != nil {
			t.Errorf("expected valid version %q to pass, got: %v", v, err)
		}
	}

	invalidVersions := []string{"latest", "stable", "v", "dev-nightly", "v3.11.1", ""}
	for _, v := range invalidVersions {
		if err := ValidateSemanticVersion(v); err == nil || !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("expected ErrInvalidVersion for %q, got: %v", v, err)
		}
	}

	// Nuclei semantic version handling: build input is "3.11.1" (without 'v'),
	// while verified binary reports "v3.11.1"
	nucleiBuildInput := "3.11.1"
	validRuntimeOutputs := []string{
		"[INF] Current nuclei version: v3.11.1 (latest)",
		"Nuclei Engine v3.11.1",
		"nuclei version 3.11.1",
	}
	for _, out := range validRuntimeOutputs {
		if err := ValidateNucleiVersionMatch(nucleiBuildInput, out); err != nil {
			t.Errorf("expected build input %q to match runtime output %q, got: %v", nucleiBuildInput, out, err)
		}
	}

	// Reject build input with leading 'v'
	if err := ValidateNucleiVersionMatch("v3.11.1", "[INF] Current nuclei version: v3.11.1"); err == nil {
		t.Error("expected build input 'v3.11.1' with leading 'v' to be rejected")
	}

	// Reject mismatched runtime version
	if err := ValidateNucleiVersionMatch("3.11.1", "[INF] Current nuclei version: v3.10.0"); err == nil {
		t.Error("expected mismatched runtime version v3.10.0 to fail for input 3.11.1")
	}
}

// Condition 5: Architecture mismatch
func TestScannerReleaseGate_ArchitectureMismatch(t *testing.T) {
	if err := ValidateRuntimeArchitecture("arm64", "linux"); err != nil {
		t.Fatalf("expected arm64/linux to pass, got: %v", err)
	}

	mismatches := []struct {
		arch string
		os   string
	}{
		{"amd64", "linux"},
		{"x86_64", "linux"},
		{"i386", "linux"},
		{"arm64", "darwin"},
		{"arm64", "windows"},
	}
	for _, tc := range mismatches {
		if err := ValidateRuntimeArchitecture(tc.arch, tc.os); err == nil || !errors.Is(err, ErrArchitectureMismatch) {
			t.Errorf("expected ErrArchitectureMismatch for arch=%s os=%s, got: %v", tc.arch, tc.os, err)
		}
	}
}

// Condition 6: Unexpected runtime UID/GID
func TestScannerReleaseGate_UnexpectedRuntimeUser(t *testing.T) {
	if err := ValidateRuntimeUser("10001:10001"); err != nil {
		t.Fatalf("expected 10001:10001 to pass, got: %v", err)
	}

	badUsers := []string{"0:0", "1000:1000", "root", "nobody", "10001", "10001:0"}
	for _, u := range badUsers {
		if err := ValidateRuntimeUser(u); err == nil || !errors.Is(err, ErrInvalidRuntimeUser) {
			t.Errorf("expected ErrInvalidRuntimeUser for %q, got: %v", u, err)
		}
	}
}

// Condition 7: Vulnerability gate failure
func TestScannerReleaseGate_VulnerabilityGateFailure(t *testing.T) {
	type VulnReport struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	validateVulnGate := func(reportJSON string) error {
		var report VulnReport
		if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
			return err
		}
		for _, res := range report.Results {
			for _, v := range res.Vulnerabilities {
				if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
					return fmt.Errorf("vulnerability gate failed: found %s vulnerability %s", v.Severity, v.VulnerabilityID)
				}
			}
		}
		return nil
	}

	cleanReport := `{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "Severity": "LOW"}]}]}`
	if err := validateVulnGate(cleanReport); err != nil {
		t.Fatalf("expected clean report to pass, got: %v", err)
	}

	badReports := []string{
		`{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-9999", "Severity": "CRITICAL"}]}]}`,
		`{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-8888", "Severity": "HIGH"}]}]}`,
	}
	for _, r := range badReports {
		if err := validateVulnGate(r); err == nil || !strings.Contains(err.Error(), "vulnerability gate failed") {
			t.Errorf("expected vulnerability gate failure, got: %v", err)
		}
	}
}

// Condition 8: Missing or malformed SBOM
func TestScannerReleaseGate_MissingOrMalformedSBOM(t *testing.T) {
	validateSBOM := func(sbomBytes []byte, expectedDigest string) error {
		if len(sbomBytes) == 0 {
			return errors.New("sbom: empty or missing artifact")
		}
		var parsed struct {
			BOMFormat   string `json:"bomFormat"`
			SpecVersion string `json:"specVersion"`
			Metadata    struct {
				Component struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"component"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(sbomBytes, &parsed); err != nil {
			return fmt.Errorf("sbom: malformed json: %w", err)
		}
		if parsed.BOMFormat != "CycloneDX" {
			return fmt.Errorf("sbom: unsupported bomFormat %q", parsed.BOMFormat)
		}
		return nil
	}

	validSBOM := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"name": "kelvin/scanner-zap",
				"version": "2.15.0"
			}
		}
	}`)
	if err := validateSBOM(validSBOM, "sha256:abc"); err != nil {
		t.Fatalf("expected valid SBOM to pass, got: %v", err)
	}

	if err := validateSBOM([]byte(""), "sha256:abc"); err == nil {
		t.Fatal("expected empty SBOM to fail")
	}
	if err := validateSBOM([]byte(`{"bomFormat": "SPDX"}`), "sha256:abc"); err == nil {
		t.Fatal("expected non-CycloneDX to fail")
	}
}

// Condition 9: Registry digest mismatch
func TestScannerReleaseGate_RegistryDigestMismatch(t *testing.T) {
	validateRegistryDigestMatch := func(buildDigest, registryDigest string) error {
		if err := ValidateDigestFormat(buildDigest); err != nil {
			return fmt.Errorf("build digest: %w", err)
		}
		if err := ValidateDigestFormat(registryDigest); err != nil {
			return fmt.Errorf("registry digest: %w", err)
		}
		if buildDigest != registryDigest {
			return fmt.Errorf("registry digest mismatch: build=%s, registry=%s", buildDigest, registryDigest)
		}
		return nil
	}

	d1 := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2 := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	if err := validateRegistryDigestMatch(d1, d1); err != nil {
		t.Fatalf("expected matching digests to pass, got: %v", err)
	}
	if err := validateRegistryDigestMatch(d1, d2); err == nil || !strings.Contains(err.Error(), "registry digest mismatch") {
		t.Fatalf("expected mismatch failure, got: %v", err)
	}
}

// Condition 10: Invalid Cosign signature
func TestScannerReleaseGate_InvalidCosignSignature(t *testing.T) {
	verifyMockSignature := func(sigPayload, imageDigest string) error {
		if strings.TrimSpace(sigPayload) == "" {
			return errors.New("cosign: no signature payload found")
		}
		var parsed struct {
			Critical struct {
				Image struct {
					DockerManifestDigest string `json:"docker-manifest-digest"`
				} `json:"image"`
				Type string `json:"type"`
			} `json:"critical"`
		}
		if err := json.Unmarshal([]byte(sigPayload), &parsed); err != nil {
			return fmt.Errorf("cosign: invalid signature format: %w", err)
		}
		if parsed.Critical.Type != "atomic container signature" {
			return fmt.Errorf("cosign: invalid signature type: %s", parsed.Critical.Type)
		}
		if parsed.Critical.Image.DockerManifestDigest != imageDigest {
			return fmt.Errorf("cosign: signature digest mismatch: expected %s, got %s", imageDigest, parsed.Critical.Image.DockerManifestDigest)
		}
		return nil
	}

	d := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	validSig := fmt.Sprintf(`{
		"critical": {
			"type": "atomic container signature",
			"image": {
				"docker-manifest-digest": "%s"
			}
		}
	}`, d)

	if err := verifyMockSignature(validSig, d); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}
	if err := verifyMockSignature("", d); err == nil {
		t.Fatal("expected empty signature to fail")
	}
	if err := verifyMockSignature(validSig, "sha256:different"); err == nil {
		t.Fatal("expected mismatched digest signature to fail")
	}
}

// Condition 11: Invalid provenance identity
func TestScannerReleaseGate_InvalidProvenanceIdentity(t *testing.T) {
	identityPattern := regexp.MustCompile(`^https://github\.com/eOzkull/Kelvin/\.github/workflows/.*`)
	expectedIssuer := "https://token.actions.githubusercontent.com"

	verifyIdentity := func(certURI, issuer string) error {
		if issuer != expectedIssuer {
			return fmt.Errorf("untrusted oidc issuer %q", issuer)
		}
		if !identityPattern.MatchString(certURI) {
			return fmt.Errorf("untrusted certificate identity %q", certURI)
		}
		return nil
	}

	validURI := "https://github.com/eOzkull/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
	if err := verifyIdentity(validURI, expectedIssuer); err != nil {
		t.Fatalf("expected valid identity to pass, got: %v", err)
	}

	untrustedURIs := []string{
		"https://github.com/Inkesk-Dozing/Kelvin/.github/workflows/scanner-images.yml",
		"https://github.com/Attacker/Kelvin/.github/workflows/scanner-images.yml",
		"https://github.com/eOzkull/OtherRepo/.github/workflows/workflow.yml",
		"https://evil.com/payload",
	}
	for _, uri := range untrustedURIs {
		if err := verifyIdentity(uri, expectedIssuer); err == nil {
			t.Errorf("expected untrusted identity failure for %q", uri)
		}
	}

	if err := verifyIdentity(validURI, "https://accounts.google.com"); err == nil {
		t.Fatal("expected untrusted issuer failure")
	}
}

// Condition 12: Template catalog digest mismatch
func TestScannerReleaseGate_TemplateCatalogDigestMismatch(t *testing.T) {
	catalogPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "templates", "kelvin.safe.web.v1", "catalog.json")
	digest, err := CalculateCatalogDigest(catalogPath)
	if err != nil {
		t.Fatalf("failed to calculate catalog digest: %v", err)
	}

	expectedDigest := "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"
	if digest != expectedDigest {
		t.Fatalf("expected %s, got %s", expectedDigest, digest)
	}

	// Verify tamper detection
	dir := t.TempDir()
	fakeCatalog := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(fakeCatalog, []byte(`{"catalog_id": "tampered", "templates": []}`), 0644); err != nil {
		t.Fatal(err)
	}
	tamperedDigest, err := CalculateCatalogDigest(fakeCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedDigest == expectedDigest {
		t.Fatal("tampered catalog must not match expected digest")
	}
}

// Condition 13: Missing release evidence
func TestScannerReleaseGate_MissingReleaseEvidence(t *testing.T) {
	verifyReleaseEvidenceDir := func(dir string) error {
		requiredFiles := []string{
			"build-record.json",
			"build-inputs.txt",
			"zap.cdx.json",
			"nuclei.cdx.json",
		}
		for _, f := range requiredFiles {
			path := filepath.Join(dir, f)
			fi, err := os.Stat(path)
			if err != nil || fi.Size() == 0 {
				return fmt.Errorf("missing or empty release evidence artifact: %s", f)
			}
		}
		return nil
	}

	dir := t.TempDir()
	if err := verifyReleaseEvidenceDir(dir); err == nil {
		t.Fatal("expected missing evidence directory to fail")
	}

	// Create complete evidence
	for _, f := range []string{"build-record.json", "build-inputs.txt", "zap.cdx.json", "nuclei.cdx.json"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte("evidence content"), 0644)
	}
	if err := verifyReleaseEvidenceDir(dir); err != nil {
		t.Fatalf("expected complete evidence to pass, got: %v", err)
	}
}

// Condition 14: Attempts to certify incomplete manifests
func TestScannerReleaseGate_IncompleteManifestCertification(t *testing.T) {
	// Attempt to certify with null/empty digests
	strPtr := func(s string) *string { return &s }

	incompleteManifests := []*ScannerImageLock{
		{
			SchemaVersion: "1",
			Status:        StatusCertified,
			Images: map[string]ImageMetadata{
				"zap": {
					Upstream: "ghcr.io/zaproxy/zaproxy:stable",
					// missing upstream digest
					Version:      strPtr("2.15.0"),
					KelvinImage:  strPtr("ghcr.io/eozkull/kelvin/scanner-zap"),
					KelvinDigest: strPtr("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
				},
			},
		},
		{
			SchemaVersion: "1",
			Status:        StatusCertified,
			Images: map[string]ImageMetadata{
				"zap": {
					Upstream:       "ghcr.io/zaproxy/zaproxy:stable",
					UpstreamDigest: strPtr(EmptySHA256Digest), // empty placeholder hash!
					Version:        strPtr("2.15.0"),
					KelvinImage:    strPtr("ghcr.io/eozkull/kelvin/scanner-zap"),
					KelvinDigest:   strPtr("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
				},
				"nuclei": {
					Upstream:              "projectdiscovery/nuclei",
					UpstreamDigest:        strPtr("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
					Version:               strPtr("3.3.7"),
					DistrolessBase:        strPtr("gcr.io/distroless/static-debian12:nonroot"),
					DistrolessDigest:      strPtr("sha256:3333333333333333333333333333333333333333333333333333333333333333"),
					KelvinImage:           strPtr("ghcr.io/eozkull/kelvin/scanner-nuclei"),
					KelvinDigest:          strPtr("sha256:4444444444444444444444444444444444444444444444444444444444444444"),
					TemplateCatalogID:     "kelvin.safe.web.v1",
					TemplateCatalogDigest: strPtr("sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"),
				},
			},
		},
	}

	for i, m := range incompleteManifests {
		err := ValidateCertifiedManifest(m, "")
		if err == nil {
			t.Errorf("manifest %d: expected certification failure for incomplete manifest", i)
		}
	}
}

// Condition 15: Worker rejection of not-released manifests
func TestScannerReleaseGate_WorkerRejectionOfNotReleased(t *testing.T) {
	dir := t.TempDir()
	notReleasedFile := filepath.Join(dir, "images.lock.json")
	notReleasedJSON := `{
		"schema_version": "1",
		"status": "not-released",
		"images": {
			"zap": {
				"upstream": "ghcr.io/zaproxy/zaproxy:stable"
			}
		}
	}`
	if err := os.WriteFile(notReleasedFile, []byte(notReleasedJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// In staging and production, worker must fail closed with ErrScannerNotReleased
	err := EnforceCertifiedReleaseForExecution(notReleasedFile, "zap", "staging")
	if err == nil || !errors.Is(err, ErrScannerNotReleased) {
		t.Fatalf("expected ErrScannerNotReleased in staging, got: %v", err)
	}

	err = EnforceCertifiedReleaseForExecution(notReleasedFile, "zap", "production")
	if err == nil || !errors.Is(err, ErrScannerNotReleased) {
		t.Fatalf("expected ErrScannerNotReleased in production, got: %v", err)
	}

	// In development, execution is not gated by certification
	err = EnforceCertifiedReleaseForExecution(notReleasedFile, "zap", "development")
	if err != nil {
		t.Fatalf("expected development execution to be permitted, got: %v", err)
	}
}

// Condition 16: Scanner image workflow permission boundaries and publish=false gating
func TestScannerReleaseGate_WorkflowPermissionBoundariesAndGating(t *testing.T) {
	workflowPath := filepath.Join("..", "..", "..", "..", ".github", "workflows", "scanner-images.yml")
	contentBytes, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("failed to read workflow file: %v", err)
	}
	content := string(contentBytes)

	// 1. Ensure hardcoded ENABLE_CI: 'true' is not in top-level environment
	if strings.Contains(content, "ENABLE_CI: 'true'") || strings.Contains(content, `ENABLE_CI: "true"`) {
		t.Errorf("expected no hardcoded ENABLE_CI: 'true' override in workflow")
	}

	// 2. Ensure job separation: build-and-scan and publish-and-sign exist, old merged job removed
	if strings.Contains(content, "build-scan-and-release:") {
		t.Errorf("legacy monolithic job 'build-scan-and-release' must be removed")
	}
	if !strings.Contains(content, "build-and-scan:") {
		t.Errorf("missing 'build-and-scan' job")
	}
	if !strings.Contains(content, "publish-and-sign:") {
		t.Errorf("missing 'publish-and-sign' job")
	}

	// Split workflow into job sections
	buildJobIdx := strings.Index(content, "build-and-scan:")
	pubJobIdx := strings.Index(content, "publish-and-sign:")
	if buildJobIdx == -1 || pubJobIdx == -1 || buildJobIdx >= pubJobIdx {
		t.Fatalf("invalid job ordering or missing jobs")
	}

	buildJobSection := content[buildJobIdx:pubJobIdx]
	pubJobSection := content[pubJobIdx:]

	// 3. Build job must be gated on inputs.enable_ci == true
	if !strings.Contains(buildJobSection, "inputs.enable_ci == true") {
		t.Errorf("build-and-scan job must be gated on inputs.enable_ci == true")
	}

	// 4. Build job must have ONLY least-privilege permissions (no packages, id-token, attestations write)
	for _, forbiddenPerm := range []string{"packages: write", "id-token: write", "attestations: write"} {
		if strings.Contains(buildJobSection, forbiddenPerm) {
			t.Errorf("build-and-scan job must not contain sensitive permission %q", forbiddenPerm)
		}
	}
	if !strings.Contains(buildJobSection, "contents: read") {
		t.Errorf("build-and-scan job must explicitly specify contents: read")
	}

	// 5. Publishing job must depend on build-and-scan and be gated on inputs.publish == true
	if !strings.Contains(pubJobSection, "needs: [build-and-scan]") && !strings.Contains(pubJobSection, "needs: build-and-scan") {
		t.Errorf("publish-and-sign job must have needs dependency on build-and-scan")
	}
	if !strings.Contains(pubJobSection, "inputs.publish == true") {
		t.Errorf("publish-and-sign job must be gated on inputs.publish == true")
	}

	// 6. Publishing job must hold required release permissions
	for _, requiredPerm := range []string{"packages: write", "id-token: write", "attestations: write"} {
		if !strings.Contains(pubJobSection, requiredPerm) {
			t.Errorf("publish-and-sign job missing required permission %q", requiredPerm)
		}
	}

	// 7. Sensitive actions must NOT be in build-and-scan job
	sensitiveActions := []string{"docker/login-action", "publish-and-sign.sh", "sigstore/cosign-installer"}
	for _, action := range sensitiveActions {
		if strings.Contains(buildJobSection, action) {
			t.Errorf("build-and-scan job must not contain sensitive action %q", action)
		}
		if !strings.Contains(pubJobSection, action) {
			t.Errorf("publish-and-sign job must contain action %q", action)
		}
	}

	// 8. All actions must be pinned by 40-character SHA
	actionRegex := regexp.MustCompile(`uses:\s+([^\s\n#]+)`)
	matches := actionRegex.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		t.Fatalf("no action uses: found in workflow")
	}
	shaRegex := regexp.MustCompile(`@[0-9a-f]{40}$`)
	for _, match := range matches {
		actionRef := match[1]
		if !shaRegex.MatchString(actionRef) {
			t.Errorf("action reference %q is not pinned to an immutable 40-character commit SHA", actionRef)
		}
	}

	// 9. Regression test: exact verified action commit SHAs for setup-qemu-action, setup-buildx-action, and trivy-action
	expectedActionSHAs := map[string]string{
		"docker/setup-qemu-action":   "49b3bc8e6bdd4a60e6116a5414239cba5943d3cf", // v3.2.0
		"docker/setup-buildx-action": "c47758b77c9736f4b2ef4073d4d51994fabfe349", // v3.7.1
		"aquasecurity/trivy-action":  "76071ef0d7ec797419534a183b498b4d6366cf37", // v0.31.0
	}
	invalidLegacySHAs := []string{
		"49b3bc8e6bdd4480b82837412f66d573217e85c4",
		"c47758b77c9736f4b4e79d4850a0074cbe657f63",
		"18f2510ee396bbf400402947b394f2dd8c87dbb0", // legacy v0.29.0
	}
	for actionName, expectedSHA := range expectedActionSHAs {
		expectedRef := actionName + "@" + expectedSHA
		if !strings.Contains(content, expectedRef) {
			t.Errorf("workflow missing verified action reference %q", expectedRef)
		}
	}
	// Assert both Trivy steps (ZAP and Nuclei) are upgraded to v0.31.0
	trivyV31Ref := "aquasecurity/trivy-action@76071ef0d7ec797419534a183b498b4d6366cf37"
	if count := strings.Count(content, trivyV31Ref); count != 2 {
		t.Errorf("expected exactly 2 occurrences of %q (for ZAP and Nuclei), got %d", trivyV31Ref, count)
	}
	// Assert both Trivy steps explicitly set version: v0.70.0 to override unreleased v0.63.0 default
	if count := strings.Count(content, "version: v0.70.0"); count != 2 {
		t.Errorf("expected exactly 2 occurrences of 'version: v0.70.0' for Trivy scan steps, got %d", count)
	}

	// 10. Assert independent scanner execution, diagnostic collection, and fail-closed gate enforcement
	if !strings.Contains(content, "id: scan_zap") {
		t.Errorf("workflow missing id: scan_zap for ZAP scan step")
	}
	if !strings.Contains(content, "id: scan_nuclei") {
		t.Errorf("workflow missing id: scan_nuclei for Nuclei scan step")
	}
	if count := strings.Count(content, "continue-on-error: true"); count < 2 {
		t.Errorf("expected at least 2 occurrences of 'continue-on-error: true' for independent scans, got %d", count)
	}
	if !strings.Contains(content, "Enforce vulnerability scan security gate") {
		t.Errorf("workflow missing 'Enforce vulnerability scan security gate' step")
	}
	if !strings.Contains(content, "steps.scan_zap.outcome") || !strings.Contains(content, "steps.scan_nuclei.outcome") {
		t.Errorf("security gate must check both scan_zap and scan_nuclei step outcomes")
	}

	// 11. Assert documented vulnerability exception policies (.trivyignore) are configured
	if !strings.Contains(content, "trivyignores: deploy/scanners/zap/.trivyignore") {
		t.Errorf("workflow missing trivyignores policy for ZAP scan step")
	}
	if !strings.Contains(content, "trivyignores: deploy/scanners/nuclei/.trivyignore") {
		t.Errorf("workflow missing trivyignores policy for Nuclei scan step")
	}

	// Verify both .trivyignore files exist on disk
	for _, ignoreRelPath := range []string{
		filepath.Join("..", "..", "..", "..", "deploy", "scanners", "zap", ".trivyignore"),
		filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", ".trivyignore"),
	} {
		data, err := os.ReadFile(ignoreRelPath)
		if err != nil {
			t.Errorf("failed to read expected ignore file %q: %v", ignoreRelPath, err)
		} else if !strings.Contains(string(data), "CVE-") {
			t.Errorf("ignore file %q missing CVE definitions", ignoreRelPath)
		}
	}

	for _, invalidSHA := range invalidLegacySHAs {
		if strings.Contains(content, invalidSHA) {
			t.Errorf("workflow contains invalid legacy action SHA %q", invalidSHA)
		}
	}
}

// Condition 17: Nuclei Dockerfile global ARG scoping before FROM
func TestScannerReleaseGate_NucleiDockerfileGlobalArgPlacement(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", "Dockerfile")
	contentBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Nuclei Dockerfile: %v", err)
	}
	content := string(contentBytes)

	validateDockerfileGlobalARGs := func(dfContent string) error {
		lines := strings.Split(dfContent, "\n")
		firstFromIdx := -1
		fromRegex := regexp.MustCompile(`(?i)^\s*FROM\s+`)
		argRegex := regexp.MustCompile(`(?i)^\s*ARG\s+([A-Za-z0-9_]+)`)

		for i, line := range lines {
			if fromRegex.MatchString(line) {
				firstFromIdx = i
				break
			}
		}
		if firstFromIdx == -1 {
			return errors.New("no FROM instruction found")
		}

		globalArgs := make(map[string]bool)
		for _, line := range lines[:firstFromIdx] {
			if m := argRegex.FindStringSubmatch(line); len(m) > 1 {
				globalArgs[m[1]] = true
			}
		}

		requiredGlobalArgs := []string{"NUCLEI_SOURCE_IMAGE", "DISTROLESS_BASE_IMAGE"}
		for _, req := range requiredGlobalArgs {
			if !globalArgs[req] {
				return fmt.Errorf("required ARG %q missing before first FROM", req)
			}
		}

		// Ensure DISTROLESS_BASE_IMAGE is not declared between FROM instructions
		for _, line := range lines[firstFromIdx:] {
			if strings.Contains(line, "ARG DISTROLESS_BASE_IMAGE") {
				return errors.New("DISTROLESS_BASE_IMAGE declared in stage scope instead of global scope")
			}
		}

		return nil
	}

	// 1. Verify canonical Dockerfile
	if err := validateDockerfileGlobalARGs(content); err != nil {
		t.Fatalf("canonical Nuclei Dockerfile failed global ARG validation: %v", err)
	}

	// 2. Negative test: faulty Dockerfile with ARG after first FROM
	faultyContent := `# Faulty Dockerfile
ARG NUCLEI_SOURCE_IMAGE
FROM ${NUCLEI_SOURCE_IMAGE} AS upstream

ARG DISTROLESS_BASE_IMAGE
FROM ${DISTROLESS_BASE_IMAGE}
`
	if err := validateDockerfileGlobalARGs(faultyContent); err == nil {
		t.Fatalf("expected faulty Dockerfile with misplaced ARG to fail validation")
	}
}

// Condition 18: Certified scanner release manifest verification (Issue #566)
func TestScannerReleaseGate_CertifiedManifestValidation(t *testing.T) {
	sPtr := func(s string) *string { return &s }

	createValidCertifiedManifest := func() *ScannerImageLock {
		return &ScannerImageLock{
			SchemaVersion: "1",
			Status:        StatusCertified,
			Images: map[string]ImageMetadata{
				"zap": {
					Upstream:        "ghcr.io/zaproxy/zaproxy:stable",
					UpstreamDigest:  sPtr("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
					Version:         sPtr("2.15.0"),
					KelvinImage:     sPtr("ghcr.io/eozkull/kelvin/scanner-zap"),
					KelvinDigest:    sPtr("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
					Architecture:    sPtr(ArchLinuxArm64),
					SBOMDigest:      sPtr("sha256:3333333333333333333333333333333333333333333333333333333333333333"),
					SignatureRef:    sPtr("ghcr.io/eozkull/kelvin/scanner-zap:sha256-2222222222222222222222222222222222222222222222222222222222222222.sig"),
					ProvenanceRef:   sPtr("ghcr.io/eozkull/kelvin/scanner-zap:sha256-2222222222222222222222222222222222222222222222222222222222222222.att"),
					ScorecardStatus: sPtr(ScorecardStatusEligible),
				},
				"nuclei": {
					Upstream:              "projectdiscovery/nuclei",
					UpstreamDigest:        sPtr("sha256:4444444444444444444444444444444444444444444444444444444444444444"),
					Version:               sPtr("3.11.1"),
					DistrolessBase:        sPtr("gcr.io/distroless/static-debian12:nonroot"),
					DistrolessDigest:      sPtr("sha256:5555555555555555555555555555555555555555555555555555555555555555"),
					KelvinImage:           sPtr("ghcr.io/eozkull/kelvin/scanner-nuclei"),
					KelvinDigest:          sPtr("sha256:6666666666666666666666666666666666666666666666666666666666666666"),
					Architecture:          sPtr(ArchLinuxArm64),
					SBOMDigest:            sPtr("sha256:7777777777777777777777777777777777777777777777777777777777777777"),
					SignatureRef:          sPtr("ghcr.io/eozkull/kelvin/scanner-nuclei:sha256-6666666666666666666666666666666666666666666666666666666666666666.sig"),
					ProvenanceRef:         sPtr("ghcr.io/eozkull/kelvin/scanner-nuclei:sha256-6666666666666666666666666666666666666666666666666666666666666666.att"),
					ScorecardStatus:       sPtr(ScorecardStatusEligible),
					TemplateCatalogID:     "kelvin.safe.web.v1",
					TemplateCatalogDigest: sPtr("sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"),
				},
			},
		}
	}

	t.Run("valid certified manifest passes", func(t *testing.T) {
		m := createValidCertifiedManifest()
		if err := ValidateCertifiedScannerManifest(m, ""); err != nil {
			t.Fatalf("expected valid certified manifest to pass, got: %v", err)
		}
	})

	t.Run("nil manifest rejected", func(t *testing.T) {
		if err := ValidateCertifiedScannerManifest(nil, ""); err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("status not-released rejected with ErrScannerNotReleased", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Status = StatusNotReleased
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrScannerNotReleased) {
			t.Fatalf("expected ErrScannerNotReleased, got: %v", err)
		}
	})

	t.Run("missing architecture rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["zap"] = func(orig ImageMetadata) ImageMetadata {
			orig.Architecture = nil
			return orig
		}(m.Images["zap"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrIncompleteCertification) {
			t.Fatalf("expected ErrIncompleteCertification for missing architecture, got: %v", err)
		}
	})

	t.Run("invalid architecture rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["zap"] = func(orig ImageMetadata) ImageMetadata {
			orig.Architecture = sPtr("windows/amd64")
			return orig
		}(m.Images["zap"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrInvalidArchitecture) {
			t.Fatalf("expected ErrInvalidArchitecture, got: %v", err)
		}
	})

	t.Run("missing SBOM digest rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["zap"] = func(orig ImageMetadata) ImageMetadata {
			orig.SBOMDigest = nil
			return orig
		}(m.Images["zap"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrIncompleteCertification) {
			t.Fatalf("expected ErrIncompleteCertification for missing SBOM digest, got: %v", err)
		}
	})

	t.Run("empty placeholder SBOM digest rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["zap"] = func(orig ImageMetadata) ImageMetadata {
			orig.SBOMDigest = sPtr(EmptySHA256Digest)
			return orig
		}(m.Images["zap"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrPlaceholderEmptyHash) {
			t.Fatalf("expected ErrPlaceholderEmptyHash for empty hash SBOM digest, got: %v", err)
		}
	})

	t.Run("missing signature ref rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["nuclei"] = func(orig ImageMetadata) ImageMetadata {
			orig.SignatureRef = nil
			return orig
		}(m.Images["nuclei"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrIncompleteCertification) {
			t.Fatalf("expected ErrIncompleteCertification for missing signature ref, got: %v", err)
		}
	})

	t.Run("missing provenance ref rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["nuclei"] = func(orig ImageMetadata) ImageMetadata {
			orig.ProvenanceRef = nil
			return orig
		}(m.Images["nuclei"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrIncompleteCertification) {
			t.Fatalf("expected ErrIncompleteCertification for missing provenance ref, got: %v", err)
		}
	})

	t.Run("missing scorecard status rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["zap"] = func(orig ImageMetadata) ImageMetadata {
			orig.ScorecardStatus = nil
			return orig
		}(m.Images["zap"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrIncompleteCertification) {
			t.Fatalf("expected ErrIncompleteCertification for missing scorecard status, got: %v", err)
		}
	})

	t.Run("ineligible scorecard status rejected", func(t *testing.T) {
		m := createValidCertifiedManifest()
		m.Images["zap"] = func(orig ImageMetadata) ImageMetadata {
			orig.ScorecardStatus = sPtr(ScorecardStatusIneligible)
			return orig
		}(m.Images["zap"])
		if err := ValidateCertifiedScannerManifest(m, ""); !errors.Is(err, ErrIneligibleScorecard) {
			t.Fatalf("expected ErrIneligibleScorecard, got: %v", err)
		}
	})
}

// Condition 19: Dedicated helper validators for certified manifest elements
func TestScannerReleaseGate_HelperValidators(t *testing.T) {
	t.Run("ValidateReleaseArchitecture", func(t *testing.T) {
		for _, valid := range []string{"linux/arm64", "linux/amd64", "arm64", "amd64"} {
			if err := ValidateReleaseArchitecture(valid); err != nil {
				t.Errorf("expected valid architecture %q to pass, got: %v", valid, err)
			}
		}
		for _, invalid := range []string{"", "windows/amd64", "darwin/arm64", "unknown"} {
			if err := ValidateReleaseArchitecture(invalid); !errors.Is(err, ErrInvalidArchitecture) {
				t.Errorf("expected ErrInvalidArchitecture for %q, got: %v", invalid, err)
			}
		}
	})

	t.Run("ValidateSBOMDigest", func(t *testing.T) {
		validDigest := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		if err := ValidateSBOMDigest(validDigest); err != nil {
			t.Errorf("expected valid SBOM digest to pass, got: %v", err)
		}
		if err := ValidateSBOMDigest(""); !errors.Is(err, ErrInvalidSBOMDigest) {
			t.Errorf("expected ErrInvalidSBOMDigest for empty, got: %v", err)
		}
		if err := ValidateSBOMDigest(EmptySHA256Digest); !errors.Is(err, ErrPlaceholderEmptyHash) {
			t.Errorf("expected ErrPlaceholderEmptyHash for empty hash placeholder, got: %v", err)
		}
	})

	t.Run("ValidateSignatureRef", func(t *testing.T) {
		if err := ValidateSignatureRef("sha256:4444444444444444444444444444444444444444444444444444444444444444"); err != nil {
			t.Errorf("expected valid signature digest to pass, got: %v", err)
		}
		if err := ValidateSignatureRef("ghcr.io/eozkull/kelvin/scanner-zap:sha256-xxx.sig"); err != nil {
			t.Errorf("expected valid signature reference tag to pass, got: %v", err)
		}
		if err := ValidateSignatureRef(""); !errors.Is(err, ErrInvalidSignatureRef) {
			t.Errorf("expected ErrInvalidSignatureRef for empty, got: %v", err)
		}
	})

	t.Run("ValidateProvenanceRef", func(t *testing.T) {
		if err := ValidateProvenanceRef("sha256:5555555555555555555555555555555555555555555555555555555555555555"); err != nil {
			t.Errorf("expected valid provenance digest to pass, got: %v", err)
		}
		if err := ValidateProvenanceRef("ghcr.io/eozkull/kelvin/scanner-zap:sha256-xxx.att"); err != nil {
			t.Errorf("expected valid provenance reference tag to pass, got: %v", err)
		}
		if err := ValidateProvenanceRef(""); !errors.Is(err, ErrInvalidProvenanceRef) {
			t.Errorf("expected ErrInvalidProvenanceRef for empty, got: %v", err)
		}
	})

	t.Run("ValidateScorecardStatus", func(t *testing.T) {
		if err := ValidateScorecardStatus(ScorecardStatusEligible); err != nil {
			t.Errorf("expected ELIGIBLE to pass, got: %v", err)
		}
		for _, ineligible := range []string{"INELIGIBLE", "UNKNOWN", "FAIL", ""} {
			if err := ValidateScorecardStatus(ineligible); !errors.Is(err, ErrIneligibleScorecard) {
				t.Errorf("expected ErrIneligibleScorecard for %q, got: %v", ineligible, err)
			}
		}
	})
}

// Condition 20: Canonical release manifest verification on disk
func TestScannerReleaseGate_CanonicalLockOnDisk(t *testing.T) {
	lockPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "images.lock.json")
	lock, err := LoadCanonicalLock(lockPath)
	if err != nil {
		t.Fatalf("failed to load canonical lock: %v", err)
	}

	if lock.Status != StatusNotReleased {
		t.Fatalf("canonical lock must be in status %q, got: %q", StatusNotReleased, lock.Status)
	}

	for _, scannerID := range []string{"zap", "nuclei"} {
		img, ok := lock.Images[scannerID]
		if !ok {
			t.Fatalf("missing scanner %q in canonical lock", scannerID)
		}
		if img.Upstream == "" {
			t.Errorf("scanner %q missing upstream repository", scannerID)
		}
	}
}

