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

	invalidVersions := []string{"latest", "stable", "v", "dev-nightly", ""}
	for _, v := range invalidVersions {
		if err := ValidateSemanticVersion(v); err == nil || !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("expected ErrInvalidVersion for %q, got: %v", v, err)
		}
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
	identityPattern := regexp.MustCompile(`^https://github\.com/Inkesk-Dozing/Kelvin/\.github/workflows/.*`)
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

	validURI := "https://github.com/Inkesk-Dozing/Kelvin/.github/workflows/scanner-images.yml@refs/heads/main"
	if err := verifyIdentity(validURI, expectedIssuer); err != nil {
		t.Fatalf("expected valid identity to pass, got: %v", err)
	}

	untrustedURIs := []string{
		"https://github.com/Attacker/Kelvin/.github/workflows/scanner-images.yml",
		"https://github.com/Inkesk-Dozing/OtherRepo/.github/workflows/workflow.yml",
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
					KelvinImage:  strPtr("ghcr.io/inkesk-dozing/kelvin/scanner-zap"),
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
					KelvinImage:    strPtr("ghcr.io/inkesk-dozing/kelvin/scanner-zap"),
					KelvinDigest:   strPtr("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
				},
				"nuclei": {
					Upstream:              "projectdiscovery/nuclei",
					UpstreamDigest:        strPtr("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
					Version:               strPtr("3.3.7"),
					DistrolessBase:        strPtr("gcr.io/distroless/static-debian12:nonroot"),
					DistrolessDigest:      strPtr("sha256:3333333333333333333333333333333333333333333333333333333333333333"),
					KelvinImage:           strPtr("ghcr.io/inkesk-dozing/kelvin/scanner-nuclei"),
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
