package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCalculateCatalogDigest_MatchesDeterministicHash(t *testing.T) {
	catalogPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "templates", "kelvin.safe.web.v1", "catalog.json")
	digest, err := CalculateCatalogDigest(catalogPath)
	if err != nil {
		t.Fatalf("failed to calculate catalog digest: %v", err)
	}

	expectedDigest := "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"
	if digest != expectedDigest {
		t.Errorf("digest mismatch: expected %s, got %s", expectedDigest, digest)
	}

	// Verify it does NOT match the empty string hash
	if digest == EmptySHA256Digest {
		t.Fatal("catalog digest must not be the empty string hash")
	}
}

func TestValidateLockConsistency_RejectsEmptyPlaceholderHash(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "lock.yaml")
	jsonFile := filepath.Join(dir, "lock.json")

	badYAML := `schema_version: "1.0"
status: "not-released"
scanners:
  nuclei:
    id: "nuclei"
    template_catalog_digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
`
	goodJSON := `{"schema_version": "1.0", "status": "not-released", "images": {}}`

	if err := os.WriteFile(yamlFile, []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonFile, []byte(goodJSON), 0644); err != nil {
		t.Fatal(err)
	}

	err := ValidateLockConsistency(yamlFile, jsonFile)
	if err == nil || !strings.Contains(err.Error(), "empty string placeholder") {
		t.Fatalf("expected empty placeholder rejection, got: %v", err)
	}
}

func TestValidateLockConsistency_RejectsStatusConflict(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "lock.yaml")
	jsonFile := filepath.Join(dir, "lock.json")

	yamlContent := `schema_version: "1.0"
status: "locked"
scanners:
  zap:
    id: "zap"
`
	jsonContent := `{"schema_version": "1.0", "status": "not-released", "images": {}}`

	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonFile, []byte(jsonContent), 0644); err != nil {
		t.Fatal(err)
	}

	err := ValidateLockConsistency(yamlFile, jsonFile)
	if err == nil || !strings.Contains(err.Error(), "status mismatch") {
		t.Fatalf("expected status mismatch rejection, got: %v", err)
	}
}

func TestValidateReleaseStatusForExecution(t *testing.T) {
	// Not released must be blocked in production and staging
	if err := ValidateReleaseStatusForExecution(StatusNotReleased, "production"); err == nil {
		t.Fatal("expected unreleased scanner to be rejected in production")
	}
	if err := ValidateReleaseStatusForExecution(StatusNotReleased, "staging"); err == nil {
		t.Fatal("expected unreleased scanner to be rejected in staging")
	}

	// Allowed in development / testing
	if err := ValidateReleaseStatusForExecution(StatusNotReleased, "development"); err != nil {
		t.Fatalf("unreleased scanner should be permitted in development: %v", err)
	}
	if err := ValidateReleaseStatusForExecution(StatusCertified, "production"); err != nil {
		t.Fatalf("certified scanner should be permitted in production: %v", err)
	}
}

func TestValidateActualProjectLocksAreConsistent(t *testing.T) {
	yamlPath := filepath.Join("..", "..", "..", "..", "deploy", "scanner-image-lock.yaml")
	jsonPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "images.lock.json")

	if err := ValidateLockConsistency(yamlPath, jsonPath); err != nil {
		t.Fatalf("repository release locks must be consistent: %v", err)
	}
}
