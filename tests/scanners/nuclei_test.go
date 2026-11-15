package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNucleiScanner_CLIInvocationAndFlagsContract(t *testing.T) {
	// 1. Verify Dockerfile entrypoint enforces -duc (no remote update checks)
	dockerfilePath := filepath.Join("..", "..", "deploy", "scanners", "nuclei", "Dockerfile")
	dfBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Nuclei Dockerfile: %v", err)
	}
	dfContent := string(dfBytes)

	if !strings.Contains(dfContent, `ENTRYPOINT ["/nuclei", "-duc"]`) {
		t.Errorf("Dockerfile entrypoint must include -duc flag to disable automatic updates")
	}

	// 2. Verify canonical worker execution flags contract
	// nuclei -duc -u <target> -t /opt/kelvin/templates/kelvin.safe.web.v1 -rl 2
	expectedFlags := []string{
		"-duc",
		"-u",
		"-t /opt/kelvin/templates/kelvin.safe.web.v1",
		"-rl 2",
	}
	canonicalCommand := "/nuclei -duc -u https://target.example.internal -t /opt/kelvin/templates/kelvin.safe.web.v1 -rl 2"
	for _, flag := range expectedFlags {
		if !strings.Contains(canonicalCommand, flag) {
			t.Errorf("canonical worker command missing required flag: %s", flag)
		}
	}

	// 3. Verify curated safe template catalog exists and is valid
	catalogDir := filepath.Join("..", "..", "deploy", "scanners", "templates", "kelvin.safe.web.v1")
	manifestPath := filepath.Join(catalogDir, "catalog.json")
	mBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read curated template catalog manifest: %v", err)
	}

	var catalogManifest struct {
		CatalogID string `json:"catalog_id"`
		Version   string `json:"version"`
		Templates []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(mBytes, &catalogManifest); err != nil {
		t.Fatalf("failed to parse catalog.json: %v", err)
	}

	if catalogManifest.CatalogID != "kelvin.safe.web.v1" {
		t.Errorf("expected catalog_id 'kelvin.safe.web.v1', got %q", catalogManifest.CatalogID)
	}
	if len(catalogManifest.Templates) == 0 {
		t.Errorf("curated template catalog must contain at least 1 template")
	}

	// Verify each template file in catalog actually exists
	for _, tmpl := range catalogManifest.Templates {
		tmplPath := filepath.Join(catalogDir, tmpl.Path)
		if _, err := os.Stat(tmplPath); os.IsNotExist(err) {
			t.Errorf("template file defined in catalog does not exist: %s", tmplPath)
		}
	}
}

func TestNucleiScanner_ContainerHardeningContracts(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "deploy", "scanners", "nuclei", "Dockerfile")
	dfBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Nuclei Dockerfile: %v", err)
	}
	dfContent := string(dfBytes)

	// Invariant: Non-root UID/GID 10001
	if !strings.Contains(dfContent, "USER 10001:10001") {
		t.Errorf("Nuclei image must declare unprivileged user 10001:10001")
	}

	// Invariant: Read-only rootfs compatibility requires writable scratch directories in /tmp
	expectedEnv := []string{
		"HOME=/tmp",
		"XDG_CONFIG_HOME=/tmp/.config",
		"XDG_CACHE_HOME=/tmp/.cache",
	}
	for _, envVar := range expectedEnv {
		if !strings.Contains(dfContent, envVar) {
			t.Errorf("Nuclei image missing read-only rootfs compatibility env: %s", envVar)
		}
	}
}

func TestNucleiScanner_FixtureTemplateValidity(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "templates", "safe.web.v1.yaml")
	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture template: %v", err)
	}
	fixtureContent := string(fixtureBytes)

	if !strings.Contains(fixtureContent, "kelvin-safe-web-fixture") {
		t.Errorf("fixture template missing ID")
	}
	if !strings.Contains(fixtureContent, "severity: low") {
		t.Errorf("fixture template must have safe/low severity")
	}
}
