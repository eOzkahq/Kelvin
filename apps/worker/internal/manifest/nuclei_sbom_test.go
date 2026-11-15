package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cycloneDXSBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Component struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			Type       string `json:"type"`
			PURL       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		BOMRef  string `json:"bom-ref"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

func TestNucleiSBOM_CycloneDXInvariantsAndLinkage(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")
	sbomPath := filepath.Join(rootPath, "deploy", "scanners", "nuclei", "sbom.cyclonedx.json")

	sbomBytes, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("failed to read nuclei sbom: %v", err)
	}

	var sbom cycloneDXSBOM
	if err := json.Unmarshal(sbomBytes, &sbom); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	// 1. Spec compliance
	if sbom.BOMFormat != "CycloneDX" {
		t.Errorf("expected bomFormat 'CycloneDX', got %q", sbom.BOMFormat)
	}
	if sbom.SpecVersion != "1.5" {
		t.Errorf("expected specVersion '1.5', got %q", sbom.SpecVersion)
	}

	// 2. Cryptographic provenance in metadata properties
	props := make(map[string]string)
	for _, p := range sbom.Metadata.Component.Properties {
		props[p.Name] = p.Value
	}

	expectedProps := map[string]string{
		"kelvin:source:commit":  "a8c88feb4a1c8e961b7902534ce3af97e9d524a4",
		"kelvin:builder:digest": "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696",
		"kelvin:runtime:user":   "10001:10001",
	}

	for k, expectedVal := range expectedProps {
		val, ok := props[k]
		if !ok {
			t.Errorf("SBOM metadata missing property %q", k)
		} else if val != expectedVal {
			t.Errorf("SBOM property %s mismatch: expected %q, got %q", k, expectedVal, val)
		}
	}

	// 3. Components verification
	purls := make(map[string]bool)
	for _, c := range sbom.Components {
		purls[c.PURL] = true
	}

	requiredPURLs := []string{
		"pkg:golang/stdlib@v1.26.10",
		"pkg:golang/github.com/go-git/go-git/v5@v5.14.0",
		"pkg:generic/kelvin.safe.web.v1@1.0.0",
	}

	for _, req := range requiredPURLs {
		if !purls[req] {
			t.Errorf("SBOM missing required component purl: %s", req)
		}
	}

	// 4. Script contracts
	scriptPath := filepath.Join(rootPath, "scripts", "scanners", "generate-sbom.sh")
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read generate-sbom.sh: %v", err)
	}
	scriptContent := string(scriptBytes)
	for _, reqContract := range []string{"calc_sha256", "CycloneDX", "nuclei.cdx.json"} {
		if !strings.Contains(scriptContent, reqContract) {
			t.Errorf("generate-sbom.sh missing required contract: %s", reqContract)
		}
	}
}
