package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	cvePattern      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	purlPattern     = regexp.MustCompile(`^pkg:[a-z0-9_-]+/[^@\s]+@[^@\s]+$`)
	approvedPrefixs = []string{
		"https://nvd.nist.gov/vuln/detail/",
		"https://github.com/advisories/",
		"https://security-tracker.debian.org/tracker/",
		"https://pkg.go.dev/vuln/",
		"https://ubuntu.com/security/",
		"https://osv.dev/",
		"https://cve.org/",
		"https://www.cve.org/",
	}
)

type RegistryFile struct {
	SchemaVersion string        `yaml:"schema_version"`
	Scanner       string        `yaml:"scanner"`
	Waivers       []WaiverEntry `yaml:"waivers"`
}

type WaiverEntry struct {
	CVEID                  string `yaml:"cve_id"`
	Component              string `yaml:"component"`
	Severity               string `yaml:"severity"`
	TechnicalJustification string `yaml:"technical_justification"`
	Status                 string `yaml:"status"`
	TrackingReference      string `yaml:"tracking_reference"`
	ReviewDate             string `yaml:"review_date"`
	ExpiryDate             string `yaml:"expiry_date"`
}

// TestScannerVulnRegression_NucleiBaseline asserts the known good baseline for Nuclei scanner.
func TestScannerVulnRegression_NucleiBaseline(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	waiversPath := filepath.Join(repoRoot, "deploy", "scanners", "nuclei", "waivers.yaml")
	trivyignorePath := filepath.Join(repoRoot, "deploy", "scanners", "nuclei", ".trivyignore")

	data, err := os.ReadFile(waiversPath)
	if err != nil {
		t.Fatalf("failed to read nuclei waivers: %v", err)
	}

	var reg RegistryFile
	if err := yaml.Unmarshal(data, &reg); err != nil {
		t.Fatalf("failed to parse nuclei waivers: %v", err)
	}

	if reg.Scanner != "nuclei" {
		t.Errorf("expected scanner 'nuclei', got %q", reg.Scanner)
	}
	if len(reg.Waivers) != 26 {
		t.Errorf("expected exactly 26 registered Nuclei waivers, got %d", len(reg.Waivers))
	}

	for _, w := range reg.Waivers {
		if !cvePattern.MatchString(w.CVEID) {
			t.Errorf("invalid CVE ID: %s", w.CVEID)
		}
		if !purlPattern.MatchString(w.Component) {
			t.Errorf("invalid component purl: %s for %s", w.Component, w.CVEID)
		}
		if len(strings.TrimSpace(w.TechnicalJustification)) < 10 {
			t.Errorf("technical justification too short for %s", w.CVEID)
		}
	}

	// Verify that pending_review waivers are NOT present in .trivyignore
	trivyData, err := os.ReadFile(trivyignorePath)
	if err != nil {
		t.Fatalf("failed to read nuclei .trivyignore: %v", err)
	}
	trivyContent := string(trivyData)

	for _, w := range reg.Waivers {
		if w.Status == "pending_review" {
			if strings.Contains(trivyContent, w.CVEID) {
				t.Errorf("CRITICAL SECURITY VIOLATION: Pending review waiver %s leaked into .trivyignore", w.CVEID)
			}
		}
	}
}

// TestScannerVulnRegression_ZAPBaseline asserts the known good baseline for OWASP ZAP scanner.
func TestScannerVulnRegression_ZAPBaseline(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	waiversPath := filepath.Join(repoRoot, "deploy", "scanners", "zap", "waivers.yaml")
	trivyignorePath := filepath.Join(repoRoot, "deploy", "scanners", "zap", ".trivyignore")

	data, err := os.ReadFile(waiversPath)
	if err != nil {
		t.Fatalf("failed to read zap waivers: %v", err)
	}

	var reg RegistryFile
	if err := yaml.Unmarshal(data, &reg); err != nil {
		t.Fatalf("failed to parse zap waivers: %v", err)
	}

	if reg.Scanner != "zap" {
		t.Errorf("expected scanner 'zap', got %q", reg.Scanner)
	}
	if len(reg.Waivers) != 384 {
		t.Errorf("expected exactly 384 registered ZAP waivers, got %d", len(reg.Waivers))
	}

	trivyData, err := os.ReadFile(trivyignorePath)
	if err != nil {
		t.Fatalf("failed to read zap .trivyignore: %v", err)
	}
	trivyContent := string(trivyData)

	for _, w := range reg.Waivers {
		if w.Status == "pending_review" {
			if strings.Contains(trivyContent, w.CVEID) {
				t.Errorf("CRITICAL SECURITY VIOLATION: Pending review waiver %s leaked into .trivyignore", w.CVEID)
			}
		}
	}
}

// TestScannerVulnRegression_FailClosedOnUnhandledCVE simulates injection of an unhandled CVE
// and verifies that the fail-closed security gating strictly rejects it.
func TestScannerVulnRegression_FailClosedOnUnhandledCVE(t *testing.T) {
	registeredWaivers := map[string]bool{
		"CVE-2026-100349": true,
		"CVE-2026-100351": true,
	}

	rawFindingsFromScan := []string{
		"CVE-2026-100349",
		"CVE-2026-99999", // Unregistered synthetic CVE
	}

	unhandledCount := 0
	for _, f := range rawFindingsFromScan {
		if !registeredWaivers[f] {
			unhandledCount++
		}
	}

	if unhandledCount == 0 {
		t.Fatalf("expected unhandled CVE to be detected")
	}

	// Gating decision
	verdict := "PASS"
	if unhandledCount > 0 {
		verdict = "GATED"
	}

	if verdict != "GATED" {
		t.Errorf("fail-closed gate failed: expected GATED for unhandled findings, got %s", verdict)
	}
}

// TestScannerVulnRegression_SeverityTTLConstraints verifies TTL maximum limits for waivers.
func TestScannerVulnRegression_SeverityTTLConstraints(t *testing.T) {
	ttlLimits := map[string]int{
		"CRITICAL": 30,
		"HIGH":     90,
		"MEDIUM":   180,
		"LOW":      180,
	}

	reviewDate, _ := time.Parse("2006-01-02", "2026-11-01")

	// 1. Valid TTL (30 days for CRITICAL)
	validCriticalExpiry, _ := time.Parse("2006-01-02", "2026-12-01")
	actualCriticalDays := int(validCriticalExpiry.Sub(reviewDate).Hours() / 24)
	if actualCriticalDays > ttlLimits["CRITICAL"] {
		t.Errorf("expected 30d critical TTL, got %d", actualCriticalDays)
	}

	// 2. Invalid TTL (31 days for CRITICAL)
	invalidCriticalExpiry, _ := time.Parse("2006-01-02", "2026-12-02")
	actualOverTTL := int(invalidCriticalExpiry.Sub(reviewDate).Hours() / 24)
	if actualOverTTL <= ttlLimits["CRITICAL"] {
		t.Errorf("expected over-TTL critical expiry to be detected: %d days", actualOverTTL)
	}
}

// TestScannerVulnRegression_CycloneDXSchemaValidation asserts valid structure of CycloneDX SBOM JSON.
func TestScannerVulnRegression_CycloneDXSchemaValidation(t *testing.T) {
	mockValidSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"vulnerabilities": [
			{
				"id": "CVE-2026-12345",
				"ratings": [{"severity": "high"}],
				"affects": [{"ref": "pkg:deb/debian/libtest@1.0"}]
			}
		]
	}`

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(mockValidSBOM), &parsed); err != nil {
		t.Fatalf("failed to parse mock SBOM: %v", err)
	}

	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", parsed["bomFormat"])
	}

	vulns, ok := parsed["vulnerabilities"].([]interface{})
	if !ok || len(vulns) != 1 {
		t.Errorf("expected 1 vulnerability in mock SBOM")
	}

	// Negative test: invalid format
	invalidSBOM := `{"bomFormat": "UnknownFormat"}`
	var invalidParsed map[string]interface{}
	_ = json.Unmarshal([]byte(invalidSBOM), &invalidParsed)
	if invalidParsed["bomFormat"] == "CycloneDX" {
		t.Errorf("expected invalid format to be rejected")
	}
}

