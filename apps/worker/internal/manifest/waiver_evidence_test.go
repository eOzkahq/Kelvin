package manifest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	cveRegex        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	purlRegex       = regexp.MustCompile(`^pkg:[a-z0-9_-]+/[^@\s]+@[^@\s]+$`)
	approvedPrefixes = []string{
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

type WaiverRegistryData struct {
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
}

func TestWaiverEvidenceValidation_Registries(t *testing.T) {
	registries := []string{
		filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", "waivers.yaml"),
		filepath.Join("..", "..", "..", "..", "deploy", "scanners", "zap", "waivers.yaml"),
	}

	for _, regPath := range registries {
		data, err := os.ReadFile(regPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", regPath, err)
		}

		var reg WaiverRegistryData
		if err := yaml.Unmarshal(data, &reg); err != nil {
			t.Fatalf("failed to parse %s: %v", regPath, err)
		}

		if len(reg.Waivers) == 0 {
			t.Fatalf("expected non-empty waivers in %s", regPath)
		}

		for _, w := range reg.Waivers {
			if !cveRegex.MatchString(w.CVEID) {
				t.Errorf("[%s] invalid CVE identifier format: %s", regPath, w.CVEID)
			}
			if !purlRegex.MatchString(w.Component) {
				t.Errorf("[%s] invalid package purl format for %s: %s", regPath, w.CVEID, w.Component)
			}
			if len(strings.TrimSpace(w.TechnicalJustification)) < 10 {
				t.Errorf("[%s] technical justification too short for %s", regPath, w.CVEID)
			}
			hasApprovedPrefix := false
			for _, prefix := range approvedPrefixes {
				if strings.HasPrefix(w.TrackingReference, prefix) {
					hasApprovedPrefix = true
					break
				}
			}
			if !hasApprovedPrefix {
				t.Errorf("[%s] unapproved tracking reference prefix for %s: %s", regPath, w.CVEID, w.TrackingReference)
			}
		}
	}
}
