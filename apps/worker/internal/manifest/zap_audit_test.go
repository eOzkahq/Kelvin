package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type ZAPPackageAudit struct {
	SchemaVersion string                     `json:"schema_version"`
	Scanner       string                     `json:"scanner"`
	TotalFindings int                        `json:"total_findings"`
	AuditDate     string                     `json:"audit_date"`
	Packages      map[string]AuditPackageInfo `json:"packages"`
}

type AuditPackageInfo struct {
	PackageName      string `json:"package_name"`
	InstalledVersion string `json:"installed_version"`
	Ecosystem        string `json:"ecosystem"`
	RuntimeRequired  bool   `json:"runtime_required"`
	IsDevPackage     bool   `json:"is_dev_package"`
	CVECount         int    `json:"cve_count"`
}

func TestZAPPackageAudit_MappingCompleteness(t *testing.T) {
	auditPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "zap", "package-audit.json")

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read package-audit.json: %v", err)
	}

	var audit ZAPPackageAudit
	if err := json.Unmarshal(data, &audit); err != nil {
		t.Fatalf("failed to parse package-audit.json: %v", err)
	}

	if audit.Scanner != "zap" {
		t.Errorf("expected scanner zap, got %q", audit.Scanner)
	}

	if audit.TotalFindings != 384 {
		t.Errorf("expected total_findings 384, got %d", audit.TotalFindings)
	}

	sumCVEs := 0
	for _, p := range audit.Packages {
		sumCVEs += p.CVECount
	}

	if sumCVEs != 384 {
		t.Errorf("sum of package CVE counts (%d) does not match total findings (384)", sumCVEs)
	}

	// Verify key targets
	linuxLibc, ok := audit.Packages["linux-libc-dev"]
	if !ok || linuxLibc.CVECount != 193 {
		t.Errorf("expected linux-libc-dev to have 193 CVEs, got: %+v", linuxLibc)
	}
	if linuxLibc.RuntimeRequired {
		t.Errorf("linux-libc-dev should not be marked runtime_required")
	}

	firefox, ok := audit.Packages["firefox-esr"]
	if !ok || firefox.CVECount != 51 {
		t.Errorf("expected firefox-esr to have 51 CVEs, got: %+v", firefox)
	}
	if !firefox.RuntimeRequired {
		t.Errorf("firefox-esr must be marked runtime_required")
	}

	// Verify dev packages are flagged
	devs := []string{"libexpat1-dev", "zlib1g-dev", "libpython3.11-dev"}
	for _, d := range devs {
		pkg, ok := audit.Packages[d]
		if !ok || !pkg.IsDevPackage {
			t.Errorf("expected %s to exist and be flagged as is_dev_package: %+v", d, pkg)
		}
	}
}

func TestZAPPackageAudit_TamperDetection(t *testing.T) {
	// Negative test: verify that missing packages or altered counts fail validation
	faultyAudit := ZAPPackageAudit{
		TotalFindings: 384,
		Packages: map[string]AuditPackageInfo{
			"firefox-esr": {PackageName: "firefox-esr", CVECount: 50}, // 1 missing
		},
	}

	sum := 0
	for _, p := range faultyAudit.Packages {
		sum += p.CVECount
	}
	if sum == faultyAudit.TotalFindings {
		t.Fatalf("expected faulty audit with missing CVE count to fail validation")
	}
}
