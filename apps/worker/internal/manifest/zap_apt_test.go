package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zapAPTLockFile struct {
	SchemaVersion  string   `json:"schema_version"`
	Packages       []string `json:"packages"`
	FixedVersion   string   `json:"fixed_version"`
	RemediatedCVEs []struct {
		CVEID             string `json:"cve_id"`
		Severity          string `json:"severity"`
		Status            string `json:"status"`
		FixedVersion      string `json:"fixed_version"`
		TrackingReference string `json:"tracking_reference"`
	} `json:"remediated_cves"`
}

func TestZAPAPTRemediation_CVEAccountedFor(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")
	zapDir := filepath.Join(rootPath, "deploy", "scanners", "zap")

	// 1. Verify packages.list exists and pins apt
	pkgListPath := filepath.Join(zapDir, "packages.list")
	pkgListBytes, err := os.ReadFile(pkgListPath)
	if err != nil {
		t.Fatalf("failed to read packages.list: %v", err)
	}
	pkgList := string(pkgListBytes)

	if !strings.Contains(pkgList, "apt") || !strings.Contains(pkgList, "libapt-pkg6.0") {
		t.Errorf("packages.list missing apt or libapt-pkg6.0 package")
	}
	if !strings.Contains(pkgList, "2.6.2") {
		t.Errorf("packages.list must pin apt to 2.6.2")
	}

	// 2. Verify apt.lock records CVE-2026-109518
	lockPath := filepath.Join(zapDir, "apt.lock")
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read apt.lock: %v", err)
	}

	var lock zapAPTLockFile
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatalf("failed to parse apt.lock: %v", err)
	}

	if len(lock.RemediatedCVEs) != 1 || lock.RemediatedCVEs[0].CVEID != "CVE-2026-109518" {
		t.Errorf("expected CVE-2026-109518 in apt.lock, got %+v", lock.RemediatedCVEs)
	}
	if lock.RemediatedCVEs[0].Status != "remediated" {
		t.Errorf("expected status 'remediated', got %q", lock.RemediatedCVEs[0].Status)
	}

	// 3. Verify Dockerfile contracts
	dockerfilePath := filepath.Join(zapDir, "Dockerfile")
	dfBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read ZAP Dockerfile: %v", err)
	}
	dfContent := string(dfBytes)

	if !strings.Contains(dfContent, "rm -rf /var/lib/apt/lists/*") {
		t.Errorf("ZAP Dockerfile must purge /var/lib/apt/lists/* to minimize container layers")
	}
	if !strings.Contains(dfContent, "apt-get clean") {
		t.Errorf("ZAP Dockerfile must run apt-get clean")
	}
}
