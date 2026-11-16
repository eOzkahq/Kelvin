package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zapFirefoxLockFile struct {
	SchemaVersion    string `json:"schema_version"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	CVECount         int    `json:"cve_count"`
	RemediatedCVEs   []struct {
		CVEID             string `json:"cve_id"`
		Severity          string `json:"severity"`
		Status            string `json:"status"`
		FixedVersion      string `json:"fixed_version"`
		TrackingReference string `json:"tracking_reference"`
	} `json:"remediated_cves"`
}

func TestZAPFirefoxRemediation_51CVEsAccountedFor(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")
	zapDir := filepath.Join(rootPath, "deploy", "scanners", "zap")

	// 1. Verify packages.list exists and pins firefox-esr
	pkgListPath := filepath.Join(zapDir, "packages.list")
	pkgListBytes, err := os.ReadFile(pkgListPath)
	if err != nil {
		t.Fatalf("failed to read packages.list: %v", err)
	}
	pkgList := string(pkgListBytes)

	if !strings.Contains(pkgList, "firefox-esr") {
		t.Errorf("packages.list missing firefox-esr package")
	}
	if !strings.Contains(pkgList, "153.7.0esr") {
		t.Errorf("packages.list must pin to patched 153.7.0esr release")
	}

	// 2. Verify firefox.lock accounts for exactly 51 CVEs
	lockPath := filepath.Join(zapDir, "firefox.lock")
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read firefox.lock: %v", err)
	}

	var lock zapFirefoxLockFile
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatalf("failed to parse firefox.lock: %v", err)
	}

	if lock.Package != "firefox-esr" {
		t.Errorf("expected package 'firefox-esr', got %q", lock.Package)
	}
	if lock.CVECount != 51 || len(lock.RemediatedCVEs) != 51 {
		t.Fatalf("expected exactly 51 remediated CVEs, got %d (count %d)", len(lock.RemediatedCVEs), lock.CVECount)
	}

	for _, rec := range lock.RemediatedCVEs {
		if rec.Status != "remediated" {
			t.Errorf("CVE %s has unexpected status %q", rec.CVEID, rec.Status)
		}
		if !strings.HasPrefix(rec.TrackingReference, "https://security-tracker.debian.org/tracker/") {
			t.Errorf("CVE %s has invalid tracking reference %q", rec.CVEID, rec.TrackingReference)
		}
	}

	// 3. Verify Dockerfile contracts
	dockerfilePath := filepath.Join(zapDir, "Dockerfile")
	dfBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read ZAP Dockerfile: %v", err)
	}
	dfContent := string(dfBytes)

	if !strings.Contains(dfContent, "packages.list") {
		t.Errorf("ZAP Dockerfile missing COPY packages.list")
	}
	if !strings.Contains(dfContent, "firefox-esr") {
		t.Errorf("ZAP Dockerfile missing firefox-esr upgrade command")
	}

	// Verify user 10001:10001 is preserved in final stage
	lines := strings.Split(dfContent, "\n")
	lastUserLine := ""
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "USER ") {
			lastUserLine = trimmed
		}
	}
	if lastUserLine != "USER 10001:10001" {
		t.Errorf("ZAP Dockerfile must conclude with USER 10001:10001, got: %q", lastUserLine)
	}
}
