package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zapSetuptoolsLockFile struct {
	SchemaVersion  string `json:"schema_version"`
	Package        string `json:"package"`
	Ecosystem      string `json:"ecosystem"`
	FixedVersion   string `json:"fixed_version"`
	RemediatedCVEs []struct {
		CVEID             string `json:"cve_id"`
		Severity          string `json:"severity"`
		Status            string `json:"status"`
		FixedVersion      string `json:"fixed_version"`
		TrackingReference string `json:"tracking_reference"`
	} `json:"remediated_cves"`
}

func TestZAPSetuptoolsRemediation_CVEAccountedFor(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")
	zapDir := filepath.Join(rootPath, "deploy", "scanners", "zap")

	// 1. Verify requirements.txt pins setuptools
	reqPath := filepath.Join(zapDir, "requirements.txt")
	reqBytes, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatalf("failed to read requirements.txt: %v", err)
	}
	reqContent := string(reqBytes)

	if !strings.Contains(reqContent, "setuptools>=78.1.1") {
		t.Errorf("requirements.txt must pin setuptools>=78.1.1, got: %q", reqContent)
	}

	// 2. Verify setuptools.lock records CVE-2025-47273
	lockPath := filepath.Join(zapDir, "setuptools.lock")
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read setuptools.lock: %v", err)
	}

	var lock zapSetuptoolsLockFile
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatalf("failed to parse setuptools.lock: %v", err)
	}

	if len(lock.RemediatedCVEs) != 1 || lock.RemediatedCVEs[0].CVEID != "CVE-2025-47273" {
		t.Errorf("expected CVE-2025-47273 in setuptools.lock, got %+v", lock.RemediatedCVEs)
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

	if !strings.Contains(dfContent, "requirements.txt") {
		t.Errorf("ZAP Dockerfile missing requirements.txt installation")
	}
}
