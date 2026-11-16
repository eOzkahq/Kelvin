package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZAPMinimization_SlimPackagesAndDockerfile(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")
	zapDir := filepath.Join(rootPath, "deploy", "scanners", "zap")

	// 1. Verify slim-packages.list exists and lists key packages
	slimListPath := filepath.Join(zapDir, "slim-packages.list")
	data, err := os.ReadFile(slimListPath)
	if err != nil {
		t.Fatalf("failed to read slim-packages.list: %v", err)
	}
	content := string(data)

	expectedPurged := []string{
		"linux-libc-dev",
		"libexpat1-dev",
		"libpython3.11-dev",
		"zlib1g-dev",
		"gcc",
		"build-essential",
	}

	for _, pkg := range expectedPurged {
		if !strings.Contains(content, pkg) {
			t.Errorf("slim-packages.list missing expected purged package: %s", pkg)
		}
	}

	// 2. Verify Dockerfile contracts
	dockerfilePath := filepath.Join(zapDir, "Dockerfile")
	dfBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read ZAP Dockerfile: %v", err)
	}
	dfContent := string(dfBytes)

	if !strings.Contains(dfContent, "slim-packages.list") {
		t.Errorf("ZAP Dockerfile missing reference to slim-packages.list")
	}
	if !strings.Contains(dfContent, "apt-get purge") {
		t.Errorf("ZAP Dockerfile missing apt-get purge instruction")
	}

	// Invariant: USER 10001:10001 must be the final active user
	lines := strings.Split(dfContent, "\n")
	lastUserLine := ""
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "USER ") {
			lastUserLine = trimmed
		}
	}
	if lastUserLine != "USER 10001:10001" {
		t.Errorf("final user in ZAP Dockerfile must be USER 10001:10001, got: %q", lastUserLine)
	}
}
