package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZAPScanner_ContainerSecuritySpecification(t *testing.T) {
	rootPath := filepath.Join("..", "..")

	// 1. Verify build script specifies proper limits and capability drop
	buildScriptPath := filepath.Join(rootPath, "scripts", "scanners", "build-images.sh")
	data, err := os.ReadFile(buildScriptPath)
	if err != nil {
		t.Fatalf("failed to read build-images.sh: %v", err)
	}
	content := string(data)

	expectedSecurityFlags := []string{
		"--read-only",
		"--memory=1.5g",
		"--cpus=1.0",
		"--pids-limit=256",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--tmpfs /tmp:rw,noexec,nosuid,size=64m",
	}

	for _, flag := range expectedSecurityFlags {
		if !strings.Contains(content, flag) {
			t.Errorf("build-images.sh missing container security contract flag: %s", flag)
		}
	}

	// 2. Verify architecture validation supports both ARM64 and AMD64
	if !strings.Contains(content, "linux/arm64") {
		t.Errorf("build-images.sh missing linux/arm64 architecture support")
	}
	if !strings.Contains(content, "validate_architecture") {
		t.Errorf("build-images.sh missing validate_architecture function")
	}
}
