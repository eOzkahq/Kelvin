package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZAPScanner_RuntimeHardeningContracts(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "deploy", "scanners", "zap", "Dockerfile")
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read ZAP Dockerfile: %v", err)
	}
	content := string(data)

	// Invariant 1: Unprivileged runtime UID/GID 10001:10001
	lines := strings.Split(content, "\n")
	lastUserLine := ""
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "USER ") {
			lastUserLine = trimmed
		}
	}
	if lastUserLine != "USER 10001:10001" {
		t.Errorf("ZAP runtime must enforce USER 10001:10001, got: %q", lastUserLine)
	}

	// Invariant 2: Read-only rootfs compatibility requires redirecting state to /tmp
	expectedEnvs := []string{
		"HOME=/tmp",
		"ZAP_HOME=/tmp/.ZAP",
		"JAVA_TOOL_OPTIONS=\"-Duser.home=/tmp\"",
	}
	for _, env := range expectedEnvs {
		if !strings.Contains(content, env) {
			t.Errorf("ZAP Dockerfile missing environment variable for read-only rootfs: %s", env)
		}
	}

	// Invariant 3: Working directory is /tmp
	if !strings.Contains(content, "WORKDIR /tmp") {
		t.Errorf("ZAP Dockerfile must set WORKDIR /tmp")
	}

	// Invariant 4: Default CMD executes zap-baseline.py with help
	if !strings.Contains(content, `CMD ["zap-baseline.py", "-h"]`) {
		t.Errorf("ZAP Dockerfile must declare CMD [\"zap-baseline.py\", \"-h\"]")
	}
}
