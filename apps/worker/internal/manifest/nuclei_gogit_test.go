package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNucleiGoGitRemediation_PatchAndModInvariants(t *testing.T) {
	nucleiDir := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei")

	// 1. Verify patches/go-git.patch exists and contains CVE-2026-71556 fix
	patchPath := filepath.Join(nucleiDir, "patches", "go-git.patch")
	patchBytes, err := os.ReadFile(patchPath)
	if err != nil {
		t.Fatalf("failed to read go-git.patch: %v", err)
	}
	patchContent := string(patchBytes)

	if !strings.Contains(patchContent, "CVE-2026-71556") {
		t.Errorf("go-git.patch missing CVE-2026-71556 reference")
	}
	if !strings.Contains(patchContent, "github.com/go-git/go-git/v5") {
		t.Errorf("go-git.patch missing target module github.com/go-git/go-git/v5")
	}
	if !strings.Contains(patchContent, "v5.14.0") {
		t.Errorf("go-git.patch must pin to patched release v5.14.0")
	}

	// 2. Verify deploy/scanners/nuclei/go.mod exists and contains fixed require/replace
	goModPath := filepath.Join(nucleiDir, "go.mod")
	goModBytes, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("failed to read deploy/scanners/nuclei/go.mod: %v", err)
	}
	goModContent := string(goModBytes)

	if !strings.Contains(goModContent, "github.com/go-git/go-git/v5 v5.14.0") {
		t.Errorf("deploy/scanners/nuclei/go.mod missing require for v5.14.0")
	}
	if !strings.Contains(goModContent, "replace github.com/go-git/go-git/v5 => github.com/go-git/go-git/v5 v5.14.0") {
		t.Errorf("deploy/scanners/nuclei/go.mod missing replace directive for v5.14.0")
	}

	// 3. Verify deploy/scanners/nuclei/go.sum exists and contains valid module checksums
	goSumPath := filepath.Join(nucleiDir, "go.sum")
	goSumBytes, err := os.ReadFile(goSumPath)
	if err != nil {
		t.Fatalf("failed to read deploy/scanners/nuclei/go.sum: %v", err)
	}
	goSumContent := string(goSumBytes)

	if !strings.Contains(goSumContent, "github.com/go-git/go-git/v5 v5.14.0") {
		t.Errorf("deploy/scanners/nuclei/go.sum missing checksum for v5.14.0")
	}
	if !strings.Contains(goSumContent, "h1:/MD3lCrGjCen5WfEAzKg00MJJffKhC8gzS80ycmCi60=") {
		t.Errorf("deploy/scanners/nuclei/go.sum missing verified checksum for v5.14.0")
	}

	// 4. Verify Dockerfile copies and executes patch
	dockerfilePath := filepath.Join(nucleiDir, "Dockerfile")
	dockerfileBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Dockerfile: %v", err)
	}
	dockerfileContent := string(dockerfileBytes)

	if !strings.Contains(dockerfileContent, "COPY deploy/scanners/nuclei/patches /src/patches") {
		t.Errorf("Dockerfile missing COPY for dependency patches")
	}
	if !strings.Contains(dockerfileContent, "go-git.patch") {
		t.Errorf("Dockerfile missing application step for go-git.patch")
	}
}
