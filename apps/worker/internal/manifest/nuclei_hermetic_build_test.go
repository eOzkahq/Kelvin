package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNucleiHermeticBuild_DockerfileStructure(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", "Dockerfile")
	contentBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Dockerfile: %v", err)
	}
	content := string(contentBytes)

	// 1. Must define multi-stage build: builder stage and distroless stage
	if !strings.Contains(content, "AS builder") {
		t.Errorf("Dockerfile missing 'AS builder' multi-stage compile stage")
	}

	// 2. Static compilation flags
	expectedFlags := []string{
		"CGO_ENABLED=0",
		"-trimpath",
		"-ldflags",
		"-s -w",
	}
	for _, flag := range expectedFlags {
		if !strings.Contains(content, flag) {
			t.Errorf("Dockerfile missing required hardened compiler flag %q", flag)
		}
	}

	// 3. User must be 10001:10001 in final stage
	if !strings.Contains(content, "USER 10001:10001") {
		t.Errorf("Dockerfile must enforce unprivileged non-root user 'USER 10001:10001'")
	}

	// 4. Entrypoint and templates
	if !strings.Contains(content, `ENTRYPOINT ["/nuclei", "-duc"]`) {
		t.Errorf("Dockerfile missing expected entrypoint")
	}
	if !strings.Contains(content, "/opt/kelvin/templates/kelvin.safe.web.v1") {
		t.Errorf("Dockerfile must copy curated Kelvin template catalog")
	}

	// 5. Global ARGs before first FROM instruction
	lines := strings.Split(content, "\n")
	firstFromIdx := -1
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToUpper(trimmed), "FROM ") {
			firstFromIdx = i
			break
		}
	}
	if firstFromIdx == -1 {
		t.Fatalf("no FROM instruction found")
	}
	globalScope := strings.Join(lines[:firstFromIdx], "\n")
	for _, requiredArg := range []string{"NUCLEI_SOURCE_IMAGE", "DISTROLESS_BASE_IMAGE"} {
		if !strings.Contains(globalScope, requiredArg) {
			t.Errorf("global scope before first FROM missing required ARG %q", requiredArg)
		}
	}
}

func TestNucleiHermeticBuild_ArtifactsAndBuildScript(t *testing.T) {
	nucleiDir := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei")

	// 1. Verify .dockerignore exists and covers sensitive files
	dockerignoreBytes, err := os.ReadFile(filepath.Join(nucleiDir, ".dockerignore"))
	if err != nil {
		t.Fatalf("missing .dockerignore in deploy/scanners/nuclei: %v", err)
	}
	dockerignore := string(dockerignoreBytes)
	for _, expectedPattern := range []string{".git", "*.md", "build.sh"} {
		if !strings.Contains(dockerignore, expectedPattern) {
			t.Errorf(".dockerignore missing pattern %q", expectedPattern)
		}
	}

	// 2. Verify build.sh exists and references source.env
	buildScriptBytes, err := os.ReadFile(filepath.Join(nucleiDir, "build.sh"))
	if err != nil {
		t.Fatalf("missing build.sh in deploy/scanners/nuclei: %v", err)
	}
	buildScript := string(buildScriptBytes)
	if !strings.Contains(buildScript, "source.env") {
		t.Errorf("build.sh must source source.env for pinned toolchain")
	}
	if !strings.Contains(buildScript, "docker buildx build") {
		t.Errorf("build.sh must execute docker buildx build")
	}
}
