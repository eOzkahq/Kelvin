package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrontendArchitecture_IssueIntegrity(t *testing.T) {
	repoRoot := filepath.Join("..", "..")

	// 1. Verify Milestone Document
	milestonePath := filepath.Join(repoRoot, ".github", "issues", "MILESTONE_FRONTEND.md")
	milestoneBytes, err := os.ReadFile(milestonePath)
	if err != nil {
		t.Fatalf("Missing MILESTONE_FRONTEND.md: %v", err)
	}
	milestoneContent := string(milestoneBytes)

	// 2. Verify FE-EPIC-01
	epicPath := filepath.Join(repoRoot, ".github", "issues", "frontend", "FE-EPIC-01_DESIGN_AND_IMPLEMENT_COMPLETE_KELVIN_FRONTEND_APPLICATION.md")
	if _, err := os.Stat(epicPath); err != nil {
		t.Errorf("Missing FE-EPIC-01 markdown file: %v", err)
	}

	// 3. Verify FE-01 through FE-24 child issues exist
	for i := 1; i <= 24; i++ {
		prefix := fmt.Sprintf("FE-%02d", i)
		if !strings.Contains(milestoneContent, prefix) {
			t.Errorf("MILESTONE_FRONTEND.md missing reference to %s", prefix)
		}

		matches, err := filepath.Glob(filepath.Join(repoRoot, ".github", "issues", "frontend", prefix+"_*.md"))
		if err != nil || len(matches) == 0 {
			t.Errorf("Missing issue definition file for %s in .github/issues/frontend/", prefix)
		}
	}
}

func TestFrontendArchitecture_ContractMapping(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	docPath := filepath.Join(repoRoot, "docs", "architecture", "FRONTEND_ARCHITECTURE_AND_API_CONTRACT_MAPPING.md")

	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("Missing FRONTEND_ARCHITECTURE_AND_API_CONTRACT_MAPPING.md: %v", err)
	}
	content := string(docBytes)

	expectedSections := []string{
		"/api/v1/auth/login",
		"/api/v1/dashboard/overview",
		"/api/v1/assessments",
		"/api/v1/findings",
		"/api/v1/remediations",
		"/api/v1/targets",
		"/api/v1/reports/generate",
		"Zero Client Secrets",
		"DOMPurify Evidence Sanitizer",
		"/services/kelvin",
	}

	for _, sec := range expectedSections {
		if !strings.Contains(content, sec) {
			t.Errorf("Frontend contract mapping document missing required entry: %s", sec)
		}
	}
}

func TestFrontendArchitecture_WebDependencies(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	pkgJsonPath := filepath.Join(repoRoot, "apps", "web", "package.json")

	pkgBytes, err := os.ReadFile(pkgJsonPath)
	if err != nil {
		t.Fatalf("Failed to read apps/web/package.json: %v", err)
	}
	content := string(pkgBytes)

	requiredDeps := []string{
		"react",
		"react-dom",
		"@tanstack/react-query",
		"react-router-dom",
		"typescript",
		"vite",
	}

	for _, dep := range requiredDeps {
		if !strings.Contains(content, dep) {
			t.Errorf("apps/web/package.json missing required dependency: %s", dep)
		}
	}
}
