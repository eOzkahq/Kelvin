package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionReadiness_ArtifactCompleteness(t *testing.T) {
	repoRoot := filepath.Join("..", "..")

	requiredArtifacts := []string{
		"docs/architecture/PRODUCTION_DEPLOYMENT_ARCHITECTURE.md",
		"infra/terraform/environments/prod/main.tf",
		"deploy/kubernetes/base/api-deployment.yaml",
		"deploy/kubernetes/base/worker-deployment.yaml",
		"deploy/ingress/nginx-ingress.conf",
		"deploy/postgres/hardening.sql",
		"docs/security/SECRETS_AND_CRYPTOGRAPHIC_KEY_MANAGEMENT.md",
		".github/workflows/ci.yml",
		"docs/release/CI_QUALITY_AND_VERIFICATION_GATES.md",
		"scripts/release/generate-sbom.sh",
		"docs/release/STAGED_DEPLOYMENT_AND_ENVIRONMENT_PROMOTION.md",
		"scripts/release/smoke-test.sh",
		"docs/database/SAFE_DATABASE_MIGRATION_AND_ROLLBACK.md",
		"packages/common/tracing/tracing.go",
		"deploy/monitoring/alerts/kelvin-slo-alerts.yml",
		"docs/operations/INCIDENT_RESPONSE_FRAMEWORK.md",
		"scripts/backup/verify-backup-integrity.sh",
		"scripts/backup/restore-database.sh",
		"scripts/testing/run-load-stress-tests.sh",
		"docs/performance/PRODUCTION_CAPACITY_AND_PERFORMANCE_OPTIMIZATION.md",
		"docs/security/INDEPENDENT_SECURITY_ASSESSMENT_REPORT.md",
		"docs/security/VULNERABILITY_MANAGEMENT_AND_PATCH_GOVERNANCE.md",
		"docs/release/PRODUCTION_READINESS_REVIEW_AND_RELEASE_DECISION.md",
		"docs/release/RELEASE_NOTES_v1.0.0.md",
	}

	for _, relPath := range requiredArtifacts {
		fullPath := filepath.Join(repoRoot, relPath)
		info, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("Required production readiness artifact missing: %s", relPath)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("Required production readiness artifact is empty: %s", relPath)
		}
	}
}

func TestProductionReadiness_SignOffAuthorization(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	prrPath := filepath.Join(repoRoot, "docs", "release", "PRODUCTION_READINESS_REVIEW_AND_RELEASE_DECISION.md")

	contentBytes, err := os.ReadFile(prrPath)
	if err != nil {
		t.Fatalf("Failed to read PRR document: %v", err)
	}
	content := string(contentBytes)

	requiredSignOffs := []string{
		"Principal Platform Architect",
		"Head of Information Security",
		"Site Reliability & Operations Lead",
		"Quality Engineering Gate Officer",
		"VP of Product & Engineering",
	}

	for _, role := range requiredSignOffs {
		if !strings.Contains(content, role) {
			t.Errorf("PRR document missing sign-off entry for: %s", role)
		}
	}

	if !strings.Contains(content, "GO — AUTHORIZED FOR PRODUCTION LAUNCH") {
		t.Errorf("PRR document missing explicit GO authorization decision")
	}
}

func TestProductionReadiness_ReleaseNotesVersion(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	rnPath := filepath.Join(repoRoot, "docs", "release", "RELEASE_NOTES_v1.0.0.md")

	contentBytes, err := os.ReadFile(rnPath)
	if err != nil {
		t.Fatalf("Failed to read Release Notes: %v", err)
	}
	content := string(contentBytes)

	if !strings.Contains(content, "v1.0.0") {
		t.Errorf("Release Notes missing version identifier v1.0.0")
	}
	if !strings.Contains(content, "General Availability (GA)") {
		t.Errorf("Release Notes missing GA status designation")
	}
}

func TestProductionReadiness_MigrationParity(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	migrationsDir := filepath.Join(repoRoot, "apps", "api", "db", "migrations")

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("Failed to read migrations directory: %v", err)
	}

	upCount := 0
	downCount := 0

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			upCount++
		}
		if strings.HasSuffix(entry.Name(), ".down.sql") {
			downCount++
		}
	}

	if upCount == 0 {
		t.Fatalf("Expected migrations, found 0")
	}

	if upCount != downCount {
		t.Errorf("Migration parity mismatch: found %d .up.sql vs %d .down.sql files", upCount, downCount)
	}

	t.Logf("Verified %d matching up/down migration pairs.", upCount)
}
