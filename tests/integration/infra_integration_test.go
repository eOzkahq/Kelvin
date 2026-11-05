package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInfraIntegration verifies the Redis 7+ and Supabase architecture integration contracts,
// configurations, environment mappings, and operational runbooks.
func TestInfraIntegration(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify Docker Compose contains Redis 7 service with healthcheck
	composePath := filepath.Join(repoRoot, "docker-compose.yml")
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.yml: %v", err)
	}
	composeStr := string(composeData)
	if !strings.Contains(composeStr, "redis:") {
		t.Errorf("docker-compose.yml must define a redis service")
	}
	if !strings.Contains(composeStr, "redis:7-alpine") {
		t.Errorf("docker-compose.yml must use redis:7-alpine")
	}
	if !strings.Contains(composeStr, "appendonly yes") {
		t.Errorf("docker-compose.yml redis service must enable appendonly")
	}

	// 2. Verify .env.example contains REDIS_URL and SUPABASE variables
	envPath := filepath.Join(repoRoot, ".env.example")
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("Failed to read .env.example: %v", err)
	}
	envStr := string(envData)
	expectedVars := []string{
		"REDIS_URL",
		"REDIS_POOL_SIZE",
		"SUPABASE_URL",
		"SUPABASE_SERVICE_ROLE_KEY",
		"SUPABASE_DB_HOST",
		"SUPABASE_STORAGE_BUCKET_REPORTS",
		"SUPABASE_STORAGE_BUCKET_EVIDENCE",
	}
	for _, v := range expectedVars {
		if !strings.Contains(envStr, v) {
			t.Errorf(".env.example missing variable definition: %s", v)
		}
	}

	// 3. Verify ADR-0006 exists and documents Redis & Supabase integration
	adrPath := filepath.Join(repoRoot, "docs", "architecture", "decisions", "ADR-0006-redis-supabase-integration.md")
	adrData, err := os.ReadFile(adrPath)
	if err != nil {
		t.Fatalf("Missing ADR-0006: %v", err)
	}
	adrStr := string(adrData)
	if !strings.Contains(adrStr, "Redis 7+") || !strings.Contains(adrStr, "Supabase") {
		t.Errorf("ADR-0006 must document Redis 7+ and Supabase architecture")
	}

	// 4. Verify Architecture and Deployment Documentation Deliverables
	docs := []string{
		"docs/architecture/redis-integration.md",
		"docs/architecture/supabase-integration.md",
		"docs/deployment/redis-setup.md",
		"docs/deployment/supabase-setup.md",
		"docs/deployment/production-configuration.md",
		"docs/operations/backup-and-recovery.md",
		"docs/operations/queue-failure-recovery.md",
	}
	for _, doc := range docs {
		p := filepath.Join(repoRoot, doc)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("Missing required documentation file: %s", doc)
		}
	}

	// 5. Verify Milestone tracking document
	milestonePath := filepath.Join(repoRoot, ".github", "issues", "MILESTONE_INFRASTRUCTURE.md")
	milestoneData, err := os.ReadFile(milestonePath)
	if err != nil {
		t.Fatalf("Missing MILESTONE_INFRASTRUCTURE.md: %v", err)
	}
	milestoneStr := string(milestoneData)
	if !strings.Contains(milestoneStr, "[x] [INFRA-01: Implement Redis & Supabase Infrastructure Integration]") {
		t.Errorf("MILESTONE_INFRASTRUCTURE.md must mark INFRA-01 as checked")
	}
}
