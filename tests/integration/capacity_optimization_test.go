package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCapacityAndOptimization validates migration 000060, performance indexes,
// and the production capacity baseline documentation.
func TestCapacityAndOptimization(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify Migration 000060 Up & Down
	upPath := filepath.Join(repoRoot, "apps", "api", "db", "migrations", "000060_performance_indexing_and_capacity.up.sql")
	upData, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("Missing migration 000060 up: %v", err)
	}
	upContent := string(upData)

	expectedIndexes := []string{
		"idx_findings_tenant_severity_status_created",
		"idx_findings_tenant_assessment",
		"idx_evidence_finding_created",
		"idx_audit_log_tenant_timestamp",
		"idx_assessments_status_scheduled",
	}
	for _, idx := range expectedIndexes {
		if !strings.Contains(upContent, idx) {
			t.Errorf("Migration 000060 missing index definition: %s", idx)
		}
	}

	downPath := filepath.Join(repoRoot, "apps", "api", "db", "migrations", "000060_performance_indexing_and_capacity.down.sql")
	if _, err := os.Stat(downPath); os.IsNotExist(err) {
		t.Fatalf("Missing migration 000060 down: %v", downPath)
	}

	// 2. Verify Capacity Baseline Documentation
	docPath := filepath.Join(repoRoot, "docs", "performance", "PRODUCTION_CAPACITY_AND_PERFORMANCE_OPTIMIZATION.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("Missing PRODUCTION_CAPACITY_AND_PERFORMANCE_OPTIMIZATION.md: %v", err)
	}
	docContent := string(data)

	for _, req := range []string{"Small Tier", "Medium Tier", "Large Enterprise Tier", "Scalability Ceilings", "Migration 000060"} {
		if !strings.Contains(docContent, req) {
			t.Errorf("PRODUCTION_CAPACITY_AND_PERFORMANCE_OPTIMIZATION.md missing section: %s", req)
		}
	}
}
