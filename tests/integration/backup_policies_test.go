package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAutomatedBackupPolicies validates that automated backup policies,
// integrity verification scripts, and RPO/RTO targets conform to Phase 5 requirements.
func TestAutomatedBackupPolicies(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify Backup Policy Manifest
	policyPath := filepath.Join(repoRoot, "deploy", "backup", "backup-policy.yaml")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("Missing deploy/backup/backup-policy.yaml: %v", err)
	}
	content := string(data)

	requiredElements := []string{
		"continuous_wal_archiving",
		"rpo_target_minutes",
		"rto_target_minutes",
		"object_lock_worm",
		"COMPLIANCE",
		"cross_region_replication",
	}
	for _, elem := range requiredElements {
		if !strings.Contains(content, elem) {
			t.Errorf("backup-policy.yaml missing required element: %s", elem)
		}
	}

	// 2. Verify Backup Integrity Script
	scriptPath := filepath.Join(repoRoot, "scripts", "backup", "verify-backup-integrity.sh")
	data, err = os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Missing scripts/backup/verify-backup-integrity.sh: %v", err)
	}
	scriptContent := string(data)

	if !strings.Contains(scriptContent, "Snapshot") {
		t.Errorf("verify-backup-integrity.sh must check snapshot status")
	}
	if !strings.Contains(scriptContent, "WAL") {
		t.Errorf("verify-backup-integrity.sh must check WAL archive")
	}

	// 3. Verify Operational Documentation
	docPath := filepath.Join(repoRoot, "docs", "operations", "AUTOMATED_PRODUCTION_BACKUP_POLICIES.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing AUTOMATED_PRODUCTION_BACKUP_POLICIES.md documentation")
	}
}
