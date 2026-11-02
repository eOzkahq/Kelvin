package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDisasterRecoveryProcedures verifies the disaster recovery scripts,
// interrupted assessment reconciliation logic, and documented recovery metrics.
func TestDisasterRecoveryProcedures(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify restore-database.sh script
	restoreScript := filepath.Join(repoRoot, "scripts", "backup", "restore-database.sh")
	data, err := os.ReadFile(restoreScript)
	if err != nil {
		t.Fatalf("Missing scripts/backup/restore-database.sh: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "restore-db-instance") {
		t.Errorf("restore-database.sh must invoke RDS restoration command")
	}

	// 2. Verify reconcile-disaster-state.sh script
	reconcileScript := filepath.Join(repoRoot, "scripts", "backup", "reconcile-disaster-state.sh")
	data, err = os.ReadFile(reconcileScript)
	if err != nil {
		t.Fatalf("Missing scripts/backup/reconcile-disaster-state.sh: %v", err)
	}
	reconContent := string(data)

	if !strings.Contains(reconContent, "DISASTER_RECOVERY_ABORT") {
		t.Errorf("reconcile-disaster-state.sh must mark active assessments with DISASTER_RECOVERY_ABORT")
	}
	if !strings.Contains(reconContent, "assessment_concurrency_locks") {
		t.Errorf("reconcile-disaster-state.sh must clear stale concurrency locks")
	}

	// 3. Verify Operational Documentation
	docPath := filepath.Join(repoRoot, "docs", "operations", "DISASTER_RECOVERY_AND_RESTORE_PROCEDURES.md")
	data, err = os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("Missing DISASTER_RECOVERY_AND_RESTORE_PROCEDURES.md: %v", err)
	}
	docContent := string(data)

	for _, req := range []string{"Recovery Point Objective", "Recovery Time Objective", "Failback Procedure", "Drill Evidence"} {
		if !strings.Contains(docContent, req) {
			t.Errorf("DISASTER_RECOVERY_AND_RESTORE_PROCEDURES.md missing required section: %s", req)
		}
	}
}
