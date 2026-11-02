package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeDatabaseMigrations verifies that all migration files exist in matched up/down pairs,
// migration scripts implement advisory locks and timeouts, and operational documentation exists.
func TestSafeDatabaseMigrations(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	migrationsDir := filepath.Join(repoRoot, "apps", "api", "db", "migrations")

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("Failed to read migrations directory: %v", err)
	}

	upMigrations := make(map[string]bool)
	downMigrations := make(map[string]bool)

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			base := strings.TrimSuffix(name, ".up.sql")
			upMigrations[base] = true
		} else if strings.HasSuffix(name, ".down.sql") {
			base := strings.TrimSuffix(name, ".down.sql")
			downMigrations[base] = true
		}
	}

	// Verify every up migration has a matching down migration
	for base := range upMigrations {
		if !downMigrations[base] {
			t.Errorf("Migration %s.up.sql is missing matching down migration %s.down.sql", base, base)
		}
	}

	if len(upMigrations) < 50 {
		t.Errorf("Expected at least 50 migration files, found %d", len(upMigrations))
	}

	// 2. Verify migrate-production.sh implements advisory locks
	migrateScript := filepath.Join(repoRoot, "scripts", "database", "migrate-production.sh")
	data, err := os.ReadFile(migrateScript)
	if err != nil {
		t.Fatalf("Missing scripts/database/migrate-production.sh: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "pg_advisory_lock") {
		t.Errorf("migrate-production.sh must enforce pg_advisory_lock")
	}
	if !strings.Contains(content, "lock_timeout") {
		t.Errorf("migrate-production.sh must set lock_timeout")
	}

	// 3. Verify rollback-production.sh
	rollbackScript := filepath.Join(repoRoot, "scripts", "database", "rollback-production.sh")
	data, err = os.ReadFile(rollbackScript)
	if err != nil {
		t.Fatalf("Missing scripts/database/rollback-production.sh: %v", err)
	}
	rollbackContent := string(data)
	if !strings.Contains(rollbackContent, "pg_advisory_lock") {
		t.Errorf("rollback-production.sh must enforce pg_advisory_lock")
	}

	// 4. Verify operational documentation
	docPath := filepath.Join(repoRoot, "docs", "database", "SAFE_DATABASE_MIGRATION_AND_ROLLBACK.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing SAFE_DATABASE_MIGRATION_AND_ROLLBACK.md documentation")
	}
}
