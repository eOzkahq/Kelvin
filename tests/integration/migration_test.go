package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestDatabaseMigrationLifecycle(t *testing.T) {
	dbURL := os.Getenv("KELVIN_DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping migration lifecycle integration test: KELVIN_DATABASE_URL not set")
	}

	// Resolve path to migrations
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}

	migrationsDir := filepath.Join(cwd, "..", "..", "apps", "api", "db", "migrations")
	sourceURL := "file://" + filepath.ToSlash(migrationsDir)

	m, err := migrate.New(sourceURL, dbURL)
	if err != nil {
		t.Fatalf("failed to create migrate instance: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	// 1. Run migrations up
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migration Up failed: %v", err)
	}

	version, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("failed to get migration version: %v", err)
	}
	if dirty {
		t.Fatalf("database is in a dirty migration state at version %d", version)
	}
	t.Logf("Database migrated up to version %d (clean)", version)

	// 2. Test down migration rollback (single step)
	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migration rollback step failed: %v", err)
	}
	t.Log("Successfully rolled back migration 1 step")

	// 3. Re-apply up to restore state
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("re-applying Up after rollback failed: %v", err)
	}
	t.Log("Successfully restored schema up to latest version")
}

