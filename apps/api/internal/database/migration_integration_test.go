package database

import (
	"errors"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"go.uber.org/zap"
)

// TestMigrationIntegrationAgainstDisposableDB verifies the full lifecycle
// of migrations against a live PostgreSQL instance when TEST_DATABASE_URL is provided.
func TestMigrationIntegrationAgainstDisposableDB(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("KELVIN_TEST_DATABASE_URL")
	}
	if dbURL == "" {
		t.Skip("skipping live database migration integration test: TEST_DATABASE_URL or KELVIN_TEST_DATABASE_URL is not set")
	}

	logger := zap.NewNop()
	migOpts := MigratorOptions{
		MigrationsPath: "../../db/migrations",
		DatabaseURL:    dbURL,
		Environment:    "testing",
	}

	migrator := NewMigratorWithOptions(migOpts, logger)

	// 1. Check initial version (nil or integer)
	initialV, dirty, err := migrator.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		t.Fatalf("failed to query initial migration version: %v", err)
	}
	if dirty {
		t.Fatalf("disposable test database is dirty at version %d; clean up required", initialV)
	}

	// 2. Run all migrations up
	if err := migrator.Up(); err != nil {
		t.Fatalf("migrator.Up() failed: %v", err)
	}

	// 3. Verify final applied version
	finalV, finalDirty, err := migrator.Version()
	if err != nil {
		t.Fatalf("failed to query post-migration version: %v", err)
	}
	if finalDirty {
		t.Fatalf("migrator completed in a dirty state at version %d", finalV)
	}
	if finalV == 0 {
		t.Fatalf("expected version > 0, got %d", finalV)
	}

	// 4. Test step rollback
	if err := migrator.Down(1); err != nil {
		t.Fatalf("migrator.Down(1) failed: %v", err)
	}
	rollbackV, rollbackDirty, err := migrator.Version()
	if err != nil {
		t.Fatalf("failed to query post-rollback version: %v", err)
	}
	if rollbackDirty {
		t.Fatalf("rollback left schema dirty: version %d", rollbackV)
	}
	if rollbackV != finalV-1 {
		t.Fatalf("expected rollback version %d, got %d", finalV-1, rollbackV)
	}

	// 5. Test disaster recovery Force
	if err := migrator.Force(int(rollbackV)); err != nil {
		t.Fatalf("migrator.Force(%d) failed: %v", rollbackV, err)
	}

	// 6. Migrate back up to latest
	if err := migrator.Up(); err != nil {
		t.Fatalf("re-migrating Up() failed: %v", err)
	}
	reupV, reupDirty, err := migrator.Version()
	if err != nil || reupDirty || reupV != finalV {
		t.Fatalf("expected version %d (dirty=false), got %d (dirty=%t), err: %v", finalV, reupV, reupDirty, err)
	}
}
