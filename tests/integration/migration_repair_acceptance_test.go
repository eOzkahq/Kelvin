package integration

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// TestMigrationFilenamePairingAndOrdering verifies Test Requirement 1:
// All migration files exist in matched up/down pairs with strictly monotonic numbering.
func TestMigrationFilenamePairingAndOrdering(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	migrationsDir := filepath.Join(repoRoot, "apps", "api", "db", "migrations")

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("failed to read migrations directory: %v", err)
	}

	upMigrations := make(map[int]string)
	downMigrations := make(map[int]string)

	re := regexp.MustCompile(`^(\d{6})_([a-zA-Z0-9_-]+)\.(up|down)\.sql$`)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := re.FindStringSubmatch(entry.Name())
		if len(matches) != 4 {
			t.Errorf("migration file does not conform to 6-digit naming standard: %s", entry.Name())
			continue
		}

		ver, _ := strconv.Atoi(matches[1])
		name := matches[2]
		direction := matches[3]

		if direction == "up" {
			if _, exists := upMigrations[ver]; exists {
				t.Errorf("duplicate up migration version %06d: %s", ver, entry.Name())
			}
			upMigrations[ver] = name
		} else {
			if _, exists := downMigrations[ver]; exists {
				t.Errorf("duplicate down migration version %06d: %s", ver, entry.Name())
			}
			downMigrations[ver] = name
		}
	}

	// Verify all up migrations have matching down migrations with exact same name
	for ver, name := range upMigrations {
		downName, exists := downMigrations[ver]
		if !exists {
			t.Errorf("migration %06d_%s.up.sql is missing matching down migration", ver, name)
		} else if downName != name {
			t.Errorf("migration %06d name mismatch: up has '%s', down has '%s'", ver, name, downName)
		}
	}

	// Verify all down migrations have matching up migrations
	for ver, name := range downMigrations {
		if _, exists := upMigrations[ver]; !exists {
			t.Errorf("migration %06d_%s.down.sql is missing matching up migration", ver, name)
		}
	}

	// Verify sequential monotonicity without gaps from 1 to 61
	if len(upMigrations) < 61 {
		t.Errorf("expected at least 61 migrations, found %d", len(upMigrations))
	}

	var versions []int
	for v := range upMigrations {
		versions = append(versions, v)
	}
	sort.Ints(versions)

	for i, v := range versions {
		expectedVer := i + 1
		if v != expectedVer {
			t.Errorf("migration gap or ordering issue: expected %06d, found %06d", expectedVer, v)
		}
	}
}

// TestUpDownSQLConsistency verifies Test Requirement 3:
// Ensures 000060 and 000061 up/down SQL symmetry and clean rollback properties.
func TestUpDownSQLConsistency(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify 000060 consistency
	m60UpPath := filepath.Join(repoRoot, "apps", "api", "db", "migrations", "000060_performance_indexing_and_capacity.up.sql")
	m60DownPath := filepath.Join(repoRoot, "apps", "api", "db", "migrations", "000060_performance_indexing_and_capacity.down.sql")

	up60Bytes, err := os.ReadFile(m60UpPath)
	if err != nil {
		t.Fatalf("failed reading 000060 up: %v", err)
	}
	down60Bytes, err := os.ReadFile(m60DownPath)
	if err != nil {
		t.Fatalf("failed reading 000060 down: %v", err)
	}

	up60 := string(up60Bytes)
	down60 := string(down60Bytes)

	idxRegex := regexp.MustCompile(`CREATE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)`)
	dropRegex := regexp.MustCompile(`DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?([a-zA-Z0-9_]+)`)

	var createdIndexes []string
	for _, match := range idxRegex.FindAllStringSubmatch(up60, -1) {
		createdIndexes = append(createdIndexes, match[1])
	}

	var droppedIndexes []string
	for _, match := range dropRegex.FindAllStringSubmatch(down60, -1) {
		droppedIndexes = append(droppedIndexes, match[1])
	}

	if len(createdIndexes) != 5 {
		t.Errorf("expected 5 created indexes in 000060 up, found %d: %v", len(createdIndexes), createdIndexes)
	}
	if len(droppedIndexes) != 5 {
		t.Errorf("expected 5 dropped indexes in 000060 down, found %d: %v", len(droppedIndexes), droppedIndexes)
	}

	for _, idx := range createdIndexes {
		found := false
		for _, dropIdx := range droppedIndexes {
			if idx == dropIdx {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("index %s created in 000060 up is NOT dropped in 000060 down", idx)
		}
	}

	// 2. Verify 000061 consistency
	m61UpPath := filepath.Join(repoRoot, "apps", "api", "db", "migrations", "000061_standardize_tenant_rls_and_job_store.up.sql")
	m61DownPath := filepath.Join(repoRoot, "apps", "api", "db", "migrations", "000061_standardize_tenant_rls_and_job_store.down.sql")

	up61Bytes, err := os.ReadFile(m61UpPath)
	if err != nil {
		t.Fatalf("failed reading 000061 up: %v", err)
	}
	down61Bytes, err := os.ReadFile(m61DownPath)
	if err != nil {
		t.Fatalf("failed reading 000061 down: %v", err)
	}

	up61 := string(up61Bytes)
	down61 := string(down61Bytes)

	// Ensure no invalid table references exist
	if strings.Contains(up61, "remediation_notes") {
		t.Errorf("000061 up contains invalid table reference 'remediation_notes'")
	}
	if !strings.Contains(up61, "remediation_updates") {
		t.Errorf("000061 up missing corrected table reference 'remediation_updates'")
	}

	// Verify rollback unforces the newly forced tables
	expectedNoForce := []string{
		"finding_risk_history",
		"finding_evidence_links",
		"remediation_tasks",
		"remediation_updates",
		"report_snapshots",
		"report_artifacts",
	}
	for _, tbl := range expectedNoForce {
		expectedStmt := fmt.Sprintf("ALTER TABLE %s NO FORCE ROW LEVEL SECURITY;", tbl)
		if !strings.Contains(down61, expectedStmt) {
			t.Errorf("000061 down missing statement: %s", expectedStmt)
		}
	}
}

// TestMigrationExecutionAndTenantIsolation verifies Requirements 4, 5, 6, 7 & 8:
// - Tests full migration against disposable PostgreSQL
// - Verifies table and column existence at version 60 and 61
// - Tests rollback and re-application
// - Verifies RLS enforcement and tenant isolation with two test tenants
func TestMigrationExecutionAndTenantIsolation(t *testing.T) {
	dbURL := os.Getenv("KELVIN_DATABASE_URL")
	if dbURL == "" {
		t.Skip("skipping database test: KELVIN_DATABASE_URL not set")
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	migrationsDir := filepath.Join(repoRoot, "apps", "api", "db", "migrations")
	sourceURL := "file://" + filepath.ToSlash(migrationsDir)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("database ping failed: %v", err)
	}

	// 1. Execute migrations up to 61
	m, err := migrate.New(sourceURL, dbURL)
	if err != nil {
		t.Fatalf("migrate.New failed: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migration Up failed: %v", err)
	}

	v, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("m.Version failed: %v", err)
	}
	if dirty {
		t.Fatalf("database is dirty at version %d", v)
	}
	if v != 61 {
		t.Fatalf("expected version 61, got %d", v)
	}
	t.Logf("Successfully applied all 61 migrations (version %d, clean)", v)

	// 2. Verify all 5 performance indexes from 000060 exist
	expectedIndexes := []string{
		"idx_findings_tenant_severity_status_created",
		"idx_findings_tenant_assessment",
		"idx_evidence_finding_created",
		"idx_audit_log_tenant_timestamp",
		"idx_assessments_status_scheduled",
	}
	for _, idxName := range expectedIndexes {
		var exists bool
		err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = $1)`, idxName).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("expected performance index %s does NOT exist in pg_indexes", idxName)
		}
	}

	// 3. Verify FORCE ROW LEVEL SECURITY on all 18 tables
	tenantTables := []string{
		"tenants", "users", "auth_sessions", "scan_profiles", "assets", "assessments",
		"jobs", "findings", "finding_events", "evidence", "reports", "finding_observations",
		"finding_risk_history", "finding_evidence_links", "remediation_tasks",
		"remediation_updates", "report_snapshots", "report_artifacts",
	}
	for _, tbl := range tenantTables {
		var rowSecurity, forceRowSecurity bool
		err := db.QueryRow(`
			SELECT c.relrowsecurity, c.relforcerowsecurity
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tbl).Scan(&rowSecurity, &forceRowSecurity)
		if err != nil {
			t.Errorf("failed querying RLS status for table %s: %v", tbl, err)
			continue
		}
		if !rowSecurity {
			t.Errorf("table %s does NOT have ROW LEVEL SECURITY enabled", tbl)
		}
		if !forceRowSecurity {
			t.Errorf("table %s does NOT have FORCE ROW LEVEL SECURITY enabled at version 61", tbl)
		}
	}

	// 4. Test Rollback step -1 (revert 000061)
	if err := m.Steps(-1); err != nil {
		t.Fatalf("rollback step -1 (000061) failed: %v", err)
	}
	v, dirty, err = m.Version()
	if err != nil || dirty || v != 60 {
		t.Fatalf("rollback step -1 failed: version=%d dirty=%t err=%v", v, dirty, err)
	}
	t.Log("Successfully rolled back migration 000061 to version 60")

	// Verify that the 6 tables newly forced in 000061 now have forcerowsecurity = false
	unforcedTables := []string{
		"finding_risk_history", "finding_evidence_links", "remediation_tasks",
		"remediation_updates", "report_snapshots", "report_artifacts",
	}
	for _, tbl := range unforcedTables {
		var forceRowSecurity bool
		_ = db.QueryRow(`
			SELECT c.relforcerowsecurity
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tbl).Scan(&forceRowSecurity)
		if forceRowSecurity {
			t.Errorf("table %s still has FORCE ROW LEVEL SECURITY after 000061 rollback", tbl)
		}
	}

	// Verify original tables STILL retain forcerowsecurity = true
	preservedTables := []string{"tenants", "users", "findings", "assessments", "jobs"}
	for _, tbl := range preservedTables {
		var forceRowSecurity bool
		_ = db.QueryRow(`
			SELECT c.relforcerowsecurity
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tbl).Scan(&forceRowSecurity)
		if !forceRowSecurity {
			t.Errorf("original table %s lost FORCE ROW LEVEL SECURITY after 000061 rollback", tbl)
		}
	}

	// 5. Test Rollback step -1 (revert 000060)
	if err := m.Steps(-1); err != nil {
		t.Fatalf("rollback step -1 (000060) failed: %v", err)
	}
	v, dirty, err = m.Version()
	if err != nil || dirty || v != 59 {
		t.Fatalf("rollback step -1 failed: version=%d dirty=%t err=%v", v, dirty, err)
	}
	t.Log("Successfully rolled back migration 000060 to version 59")

	// Verify the 5 performance indexes are dropped
	for _, idxName := range expectedIndexes {
		var exists bool
		_ = db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = $1)`, idxName).Scan(&exists)
		if exists {
			t.Errorf("index %s still exists after 000060 rollback", idxName)
		}
	}

	// 6. Re-apply up to 61
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("re-applying Up after rollback failed: %v", err)
	}
	v, dirty, err = m.Version()
	if err != nil || dirty || v != 61 {
		t.Fatalf("restoration failed: version=%d dirty=%t err=%v", v, dirty, err)
	}
	t.Log("Successfully restored schema up to version 61")

	// 7. Verify RLS Enforcement and Multi-Tenant Isolation with kelvin_app role
	// Set up kelvin_app role
	_, _ = db.Exec(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kelvin_app') THEN
				CREATE ROLE kelvin_app WITH LOGIN NOINHERIT;
			END IF;
		END $$;
		GRANT USAGE ON SCHEMA public TO kelvin_app;
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO kelvin_app;
		GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO kelvin_app;
	`)

	tenantA := uuid.New()
	tenantB := uuid.New()
	projectA := uuid.New()
	projectB := uuid.New()
	findingA := uuid.New()

	// Seed Tenant A and Tenant B data
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx failed: %v", err)
	}
	_, _ = tx.Exec(`SET LOCAL ROLE kelvin_app`)

	// Insert Tenant A
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true), set_config('app.tenant_id', $1, true)`, tenantA.String())
	if _, err := tx.Exec(`INSERT INTO tenants(id, name, slug) VALUES($1, $2, $3)`, tenantA, "Tenant A", "t-a-"+tenantA.String()[:8]); err != nil {
		_ = tx.Rollback()
		t.Fatalf("failed inserting Tenant A: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO projects(id, tenant_id, name) VALUES($1, $2, $3)`, projectA, tenantA, "Project A"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("failed inserting Project A: %v", err)
	}

	// Insert Tenant B
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true), set_config('app.tenant_id', $1, true)`, tenantB.String())
	if _, err := tx.Exec(`INSERT INTO tenants(id, name, slug) VALUES($1, $2, $3)`, tenantB, "Tenant B", "t-b-"+tenantB.String()[:8]); err != nil {
		_ = tx.Rollback()
		t.Fatalf("failed inserting Tenant B: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO projects(id, tenant_id, name) VALUES($1, $2, $3)`, projectB, tenantB, "Project B"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("failed inserting Project B: %v", err)
	}

	// Insert scan_profile, assessment, job, finding for Tenant A
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true), set_config('app.tenant_id', $1, true)`, tenantA.String())
	scanProfileA := uuid.New()
	_, err = tx.Exec(`INSERT INTO scan_profiles(id, tenant_id, profile_id, version, definition) VALUES($1, $2, $3, $4, '{}'::jsonb)`, scanProfileA, tenantA, "prof-1", "1.0")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert scan profile failed: %v", err)
	}

	assessmentA := uuid.New()
	_, err = tx.Exec(`INSERT INTO assessments(id, tenant_id, project_id, name, profile_id, profile_snapshot, correlation_id) VALUES($1, $2, $3, $4, $5, '{}'::jsonb, $6)`,
		assessmentA, tenantA, projectA, "Assessment A", scanProfileA, uuid.New())
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert assessment failed: %v", err)
	}

	jobA := uuid.New()
	_, err = tx.Exec(`INSERT INTO jobs(id, tenant_id, assessment_id, correlation_id) VALUES($1, $2, $3, $4)`,
		jobA, tenantA, assessmentA, uuid.New())
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert job failed: %v", err)
	}

	fingerprintA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, err = tx.Exec(`
		INSERT INTO findings(
			id, tenant_id, project_id, assessment_id, job_id, fingerprint, title,
			severity, confidence, status, first_seen_at, last_seen_at, first_job_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'HIGH', 0.950, 'OPEN', now(), now(), $5)
	`, findingA, tenantA, projectA, assessmentA, jobA, fingerprintA, "Test SQL Injection")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert finding failed: %v", err)
	}

	// Insert remediation task and update for Tenant A
	remTaskA := uuid.New()
	_, err = tx.Exec(`INSERT INTO remediation_tasks(id, tenant_id, finding_id, title) VALUES($1, $2, $3, 'Fix SQLi')`, remTaskA, tenantA, findingA)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert remediation task failed: %v", err)
	}

	remUpdateA := uuid.New()
	_, err = tx.Exec(`INSERT INTO remediation_updates(id, tenant_id, task_id, author_id, previous_state, new_state) VALUES($1, $2, $3, 'analyst-1', 'OPEN', 'IN_PROGRESS')`, remUpdateA, tenantA, remTaskA)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert remediation update failed: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed data failed: %v", err)
	}

	// --- Multi-Tenant Isolation Verifications ---

	// Assertion 1: Tenant A can read its own finding and remediation updates
	txA, err := db.Begin()
	if err != nil {
		t.Fatalf("begin txA failed: %v", err)
	}
	defer txA.Rollback()
	_, _ = txA.Exec(`SET LOCAL ROLE kelvin_app`)
	_, _ = txA.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantA.String())

	var readTitle string
	err = txA.QueryRow(`SELECT title FROM findings WHERE id = $1`, findingA).Scan(&readTitle)
	if err != nil || readTitle != "Test SQL Injection" {
		t.Fatalf("Tenant A could not read its own finding: %v", err)
	}

	var updateCount int
	_ = txA.QueryRow(`SELECT COUNT(*) FROM remediation_updates WHERE id = $1`, remUpdateA).Scan(&updateCount)
	if updateCount != 1 {
		t.Fatalf("Tenant A expected 1 remediation update, got %d", updateCount)
	}

	// Assertion 2: Tenant B CANNOT read Tenant A's finding or remediation updates
	txB, err := db.Begin()
	if err != nil {
		t.Fatalf("begin txB failed: %v", err)
	}
	defer txB.Rollback()
	_, _ = txB.Exec(`SET LOCAL ROLE kelvin_app`)
	_, _ = txB.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantB.String())

	var tenantBVisibleCount int
	_ = txB.QueryRow(`SELECT COUNT(*) FROM findings WHERE id = $1`, findingA).Scan(&tenantBVisibleCount)
	if tenantBVisibleCount != 0 {
		t.Fatalf("CRITICAL SECURITY FAILURE: Tenant B was able to view Tenant A finding (visible rows: %d)", tenantBVisibleCount)
	}

	_ = txB.QueryRow(`SELECT COUNT(*) FROM remediation_updates WHERE id = $1`, remUpdateA).Scan(&tenantBVisibleCount)
	if tenantBVisibleCount != 0 {
		t.Fatalf("CRITICAL SECURITY FAILURE: Tenant B was able to view Tenant A remediation update")
	}

	// Assertion 3: Tenant B CANNOT mutate or delete Tenant A's finding
	res, err := txB.Exec(`UPDATE findings SET title = 'Hacked by Tenant B' WHERE id = $1`, findingA)
	if err != nil {
		t.Logf("Tenant B update correctly failed: %v", err)
	} else {
		affected, _ := res.RowsAffected()
		if affected != 0 {
			t.Fatalf("CRITICAL SECURITY FAILURE: Tenant B updated Tenant A finding (rows affected: %d)", affected)
		}
	}

	res, err = txB.Exec(`DELETE FROM findings WHERE id = $1`, findingA)
	if err != nil {
		t.Logf("Tenant B delete correctly failed: %v", err)
	} else {
		affected, _ := res.RowsAffected()
		if affected != 0 {
			t.Fatalf("CRITICAL SECURITY FAILURE: Tenant B deleted Tenant A finding (rows affected: %d)", affected)
		}
	}

	// Assertion 4: Unauthenticated / Missing tenant context fails closed (0 visible rows)
	txNoTenant, err := db.Begin()
	if err != nil {
		t.Fatalf("begin txNoTenant failed: %v", err)
	}
	defer txNoTenant.Rollback()
	_, _ = txNoTenant.Exec(`SET LOCAL ROLE kelvin_app`)

	var noTenantCount int
	_ = txNoTenant.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&noTenantCount)
	if noTenantCount != 0 {
		t.Fatalf("FAIL-CLOSED BREACH: Queries without tenant context returned %d rows; expected 0", noTenantCount)
	}
	t.Log("All RLS and multi-tenant isolation invariants successfully verified!")
}
