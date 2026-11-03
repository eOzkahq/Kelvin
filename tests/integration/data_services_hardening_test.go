package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDataServicesHardening verifies the SQL role definitions, PgBouncer pooler config,
// and durable queue configurations for Phase 5 data hardening.
func TestDataServicesHardening(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify PostgreSQL Hardening SQL
	sqlPath := filepath.Join(repoRoot, "deploy", "postgres", "hardening.sql")
	sqlData, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("Missing deploy/postgres/hardening.sql: %v", err)
	}
	sql := string(sqlData)

	expectedRoles := []string{"kelvin_migrator", "kelvin_app", "kelvin_auditor"}
	for _, role := range expectedRoles {
		if !strings.Contains(sql, role) {
			t.Errorf("hardening.sql missing role definition: %s", role)
		}
	}

	if !strings.Contains(sql, "REVOKE CREATE ON SCHEMA public FROM PUBLIC;") {
		t.Errorf("hardening.sql must revoke public schema creation from PUBLIC")
	}

	if !strings.Contains(sql, "statement_timeout = '30s'") {
		t.Errorf("hardening.sql must enforce statement_timeout for kelvin_app")
	}

	// 2. Verify PgBouncer Configuration
	iniPath := filepath.Join(repoRoot, "deploy", "postgres", "pgbouncer.ini")
	iniData, err := os.ReadFile(iniPath)
	if err != nil {
		t.Fatalf("Missing deploy/postgres/pgbouncer.ini: %v", err)
	}
	ini := string(iniData)

	if !strings.Contains(ini, "pool_mode = transaction") {
		t.Errorf("pgbouncer.ini must use transaction pool mode")
	}

	if !strings.Contains(ini, "server_reset_query = DISCARD ALL") {
		t.Errorf("pgbouncer.ini must execute DISCARD ALL on server reset")
	}

	if !strings.Contains(ini, "client_tls_sslmode = require") {
		t.Errorf("pgbouncer.ini must require client TLS")
	}

	// 3. Verify Redis Broker Terraform Module has noeviction
	brokerTfPath := filepath.Join(repoRoot, "infra", "terraform", "modules", "broker", "main.tf")
	brokerData, err := os.ReadFile(brokerTfPath)
	if err != nil {
		t.Fatalf("Missing infra/terraform/modules/broker/main.tf: %v", err)
	}
	brokerTf := string(brokerData)

	if !strings.Contains(brokerTf, "\"noeviction\"") {
		t.Errorf("Redis parameter group must specify noeviction maxmemory policy")
	}
}
