package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNormalizeSourceURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"db/migrations", "file://db/migrations"},
		{"file://db/migrations", "file://db/migrations"},
		{"C:\\projects\\kelvin\\migrations", "file://C:/projects/kelvin/migrations"},
		{"file://C:\\projects\\kelvin\\migrations", "file://C:/projects/kelvin/migrations"},
	}

	for _, tt := range tests {
		actual := normalizeSourceURL(tt.input)
		if actual != tt.expected {
			t.Errorf("normalizeSourceURL(%q) = %q; expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestNewMigrator_Validation(t *testing.T) {
	mig := NewMigrator("db/migrations", "invalid-url?sslmode=disable", zap.NewNop())
	if mig == nil {
		t.Fatal("expected migrator instance, got nil")
	}

	// Attempting to instantiate with malformed URL should fail fast
	_, err := mig.instance()
	if err == nil {
		t.Fatal("expected error on malformed database URL, got nil")
	}
	if !strings.Contains(err.Error(), "failed to initialize golang-migrate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestMigrator_MissingSSLModeFails(t *testing.T) {
	urls := []string{
		"postgres://kelvin:secret@localhost:5432/kelvin_dev",
		"postgres://kelvin:secret@localhost:5432/kelvin_dev?param=value",
	}

	for _, u := range urls {
		mig := NewMigrator("../../db/migrations", u, zap.NewNop())
		_, err := mig.instance()
		if err == nil {
			t.Fatalf("expected error for missing sslmode on %s, got nil", u)
		}
		if !strings.Contains(err.Error(), "missing required 'sslmode'") {
			t.Errorf("expected missing sslmode error message, got: %v", err)
		}
	}
}

func TestMigrator_InsecureSSLModeInStagingAndProduction(t *testing.T) {
	insecureModes := []string{"disable", "allow", "prefer", "require"}
	environments := []string{"staging", "production"}

	for _, env := range environments {
		for _, mode := range insecureModes {
			u := "postgres://user:password@db.supabase.co:5432/postgres?sslmode=" + mode
			mig := NewMigratorWithOptions(MigratorOptions{
				MigrationsPath: "../../db/migrations",
				DatabaseURL:    u,
				Environment:    env,
			}, zap.NewNop())

			_, err := mig.instance()
			if err == nil {
				t.Fatalf("expected error for insecure sslmode=%s in %s, got nil", mode, env)
			}
			if !strings.Contains(err.Error(), "insecure sslmode") || !strings.Contains(err.Error(), "verify-full is strictly required") {
				t.Errorf("expected insecure sslmode error in %s, got: %v", env, err)
			}
		}
	}
}

func TestMigrator_MissingCACertificateFile(t *testing.T) {
	u := "postgres://user:password@db.supabase.co:5432/postgres?sslmode=verify-full&sslrootcert=/nonexistent/ca-cert.crt"
	mig := NewMigratorWithOptions(MigratorOptions{
		MigrationsPath: "../../db/migrations",
		DatabaseURL:    u,
		Environment:    "staging",
	}, zap.NewNop())

	_, err := mig.instance()
	if err == nil {
		t.Fatal("expected error when sslrootcert file does not exist, got nil")
	}
	if !strings.Contains(err.Error(), "CA certificate file not found") {
		t.Errorf("expected CA certificate file not found error, got: %v", err)
	}
}

func TestMigrator_VerifiedTLSAndCACertConfiguration(t *testing.T) {
	// Create a temporary valid certificate file
	tmpDir := t.TempDir()
	caCertFile := filepath.Join(tmpDir, "supabase-ca.crt")
	if err := os.WriteFile(caCertFile, []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatalf("failed to create temp CA cert: %v", err)
	}

	u := "postgres://user:password@127.0.0.1:5432/postgres?sslmode=verify-full"
	mig := NewMigratorWithOptions(MigratorOptions{
		MigrationsPath: "../../db/migrations",
		DatabaseURL:    u,
		Environment:    "staging",
		CACertPath:     caCertFile,
	}, zap.NewNop())

	// instance() should pass validation and attempt driver connection (which may fail dialing localhost:5432, but TLS config is valid)
	_, err := mig.instance()
	if err != nil && !strings.Contains(err.Error(), "failed to initialize golang-migrate") {
		t.Fatalf("expected valid TLS setup to pass pre-connection validation, got: %v", err)
	}
}

func TestMigrator_ExplicitDevelopmentMode(t *testing.T) {
	u := "postgres://kelvin:devpass@localhost:5432/kelvin_dev?sslmode=disable"
	mig := NewMigratorWithOptions(MigratorOptions{
		MigrationsPath: "../../db/migrations",
		DatabaseURL:    u,
		Environment:    "development",
	}, zap.NewNop())

	_, err := mig.instance()
	// Should pass sslmode check; failure to connect to localhost is expected if no DB is running
	if err != nil && !strings.Contains(err.Error(), "failed to initialize golang-migrate") {
		t.Fatalf("unexpected validation error in development: %v", err)
	}
}
