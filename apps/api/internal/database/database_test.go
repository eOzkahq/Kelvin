package database

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func generateValidCACertFile(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Kelvin Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test-ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write test CA cert: %v", err)
	}
	return certPath
}

func TestBuildPgxPoolConfig(t *testing.T) {
	validCA := generateValidCACertFile(t)

	t.Run("Configured CA path reaches pgx TLS configuration and preserves hostname verification", func(t *testing.T) {
		u := "postgres://dbuser:secret@db.staging.supabase.co:5432/postgres?sslmode=verify-full"
		poolCfg := PoolConfig{
			MaxConns:        10,
			MinConns:        2,
			MaxConnLifetime: 15 * time.Minute,
			MaxConnIdleTime: 2 * time.Minute,
			SSLRootCert:     validCA,
		}

		cfg, err := BuildPgxPoolConfig(u, poolCfg)
		if err != nil {
			t.Fatalf("expected successful pool config build, got: %v", err)
		}

		if cfg.MaxConns != 10 {
			t.Errorf("expected MaxConns=10, got %d", cfg.MaxConns)
		}
		if cfg.MinConns != 2 {
			t.Errorf("expected MinConns=2, got %d", cfg.MinConns)
		}
		if cfg.MaxConnLifetime != 15*time.Minute {
			t.Errorf("expected MaxConnLifetime=15m, got %v", cfg.MaxConnLifetime)
		}
		if cfg.MaxConnIdleTime != 2*time.Minute {
			t.Errorf("expected MaxConnIdleTime=2m, got %v", cfg.MaxConnIdleTime)
		}

		tlsCfg := cfg.ConnConfig.TLSConfig
		if tlsCfg == nil {
			t.Fatal("expected non-nil TLSConfig")
		}
		if tlsCfg.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify=false for verified TLS")
		}
		if tlsCfg.ServerName != "db.staging.supabase.co" {
			t.Errorf("expected ServerName='db.staging.supabase.co', got %q", tlsCfg.ServerName)
		}
		if tlsCfg.RootCAs == nil {
			t.Error("expected non-nil RootCAs populated from configured CA cert")
		}
	})

	t.Run("Existing URL sslrootcert is preserved appropriately when poolCfg SSLRootCert is empty", func(t *testing.T) {
		u := "postgres://dbuser:secret@db.staging.supabase.co:5432/postgres?sslmode=verify-full&sslrootcert=" + validCA
		poolCfg := DefaultPoolConfig()

		cfg, err := BuildPgxPoolConfig(u, poolCfg)
		if err != nil {
			t.Fatalf("expected successful pool config build with URL sslrootcert, got: %v", err)
		}

		tlsCfg := cfg.ConnConfig.TLSConfig
		if tlsCfg == nil || tlsCfg.RootCAs == nil {
			t.Fatal("expected non-nil TLSConfig with RootCAs from URL sslrootcert")
		}
		if tlsCfg.ServerName != "db.staging.supabase.co" {
			t.Errorf("expected ServerName='db.staging.supabase.co', got %q", tlsCfg.ServerName)
		}
		if tlsCfg.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify=false")
		}
	})

	t.Run("Conflicting CA configuration is rejected", func(t *testing.T) {
		u := "postgres://dbuser:secret@db.staging.supabase.co:5432/postgres?sslmode=verify-full&sslrootcert=" + validCA
		poolCfg := DefaultPoolConfig()
		poolCfg.SSLRootCert = "/different/path/ca.crt"

		_, err := BuildPgxPoolConfig(u, poolCfg)
		if err == nil {
			t.Fatal("expected error on conflicting CA paths, got nil")
		}
		if !strings.Contains(err.Error(), "conflicting CA certificate paths configured") {
			t.Errorf("expected conflict error, got: %v", err)
		}
	})

	t.Run("Missing CA file fails safely", func(t *testing.T) {
		u := "postgres://dbuser:secret@db.staging.supabase.co:5432/postgres?sslmode=verify-full"
		poolCfg := DefaultPoolConfig()
		poolCfg.SSLRootCert = "/non/existent/supabase-ca.crt"

		_, err := BuildPgxPoolConfig(u, poolCfg)
		if err == nil {
			t.Fatal("expected error for non-existent CA file, got nil")
		}
		if !strings.Contains(err.Error(), "CA certificate file not found") {
			t.Errorf("expected 'CA certificate file not found' error, got: %v", err)
		}
	})

	t.Run("Invalid PEM format fails safely", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidFile := filepath.Join(tmpDir, "invalid.crt")
		_ = os.WriteFile(invalidFile, []byte("NOT-A-CERTIFICATE"), 0600)

		u := "postgres://dbuser:secret@db.staging.supabase.co:5432/postgres?sslmode=verify-full"
		poolCfg := DefaultPoolConfig()
		poolCfg.SSLRootCert = invalidFile

		_, err := BuildPgxPoolConfig(u, poolCfg)
		if err == nil {
			t.Fatal("expected error for invalid PEM format, got nil")
		}
		if !strings.Contains(err.Error(), "invalid PEM format") {
			t.Errorf("expected invalid PEM format error, got: %v", err)
		}
	})

	t.Run("Empty database URL returns error", func(t *testing.T) {
		_, err := BuildPgxPoolConfig("", DefaultPoolConfig())
		if err == nil {
			t.Fatal("expected error for empty database URL, got nil")
		}
	})
}
