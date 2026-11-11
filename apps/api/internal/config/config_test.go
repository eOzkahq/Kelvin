package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clean environment
	os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected successful config load with defaults, got: %v", err)
	}

	if cfg.Env != EnvDevelopment {
		t.Errorf("expected Env %q, got %q", EnvDevelopment, cfg.Env)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("expected default Addr :8080, got %q", cfg.Addr)
	}
	if cfg.APIVersion != "1.0.0-alpha" {
		t.Errorf("expected default APIVersion 1.0.0-alpha, got %q", cfg.APIVersion)
	}
	if !cfg.Development {
		t.Errorf("expected Development to be true for development environment")
	}
}

func TestLoadInvalidEnvironment(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "invalid-env")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error on invalid KELVIN_ENV, got nil")
	}
}

func TestLoadInvalidBodyLimit(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_API_BODY_LIMIT_BYTES", "-50")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error on negative KELVIN_API_BODY_LIMIT_BYTES, got nil")
	}
}

func TestLoadProductionMissingDatabaseURL(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "production")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when KELVIN_DATABASE_URL is missing in production, got nil")
	}
}

func TestLoadProductionValidDatabaseURL(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "production")
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin_prod?sslmode=verify-full")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("KELVIN_JWT_SECRET", "test-secret-at-least-32-bytes-long")
	_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "test-evidence-signing-key-32-bytes-long!")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected success with valid production database URL, got: %v", err)
	}

	if cfg.Development {
		t.Error("expected Development to be false in production")
	}
	if cfg.Database.URL != "postgres://user:pass@db.internal:5432/kelvin_prod?sslmode=verify-full" {
		t.Errorf("expected database URL to match, got %q", cfg.Database.URL)
	}
	if cfg.ShutdownTimeoutS != 30 {
		t.Errorf("expected shutdown timeout to default to 30s, got %d", cfg.ShutdownTimeoutS)
	}
}

func TestLoadProductionRejectsInsecureSSLMode(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "production")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("KELVIN_JWT_SECRET", "test-secret-at-least-32-bytes-long")
	_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "test-evidence-signing-key-32-bytes-long!")

	insecureURLs := []string{
		"postgres://user:pass@db.internal:5432/kelvin_prod?sslmode=disable",
		"postgres://user:pass@db.internal:5432/kelvin_prod?sslmode=allow",
		"postgres://user:pass@db.internal:5432/kelvin_prod?sslmode=prefer",
		"postgres://user:pass@db.internal:5432/kelvin_prod",
	}

	for _, u := range insecureURLs {
		_ = os.Setenv("KELVIN_DATABASE_URL", u)
		if _, err := Load(); err == nil {
			t.Fatalf("expected production to reject insecure database URL %q, but succeeded", u)
		}
	}
}

func TestLoadRejectsWildcardCORS(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "production")
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin_prod?sslmode=verify-full")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("KELVIN_JWT_SECRET", "test-secret-at-least-32-bytes-long")
	_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "test-evidence-signing-key-32-bytes-long!")
	_ = os.Setenv("KELVIN_API_ALLOWED_ORIGINS", "https://eozka.com,*")

	if _, err := Load(); err == nil {
		t.Fatal("expected config Load to reject wildcard '*' CORS origin")
	}
}

func TestLoadProductionRequiresJWTSecret(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "production")
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin_prod")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	if _, err := Load(); err == nil {
		t.Fatal("expected production configuration to require a JWT signing secret")
	}
}

func TestLoadProductionRequiresEvidenceSigningKey(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "production")
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin_prod")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("KELVIN_JWT_SECRET", "test-secret-at-least-32-bytes-long")

	// Missing signing key
	if _, err := Load(); err == nil {
		t.Fatal("expected production configuration to require an evidence signing key")
	}

	// Default fallback key rejected
	_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "kelvin-default-evidence-signing-key-32-bytes")
	if _, err := Load(); err == nil {
		t.Fatal("expected production configuration to reject the hardcoded default fallback key")
	}
}

func TestLoadStagingDatabaseTLS_Enforced(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "staging")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.staging:6379")
	_ = os.Setenv("KELVIN_JWT_SECRET", "staging-jwt-secret-min-32-bytes-secure!")
	_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "staging-evidence-secret-min-32-bytes!")

	t.Run("Rejects missing or insecure sslmode in staging and redacts credentials", func(t *testing.T) {
		insecureURLs := []string{
			"postgres://dbuser:supersecretpassword@db.staging:5432/kelvin_staging",
			"postgres://dbuser:supersecretpassword@db.staging:5432/kelvin_staging?sslmode=disable",
			"postgres://dbuser:supersecretpassword@db.staging:5432/kelvin_staging?sslmode=prefer",
		}
		for _, rawURL := range insecureURLs {
			_ = os.Setenv("KELVIN_DATABASE_URL", rawURL)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for staging URL %s, but succeeded", rawURL)
			}
			if strings.Contains(err.Error(), "supersecretpassword") {
				t.Errorf("error leaked sensitive database credentials: %v", err)
			}
		}
	})

	t.Run("Accepts verify-full in staging", func(t *testing.T) {
		_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://dbuser:pass@db.staging:5432/kelvin_staging?sslmode=verify-full")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected success with verify-full in staging, got: %v", err)
		}
		if cfg.Database.MaxConns != 5 {
			t.Errorf("expected default staging max_conns to be 5, got %d", cfg.Database.MaxConns)
		}
		if cfg.Database.MinConns != 1 {
			t.Errorf("expected default staging min_conns to be 1, got %d", cfg.Database.MinConns)
		}
	})
}

func TestLoadStagingDatabaseSSLRootCert(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "staging")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.staging:6379")
	_ = os.Setenv("KELVIN_JWT_SECRET", "staging-jwt-secret-min-32-bytes-secure!")
	_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "staging-evidence-secret-min-32-bytes!")

	t.Run("Fails if configured sslrootcert does not exist", func(t *testing.T) {
		_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://dbuser:pass@db.staging:5432/kelvin_staging?sslmode=verify-full")
		_ = os.Setenv("KELVIN_DATABASE_SSL_ROOT_CERT", "/non/existent/ca.crt")
		_, err := Load()
		if err == nil {
			t.Fatal("expected error when sslrootcert does not exist, got nil")
		}
		if !strings.Contains(err.Error(), "configured database sslrootcert file does not exist") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Succeeds when sslrootcert exists", func(t *testing.T) {
		certPath := "./test_ca_cert.crt"
		if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"), 0600); err != nil {
			t.Fatalf("failed to create cert file: %v", err)
		}
		defer os.Remove(certPath)

		_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://dbuser:pass@db.staging:5432/kelvin_staging?sslmode=verify-full")
		_ = os.Setenv("KELVIN_DATABASE_SSL_ROOT_CERT", certPath)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected success with existing sslrootcert, got: %v", err)
		}
		if cfg.Database.SSLRootCert != certPath {
			t.Errorf("expected SSLRootCert %q, got %q", certPath, cfg.Database.SSLRootCert)
		}
	})
}

func TestLoadDatabasePoolSizingDefaults(t *testing.T) {
	t.Run("Development defaults to 25/5", func(t *testing.T) {
		os.Clearenv()
		_ = os.Setenv("KELVIN_ENV", "development")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Database.MaxConns != 25 || cfg.Database.MinConns != 5 {
			t.Errorf("expected 25/5 dev pool defaults, got max=%d min=%d", cfg.Database.MaxConns, cfg.Database.MinConns)
		}
	})

	t.Run("Production defaults to 5/1 and respects explicit overrides", func(t *testing.T) {
		os.Clearenv()
		_ = os.Setenv("KELVIN_ENV", "production")
		_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin?sslmode=verify-full")
		_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
		_ = os.Setenv("KELVIN_JWT_SECRET", "test-secret-at-least-32-bytes-long")
		_ = os.Setenv("KELVIN_EVIDENCE_SIGNING_KEY", "test-evidence-signing-key-32-bytes-long!")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Database.MaxConns != 5 || cfg.Database.MinConns != 1 {
			t.Errorf("expected 5/1 prod pool defaults, got max=%d min=%d", cfg.Database.MaxConns, cfg.Database.MinConns)
		}

		// Explicit overrides
		_ = os.Setenv("KELVIN_DATABASE_MAX_CONNS", "10")
		_ = os.Setenv("KELVIN_DATABASE_MIN_CONNS", "2")
		cfgOverride, err := Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfgOverride.Database.MaxConns != 10 || cfgOverride.Database.MinConns != 2 {
			t.Errorf("expected 10/2 pool override, got max=%d min=%d", cfgOverride.Database.MaxConns, cfgOverride.Database.MinConns)
		}
	})
}
