package config

import (
	"os"
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
