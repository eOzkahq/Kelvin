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
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin_prod")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected success with valid production database URL, got: %v", err)
	}

	if cfg.Development {
		t.Error("expected Development to be false in production")
	}
	if cfg.Database.URL != "postgres://user:pass@db.internal:5432/kelvin_prod" {
		t.Errorf("expected database URL to match, got %q", cfg.Database.URL)
	}
}

