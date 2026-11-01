package adapter

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultConfigurationsValid(t *testing.T) {
	engines := []string{"preflight", "tls", "headers", "zap", "nuclei"}
	for _, engine := range engines {
		t.Run(engine, func(t *testing.T) {
			cfg, err := NewDefaultConfiguration(engine)
			if err != nil {
				t.Fatalf("failed to create default config for %s: %v", engine, err)
			}
			if err := ValidateEngineConfiguration(cfg); err != nil {
				t.Fatalf("default config for %s should be valid: %v", engine, err)
			}
		})
	}
}

func TestUnsupportedEngineRejected(t *testing.T) {
	_, err := NewDefaultConfiguration("nmap")
	if !errors.Is(err, ErrUnsupportedEngine) {
		t.Fatalf("expected ErrUnsupportedEngine for nmap, got %v", err)
	}
}

func TestPreflightConfigValidationBounds(t *testing.T) {
	cfg, _ := NewDefaultConfiguration("preflight")
	cfg.Preflight.MaxRedirects = 100 // exceeds bound 10
	if err := ValidateEngineConfiguration(cfg); !errors.Is(err, ErrConfigOutOfRange) {
		t.Fatalf("expected ErrConfigOutOfRange for excessive redirects, got %v", err)
	}

	cfg, _ = NewDefaultConfiguration("preflight")
	cfg.Preflight.UserAgent = "Scanner\r\nInjected-Header: evil"
	if err := ValidateEngineConfiguration(cfg); !errors.Is(err, ErrUnsafeConfigOption) {
		t.Fatalf("expected ErrUnsafeConfigOption for CRLF in user_agent, got %v", err)
	}
}

func TestZAPBaselineRejectsActiveMode(t *testing.T) {
	cfg, _ := NewDefaultConfiguration("zap")
	cfg.ZAP.ScanMode = "active" // active attack mode forbidden
	if err := ValidateEngineConfiguration(cfg); !errors.Is(err, ErrUnsafeConfigOption) {
		t.Fatalf("expected ErrUnsafeConfigOption for active ZAP scan mode, got %v", err)
	}
}

func TestNucleiRejectsNonCuratedCatalog(t *testing.T) {
	cfg, _ := NewDefaultConfiguration("nuclei")
	cfg.Nuclei.CuratedCatalogOnly = false // cannot disable curated catalog
	if err := ValidateEngineConfiguration(cfg); !errors.Is(err, ErrUnsafeConfigOption) {
		t.Fatalf("expected ErrUnsafeConfigOption when curated_catalog_only=false, got %v", err)
	}
}

func TestNucleiRejectsExcessiveRateLimit(t *testing.T) {
	cfg, _ := NewDefaultConfiguration("nuclei")
	cfg.Nuclei.RequestRateLimit = 500 // exceeds maximum 50
	if err := ValidateEngineConfiguration(cfg); !errors.Is(err, ErrConfigOutOfRange) {
		t.Fatalf("expected ErrConfigOutOfRange for excessive rate limit, got %v", err)
	}
}

func TestSchemaVersionEnforced(t *testing.T) {
	cfg, _ := NewDefaultConfiguration("preflight")
	cfg.SchemaVersion = "2.0"
	if err := ValidateEngineConfiguration(cfg); !errors.Is(err, ErrInvalidConfigSchema) {
		t.Fatalf("expected ErrInvalidConfigSchema, got %v", err)
	}
}
