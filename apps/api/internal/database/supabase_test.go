package database

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultSupabaseConfig(t *testing.T) {
	cfg := DefaultSupabaseConfig()
	if cfg.Port != 5432 {
		t.Errorf("expected port 5432, got %d", cfg.Port)
	}
	if cfg.Name != "postgres" {
		t.Errorf("expected database name postgres, got %s", cfg.Name)
	}
	if cfg.SSLMode != "verify-full" {
		t.Errorf("expected sslmode verify-full, got %s", cfg.SSLMode)
	}
	if cfg.MaxOpenConns != 25 {
		t.Errorf("expected max open conns 25, got %d", cfg.MaxOpenConns)
	}
	if cfg.ConnMaxLifetime != 1*time.Hour {
		t.Errorf("expected conn max lifetime 1h, got %v", cfg.ConnMaxLifetime)
	}
}

func TestBuildSupabaseDatabaseURL(t *testing.T) {
	tests := []struct {
		name       string
		cfg        SupabaseConfig
		expectHost string
		expectUser string
		expectPass string
		expectSSL  string
	}{
		{
			name: "full config with password",
			cfg: SupabaseConfig{
				Host:     "db.supabase.kelvin.internal",
				Port:     5432,
				Name:     "kelvindb",
				User:     "postgres",
				Password: "supersecretpassword",
				SSLMode:  "verify-full",
			},
			expectHost: "db.supabase.kelvin.internal:5432",
			expectUser: "postgres",
			expectPass: "supersecretpassword",
			expectSSL:  "sslmode=verify-full",
		},
		{
			name: "default values filled",
			cfg: SupabaseConfig{
				Host: "127.0.0.1",
				User: "appuser",
			},
			expectHost: "127.0.0.1:5432",
			expectUser: "appuser",
			expectSSL:  "sslmode=verify-full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := BuildSupabaseDatabaseURL(tt.cfg)
			if !strings.Contains(res, tt.expectHost) {
				t.Errorf("expected host %s in url %s", tt.expectHost, res)
			}
			if !strings.Contains(res, tt.expectUser) {
				t.Errorf("expected user %s in url %s", tt.expectUser, res)
			}
			if tt.expectPass != "" && !strings.Contains(res, tt.expectPass) {
				t.Errorf("expected password in url %s", res)
			}
			if !strings.Contains(res, tt.expectSSL) {
				t.Errorf("expected sslmode in url %s", res)
			}
		})
	}
}
