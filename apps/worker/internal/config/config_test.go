package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected successful worker config load with defaults, got: %v", err)
	}

	if cfg.Env != EnvDevelopment {
		t.Errorf("expected Env %q, got %q", EnvDevelopment, cfg.Env)
	}
	if cfg.WorkerID != "worker-local-01" {
		t.Errorf("expected default WorkerID 'worker-local-01', got %q", cfg.WorkerID)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("expected default PollInterval 5s, got %v", cfg.PollInterval)
	}
	if !cfg.Development {
		t.Errorf("expected Development to be true for development environment")
	}
}

func TestLoadInvalidWorkerID(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_WORKER_ID", "   ")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error on empty KELVIN_WORKER_ID, got nil")
	}
}

func TestLoadInvalidPollInterval(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_WORKER_POLL_INTERVAL", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error on malformed KELVIN_WORKER_POLL_INTERVAL, got nil")
	}
}

func TestLoadCustomValidWorkerConfig(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "staging")
	_ = os.Setenv("KELVIN_WORKER_ID", "worker-prod-az1-05")
	_ = os.Setenv("KELVIN_WORKER_POLL_INTERVAL", "10s")
	_ = os.Setenv("KELVIN_LOG_LEVEL", "warn")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("REDIS_TLS_ENABLED", "true")
	_ = os.Setenv("KELVIN_REDIS_PASSWORD", "secret-broker-pass")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected success with custom config, got: %v", err)
	}

	if cfg.Development {
		t.Error("expected Development to be false in staging")
	}
	if cfg.WorkerID != "worker-prod-az1-05" {
		t.Errorf("expected WorkerID 'worker-prod-az1-05', got %q", cfg.WorkerID)
	}
	if cfg.PollInterval != 10*time.Second {
		t.Errorf("expected PollInterval 10s, got %v", cfg.PollInterval)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("expected LogLevel 'warn', got %q", cfg.LogLevel)
	}
	if cfg.Redis.Password != "secret-broker-pass" {
		t.Errorf("expected Redis password to match, got %q", cfg.Redis.Password)
	}
	if !cfg.Redis.TLSEnabled {
		t.Errorf("expected Redis TLSEnabled to be true in staging when REDIS_TLS_ENABLED=true")
	}
}

func TestWorkerRedisTLS_TableDriven(t *testing.T) {
	testCases := []struct {
		name        string
		env         string
		redisURL    string
		redisAddr   string
		tlsEnabled  string
		expectError bool
		expectedTLS bool
		errorMsg    string
	}{
		{
			name:        "Staging rediss:// URL enables TLS regardless of boolean",
			env:         "staging",
			redisURL:    "rediss://:pass@managed-redis.prod:6380/0",
			tlsEnabled:  "false",
			expectError: false,
			expectedTLS: true,
		},
		{
			name:        "Production rediss:// URL enables TLS without explicit boolean",
			env:         "production",
			redisURL:    "rediss://:pass@managed-redis.prod:6380/0",
			expectError: false,
			expectedTLS: true,
		},
		{
			name:        "Staging REDIS_TLS_ENABLED=true with Addr enables TLS",
			env:         "staging",
			redisAddr:   "managed-redis.prod:6380",
			tlsEnabled:  "true",
			expectError: false,
			expectedTLS: true,
		},
		{
			name:        "Staging plaintext redis:// URL is rejected",
			env:         "staging",
			redisURL:    "redis://:pass@insecure-redis.prod:6379/0",
			expectError: true,
			errorMsg:    "insecure plaintext Redis URL",
		},
		{
			name:        "Production plaintext redis:// URL is rejected",
			env:         "production",
			redisURL:    "redis://:pass@insecure-redis.prod:6379/0",
			expectError: true,
			errorMsg:    "insecure plaintext Redis URL",
		},
		{
			name:        "Staging plaintext Addr without TLS is rejected",
			env:         "staging",
			redisAddr:   "insecure-redis.prod:6379",
			tlsEnabled:  "false",
			expectError: true,
			errorMsg:    "plaintext Redis is prohibited in staging; REDIS_TLS_ENABLED=true is strictly required",
		},
		{
			name:        "Development allows plaintext redis:// URL",
			env:         "development",
			redisURL:    "redis://localhost:6379/0",
			expectError: false,
			expectedTLS: false,
		},
		{
			name:        "Development allows plaintext Addr without TLS",
			env:         "development",
			redisAddr:   "localhost:6379",
			tlsEnabled:  "false",
			expectError: false,
			expectedTLS: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()
			_ = os.Setenv("KELVIN_ENV", tc.env)
			_ = os.Setenv("KELVIN_WORKER_ID", "test-worker-01")
			if tc.redisURL != "" {
				_ = os.Setenv("KELVIN_REDIS_URL", tc.redisURL)
			}
			if tc.redisAddr != "" {
				_ = os.Setenv("KELVIN_REDIS_ADDR", tc.redisAddr)
			}
			if tc.tlsEnabled != "" {
				_ = os.Setenv("REDIS_TLS_ENABLED", tc.tlsEnabled)
			}

			cfg, err := Load()
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tc.errorMsg, err.Error())
				}
				if strings.Contains(err.Error(), ":pass@") {
					t.Errorf("error leaked password: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tc.name, err)
				}
				if cfg.Redis.TLSEnabled != tc.expectedTLS {
					t.Errorf("expected TLSEnabled=%v, got %v", tc.expectedTLS, cfg.Redis.TLSEnabled)
				}
				if tc.redisURL != "" && cfg.Redis.URL != tc.redisURL {
					t.Errorf("expected Redis URL %q, got %q", tc.redisURL, cfg.Redis.URL)
				}
			}
		})
	}
}

func TestWorkerDatabaseSSLMode_TableDriven(t *testing.T) {
	testCases := []struct {
		name        string
		env         string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Staging exact verify-full accepted",
			env:         "staging",
			url:         "postgres://user:supersecretpass@db.internal:5432/kelvin_staging?sslmode=verify-full",
			expectError: false,
		},
		{
			name:        "Production exact verify-full accepted",
			env:         "production",
			url:         "postgres://user:supersecretpass@db.internal:5432/kelvin_prod?sslmode=verify-full",
			expectError: false,
		},
		{
			name:        "Staging verify-ca rejected",
			env:         "staging",
			url:         "postgres://user:supersecretpass@db.internal:5432/kelvin_staging?sslmode=verify-ca",
			expectError: true,
			errorMsg:    "verified database TLS (sslmode=verify-full) is required in staging; got \"verify-ca\"",
		},
		{
			name:        "Production require rejected",
			env:         "production",
			url:         "postgres://user:supersecretpass@db.internal:5432/kelvin_prod?sslmode=require",
			expectError: true,
			errorMsg:    "verified database TLS (sslmode=verify-full) is required in production; got \"require\"",
		},
		{
			name:        "Production disable rejected",
			env:         "production",
			url:         "postgres://user:supersecretpass@db.internal:5432/kelvin_prod?sslmode=disable",
			expectError: true,
			errorMsg:    "verified database TLS (sslmode=verify-full) is required in production; got \"disable\"",
		},
		{
			name:        "Development disable accepted",
			env:         "development",
			url:         "postgres://user:supersecretpass@localhost:5432/kelvin_dev?sslmode=disable",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()
			_ = os.Setenv("KELVIN_ENV", tc.env)
			_ = os.Setenv("KELVIN_WORKER_ID", "test-worker-01")
			_ = os.Setenv("KELVIN_DATABASE_URL", tc.url)
			_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
			_ = os.Setenv("REDIS_TLS_ENABLED", "true")

			cfg, err := Load()
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tc.errorMsg, err.Error())
				}
				if strings.Contains(err.Error(), "supersecretpass") {
					t.Errorf("error leaked password: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tc.name, err)
				}
				if cfg.Database.URL != tc.url {
					t.Errorf("expected URL %q, got %q", tc.url, cfg.Database.URL)
				}
			}
		})
	}
}

func TestWorkerDatabaseSSLRootCertValidation(t *testing.T) {
	certPath := "ca-kelvin-test.crt"
	if err := os.WriteFile(certPath, []byte("fake cert"), 0600); err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer func() {
		_ = os.Remove(certPath)
	}()

	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "staging")
	_ = os.Setenv("KELVIN_WORKER_ID", "test-worker-01")
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin?sslmode=verify-full")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("REDIS_TLS_ENABLED", "true")
	_ = os.Setenv("KELVIN_DATABASE_SSL_ROOT_CERT", "/nonexistent/ca.crt")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when SSL root cert file does not exist, got nil")
	}
	if !strings.Contains(err.Error(), "database sslrootcert file \"/nonexistent/ca.crt\" is not accessible") {
		t.Errorf("expected missing cert error, got: %v", err)
	}

	_ = os.Setenv("KELVIN_DATABASE_SSL_ROOT_CERT", certPath)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected success with existing cert file, got: %v", err)
	}
	if cfg.Database.SSLRootCert != certPath {
		t.Errorf("expected SSLRootCert %q, got %q", certPath, cfg.Database.SSLRootCert)
	}
}

func TestConfig_RejectsTemplateNotConfigured(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_CONFIG_STATUS", "TEMPLATE_NOT_CONFIGURED")
	_ = os.Setenv("KELVIN_ENV", "staging")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when KELVIN_CONFIG_STATUS=TEMPLATE_NOT_CONFIGURED, got nil")
	}
	if !strings.Contains(err.Error(), "TEMPLATE_NOT_CONFIGURED") {
		t.Errorf("expected error mentioning TEMPLATE_NOT_CONFIGURED, got: %v", err)
	}
}

func TestConfig_RejectsPlaceholderCredentialsInStagingProduction(t *testing.T) {
	testCases := []struct {
		name      string
		envKey    string
		envVal    string
		errSubstr string
	}{
		{
			name:      "Rejects REPLACE_WITH_ in database URL",
			envKey:    "KELVIN_DATABASE_URL",
			envVal:    "postgres://kelvin_worker:REPLACE_WITH_SUPABASE_PASSWORD@db.example.com:5432/kelvin?sslmode=verify-full",
			errSubstr: "database URL contains unconfigured placeholder credentials",
		},
		{
			name:      "Rejects your-project in database URL",
			envKey:    "KELVIN_DATABASE_URL",
			envVal:    "postgres://postgres.your-project:pass@aws-0-us-west-1.pooler.supabase.com:6543/postgres?sslmode=verify-full",
			errSubstr: "database URL contains unconfigured placeholder credentials",
		},
		{
			name:      "Rejects REPLACE_WITH_ in redis URL",
			envKey:    "KELVIN_REDIS_URL",
			envVal:    "rediss://default:REPLACE_WITH_PASSWORD@redis.example.com:6379",
			errSubstr: "redis URL contains unconfigured placeholder credentials",
		},
		{
			name:      "Rejects your-upstash in redis URL",
			envKey:    "KELVIN_REDIS_URL",
			envVal:    "rediss://default:pass@your-upstash.upstash.io:6379",
			errSubstr: "redis URL contains unconfigured placeholder credentials",
		},
		{
			name:      "Rejects REPLACE_WITH_ in redis password",
			envKey:    "KELVIN_REDIS_PASSWORD",
			envVal:    "REPLACE_WITH_ACTUAL_REDIS_PASSWORD",
			errSubstr: "redis password contains unconfigured placeholder value",
		},
		{
			name:      "Rejects REPLACE_WITH_ in worker token secret",
			envKey:    "KELVIN_WORKER_TOKEN_SECRET",
			envVal:    "REPLACE_WITH_HEX_OR_BASE64_AT_LEAST_32_BYTES_SECRET_TOKEN",
			errSubstr: "worker token secret contains unconfigured placeholder value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()
			_ = os.Setenv("KELVIN_ENV", "staging")
			_ = os.Setenv("KELVIN_WORKER_ID", "test-worker-01")
			_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin?sslmode=verify-full")
			_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
			_ = os.Setenv("REDIS_TLS_ENABLED", "true")
			_ = os.Setenv(tc.envKey, tc.envVal)

			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for placeholder %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Errorf("expected error containing %q, got: %v", tc.errSubstr, err)
			}
			// Verify secret values are not leaked in error message
			if strings.Contains(err.Error(), tc.envVal) {
				t.Errorf("error leaked sensitive placeholder value: %v", err)
			}
		})
	}
}

func TestCanaryOnlyAndResourceLimitsConfig(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("KELVIN_ENV", "staging")
	_ = os.Setenv("KELVIN_WORKER_ID", "oracle-arm64-worker-01")
	_ = os.Setenv("KELVIN_CANARY_ONLY", "true")
	_ = os.Setenv("KELVIN_CANARY_ALLOWED_TARGETS", "scanner-mock.kelvin.internal,mock-target.kelvin.internal,127.0.0.1")
	_ = os.Setenv("KELVIN_LIMITS_CPU_QUOTA", "1.0")
	_ = os.Setenv("KELVIN_LIMITS_MEMORY_LIMIT", "2048M")
	_ = os.Setenv("KELVIN_LIMITS_MAX_PIDS", "64")
	_ = os.Setenv("KELVIN_DATABASE_URL", "postgres://user:pass@db.internal:5432/kelvin?sslmode=verify-full")
	_ = os.Setenv("KELVIN_REDIS_ADDR", "redis.internal:6379")
	_ = os.Setenv("REDIS_TLS_ENABLED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected successful config load, got: %v", err)
	}

	if !cfg.CanaryOnly {
		t.Errorf("expected CanaryOnly=true, got false")
	}
	if len(cfg.CanaryAllowedTargets) != 3 {
		t.Fatalf("expected 3 allowed targets, got %d: %v", len(cfg.CanaryAllowedTargets), cfg.CanaryAllowedTargets)
	}
	if cfg.CanaryAllowedTargets[0] != "scanner-mock.kelvin.internal" {
		t.Errorf("expected target 0 to be scanner-mock.kelvin.internal, got %s", cfg.CanaryAllowedTargets[0])
	}

	lim, err := cfg.ToLimits()
	if err != nil {
		t.Fatalf("expected valid limits, got: %v", err)
	}
	if lim.CPUQuota != "1.0" {
		t.Errorf("expected CPUQuota '1.0', got %s", lim.CPUQuota)
	}
	if lim.MemoryLimit != "2048M" {
		t.Errorf("expected MemoryLimit '2048M', got %s", lim.MemoryLimit)
	}
	if lim.MaxPIDs != 64 {
		t.Errorf("expected MaxPIDs 64, got %d", lim.MaxPIDs)
	}
}
