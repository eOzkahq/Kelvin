package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/api/internal/config"
)

func TestMain_ConfigErrorOutputsToStderr(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_ConfigErrorOutputsToStderr")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"KELVIN_ENV=staging",
		"KELVIN_DATABASE_URL=",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected main() to exit with non-zero exit code on invalid staging config")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got: %T", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}

	out := stderr.String()
	if !strings.Contains(out, "api startup configuration error:") {
		t.Errorf("expected stderr to contain 'api startup configuration error:', got: %q", out)
	}
}

func TestMain_InvalidLogLevelOutputsToStderr(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_InvalidLogLevelOutputsToStderr")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"KELVIN_ENV=development",
		"KELVIN_LOG_LEVEL=invalid-level",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected main() to exit with non-zero exit code on invalid log level")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got: %T", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}

	out := stderr.String()
	if !strings.Contains(out, "api startup configuration error:") {
		t.Errorf("expected stderr to contain 'api startup configuration error:', got: %q", out)
	}
}

// TestStagingConfigurationValidationStrictness verifies that staging config checks remain fail-closed:
// - Missing database URL rejected
// - Insecure database SSL modes rejected
// - Plaintext Redis without TLS rejected
// - Missing JWT secret rejected
func TestStagingConfigurationValidationStrictness(t *testing.T) {
	baseStagingEnv := map[string]string{
		"KELVIN_ENV":                  "staging",
		"KELVIN_DATABASE_URL":         "postgres://user:pass@db.supabase.co:5432/postgres?sslmode=verify-full",
		"KELVIN_JWT_SECRET":           "valid-jwt-secret-with-32-chars-long!",
		"KELVIN_EVIDENCE_SIGNING_KEY": "valid-signing-key-with-32-bytes-len!",
		"REDIS_URL":                   "rediss://redis.staging:6379",
		"REDIS_TLS_ENABLED":           "true",
		"SUPABASE_URL":                "https://example.supabase.co",
		"SUPABASE_SERVICE_ROLE_KEY":   "service-role-key-test",
	}

	setEnvMap := func(m map[string]string) {
		os.Clearenv()
		for k, v := range m {
			_ = os.Setenv(k, v)
		}
	}

	t.Run("Valid staging configuration passes", func(t *testing.T) {
		setEnvMap(baseStagingEnv)
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("expected valid staging config to pass, got: %v", err)
		}
		if cfg.Env != config.EnvStaging {
			t.Errorf("expected Env %q, got %q", config.EnvStaging, cfg.Env)
		}
	})

	t.Run("Insecure sslmode=disable strictly rejected in staging", func(t *testing.T) {
		env := make(map[string]string)
		for k, v := range baseStagingEnv {
			env[k] = v
		}
		env["KELVIN_DATABASE_URL"] = "postgres://user:pass@db.supabase.co:5432/postgres?sslmode=disable"
		setEnvMap(env)

		_, err := config.Load()
		if err == nil {
			t.Fatal("expected error rejecting sslmode=disable in staging, got nil")
		}
		if !strings.Contains(err.Error(), "sslmode=verify-full") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("Plaintext redis strictly rejected in staging", func(t *testing.T) {
		env := make(map[string]string)
		for k, v := range baseStagingEnv {
			env[k] = v
		}
		env["REDIS_URL"] = "redis://redis.staging:6379"
		env["REDIS_TLS_ENABLED"] = "false"
		setEnvMap(env)

		_, err := config.Load()
		if err == nil {
			t.Fatal("expected error rejecting plaintext redis in staging, got nil")
		}
		if !strings.Contains(err.Error(), "prohibited in staging") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("Missing JWT secret strictly rejected in staging", func(t *testing.T) {
		env := make(map[string]string)
		for k, v := range baseStagingEnv {
			env[k] = v
		}
		env["KELVIN_JWT_SECRET"] = ""
		setEnvMap(env)

		_, err := config.Load()
		if err == nil {
			t.Fatal("expected error rejecting missing JWT secret in staging, got nil")
		}
		if !strings.Contains(err.Error(), "KELVIN_JWT_SECRET") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
