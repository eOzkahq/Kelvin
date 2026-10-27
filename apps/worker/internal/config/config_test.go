package config

import (
	"os"
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
}

