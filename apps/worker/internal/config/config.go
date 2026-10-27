package config

import (
	"fmt"
	"os"
	"time"
)

// Config is the runtime configuration of the worker daemon (.env.example).
type Config struct {
	WorkerID     string
	PollInterval time.Duration
	LogLevel     string
	Development  bool
}

// FromEnv loads worker configuration from environment variables.
func FromEnv() (Config, error) {
	cfg := Config{
		WorkerID:     getEnv("KELVIN_WORKER_ID", "worker-local-01"),
		PollInterval: 5 * time.Second,
		LogLevel:     getEnv("KELVIN_LOG_LEVEL", "info"),
		Development:  getEnv("KELVIN_ENV", "development") == "development",
	}
	if v := os.Getenv("KELVIN_WORKER_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("KELVIN_WORKER_POLL_INTERVAL must be a positive duration, got %q", v)
		}
		cfg.PollInterval = d
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
