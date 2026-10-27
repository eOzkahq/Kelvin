package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config is the runtime configuration of the API control plane, sourced from
// environment variables (.env.example). Defaults run a development instance
// with no external dependencies.
type Config struct {
	Addr             string
	APIVersion       string
	BodyLimitBytes   int64
	LogLevel         string
	Development      bool
	ShutdownTimeoutS int
}

// FromEnv loads configuration from environment variables with safe defaults.
func FromEnv() (Config, error) {
	cfg := Config{
		Addr:             getEnv("KELVIN_API_ADDR", ":8080"),
		APIVersion:       getEnv("KELVIN_API_VERSION", "1.0.0-alpha"),
		BodyLimitBytes:   1 << 20,
		LogLevel:         getEnv("KELVIN_LOG_LEVEL", "info"),
		Development:      getEnv("KELVIN_ENV", "development") == "development",
		ShutdownTimeoutS: 10,
	}
	if v := os.Getenv("KELVIN_API_BODY_LIMIT_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("KELVIN_API_BODY_LIMIT_BYTES must be a positive integer, got %q", v)
		}
		cfg.BodyLimitBytes = n
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
