package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Environment denotes the runtime deployment stage.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvTesting     Environment = "testing"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// Valid returns true if the environment is one of the supported tiers.
func (e Environment) Valid() bool {
	switch e {
	case EnvDevelopment, EnvTesting, EnvStaging, EnvProduction:
		return true
	default:
		return false
	}
}

// DatabaseConfig holds typed relational database parameters.
type DatabaseConfig struct {
	URL      string `mapstructure:"url"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"` // Sensitive - redacted in logs
	Database string `mapstructure:"database"`
	SSLMode  string `mapstructure:"sslmode"`
}

// RedisConfig holds typed Redis task broker parameters (ADR-0003).
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"` // Sensitive - redacted in logs
	DB       int    `mapstructure:"db"`
}

// StorageConfig holds MinIO / S3 object store parameters.
type StorageConfig struct {
	Endpoint       string `mapstructure:"endpoint"`
	AccessKey      string `mapstructure:"access_key"` // Sensitive - redacted in logs
	SecretKey      string `mapstructure:"secret_key"` // Sensitive - redacted in logs
	EvidenceBucket string `mapstructure:"evidence_bucket"`
	ReportsBucket  string `mapstructure:"reports_bucket"`
	UseSSL         bool   `mapstructure:"use_ssl"`
}

// IdempotencyConfig holds idempotency store settings.
type IdempotencyConfig struct {
	TTLSeconds int64 `mapstructure:"ttl_seconds"` // TTL for idempotency records (default 24h = 86400)
}

// Config represents the immutable, strongly-typed configuration of the API control plane.
type Config struct {
	Env              Environment       `mapstructure:"env"`
	LogLevel         string            `mapstructure:"log_level"`
	Addr             string            `mapstructure:"addr"`
	APIVersion       string            `mapstructure:"api_version"`
	BodyLimitBytes   int64             `mapstructure:"body_limit_bytes"`
	ShutdownTimeoutS int               `mapstructure:"shutdown_timeout_s"`
	Development      bool              `mapstructure:"development"`
	Database         DatabaseConfig    `mapstructure:"database"`
	Redis            RedisConfig       `mapstructure:"redis"`
	Storage          StorageConfig     `mapstructure:"storage"`
	Idempotency      IdempotencyConfig `mapstructure:"idempotency"`
}

// Load loads, parses, and validates the API control plane configuration using spf13/viper.
// It fails fast if any required variables are missing or malformed.
func Load() (Config, error) {
	v := viper.New()

	v.SetEnvPrefix("KELVIN")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults
	v.SetDefault("env", string(EnvDevelopment))
	v.SetDefault("log_level", "info")
	v.SetDefault("api.addr", ":8080")
	v.SetDefault("api.version", "1.0.0-alpha")
	v.SetDefault("api.body_limit_bytes", int64(1<<20)) // 1 MiB
	v.SetDefault("api.shutdown_timeout_s", 10)

	// Idempotency record TTL (default 24 hours = 86400 seconds).
	v.SetDefault("idempotency.ttl_seconds", int64(86400))

	// Direct environment bindings for compatibility with KELVIN_* and service-specific envs
	bindEnvWithFallback(v, "env", "KELVIN_ENV")
	bindEnvWithFallback(v, "log_level", "KELVIN_LOG_LEVEL")
	bindEnvWithFallback(v, "api.addr", "KELVIN_API_ADDR")
	bindEnvWithFallback(v, "api.version", "KELVIN_API_VERSION")
	bindEnvWithFallback(v, "api.body_limit_bytes", "KELVIN_API_BODY_LIMIT_BYTES")

	bindEnvWithFallback(v, "idempotency.ttl_seconds", "KELVIN_IDEMPOTENCY_TTL_SECONDS")

	bindEnvWithFallback(v, "database.url", "KELVIN_DATABASE_URL")
	bindEnvWithFallback(v, "database.host", "POSTGRES_HOST")
	bindEnvWithFallback(v, "database.port", "POSTGRES_PORT")
	bindEnvWithFallback(v, "database.user", "POSTGRES_USER")
	bindEnvWithFallback(v, "database.password", "POSTGRES_PASSWORD")
	bindEnvWithFallback(v, "database.database", "POSTGRES_DB")

	bindEnvWithFallback(v, "redis.addr", "KELVIN_REDIS_ADDR")
	bindEnvWithFallback(v, "redis.password", "KELVIN_REDIS_PASSWORD")

	bindEnvWithFallback(v, "storage.endpoint", "MINIO_ENDPOINT")
	bindEnvWithFallback(v, "storage.access_key", "MINIO_ROOT_USER")
	bindEnvWithFallback(v, "storage.secret_key", "MINIO_ROOT_PASSWORD")
	bindEnvWithFallback(v, "storage.evidence_bucket", "MINIO_BUCKET_EVIDENCE")
	bindEnvWithFallback(v, "storage.reports_bucket", "MINIO_BUCKET_REPORTS")

	envStr := v.GetString("env")
	env := Environment(strings.ToLower(envStr))
	if !env.Valid() {
		return Config{}, fmt.Errorf("invalid KELVIN_ENV: %q (must be one of: %s, %s, %s, %s)",
			envStr, EnvDevelopment, EnvTesting, EnvStaging, EnvProduction)
	}

	addr := v.GetString("api.addr")
	if addr == "" {
		return Config{}, errors.New("KELVIN_API_ADDR must not be empty")
	}

	bodyLimit := v.GetInt64("api.body_limit_bytes")
	if bodyLimit <= 0 {
		return Config{}, fmt.Errorf("KELVIN_API_BODY_LIMIT_BYTES must be a positive integer, got %d", bodyLimit)
	}

	logLevel := strings.ToLower(v.GetString("log_level"))
	switch logLevel {
	case "debug", "info", "warn", "error":
	default:
		return Config{}, fmt.Errorf("invalid KELVIN_LOG_LEVEL: %q (must be debug, info, warn, or error)", logLevel)
	}

	dbURL := v.GetString("database.url")
	if dbURL != "" {
		if !strings.HasPrefix(dbURL, "postgres://") && !strings.HasPrefix(dbURL, "postgresql://") {
			return Config{}, fmt.Errorf("invalid KELVIN_DATABASE_URL: %q (must start with postgres:// or postgresql://)", dbURL)
		}
		if _, err := url.Parse(dbURL); err != nil {
			return Config{}, fmt.Errorf("invalid KELVIN_DATABASE_URL: %w", err)
		}
	} else if env == EnvStaging || env == EnvProduction {
		return Config{}, errors.New("KELVIN_DATABASE_URL is required in staging and production environments")
	}

	cfg := Config{
		Env:              env,
		LogLevel:         logLevel,
		Addr:             addr,
		APIVersion:       v.GetString("api.version"),
		BodyLimitBytes:   bodyLimit,
		ShutdownTimeoutS: v.GetInt("api.shutdown_timeout_s"),
		Development:      env == EnvDevelopment || env == EnvTesting,
		Database: DatabaseConfig{
			URL:      dbURL,
			Host:     v.GetString("database.host"),
			Port:     v.GetInt("database.port"),
			User:     v.GetString("database.user"),
			Password: v.GetString("database.password"),
			Database: v.GetString("database.database"),
			SSLMode:  "disable",
		},
		Redis: RedisConfig{
			Addr:     v.GetString("redis.addr"),
			Password: v.GetString("redis.password"),
			DB:       v.GetInt("redis.db"),
		},
		Storage: StorageConfig{
			Endpoint:       v.GetString("storage.endpoint"),
			AccessKey:      v.GetString("storage.access_key"),
			SecretKey:      v.GetString("storage.secret_key"),
			EvidenceBucket: v.GetString("storage.evidence_bucket"),
			ReportsBucket:  v.GetString("storage.reports_bucket"),
			UseSSL:         v.GetBool("storage.use_ssl"),
		},
		Idempotency: IdempotencyConfig{
			TTLSeconds: v.GetInt64("idempotency.ttl_seconds"),
		},
	}

	return cfg, nil
}

func bindEnvWithFallback(v *viper.Viper, viperKey, envKey string) {
	if val := os.Getenv(envKey); val != "" {
		v.Set(viperKey, val)
	}
}

// FromEnv maintains backwards compatibility with earlier scaffold callers.
func FromEnv() (Config, error) {
	return Load()
}
