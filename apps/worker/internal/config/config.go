package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

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

// DatabaseConfig holds relational database connection settings for workers.
type DatabaseConfig struct {
	URL string `mapstructure:"url"`
}

// RedisConfig holds Redis task broker connection settings for worker queue polling.
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"` // Sensitive - redacted in logs
	DB       int    `mapstructure:"db"`
}

// StorageConfig holds MinIO / S3 object store settings for worker evidence upload.
type StorageConfig struct {
	Endpoint       string `mapstructure:"endpoint"`
	AccessKey      string `mapstructure:"access_key"` // Sensitive - redacted in logs
	SecretKey      string `mapstructure:"secret_key"` // Sensitive - redacted in logs
	EvidenceBucket string `mapstructure:"evidence_bucket"`
	UseSSL         bool   `mapstructure:"use_ssl"`
}

// Config is the immutable runtime configuration of the worker daemon (.env.example).
type Config struct {
	Env          Environment    `mapstructure:"env"`
	LogLevel     string         `mapstructure:"log_level"`
	WorkerID     string         `mapstructure:"worker_id"`
	PollInterval time.Duration  `mapstructure:"poll_interval"`
	Development  bool           `mapstructure:"development"`
	Database     DatabaseConfig `mapstructure:"database"`
	Redis        RedisConfig    `mapstructure:"redis"`
	Storage      StorageConfig  `mapstructure:"storage"`
}

// Load loads and validates worker configuration from environment variables using spf13/viper.
// It fails fast if any required variables are missing or malformed.
func Load() (Config, error) {
	v := viper.New()

	v.SetEnvPrefix("KELVIN")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults
	v.SetDefault("env", string(EnvDevelopment))
	v.SetDefault("log_level", "info")
	v.SetDefault("worker.id", "worker-local-01")
	v.SetDefault("worker.poll_interval", "5s")

	bindEnvWithFallback(v, "env", "KELVIN_ENV")
	bindEnvWithFallback(v, "log_level", "KELVIN_LOG_LEVEL")
	bindEnvWithFallback(v, "worker.id", "KELVIN_WORKER_ID")
	bindEnvWithFallback(v, "worker.poll_interval", "KELVIN_WORKER_POLL_INTERVAL")

	bindEnvWithFallback(v, "database.url", "KELVIN_DATABASE_URL")
	bindEnvWithFallback(v, "redis.addr", "KELVIN_REDIS_ADDR")
	bindEnvWithFallback(v, "redis.password", "KELVIN_REDIS_PASSWORD")
	bindEnvWithFallback(v, "storage.endpoint", "MINIO_ENDPOINT")
	bindEnvWithFallback(v, "storage.access_key", "MINIO_ROOT_USER")
	bindEnvWithFallback(v, "storage.secret_key", "MINIO_ROOT_PASSWORD")
	bindEnvWithFallback(v, "storage.evidence_bucket", "MINIO_BUCKET_EVIDENCE")

	envStr := v.GetString("env")
	env := Environment(strings.ToLower(envStr))
	if !env.Valid() {
		return Config{}, fmt.Errorf("invalid KELVIN_ENV: %q (must be one of: %s, %s, %s, %s)",
			envStr, EnvDevelopment, EnvTesting, EnvStaging, EnvProduction)
	}

	workerID := v.GetString("worker.id")
	if strings.TrimSpace(workerID) == "" {
		return Config{}, errors.New("KELVIN_WORKER_ID must not be empty")
	}

	pollIntervalStr := v.GetString("worker.poll_interval")
	pollInterval, err := time.ParseDuration(pollIntervalStr)
	if err != nil || pollInterval <= 0 {
		return Config{}, fmt.Errorf("KELVIN_WORKER_POLL_INTERVAL must be a positive duration, got %q", pollIntervalStr)
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
	}

	cfg := Config{
		Env:          env,
		LogLevel:     logLevel,
		WorkerID:     workerID,
		PollInterval: pollInterval,
		Development:  env == EnvDevelopment || env == EnvTesting,
		Database: DatabaseConfig{
			URL: dbURL,
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
			UseSSL:         v.GetBool("storage.use_ssl"),
		},
	}

	return cfg, nil
}

func bindEnvWithFallback(v *viper.Viper, viperKey, envKey string) {
	if val := os.Getenv(envKey); val != "" {
		v.Set(viperKey, val)
	}
}

// FromEnv maintains backwards compatibility with earlier callers.
func FromEnv() (Config, error) {
	return Load()
}
