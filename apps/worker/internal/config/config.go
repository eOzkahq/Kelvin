package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/limits"
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
	URL         string `mapstructure:"url"`
	SSLRootCert string `mapstructure:"sslrootcert"`
}

// RedisConfig holds Redis task broker connection settings for worker queue polling.
type RedisConfig struct {
	URL               string `mapstructure:"url"`
	Addr              string `mapstructure:"addr"`
	Password          string `mapstructure:"password"` // Sensitive - redacted in logs
	DB                int    `mapstructure:"db"`
	TLSEnabled        bool   `mapstructure:"tls_enabled"`
	WorkerTokenSecret string `mapstructure:"worker_token_secret"` // Sensitive; at least 32 bytes when enabled
}

// StorageConfig holds MinIO / S3 object store settings for worker evidence upload.
type StorageConfig struct {
	Endpoint       string `mapstructure:"endpoint"`
	AccessKey      string `mapstructure:"access_key"` // Sensitive - redacted in logs
	SecretKey      string `mapstructure:"secret_key"` // Sensitive - redacted in logs
	EvidenceBucket string `mapstructure:"evidence_bucket"`
	UseSSL         bool   `mapstructure:"use_ssl"`
}

// ResourceLimits are the enforceable cgroup/container bounds applied to every
// sandboxed scanner execution (P1-29).
type ResourceLimits struct {
	CPUQuota             string `mapstructure:"cpu_quota"`
	MemoryLimit          string `mapstructure:"memory_limit"`
	DiskLimit            string `mapstructure:"disk_limit"`
	MaxPIDs              int64  `mapstructure:"max_pids"`
	MaxConcurrentConns   int    `mapstructure:"max_concurrent_conns"`
	MaxRequestsPerTarget int    `mapstructure:"max_requests_per_target"`
	HardDeadlineSeconds  int64  `mapstructure:"hard_execution_deadline_seconds"`
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
	Limits       ResourceLimits `mapstructure:"limits"`
}

// toLimits converts config values into a limits.Limits, applying safe defaults
// for unset fields.
func (c Config) toLimits() (limits.Limits, error) {
	l := limits.DefaultLimits()
	if c.Limits.CPUQuota != "" {
		l.CPUQuota = c.Limits.CPUQuota
	}
	if c.Limits.MemoryLimit != "" {
		l.MemoryLimit = c.Limits.MemoryLimit
	}
	if c.Limits.DiskLimit != "" {
		l.DiskLimit = c.Limits.DiskLimit
	}
	if c.Limits.MaxPIDs > 0 {
		l.MaxPIDs = c.Limits.MaxPIDs
	}
	if c.Limits.MaxConcurrentConns > 0 {
		l.MaxConcurrentConns = c.Limits.MaxConcurrentConns
	}
	if c.Limits.MaxRequestsPerTarget > 0 {
		l.MaxRequestsPerTarget = c.Limits.MaxRequestsPerTarget
	}
	if c.Limits.HardDeadlineSeconds > 0 {
		l.HardDeadline = time.Duration(c.Limits.HardDeadlineSeconds) * time.Second
	}
	return l, l.Validate()
}

// hardDeadline returns the parsed hard deadline from config.
func (c Config) hardDeadline() time.Duration {
	if c.Limits.HardDeadlineSeconds > 0 {
		return time.Duration(c.Limits.HardDeadlineSeconds) * time.Second
	}
	return limits.DefaultLimits().HardDeadline
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

	// Resource limits defaults (P1-29); all are overridable via KELVIN_LIMITS_*.
	v.SetDefault("limits.cpu_quota", "1")
	v.SetDefault("limits.memory_limit", "512m")
	v.SetDefault("limits.disk_limit", "2g")
	v.SetDefault("limits.max_pids", int64(64))
	v.SetDefault("limits.max_concurrent_conns", 10)
	v.SetDefault("limits.max_requests_per_target", 5000)
	v.SetDefault("limits.hard_execution_deadline_seconds", int64(1800))

	bindEnvWithFallback(v, "env", "KELVIN_ENV")
	bindEnvWithFallback(v, "log_level", "KELVIN_LOG_LEVEL")
	bindEnvWithFallback(v, "worker.id", "KELVIN_WORKER_ID")
	bindEnvWithFallback(v, "worker.poll_interval", "KELVIN_WORKER_POLL_INTERVAL")

	bindEnvWithFallback(v, "limits.cpu_quota", "KELVIN_LIMITS_CPU_QUOTA")
	bindEnvWithFallback(v, "limits.memory_limit", "KELVIN_LIMITS_MEMORY_LIMIT")
	bindEnvWithFallback(v, "limits.disk_limit", "KELVIN_LIMITS_DISK_LIMIT")
	bindEnvWithFallback(v, "limits.max_pids", "KELVIN_LIMITS_MAX_PIDS")
	bindEnvWithFallback(v, "limits.max_concurrent_conns", "KELVIN_LIMITS_MAX_CONCURRENT_CONNS")
	bindEnvWithFallback(v, "limits.max_requests_per_target", "KELVIN_LIMITS_MAX_REQUESTS_PER_TARGET")
	bindEnvWithFallback(v, "limits.hard_execution_deadline_seconds", "KELVIN_LIMITS_HARD_EXECUTION_DEADLINE_SECONDS")

	bindEnvWithFallback(v, "database.url", "KELVIN_DATABASE_URL")
	bindEnvWithFallback(v, "database.url", "SUPABASE_DB_URL")
	bindEnvWithFallback(v, "database.sslrootcert", "KELVIN_DATABASE_SSL_ROOT_CERT")
	bindEnvWithFallback(v, "database.sslrootcert", "SUPABASE_CA_CERT_PATH")
	bindEnvWithFallback(v, "redis.url", "KELVIN_REDIS_URL")
	bindEnvWithFallback(v, "redis.url", "REDIS_URL")
	bindEnvWithFallback(v, "redis.addr", "KELVIN_REDIS_ADDR")
	bindEnvWithFallback(v, "redis.password", "KELVIN_REDIS_PASSWORD")
	bindEnvWithFallback(v, "redis.password", "REDIS_PASSWORD")
	bindEnvWithFallback(v, "redis.tls_enabled", "REDIS_TLS_ENABLED")
	bindEnvWithFallback(v, "redis.worker_token_secret", "KELVIN_WORKER_TOKEN_SECRET")
	bindEnvWithFallback(v, "storage.endpoint", "MINIO_ENDPOINT")
	bindEnvWithFallback(v, "storage.access_key", "MINIO_ROOT_USER")
	bindEnvWithFallback(v, "storage.secret_key", "MINIO_ROOT_PASSWORD")
	bindEnvWithFallback(v, "storage.evidence_bucket", "MINIO_BUCKET_EVIDENCE")
	bindEnvWithFallback(v, "storage.evidence_bucket", "SUPABASE_STORAGE_BUCKET_EVIDENCE")

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
	workerTokenSecret := v.GetString("redis.worker_token_secret")
	if workerTokenSecret != "" && len(workerTokenSecret) < 32 {
		return Config{}, errors.New("KELVIN_WORKER_TOKEN_SECRET must contain at least 32 bytes when configured")
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
			return Config{}, fmt.Errorf("invalid KELVIN_DATABASE_URL: %q (must start with postgres:// or postgresql://)", redactURL(dbURL))
		}
		u, err := url.Parse(dbURL)
		if err != nil {
			return Config{}, fmt.Errorf("invalid KELVIN_DATABASE_URL: %w", err)
		}
		sslMode := strings.ToLower(u.Query().Get("sslmode"))
		if env == EnvProduction || env == EnvStaging {
			if sslMode != "verify-full" {
				return Config{}, fmt.Errorf("verified database TLS (sslmode=verify-full) is required in %s; got %q", env, sslMode)
			}
		}
	}

	redisAddr := v.GetString("redis.addr")
	redisURL := v.GetString("redis.url")
	if redisAddr == "" && redisURL != "" {
		if u, err := url.Parse(redisURL); err == nil && u.Host != "" {
			redisAddr = u.Host
			if p, ok := u.User.Password(); ok && v.GetString("redis.password") == "" {
				v.Set("redis.password", p)
			}
		}
	}

	redisTLSEnabled := v.GetBool("redis.tls_enabled")
	if strings.HasPrefix(redisURL, "rediss://") {
		redisTLSEnabled = true
	}

	if env == EnvStaging || env == EnvProduction {
		if redisURL != "" && strings.HasPrefix(redisURL, "redis://") {
			return Config{}, fmt.Errorf("insecure plaintext Redis URL (%s) is prohibited in %s; rediss:// TLS scheme is strictly required", redactURL(redisURL), env)
		}
		if redisURL == "" && redisAddr != "" && !redisTLSEnabled {
			return Config{}, fmt.Errorf("plaintext Redis is prohibited in %s; REDIS_TLS_ENABLED=true is strictly required", env)
		}
		if !redisTLSEnabled {
			redisTLSEnabled = true
		}
	}

	cfg := Config{
		Env:          env,
		LogLevel:     logLevel,
		WorkerID:     workerID,
		PollInterval: pollInterval,
		Development:  env == EnvDevelopment || env == EnvTesting,
		Database: DatabaseConfig{
			URL:         dbURL,
			SSLRootCert: v.GetString("database.sslrootcert"),
		},
		Redis: RedisConfig{
			URL:               redisURL,
			Addr:              redisAddr,
			Password:          v.GetString("redis.password"),
			DB:                v.GetInt("redis.db"),
			TLSEnabled:        redisTLSEnabled,
			WorkerTokenSecret: workerTokenSecret,
		},
		Storage: StorageConfig{
			Endpoint:       v.GetString("storage.endpoint"),
			AccessKey:      v.GetString("storage.access_key"),
			SecretKey:      v.GetString("storage.secret_key"),
			EvidenceBucket: v.GetString("storage.evidence_bucket"),
			UseSSL:         v.GetBool("storage.use_ssl"),
		},
		Limits: ResourceLimits{
			CPUQuota:             v.GetString("limits.cpu_quota"),
			MemoryLimit:          v.GetString("limits.memory_limit"),
			DiskLimit:            v.GetString("limits.disk_limit"),
			MaxPIDs:              v.GetInt64("limits.max_pids"),
			MaxConcurrentConns:   v.GetInt("limits.max_concurrent_conns"),
			MaxRequestsPerTarget: v.GetInt("limits.max_requests_per_target"),
			HardDeadlineSeconds:  v.GetInt64("limits.hard_execution_deadline_seconds"),
		},
	}

	if cfg.Database.SSLRootCert != "" {
		if fi, err := os.Stat(cfg.Database.SSLRootCert); err != nil {
			return Config{}, fmt.Errorf("database sslrootcert file %q is not accessible: %w", cfg.Database.SSLRootCert, err)
		} else if fi.IsDir() {
			return Config{}, fmt.Errorf("database sslrootcert path %q is a directory, expected file", cfg.Database.SSLRootCert)
		}
	}

	if _, err := cfg.toLimits(); err != nil {
		return Config{}, fmt.Errorf("invalid resource limits: %w", err)
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

func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid-url]"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "REDACTED")
	}
	return u.String()
}
