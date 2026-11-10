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

type AuthConfig struct {
	JWTSecret string `mapstructure:"jwt_secret"`
}

// RedisConfig holds typed Redis task broker parameters (ADR-0003).
type RedisConfig struct {
	URL        string `mapstructure:"url"`
	Addr       string `mapstructure:"addr"`
	Password   string `mapstructure:"password"` // Sensitive - redacted in logs
	DB         int    `mapstructure:"db"`
	TLSEnabled bool   `mapstructure:"tls_enabled"`
}

// SupabaseConfig holds managed cloud settings for Supabase PostgreSQL and Storage (INFRA-01).
type SupabaseConfig struct {
	URL            string `mapstructure:"url"`
	AnonKey        string `mapstructure:"anon_key"`
	ServiceRoleKey string `mapstructure:"service_role_key"` // Sensitive - redacted in logs
	DBHost         string `mapstructure:"db_host"`
	DBPort         int    `mapstructure:"db_port"`
	DBName         string `mapstructure:"db_name"`
	DBUser         string `mapstructure:"db_user"`
	DBPassword     string `mapstructure:"db_password"` // Sensitive - redacted in logs
	DBSSLMode      string `mapstructure:"db_sslmode"`
	ReportsBucket  string `mapstructure:"storage_bucket_reports"`
	EvidenceBucket string `mapstructure:"storage_bucket_evidence"`
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

// EvidenceConfig holds evidence artifact storage and signed URL settings.
type EvidenceConfig struct {
	SigningKey          string `mapstructure:"signing_key"`            // HMAC signing key for signed URLs (32+ bytes)
	SignedURLTTLSeconds int    `mapstructure:"signed_url_ttl_seconds"` // TTL for signed download URLs (default 15min = 900)
}

// RetentionConfig holds evidence retention policy settings.
type RetentionConfig struct {
	ActiveDays     int `mapstructure:"active_days"`      // Days evidence remains active (default 90)
	ArchivedDays   int `mapstructure:"archived_days"`    // Days evidence remains archived (default 270)
	PurgeGraceDays int `mapstructure:"purge_grace_days"` // Grace days before hard delete (default 7)
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
	Auth             AuthConfig        `mapstructure:"auth"`
	Redis            RedisConfig       `mapstructure:"redis"`
	Supabase         SupabaseConfig    `mapstructure:"supabase"`
	Storage          StorageConfig     `mapstructure:"storage"`
	Idempotency      IdempotencyConfig `mapstructure:"idempotency"`
	Evidence         EvidenceConfig    `mapstructure:"evidence"`
	Retention        RetentionConfig   `mapstructure:"retention"`
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

	// Evidence signed URL TTL (default 5 minutes = 300 seconds).
	v.SetDefault("evidence.signed_url_ttl_seconds", 300)

	// Supabase private storage bucket defaults.
	v.SetDefault("supabase.storage_bucket_reports", "kelvin-reports")
	v.SetDefault("supabase.storage_bucket_evidence", "kelvin-evidence")

	// Evidence retention policy defaults (DATA_LIFECYCLE.md §3).
	v.SetDefault("retention.active_days", 90)
	v.SetDefault("retention.archived_days", 270)
	v.SetDefault("retention.purge_grace_days", 7)

	// Direct environment bindings for compatibility with KELVIN_* and service-specific envs
	bindEnvWithFallback(v, "env", "KELVIN_ENV")
	bindEnvWithFallback(v, "log_level", "KELVIN_LOG_LEVEL")
	bindEnvWithFallback(v, "api.addr", "KELVIN_API_ADDR")
	bindEnvWithFallback(v, "api.version", "KELVIN_API_VERSION")
	bindEnvWithFallback(v, "api.body_limit_bytes", "KELVIN_API_BODY_LIMIT_BYTES")

	bindEnvWithFallback(v, "idempotency.ttl_seconds", "KELVIN_IDEMPOTENCY_TTL_SECONDS")
	bindEnvWithFallback(v, "evidence.signing_key", "KELVIN_EVIDENCE_SIGNING_KEY")
	bindEnvWithFallback(v, "evidence.signed_url_ttl_seconds", "KELVIN_EVIDENCE_SIGNED_URL_TTL_SECONDS")
	bindEnvWithFallback(v, "retention.active_days", "KELVIN_RETENTION_ACTIVE_DAYS")
	bindEnvWithFallback(v, "retention.archived_days", "KELVIN_RETENTION_ARCHIVED_DAYS")
	bindEnvWithFallback(v, "retention.purge_grace_days", "KELVIN_RETENTION_PURGE_GRACE_DAYS")

	bindEnvWithFallback(v, "database.url", "KELVIN_DATABASE_URL")
	bindEnvWithFallback(v, "database.host", "POSTGRES_HOST")
	bindEnvWithFallback(v, "database.port", "POSTGRES_PORT")
	bindEnvWithFallback(v, "database.user", "POSTGRES_USER")
	bindEnvWithFallback(v, "database.password", "POSTGRES_PASSWORD")
	bindEnvWithFallback(v, "database.database", "POSTGRES_DB")
	bindEnvWithFallback(v, "auth.jwt_secret", "KELVIN_JWT_SECRET")

	bindEnvWithFallback(v, "redis.url", "REDIS_URL")
	bindEnvWithFallback(v, "redis.addr", "KELVIN_REDIS_ADDR")
	bindEnvWithFallback(v, "redis.password", "KELVIN_REDIS_PASSWORD")
	bindEnvWithFallback(v, "redis.password", "REDIS_PASSWORD")
	bindEnvWithFallback(v, "redis.db", "REDIS_DB")
	bindEnvWithFallback(v, "redis.tls_enabled", "REDIS_TLS_ENABLED")

	bindEnvWithFallback(v, "supabase.url", "SUPABASE_URL")
	bindEnvWithFallback(v, "supabase.anon_key", "SUPABASE_ANON_KEY")
	bindEnvWithFallback(v, "supabase.service_role_key", "SUPABASE_SERVICE_ROLE_KEY")
	bindEnvWithFallback(v, "supabase.db_host", "SUPABASE_DB_HOST")
	bindEnvWithFallback(v, "supabase.db_port", "SUPABASE_DB_PORT")
	bindEnvWithFallback(v, "supabase.db_name", "SUPABASE_DB_NAME")
	bindEnvWithFallback(v, "supabase.db_user", "SUPABASE_DB_USER")
	bindEnvWithFallback(v, "supabase.db_password", "SUPABASE_DB_PASSWORD")
	bindEnvWithFallback(v, "supabase.db_sslmode", "SUPABASE_DB_SSLMODE")
	bindEnvWithFallback(v, "supabase.storage_bucket_reports", "SUPABASE_STORAGE_BUCKET_REPORTS")
	bindEnvWithFallback(v, "supabase.storage_bucket_evidence", "SUPABASE_STORAGE_BUCKET_EVIDENCE")

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
	supabaseHost := v.GetString("supabase.db_host")
	if dbURL == "" && supabaseHost != "" {
		port := v.GetInt("supabase.db_port")
		if port <= 0 {
			port = 5432
		}
		user := v.GetString("supabase.db_user")
		if user == "" {
			user = "postgres"
		}
		name := v.GetString("supabase.db_name")
		if name == "" {
			name = "postgres"
		}
		sslMode := v.GetString("supabase.db_sslmode")
		if sslMode == "" {
			sslMode = "verify-full"
		}
		userInfo := url.User(user)
		if pw := v.GetString("supabase.db_password"); pw != "" {
			userInfo = url.UserPassword(user, pw)
		}
		u := url.URL{
			Scheme:   "postgresql",
			User:     userInfo,
			Host:     fmt.Sprintf("%s:%d", supabaseHost, port),
			Path:     "/" + name,
			RawQuery: "sslmode=" + sslMode,
		}
		dbURL = u.String()
	}

	if dbURL != "" {
		if !strings.HasPrefix(dbURL, "postgres://") && !strings.HasPrefix(dbURL, "postgresql://") {
			return Config{}, fmt.Errorf("invalid KELVIN_DATABASE_URL: %q (must start with postgres:// or postgresql://)", dbURL)
		}
		if _, err := url.Parse(dbURL); err != nil {
			return Config{}, fmt.Errorf("invalid KELVIN_DATABASE_URL: %w", err)
		}
	} else if env == EnvStaging || env == EnvProduction {
		return Config{}, errors.New("KELVIN_DATABASE_URL or SUPABASE_DB_HOST is required in staging and production environments")
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
	if (env == EnvStaging || env == EnvProduction) && redisAddr == "" && redisURL == "" {
		return Config{}, errors.New("KELVIN_REDIS_ADDR or REDIS_URL is required in staging and production environments")
	}
	jwtSecret := v.GetString("auth.jwt_secret")
	if env == EnvStaging || env == EnvProduction {
		if len(jwtSecret) < 32 {
			return Config{}, errors.New("KELVIN_JWT_SECRET of at least 32 bytes is required in staging and production")
		}
	} else if jwtSecret != "" && len(jwtSecret) < 32 {
		return Config{}, errors.New("KELVIN_JWT_SECRET must be at least 32 bytes when set")
	}

	signingKey := v.GetString("evidence.signing_key")
	if env == EnvStaging || env == EnvProduction {
		if len(signingKey) < 32 || signingKey == "kelvin-default-evidence-signing-key-32-bytes" {
			return Config{}, errors.New("KELVIN_EVIDENCE_SIGNING_KEY of at least 32 bytes is required in staging and production; hardcoded fallback key is prohibited")
		}
	} else if signingKey != "" && (len(signingKey) < 32 || signingKey == "kelvin-default-evidence-signing-key-32-bytes") {
		return Config{}, errors.New("KELVIN_EVIDENCE_SIGNING_KEY must be at least 32 bytes and cannot use default fallback key")
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
		Auth: AuthConfig{JWTSecret: jwtSecret},
		Redis: RedisConfig{
			URL:        redisURL,
			Addr:       redisAddr,
			Password:   v.GetString("redis.password"),
			DB:         v.GetInt("redis.db"),
			TLSEnabled: v.GetBool("redis.tls_enabled") || strings.HasPrefix(redisURL, "rediss://"),
		},
		Supabase: SupabaseConfig{
			URL:            v.GetString("supabase.url"),
			AnonKey:        v.GetString("supabase.anon_key"),
			ServiceRoleKey: v.GetString("supabase.service_role_key"),
			DBHost:         v.GetString("supabase.db_host"),
			DBPort:         v.GetInt("supabase.db_port"),
			DBName:         v.GetString("supabase.db_name"),
			DBUser:         v.GetString("supabase.db_user"),
			DBPassword:     v.GetString("supabase.db_password"),
			DBSSLMode:      v.GetString("supabase.db_sslmode"),
			ReportsBucket:  v.GetString("supabase.storage_bucket_reports"),
			EvidenceBucket: v.GetString("supabase.storage_bucket_evidence"),
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
		Evidence: EvidenceConfig{
			SigningKey:          v.GetString("evidence.signing_key"),
			SignedURLTTLSeconds: v.GetInt("evidence.signed_url_ttl_seconds"),
		},
		Retention: RetentionConfig{
			ActiveDays:     v.GetInt("retention.active_days"),
			ArchivedDays:   v.GetInt("retention.archived_days"),
			PurgeGraceDays: v.GetInt("retention.purge_grace_days"),
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
