package database

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// SupabaseConfig holds configuration specific to Supabase Managed PostgreSQL.
type SupabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Name            string        `mapstructure:"name"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int32         `mapstructure:"max_open_conns"`
	MaxIdleConns    int32         `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// DefaultSupabaseConfig returns enterprise defaults for Supabase PostgreSQL.
func DefaultSupabaseConfig() SupabaseConfig {
	return SupabaseConfig{
		Port:            5432,
		Name:            "postgres",
		User:            "postgres",
		SSLMode:         "verify-full",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 1 * time.Hour,
	}
}

// BuildSupabaseDatabaseURL constructs a compliant PostgreSQL connection URL from SupabaseConfig.
func BuildSupabaseDatabaseURL(cfg SupabaseConfig) string {
	if cfg.Port <= 0 {
		cfg.Port = 5432
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "verify-full"
	}
	if cfg.Name == "" {
		cfg.Name = "postgres"
	}

	userInfo := url.User(cfg.User)
	if cfg.Password != "" {
		userInfo = url.UserPassword(cfg.User, cfg.Password)
	}

	u := url.URL{
		Scheme: "postgresql",
		User:   userInfo,
		Host:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Path:   "/" + cfg.Name,
	}

	q := u.Query()
	q.Set("sslmode", cfg.SSLMode)
	u.RawQuery = q.Encode()

	return u.String()
}

// NewSupabasePool creates and initializes a pgxpool tailored for Supabase.
func NewSupabasePool(ctx context.Context, cfg SupabaseConfig, log *zap.Logger) (*pgxpool.Pool, error) {
	if cfg.Host == "" {
		return nil, errors.New("supabase: host is required")
	}

	connURL := BuildSupabaseDatabaseURL(cfg)
	poolCfg := PoolConfig{
		MaxConns:        cfg.MaxOpenConns,
		MinConns:        cfg.MaxIdleConns,
		MaxConnLifetime: cfg.ConnMaxLifetime,
		MaxConnIdleTime: 5 * time.Minute,
		HealthTimeout:   3 * time.Second,
	}

	if poolCfg.MaxConns <= 0 {
		poolCfg.MaxConns = 25
	}
	if poolCfg.MinConns <= 0 {
		poolCfg.MinConns = 5
	}
	if poolCfg.MaxConnLifetime <= 0 {
		poolCfg.MaxConnLifetime = 1 * time.Hour
	}

	log.Info("initializing supabase postgresql pool",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Name),
		zap.String("sslmode", cfg.SSLMode),
		zap.Int32("max_open_conns", poolCfg.MaxConns),
	)

	return NewPool(ctx, connURL, poolCfg, log)
}

// CheckSupabaseHealth performs a ping check against the Supabase database.
func CheckSupabaseHealth(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("supabase: pool is uninitialized")
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return pool.Ping(ctxTimeout)
}
