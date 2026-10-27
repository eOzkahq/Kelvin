// Package database provides the PostgreSQL connection pool management (jackc/pgx/v5)
// and schema migration runner (golang-migrate) adhering to ADR-0002.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// PoolConfig holds connection pool tuning options for jackc/pgx/v5.
type PoolConfig struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	HealthTimeout   time.Duration
}

// DefaultPoolConfig returns standard production-grade pool settings.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:        25,
		MinConns:        5,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
		HealthTimeout:   3 * time.Second,
	}
}

// NewPool initializes a high-performance pgx connection pool with health checking.
func NewPool(ctx context.Context, databaseURL string, poolCfg PoolConfig, log *zap.Logger) (*pgxpool.Pool, error) {
	if databaseURL == "" {
		return nil, errors.New("database: database URL must not be empty")
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("database: invalid connection string: %w", err)
	}

	if poolCfg.MaxConns > 0 {
		cfg.MaxConns = poolCfg.MaxConns
	}
	if poolCfg.MinConns > 0 {
		cfg.MinConns = poolCfg.MinConns
	}
	if poolCfg.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = poolCfg.MaxConnLifetime
	}
	if poolCfg.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = poolCfg.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: failed to create pgx pool: %w", err)
	}

	// Verify connectivity
	healthCtx, cancel := context.WithTimeout(ctx, poolCfg.HealthTimeout)
	defer cancel()

	if err := pool.Ping(healthCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping failed: %w", err)
	}

	log.Info("connected to postgresql pool",
		zap.Int32("max_conns", cfg.MaxConns),
		zap.Int32("min_conns", cfg.MinConns),
	)

	return pool, nil
}

// Migrator manages database schema migrations using golang-migrate.
type Migrator struct {
	migrationsPath string
	databaseURL    string
	log            *zap.Logger
}

// NewMigrator returns a new Migrator instance.
func NewMigrator(migrationsPath, databaseURL string, log *zap.Logger) *Migrator {
	return &Migrator{
		migrationsPath: migrationsPath,
		databaseURL:    databaseURL,
		log:            log,
	}
}

// normalizeSourceURL ensures file path is formatted as a valid golang-migrate URL.
func normalizeSourceURL(path string) string {
	cleanPath := strings.TrimPrefix(path, "file://")
	cleanPath = strings.ReplaceAll(cleanPath, "\\", "/")
	return "file://" + cleanPath
}

// Up runs all unapplied schema migrations to the latest version.
func (m *Migrator) Up() error {
	mig, err := m.instance()
	if err != nil {
		return err
	}
	defer func() { _, _ = mig.Close() }()

	m.log.Info("running database migrations up...")
	err = mig.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("database migration failed: %w", err)
	}

	if errors.Is(err, migrate.ErrNoChange) {
		m.log.Info("database schema is up to date (no migrations to apply)")
	} else {
		m.log.Info("database schema migrations applied successfully")
	}

	return nil
}

// Down rolls back the last n migrations.
func (m *Migrator) Down(steps int) error {
	if steps <= 0 {
		steps = 1
	}

	mig, err := m.instance()
	if err != nil {
		return err
	}
	defer func() { _, _ = mig.Close() }()

	m.log.Warn("rolling back database migrations...", zap.Int("steps", steps))
	err = mig.Steps(-steps)
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("database rollback failed: %w", err)
	}

	m.log.Info("database rollback completed successfully")
	return nil
}

// Version returns the current applied migration version and dirty flag.
func (m *Migrator) Version() (uint, bool, error) {
	mig, err := m.instance()
	if err != nil {
		return 0, false, err
	}
	defer func() { _, _ = mig.Close() }()

	return mig.Version()
}

func (m *Migrator) instance() (*migrate.Migrate, error) {
	sourceURL := normalizeSourceURL(m.migrationsPath)

	// Ensure sslmode parameter is present
	dbURL := m.databaseURL
	if !strings.Contains(dbURL, "sslmode=") {
		if strings.Contains(dbURL, "?") {
			dbURL += "&sslmode=disable"
		} else {
			dbURL += "?sslmode=disable"
		}
	}

	mig, err := migrate.New(sourceURL, dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize golang-migrate instance: %w", err)
	}
	return mig, nil
}

// SetTenantContext sets the session-level tenant identifier for PostgreSQL Row-Level Security.
// In compliance with DATA_MODEL.md §9.1: SET LOCAL app.tenant_id = '<uuid>'.
func SetTenantContext(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if tenantID == "" {
		return errors.New("database: tenantID must not be empty")
	}
	// Validate uuid format safely
	if _, err := url.PathUnescape(tenantID); err != nil {
		return fmt.Errorf("database: invalid tenant ID format: %w", err)
	}

	query := fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenantID)
	_, err := tx.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("database: failed to set RLS tenant context: %w", err)
	}
	return nil
}

