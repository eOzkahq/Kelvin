// Package database provides the PostgreSQL connection pool management (jackc/pgx/v5)
// and schema migration runner (golang-migrate) adhering to ADR-0002.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
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
	env            string
	caCertPath     string
	log            *zap.Logger
}

// MigratorOptions holds configuration options for Migrator initialization.
type MigratorOptions struct {
	MigrationsPath string
	DatabaseURL    string
	Environment    string
	CACertPath     string
}

// NewMigrator returns a new Migrator instance.
func NewMigrator(migrationsPath, databaseURL string, log *zap.Logger) *Migrator {
	return &Migrator{
		migrationsPath: migrationsPath,
		databaseURL:    databaseURL,
		log:            log,
	}
}

// NewMigratorWithOptions returns a new Migrator configured with explicit options.
func NewMigratorWithOptions(opts MigratorOptions, log *zap.Logger) *Migrator {
	return &Migrator{
		migrationsPath: opts.MigrationsPath,
		databaseURL:    opts.DatabaseURL,
		env:            strings.ToLower(strings.TrimSpace(opts.Environment)),
		caCertPath:     strings.TrimSpace(opts.CACertPath),
		log:            log,
	}
}

// SetEnvironment configures the target environment tier ("development", "staging", "production").
func (m *Migrator) SetEnvironment(env string) {
	m.env = strings.ToLower(strings.TrimSpace(env))
}

// SetCACertPath sets a custom CA certificate path for verified TLS.
func (m *Migrator) SetCACertPath(path string) {
	m.caCertPath = strings.TrimSpace(path)
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

// Force sets the schema version and clears the dirty flag (useful for disaster recovery).
func (m *Migrator) Force(version int) error {
	mig, err := m.instance()
	if err != nil {
		return err
	}
	defer func() { _, _ = mig.Close() }()

	m.log.Warn("forcing migration version...", zap.Int("version", version))
	return mig.Force(version)
}

func (m *Migrator) instance() (*migrate.Migrate, error) {
	sourceURL := normalizeSourceURL(m.migrationsPath)

	if m.databaseURL == "" {
		return nil, errors.New("database migration: database connection URL is required and must not be empty")
	}

	u, err := url.Parse(m.databaseURL)
	if err != nil {
		return nil, fmt.Errorf("database migration: invalid database connection URL: %w", err)
	}

	q := u.Query()
	sslMode := strings.ToLower(strings.TrimSpace(q.Get("sslmode")))

	// Insecure implicit fallback (?sslmode=disable) is strictly prohibited.
	// Missing SSL mode produces a clear error.
	if sslMode == "" {
		return nil, errors.New("database migration: missing required 'sslmode' query parameter in database URL (staging and production require sslmode=verify-full; local development requires explicit deliberate configuration)")
	}

	env := m.env
	if env == "" {
		if envVal := os.Getenv("KELVIN_ENV"); envVal != "" {
			env = strings.ToLower(strings.TrimSpace(envVal))
		} else if envVal := os.Getenv("APP_ENV"); envVal != "" {
			env = strings.ToLower(strings.TrimSpace(envVal))
		}
	}

	isStagingOrProd := env == "production" || env == "staging"
	if isStagingOrProd {
		if sslMode != "verify-full" {
			return nil, fmt.Errorf("database migration: insecure sslmode=%q is prohibited in %s (sslmode=verify-full is strictly required)", sslMode, env)
		}
	}

	// Apply configured CA certificate path if provided and not already present in URL query
	if m.caCertPath != "" && q.Get("sslrootcert") == "" {
		q.Set("sslrootcert", m.caCertPath)
		u.RawQuery = q.Encode()
	}

	// If sslrootcert is configured, verify that the certificate file exists
	if rootCert := q.Get("sslrootcert"); rootCert != "" {
		if _, statErr := os.Stat(rootCert); statErr != nil {
			return nil, fmt.Errorf("database migration: CA certificate file not found at sslrootcert path %q: %w", rootCert, statErr)
		}
	}

	dbURL := u.String()
	mig, err := migrate.New(sourceURL, dbURL)
	if err != nil {
		redactedHost := u.Host
		return nil, fmt.Errorf("failed to initialize golang-migrate instance for %s: %w", redactedHost, err)
	}
	return mig, nil
}

// SetTenantContext sets the transaction-local application role and tenant for PostgreSQL RLS.
// In compliance with DATA_MODEL.md §9.1: transaction-local app.tenant_id.
func SetTenantContext(ctx context.Context, tx *sql.Tx, tenantID string) error {
	id, err := uuid.Parse(tenantID)
	if err != nil || id == uuid.Nil {
		return errors.New("database: invalid tenant ID")
	}
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE kelvin_app"); err != nil {
		return fmt.Errorf("database: assume tenant-scoped application role: %w", err)
	}
	_, err = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", id.String())
	if err != nil {
		return fmt.Errorf("database: failed to set RLS tenant context: %w", err)
	}
	return nil
}
