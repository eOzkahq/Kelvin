package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/database"
	"github.com/kelvin/kelvin/packages/common/logging"
	"go.uber.org/zap"
)

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

func resolveMigrationsPath(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return filepath.Abs(customPath)
		}
	}

	candidates := []string{
		"apps/api/db/migrations",
		"db/migrations",
		"/app/db/migrations",
		"../db/migrations",
		"../../db/migrations",
		"../../apps/api/db/migrations",
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return filepath.Abs(c)
		}
	}

	return "", fmt.Errorf("unable to locate database migrations directory; please specify with -path or KELVIN_MIGRATIONS_PATH")
}

func main() {
	var (
		pathFlag    = flag.String("path", os.Getenv("KELVIN_MIGRATIONS_PATH"), "Path to SQL migrations directory")
		envFlag     = flag.String("env", os.Getenv("KELVIN_ENV"), "Runtime environment (development, staging, production)")
		certFlag    = flag.String("ca-cert", os.Getenv("KELVIN_DATABASE_SSL_ROOT_CERT"), "Path to CA certificate bundle for verified TLS")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <command> [arguments]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  up               Apply all pending migrations")
		fmt.Fprintln(os.Stderr, "  down [steps]     Roll back last N migrations (default 1)")
		fmt.Fprintln(os.Stderr, "  version          Display current database migration version and dirty status")
		fmt.Fprintln(os.Stderr, "  force <version>  Force migration version and clear dirty state (disaster recovery)")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	command := strings.ToLower(args[0])

	if *envFlag != "" {
		_ = os.Setenv("KELVIN_ENV", *envFlag)
	}
	if *certFlag != "" {
		_ = os.Setenv("KELVIN_DATABASE_SSL_ROOT_CERT", *certFlag)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.New("info", cfg.Development)
	if err != nil {
		logger = zap.NewNop()
	}
	defer func() { _ = logger.Sync() }()

	migPath, err := resolveMigrationsPath(*pathFlag)
	if err != nil {
		logger.Fatal("failed to resolve migrations directory", zap.Error(err))
	}

	migOpts := database.MigratorOptions{
		MigrationsPath: migPath,
		DatabaseURL:    cfg.Database.URL,
		Environment:    string(cfg.Env),
		CACertPath:     cfg.Database.SSLRootCert,
	}

	migrator := database.NewMigratorWithOptions(migOpts, logger)

	logger.Info("KELVIN migration CLI initialized",
		zap.String("environment", string(cfg.Env)),
		zap.String("migrations_path", migPath),
		zap.String("database_host", redactURL(cfg.Database.URL)),
		zap.String("command", command),
	)

	switch command {
	case "version":
		v, dirty, err := migrator.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				fmt.Println("Current schema version: nil (no migrations applied yet)")
				return
			}
			logger.Fatal("failed to read migration version", zap.Error(err))
		}
		fmt.Printf("Current schema version: %d (dirty: %t)\n", v, dirty)
		if dirty {
			fmt.Fprintln(os.Stderr, "WARNING: Schema is currently marked as DIRTY. Resolve manually or run 'force <version>'.")
			os.Exit(1)
		}

	case "up":
		// 1. Pre-flight check: refuse to run if database is dirty
		v, dirty, err := migrator.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			logger.Fatal("pre-flight migration version check failed", zap.Error(err))
		}
		if dirty {
			logger.Fatal("DATABASE MIGRATION REJECTED: Schema is currently in a DIRTY state. Automatic migration cannot proceed on a dirty database. Investigate the failed migration, repair schema manually, and use 'force <version>' to reset the dirty status.",
				zap.Uint("dirty_version", v),
			)
		}

		if errors.Is(err, migrate.ErrNilVersion) {
			logger.Info("starting migration from scratch (no prior version)")
		} else {
			logger.Info("pre-flight check passed", zap.Uint("starting_version", v))
		}

		// 2. Execute migrations up
		if err := migrator.Up(); err != nil {
			logger.Fatal("database migration failed", zap.Error(err))
		}

		// 3. Post-migration verification
		vEnd, dirtyEnd, err := migrator.Version()
		if err != nil {
			logger.Fatal("post-migration verification failed", zap.Error(err))
		}
		if dirtyEnd {
			logger.Fatal("migration completed in a DIRTY state! Immediate intervention required", zap.Uint("dirty_version", vEnd))
		}
		logger.Info("database migrations verified successfully", zap.Uint("active_version", vEnd))
		fmt.Printf("Database schema is up to date at version %d (dirty: %t)\n", vEnd, dirtyEnd)

	case "down":
		steps := 1
		if len(args) > 1 {
			parsed, err := strconv.Atoi(args[1])
			if err != nil || parsed <= 0 {
				logger.Fatal("invalid down steps count; must be positive integer", zap.String("input", args[1]))
			}
			steps = parsed
		}

		vStart, _, _ := migrator.Version()
		logger.Warn("initiating rollback", zap.Uint("from_version", vStart), zap.Int("steps", steps))

		if err := migrator.Down(steps); err != nil {
			logger.Fatal("database rollback failed", zap.Error(err))
		}

		vEnd, dirtyEnd, err := migrator.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			logger.Fatal("post-rollback version check failed", zap.Error(err))
		}
		logger.Info("rollback finished", zap.Uint("new_version", vEnd), zap.Bool("dirty", dirtyEnd))
		fmt.Printf("Database rolled back to version %d (dirty: %t)\n", vEnd, dirtyEnd)

	case "force":
		if len(args) < 2 {
			logger.Fatal("force command requires a target version argument, e.g. 'migrate force 61'")
		}
		targetVersion, err := strconv.Atoi(args[1])
		if err != nil || targetVersion < 0 {
			logger.Fatal("invalid force version; must be non-negative integer", zap.String("input", args[1]))
		}

		logger.Warn("forcing database schema version and clearing dirty flag", zap.Int("target_version", targetVersion))
		if err := migrator.Force(targetVersion); err != nil {
			logger.Fatal("force version failed", zap.Error(err))
		}

		fmt.Printf("Schema version forced to %d. Dirty flag cleared.\n", targetVersion)

	default:
		flag.Usage()
		os.Exit(1)
	}
}
