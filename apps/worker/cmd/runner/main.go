package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/config"
	"github.com/kelvin/kelvin/apps/worker/internal/daemon"
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/logging"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	commonredis "github.com/kelvin/kelvin/packages/common/redis"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "worker startup configuration error: %v\n", err)
		os.Exit(1)
	}

	log, err := logging.New(cfg.LogLevel, cfg.Development)
	if err != nil {
		fmt.Fprintf(os.Stderr, "worker startup logger initialization error: %v\n", err)
		os.Exit(1)
	}
	logging.SetDefault(log)
	defer func() { _ = log.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Initialize OCI sandbox executor
	var executor sandbox.Executor
	ociExec, err := sandbox.NewOCIExecutor()
	if err != nil {
		if cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging {
			log.Fatal("sandbox executor initialization failed", zap.Error(err))
		}
		log.Warn("no OCI container runtime found, falling back to simulated sandbox", zap.Error(err))
		executor = sandbox.NewFake()
	} else {
		if err := ociExec.VerifyRuntime(ctx); err != nil {
			if cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging {
				log.Fatal("sandbox runtime verification failed", zap.Error(err))
			}
			log.Warn("OCI container runtime verification failed, falling back to simulated sandbox", zap.Error(err))
			executor = sandbox.NewFake()
		} else {
			if cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging {
				if err := ociExec.VerifyRootlessPodman(ctx); err != nil {
					if os.Getenv("KELVIN_ALLOW_INSECURE_RUNTIME") != "true" {
						log.Fatal("ADR-0008 runtime verification failed: rootless podman and cgroups v2 are required", zap.Error(err))
					}
					log.Warn("running with non-compliant runtime because KELVIN_ALLOW_INSECURE_RUNTIME is set", zap.Error(err))
				}
				if err := ociExec.VerifyScannerNetwork(ctx, ""); err != nil {
					if os.Getenv("KELVIN_ALLOW_INSECURE_RUNTIME") != "true" {
						log.Fatal("ADR-0008 network verification failed: internal scanner network is required", zap.Error(err))
					}
					log.Warn("internal scanner network verification failed", zap.Error(err))
				}
			}
			log.Info("OCI container runtime verified",
				zap.String("runtime", ociExec.RuntimePath()),
				zap.String("cgroups", ociExec.Metadata().CgroupVersion),
				zap.Bool("rootless", ociExec.Metadata().Rootless),
				zap.String("oci_runtime", ociExec.Metadata().OCIRuntime))
			executor = ociExec
		}
	}

	// 1.1 Verify Scanner Image Release Status (Fail-Closed Governance)
	canonicalLockPath := "deploy/scanners/images.lock.json"
	yamlLockPath := "deploy/scanner-image-lock.yaml"
	lock, err := manifest.LoadCanonicalLock(canonicalLockPath)
	if err != nil {
		if cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging {
			log.Fatal("missing or invalid release manifest in production/staging environment", zap.Error(err))
		}
		log.Warn("release manifest not found at canonical path, skipping pre-flight release check in dev", zap.Error(err))
	} else {
		log.Info("scanner release manifest loaded",
			zap.String("status", lock.Status),
			zap.String("schema_version", lock.SchemaVersion))
		if (cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging) {
			if err := manifest.ValidateLockConsistency(yamlLockPath, canonicalLockPath); err != nil {
				log.Fatal("release manifests are inconsistent", zap.Error(err))
			}
			if lock.Status != manifest.StatusCertified {
				log.Warn("ATTENTION: Scanner images are currently marked NOT-RELEASED. Execution of unreleased container images will fail closed until verified images are released and certified.")
			}
		}
	}

	// 2. Register MVP scanner adapters into registry
	registry := adapters.NewRegistry()
	if err := adapters.RegisterDefaultAdapters(registry, executor); err != nil {
		log.Fatal("failed to register default scanner adapters", zap.Error(err))
	}
	if err := registry.Initialize(ctx, log); err != nil {
		log.Fatal("failed to initialize adapter registry", zap.Error(err))
	}

	// 3. Connect Redis Queue Consumer
	var workQueue queue.Queue = queue.NopQueue{}
	isProdLike := cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging
	if isProdLike && cfg.Redis.URL == "" && cfg.Redis.Addr == "" {
		log.Fatal("KELVIN_REDIS_ADDR or REDIS_URL is required in staging and production")
	}
	if isProdLike && cfg.Redis.WorkerTokenSecret == "" {
		log.Fatal("KELVIN_WORKER_TOKEN_SECRET is required in staging and production")
	}
	if cfg.Redis.URL != "" || cfg.Redis.Addr != "" {
		redisCfg := commonredis.Config{
			URL:          cfg.Redis.URL,
			Addr:         cfg.Redis.Addr,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			TLSEnabled:   cfg.Redis.TLSEnabled || strings.HasPrefix(cfg.Redis.URL, "rediss://") || isProdLike,
			PoolSize:     commonredis.WorkerPoolSize,
			MinIdleConns: commonredis.WorkerMinIdleConns,
			DialTimeout:  commonredis.DefaultDialTimeout,
			ReadTimeout:  commonredis.DefaultReadTimeout,
			WriteTimeout: commonredis.DefaultWriteTimeout,
		}
		redisClient, err := commonredis.NewClient(redisCfg)
		if err != nil {
			log.Fatal("redis client initialization failed", zap.Error(err))
		}
		if err := redisClient.Ping(ctx); err != nil {
			log.Fatal("redis connection failed", zap.Error(err))
		}
		defer func() { _ = redisClient.Close() }()
		shared, err := commonqueue.NewRedis(redisClient.UniversalClient(), commonqueue.RedisConfig{
			Prefix:      "kelvin:jobs",
			Group:       "workers",
			Consumer:    cfg.WorkerID,
			WorkerID:    cfg.WorkerID,
			TokenSecret: []byte(cfg.Redis.WorkerTokenSecret),
		})
		if err != nil {
			log.Fatal("redis queue initialization failed", zap.Error(err))
		}
		workQueue, err = queue.NewRedisQueue(shared, cfg.WorkerID)
		if err != nil {
			log.Fatal("worker queue initialization failed", zap.Error(err))
		}
		log.Info("worker connected to redis job stream",
			zap.String("stream", "kelvin:jobs:stream"),
			zap.String("group", "workers"),
			zap.String("consumer", cfg.WorkerID),
		)
	} else if cfg.Env == config.EnvProduction {
		log.Fatal("worker queue must be connected to Redis in production")
	}

	// 4. Initialize Database Connection Pool and State Syncer
	var stateSyncer daemon.StateSyncer = daemon.NewMemoryStateSyncer()
	if cfg.Database.URL != "" {
		poolCfg, err := pgxpool.ParseConfig(cfg.Database.URL)
		if err == nil {
			caPath := cfg.Database.SSLRootCert
			if caPath == "" {
				if parsed, pErr := url.Parse(cfg.Database.URL); pErr == nil {
					caPath = parsed.Query().Get("sslrootcert")
				}
			}
			if caPath != "" {
				if caBytes, rErr := os.ReadFile(caPath); rErr == nil {
					pool, pErr := x509.SystemCertPool()
					if pErr != nil || pool == nil {
						pool = x509.NewCertPool()
					}
					if pool.AppendCertsFromPEM(caBytes) {
						if poolCfg.ConnConfig.TLSConfig == nil {
							poolCfg.ConnConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
						}
						poolCfg.ConnConfig.TLSConfig.RootCAs = pool
						if parsed, pErr := url.Parse(cfg.Database.URL); pErr == nil && parsed.Hostname() != "" {
							poolCfg.ConnConfig.TLSConfig.ServerName = parsed.Hostname()
						}
					}
				}
			}
			dbPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
			if err == nil {
				defer dbPool.Close()
				stateSyncer = daemon.NewPostgresStateSyncer(dbPool)
				log.Info("worker database state synchronizer initialized with PostgreSQL pool")
			} else {
				log.Warn("failed to initialize worker database connection pool", zap.Error(err))
			}
		}
	}

	// 5. Initialize Readiness Checker & Diagnostics HTTP Server (:8081/healthz, :8081/readyz)
	checker := readiness.NewDefaultChecker(registry, exec.LookPath, "deploy/catalogs", "/tmp/kelvin-workspace", log)
	healthAddr := cfg.HealthAddr
	if healthAddr == "" {
		healthAddr = ":8081"
	}
	healthServer := &http.Server{
		Addr:    healthAddr,
		Handler: readiness.HTTPHandler(checker),
	}
	go func() {
		log.Info("worker diagnostics HTTP server listening", zap.String("addr", healthAddr))
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("worker diagnostics HTTP server terminated", zap.Error(err))
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = healthServer.Shutdown(shutdownCtx)
	}()

	// 6. Run Daemon loop with concurrency, lease recovery, and resource bounds
	configuredLimits, err := cfg.ToLimits()
	if err != nil {
		log.Fatal("invalid worker resource limits", zap.Error(err))
	}

	err = daemon.Run(ctx, log, daemon.Config{
		WorkerID:             cfg.WorkerID,
		Env:                  string(cfg.Env),
		PollInterval:         cfg.PollInterval,
		Executor:             executor,
		Limits:               configuredLimits,
		Metrics:              metrics.Default(),
		ReadinessChecker:      checker,
		ScopePolicyProvider:  adapters.DefaultScopePolicyProvider,
		StateSyncer:          stateSyncer,
		CanaryOnly:           cfg.CanaryOnly,
		CanaryAllowedTargets: cfg.CanaryAllowedTargets,
	}, workQueue, registry)
	if err != nil {
		log.Fatal("worker daemon failed", zap.Error(err))
	}
}
