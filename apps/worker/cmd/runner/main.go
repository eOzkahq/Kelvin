package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/config"
	"github.com/kelvin/kelvin/apps/worker/internal/daemon"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
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
	if lock, err := manifest.LoadCanonicalLock(canonicalLockPath); err == nil {
		log.Info("scanner release manifest loaded",
			zap.String("status", lock.Status),
			zap.String("schema_version", lock.SchemaVersion))
		if (cfg.Env == config.EnvProduction || cfg.Env == config.EnvStaging) && lock.Status == manifest.StatusNotReleased {
			log.Warn("ATTENTION: Scanner images are currently marked NOT-RELEASED. Any execution attempt for unreleased container images will fail closed until verified images are released and certified.")
		}
	} else {
		log.Warn("release manifest not found at canonical path, skipping pre-flight release check", zap.Error(err))
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
	} else if cfg.Env == config.EnvProduction {
		log.Fatal("worker queue must be connected to Redis in production")
	}

	// 4. Run Daemon loop with concurrency and resource bounds
	err = daemon.Run(ctx, log, daemon.Config{
		WorkerID:     cfg.WorkerID,
		PollInterval: cfg.PollInterval,
		Executor:     executor,
		Limits:       limits.DefaultLimits(),
		Metrics:      metrics.Default(),
	}, workQueue, registry)
	if err != nil {
		log.Fatal("worker daemon failed", zap.Error(err))
	}
}
