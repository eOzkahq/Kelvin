package main

import (
	"context"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/config"
	"github.com/kelvin/kelvin/apps/worker/internal/daemon"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
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
		zap.NewNop().Fatal("invalid configuration", zap.Error(err))
	}

	log, err := logging.New(cfg.LogLevel, cfg.Development)
	if err != nil {
		zap.NewNop().Fatal("invalid log level", zap.Error(err))
	}
	logging.SetDefault(log)
	defer func() { _ = log.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	registry := adapters.NewRegistry()
	var executor sandbox.Executor
	var workQueue queue.Queue = queue.NopQueue{}
	if cfg.Env == config.EnvProduction && cfg.Redis.URL == "" && cfg.Redis.Addr == "" {
		log.Fatal("KELVIN_REDIS_ADDR or REDIS_URL is required in production")
	}
	if cfg.Env == config.EnvProduction && cfg.Redis.WorkerTokenSecret == "" {
		log.Fatal("KELVIN_WORKER_TOKEN_SECRET is required in production")
	}
	if cfg.Redis.URL != "" || cfg.Redis.Addr != "" {
		if len(registry.Names()) == 0 {
			log.Fatal("worker queue is configured but no scanner adapters are registered")
		}
		var err error
		executor, err = sandbox.NewOCIExecutor()
		if err != nil {
			log.Fatal("sandbox executor initialization failed", zap.Error(err))
		}
		redisCfg := commonredis.Config{
			URL:          cfg.Redis.URL,
			Addr:         cfg.Redis.Addr,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			TLSEnabled:   cfg.Redis.TLSEnabled || strings.HasPrefix(cfg.Redis.URL, "rediss://") || cfg.Env == config.EnvProduction,
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
		shared, err := commonqueue.NewRedis(redisClient.UniversalClient(), commonqueue.RedisConfig{Prefix: "kelvin:jobs", Group: "workers", Consumer: cfg.WorkerID, WorkerID: cfg.WorkerID, TokenSecret: []byte(cfg.Redis.WorkerTokenSecret)})
		if err != nil {
			log.Fatal("redis queue initialization failed", zap.Error(err))
		}
		workQueue, err = queue.NewRedisQueue(shared, cfg.WorkerID)
		if err != nil {
			log.Fatal("worker queue initialization failed", zap.Error(err))
		}
	}
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
