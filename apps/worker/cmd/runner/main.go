package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/config"
	"github.com/kelvin/kelvin/apps/worker/internal/daemon"
	"github.com/kelvin/kelvin/apps/worker/internal/queue"
	"github.com/kelvin/kelvin/packages/common/logging"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/redis/go-redis/v9"
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
	var workQueue queue.Queue = queue.NopQueue{}
	if cfg.Env == config.EnvProduction && cfg.Redis.Addr == "" {
		log.Fatal("KELVIN_REDIS_ADDR is required in production")
	}
	if cfg.Env == config.EnvProduction && cfg.Redis.WorkerTokenSecret == "" {
		log.Fatal("KELVIN_WORKER_TOKEN_SECRET is required in production")
	}
	if cfg.Redis.Addr != "" {
		client := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB})
		if err := client.Ping(ctx).Err(); err != nil {
			log.Fatal("redis connection failed", zap.Error(err))
		}
		defer func() { _ = client.Close() }()
		shared, err := commonqueue.NewRedis(client, commonqueue.RedisConfig{Prefix: "kelvin:jobs", Group: "workers", Consumer: cfg.WorkerID, WorkerID: cfg.WorkerID, TokenSecret: []byte(cfg.Redis.WorkerTokenSecret)})
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
	}, workQueue, registry)
	if err != nil {
		log.Fatal("worker daemon failed", zap.Error(err))
	}
}
