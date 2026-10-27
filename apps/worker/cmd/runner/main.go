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
	err = daemon.Run(ctx, log, daemon.Config{
		WorkerID:     cfg.WorkerID,
		PollInterval: cfg.PollInterval,
	}, queue.NopQueue{}, registry)
	if err != nil {
		log.Fatal("worker daemon failed", zap.Error(err))
	}
}
