package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
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

	server := httpapi.New(cfg, log)
	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          nil,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("api listening",
			zap.String("addr", cfg.Addr),
			zap.String("api_version", cfg.APIVersion),
			zap.Bool("development", cfg.Development),
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Fatal("api server failed", zap.Error(err))
	case <-ctx.Done():
	}

	log.Info("api shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeoutS)*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", zap.Error(err))
	}
}
