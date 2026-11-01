package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/database"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/packages/common/logging"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type redisPinger struct{ client *redis.Client }

func (p redisPinger) Ping(ctx context.Context) error { return p.client.Ping(ctx).Err() }

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
	ready := httpapi.ReadyCheckers{}
	if cfg.Database.URL != "" {
		pool, err := database.NewPool(context.Background(), cfg.Database.URL, database.DefaultPoolConfig(), log)
		if err != nil {
			log.Fatal("database connection failed", zap.Error(err))
		}
		defer pool.Close()
		ready.DB = pool
	}
	if cfg.Redis.Addr != "" {
		redisClient := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB})
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			log.Fatal("redis connection failed", zap.Error(err))
		}
		defer func() { _ = redisClient.Close() }()
		ready.Redis = redisPinger{client: redisClient}
	}
	server.SetReadyCheckers(ready)
	if cfg.Auth.JWTSecret != "" {
		tokenService, err := auth.NewTokenService(cfg.Auth.JWTSecret)
		if err != nil {
			log.Fatal("JWT authentication configuration failed", zap.Error(err))
		}
		server.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
			roles := auth.RequireRole(auth.RoleTenantAdmin, auth.RoleSecurityAnalyst)(next)
			return auth.Middleware(tokenService)(roles)
		})
	}
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
