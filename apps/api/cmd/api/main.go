package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/database"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/apps/api/internal/idempotency"
	"github.com/kelvin/kelvin/apps/api/internal/storage"
	"github.com/kelvin/kelvin/apps/api/pkg/job"
	"github.com/kelvin/kelvin/packages/common/logging"
	commonredis "github.com/kelvin/kelvin/packages/common/redis"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type redisPinger struct{ client redis.UniversalClient }

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

	isProduction := cfg.Env == config.EnvProduction || (!cfg.Development && cfg.Env != config.EnvTesting)

	// 1. PostgreSQL connection & repositories
	if cfg.Database.URL != "" {
		pool, err := database.NewPool(context.Background(), cfg.Database.URL, database.DefaultPoolConfig(), log)
		if err != nil {
			log.Fatal("database connection failed", zap.Error(err))
		}
		defer pool.Close()
		ready.DB = pool

		// Composition Root: Wire Job Store and Findings Repository
		server.SetJobStore(job.Store{DB: pool})
		findingRepo := findings.NewPostgresFindingRepository(pool)
		server.SetFindingStore(findingRepo)
	} else if isProduction {
		log.Fatal("database connection is required in production")
	}

	// 2. Redis connection & Idempotency Store
	if cfg.Redis.URL != "" || cfg.Redis.Addr != "" {
		redisCfg := commonredis.Config{
			URL:          cfg.Redis.URL,
			Addr:         cfg.Redis.Addr,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			TLSEnabled:   cfg.Redis.TLSEnabled || strings.HasPrefix(cfg.Redis.URL, "rediss://") || isProduction,
			PoolSize:     commonredis.APIPoolSize,
			MinIdleConns: commonredis.APIMinIdleConns,
			DialTimeout:  commonredis.DefaultDialTimeout,
			ReadTimeout:  commonredis.DefaultReadTimeout,
			WriteTimeout: commonredis.DefaultWriteTimeout,
		}
		redisClient, err := commonredis.NewClient(redisCfg)
		if err != nil {
			log.Fatal("redis initialization failed", zap.Error(err))
		}
		if err := redisClient.Ping(context.Background()); err != nil {
			log.Fatal("redis connection failed", zap.Error(err))
		}
		defer func() { _ = redisClient.Close() }()
		ready.Redis = redisPinger{client: redisClient.UniversalClient()}

		// Composition Root: Wire Redis Idempotency Store
		idempTTL := time.Duration(cfg.Idempotency.TTLSeconds) * time.Second
		if idempTTL <= 0 {
			idempTTL = 24 * time.Hour
		}
		server.SetIdempotencyStore(idempotency.NewRedisStore(redisClient.UniversalClient(), idempTTL))
	} else if isProduction {
		log.Fatal("redis broker is required in production")
	}

	server.SetReadyCheckers(ready)

	// 3. Supabase Storage Provider
	if cfg.Supabase.URL != "" && cfg.Supabase.ServiceRoleKey != "" {
		_, err := storage.NewSupabaseStorageProvider(storage.Config{
			URL:             cfg.Supabase.URL,
			ServiceRoleKey:  cfg.Supabase.ServiceRoleKey,
			ReportsBucket:   cfg.Supabase.ReportsBucket,
			EvidenceBucket:  cfg.Supabase.EvidenceBucket,
			SignedURLExpiry: 300 * time.Second,
		})
		if err != nil {
			log.Fatal("supabase storage provider initialization failed", zap.Error(err))
		}
	} else if isProduction {
		log.Warn("supabase storage not fully configured; check cloud environment settings")
	}

	// 4. Authentication Middleware
	if cfg.Auth.JWTSecret != "" {
		tokenService, err := auth.NewTokenService(cfg.Auth.JWTSecret)
		if err != nil {
			log.Fatal("JWT authentication configuration failed", zap.Error(err))
		}
		server.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
			roles := auth.RequireRole(auth.RoleTenantAdmin, auth.RoleSecurityAnalyst)(next)
			return auth.Middleware(tokenService)(roles)
		})
	} else if isProduction {
		log.Fatal("JWT secret is required in production")
	}

	// 5. Fail-fast validation of required dependencies in production
	if err := server.ValidateDependencies(isProduction); err != nil {
		log.Fatal("production dependency validation failed", zap.Error(err))
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
			zap.String("env", string(cfg.Env)),
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
