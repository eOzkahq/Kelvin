package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Default configuration constants for Redis 7+ infrastructure.
const (
	DefaultPoolSize     = 5
	DefaultMinIdleConns = 2
	APIPoolSize         = 5
	APIMinIdleConns     = 2
	WorkerPoolSize      = 3
	WorkerMinIdleConns  = 1
	DefaultDialTimeout  = 5 * time.Second
	DefaultReadTimeout  = 3 * time.Second
	DefaultWriteTimeout = 3 * time.Second
)

// Config encapsulates connection and pooling settings for the Redis infrastructure.
type Config struct {
	URL          string        `json:"url"`
	Addr         string        `json:"addr"`
	Password     string        `json:"-"` // sensitive
	DB           int           `json:"db"`
	TLSEnabled   bool          `json:"tls_enabled"`
	PoolSize     int           `json:"pool_size"`
	MinIdleConns int           `json:"min_idle_conns"`
	DialTimeout  time.Duration `json:"dial_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
}

// Client wraps the underlying go-redis client with connection pooling, health checks, and metrics.
type Client struct {
	rdb redis.UniversalClient
	cfg Config
}

// DefaultConfig returns safe production defaults for Redis client configuration.
func DefaultConfig() Config {
	return Config{
		Addr:         "localhost:6379",
		DB:           0,
		TLSEnabled:   false,
		PoolSize:     DefaultPoolSize,
		MinIdleConns: DefaultMinIdleConns,
		DialTimeout:  DefaultDialTimeout,
		ReadTimeout:  DefaultReadTimeout,
		WriteTimeout: DefaultWriteTimeout,
	}
}

// NewClient initializes and connects a pooled Redis client based on Config.
func NewClient(cfg Config) (*Client, error) {
	opts := &redis.Options{
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	if opts.PoolSize <= 0 {
		opts.PoolSize = DefaultPoolSize
	}
	if opts.MinIdleConns <= 0 {
		opts.MinIdleConns = DefaultMinIdleConns
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = DefaultReadTimeout
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = DefaultWriteTimeout
	}

	if cfg.URL != "" {
		parsed, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("redis: invalid REDIS_URL: %w", err)
		}
		opts.Addr = parsed.Addr
		opts.Username = parsed.Username
		opts.Password = parsed.Password
		opts.DB = parsed.DB
		if parsed.TLSConfig != nil {
			opts.TLSConfig = parsed.TLSConfig
		}
		if strings.HasPrefix(cfg.URL, "rediss://") {
			cfg.TLSEnabled = true
		}
	} else {
		if cfg.Addr == "" {
			opts.Addr = "localhost:6379"
		} else {
			opts.Addr = cfg.Addr
		}
		opts.Password = cfg.Password
		opts.DB = cfg.DB
	}

	if cfg.TLSEnabled {
		if opts.TLSConfig == nil {
			opts.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		if opts.TLSConfig.ServerName == "" {
			host := opts.Addr
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			opts.TLSConfig.ServerName = host
		}
	}

	rdb := redis.NewClient(opts)
	return &Client{
		rdb: rdb,
		cfg: cfg,
	}, nil
}

// NewFromUniversal creates a Client wrapper around an existing redis.UniversalClient (e.g. for mocks).
func NewFromUniversal(rdb redis.UniversalClient, cfg Config) *Client {
	return &Client{
		rdb: rdb,
		cfg: cfg,
	}
}

// UniversalClient exposes the underlying UniversalClient interface.
func (c *Client) UniversalClient() redis.UniversalClient {
	return c.rdb
}

// Ping verifies network connectivity to the Redis instance with a timeout.
func (c *Client) Ping(ctx context.Context) error {
	if c.rdb == nil {
		return errors.New("redis: client is uninitialized")
	}
	return c.rdb.Ping(ctx).Err()
}

// IsReady returns true if a PING command succeeds within 1 second.
func (c *Client) IsReady(ctx context.Context) bool {
	ctxTimeout, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return c.Ping(ctxTimeout) == nil
}

// Close gracefully closes connections in the pool.
func (c *Client) Close() error {
	if c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

// ParseRedisURL parses standard redis:// or rediss:// connection strings into Config.
func ParseRedisURL(rawURL string) (Config, error) {
	cfg := DefaultConfig()
	if rawURL == "" {
		return cfg, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return cfg, fmt.Errorf("invalid redis url: %w", err)
	}

	cfg.URL = rawURL
	cfg.Addr = u.Host
	if u.Scheme == "rediss" {
		cfg.TLSEnabled = true
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			cfg.Password = p
		}
	}

	path := strings.TrimPrefix(u.Path, "/")
	if path != "" {
		if dbNum, err := strconv.Atoi(path); err == nil {
			cfg.DB = dbNum
		}
	}

	return cfg, nil
}
