package redis

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Addr != "localhost:6379" {
		t.Errorf("expected default addr 'localhost:6379', got %s", cfg.Addr)
	}
	if cfg.PoolSize != DefaultPoolSize {
		t.Errorf("expected default pool size %d, got %d", DefaultPoolSize, cfg.PoolSize)
	}
	if cfg.MinIdleConns != DefaultMinIdleConns {
		t.Errorf("expected default min idle conns %d, got %d", DefaultMinIdleConns, cfg.MinIdleConns)
	}
	if cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("expected default dial timeout %v, got %v", DefaultDialTimeout, cfg.DialTimeout)
	}
}

func TestParseRedisURL(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		expectAddr string
		expectPass string
		expectDB   int
		expectTLS  bool
		expectErr  bool
	}{
		{
			name:       "empty url returns default",
			rawURL:     "",
			expectAddr: "localhost:6379",
			expectDB:   0,
			expectTLS:  false,
		},
		{
			name:       "standard redis url",
			rawURL:     "redis://default:secret123@redis.kelvin.internal:6379/2",
			expectAddr: "redis.kelvin.internal:6379",
			expectPass: "secret123",
			expectDB:   2,
			expectTLS:  false,
		},
		{
			name:       "rediss tls url",
			rawURL:     "rediss://:prodpass@secure-redis.cloud.internal:6380/0",
			expectAddr: "secure-redis.cloud.internal:6380",
			expectPass: "prodpass",
			expectDB:   0,
			expectTLS:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseRedisURL(tt.rawURL)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for url %s, got nil", tt.rawURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Addr != tt.expectAddr {
				t.Errorf("expected addr %s, got %s", tt.expectAddr, cfg.Addr)
			}
			if cfg.Password != tt.expectPass {
				t.Errorf("expected password %s, got %s", tt.expectPass, cfg.Password)
			}
			if cfg.DB != tt.expectDB {
				t.Errorf("expected db %d, got %d", tt.expectDB, cfg.DB)
			}
			if cfg.TLSEnabled != tt.expectTLS {
				t.Errorf("expected tls %v, got %v", tt.expectTLS, cfg.TLSEnabled)
			}
		})
	}
}

func TestNewClientOptions(t *testing.T) {
	cfg := Config{
		Addr:         "127.0.0.1:6379",
		TLSEnabled:   true,
		PoolSize:     50,
		MinIdleConns: 10,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if client.UniversalClient() == nil {
		t.Errorf("expected initialized UniversalClient")
	}

	// Verify uninitialized client error handling
	uninitClient := &Client{rdb: nil}
	if err := uninitClient.Ping(context.Background()); err == nil {
		t.Errorf("expected error when pinging uninitialized client")
	}
	if uninitClient.IsReady(context.Background()) {
		t.Errorf("expected IsReady to be false on uninitialized client")
	}
}
