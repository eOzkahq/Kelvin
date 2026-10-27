package logging

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRedactingCore(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	redactingCore := NewRedactingCore(core)
	logger := zap.New(redactingCore)

	logger.Info("testing redaction",
		zap.String("username", "admin"),
		zap.String("password", "super-secret-password-123"),
		zap.String("api_key", "sec_token_9999"),
		zap.String("jwt_secret", "jwt-signing-secret"),
		zap.String("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret"),
		zap.String("cookie", "session_id=12345; auth_token=secret"),
		zap.String("host", "localhost:8080"),
		zap.Int("port", 8080),
	)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}

	fields := entries[0].ContextMap()

	// Sensitive fields must be replaced with MaskedValue
	sensitiveKeys := []string{"password", "api_key", "jwt_secret", "authorization", "cookie"}
	for _, key := range sensitiveKeys {
		val, exists := fields[key]
		if !exists {
			t.Errorf("expected field %q in log entry", key)
			continue
		}
		if val != MaskedValue {
			t.Errorf("field %q was not redacted, got %v, expected %s", key, val, MaskedValue)
		}
	}

	// Non-sensitive fields must remain intact
	if fields["username"] != "admin" {
		t.Errorf("expected username to be 'admin', got %v", fields["username"])
	}
	if fields["host"] != "localhost:8080" {
		t.Errorf("expected host to be 'localhost:8080', got %v", fields["host"])
	}
	if fields["port"] != int64(8080) {
		t.Errorf("expected port to be 8080, got %v", fields["port"])
	}
}

func TestRedactingCoreWith(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	redactingCore := NewRedactingCore(core)
	logger := zap.New(redactingCore).With(
		zap.String("tenant_token", "top-secret-token"),
		zap.String("tenant_id", "11111111-1111-1111-1111-111111111111"),
	)

	logger.Info("child logger message", zap.String("db_password", "db-pass-456"))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}

	fields := entries[0].ContextMap()

	if fields["tenant_token"] != MaskedValue {
		t.Errorf("expected tenant_token to be redacted, got %v", fields["tenant_token"])
	}
	if fields["db_password"] != MaskedValue {
		t.Errorf("expected db_password to be redacted, got %v", fields["db_password"])
	}
	if fields["tenant_id"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("expected tenant_id to be preserved, got %v", fields["tenant_id"])
	}
}

func TestInlineValueRedaction(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	redactingCore := NewRedactingCore(core)
	logger := zap.New(redactingCore)

	logger.Info("connected with url", zap.String("db_connection", "postgres://user:supersecretpass@localhost:5432/kelvin"))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}

	fields := entries[0].ContextMap()
	connStr, ok := fields["db_connection"].(string)
	if !ok {
		t.Fatalf("expected db_connection to be a string")
	}
	if connStr == "postgres://user:supersecretpass@localhost:5432/kelvin" {
		t.Errorf("database password was not sanitized: %s", connStr)
	}
}
