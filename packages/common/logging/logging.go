// Package logging provides the shared structured logger (ADR-0001: zap) and
// request-scoped context plumbing. API_STANDARDS.md §10.1 makes the
// correlation ID a mandatory field on every structured log line.
package logging

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey int

const (
	loggerKey ctxKey = iota
	correlationKey
)

var defaultLogger = zap.NewNop()

// New builds a production (or development) zap logger at the given level.
func New(level string, development bool) (*zap.Logger, error) {
	var cfg zap.Config
	if development {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
	}
	cfg.DisableStacktrace = true
	if level != "" {
		if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
			return nil, err
		}
	}
	return cfg.Build()
}

// SetDefault installs the process-wide fallback logger used when a request
// context carries no logger.
func SetDefault(l *zap.Logger) {
	if l != nil {
		defaultLogger = l
	}
}

// WithLogger stores a request-scoped logger in the context.
func WithLogger(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext returns the request-scoped logger, or the process default.
func FromContext(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok && l != nil {
		return l
	}
	return defaultLogger
}

// WithCorrelation attaches the correlation ID to the context and derives a
// logger from ctx that stamps the field on every line (API_STANDARDS §10.1).
func WithCorrelation(ctx context.Context, id string) context.Context {
	ctx = context.WithValue(ctx, correlationKey, id)
	return WithLogger(ctx, FromContext(ctx).With(zap.String("correlation_id", id)))
}

// CorrelationFromContext returns the correlation ID, or "" if none is set.
func CorrelationFromContext(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey).(string)
	return id
}
