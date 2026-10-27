// Package logging provides the shared structured logger (ADR-0001: zap) and
// request-scoped context plumbing. API_STANDARDS.md §10.1 makes the
// correlation ID a mandatory field on every structured log line.
//
// This package also implements automated sensitive field and token redaction interceptors
// in compliance with Issue 15/19 / ADR-0001 / ADR-0002 / ADR-0003.
package logging

import (
	"context"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey int

const (
	loggerKey ctxKey = iota
	correlationKey
)

var defaultLogger = zap.NewNop()

// MaskedValue is the replacement text for redacted sensitive fields and secrets.
const MaskedValue = "[REDACTED]"

// SensitiveFieldPatterns contains case-insensitive substrings identifying sensitive field keys.
var SensitiveFieldPatterns = []string{
	"authorization",
	"password",
	"secret",
	"token",
	"api_key",
	"apikey",
	"private_key",
	"privatekey",
	"auth",
	"jwt",
	"cert",
	"cookie",
	"set-cookie",
	"key",
}

// Regex patterns to detect and sanitize inline tokens, bearer headers, and keys in string values.
var sensitiveValueRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
	regexp.MustCompile(`(?i)(basic\s+)[A-Za-z0-9+/=]+`),
	regexp.MustCompile(`(?i)(postgres(?:ql)?://[^:]+:)([^@]+)(@)`),
	regexp.MustCompile(`(?i)(password\s*[:=]\s*)[^\s,;]+`),
	regexp.MustCompile(`(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+`),
	regexp.MustCompile(`(?i)(token\s*[:=]\s*)[^\s,;]+`),
}

// isSensitiveKey returns true if the key name matches any known sensitive patterns.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range SensitiveFieldPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// SanitizeString cleans up sensitive tokens or authorization strings from arbitrary log strings.
func SanitizeString(s string) string {
	res := s
	for _, re := range sensitiveValueRegexes {
		res = re.ReplaceAllString(res, "${1}"+MaskedValue)
	}
	return res
}

// redactField returns a sanitized copy of the zapcore.Field if its key or content is sensitive.
func redactField(f zapcore.Field) zapcore.Field {
	if isSensitiveKey(f.Key) {
		return zap.String(f.Key, MaskedValue)
	}
	if f.Type == zapcore.StringType {
		f.String = SanitizeString(f.String)
	}
	return f
}

// RedactingCore wraps a zapcore.Core and intercepts all logged fields to redact sensitive keys and values.
type RedactingCore struct {
	zapcore.Core
}

// NewRedactingCore creates a new RedactingCore wrapping the given core.
func NewRedactingCore(c zapcore.Core) zapcore.Core {
	return &RedactingCore{Core: c}
}

// With adds fields to the core, ensuring any sensitive keys are redacted before storing.
func (r *RedactingCore) With(fields []zapcore.Field) zapcore.Core {
	sanitized := make([]zapcore.Field, len(fields))
	for i, f := range fields {
		sanitized[i] = redactField(f)
	}
	return &RedactingCore{Core: r.Core.With(sanitized)}
}

// Check determines whether the supplied entry should be logged.
func (r *RedactingCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if r.Enabled(entry.Level) {
		return ce.AddCore(entry, r)
	}
	return ce
}

// Write intercepts and redacts sensitive fields on each log write.
func (r *RedactingCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	sanitized := make([]zapcore.Field, len(fields))
	for i, f := range fields {
		sanitized[i] = redactField(f)
	}
	// Also sanitize message text in case sensitive data is formatted into the log message
	entry.Message = SanitizeString(entry.Message)
	return r.Core.Write(entry, sanitized)
}

// New builds a production (or development) zap logger with automated redaction.
// In production mode, structured JSON formatting is always enforced.
func New(level string, development bool) (*zap.Logger, error) {
	var cfg zap.Config
	if development {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
		cfg.Encoding = "json"
	}
	cfg.DisableStacktrace = true
	if level != "" {
		if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
			return nil, err
		}
	}

	logger, err := cfg.Build(zap.WrapCore(func(c zapcore.Core) zapcore.Core {
		return NewRedactingCore(c)
	}))
	if err != nil {
		return nil, err
	}
	return logger, nil
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
