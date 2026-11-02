package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kelvin/kelvin/packages/common/logging"
	"github.com/kelvin/kelvin/packages/common/tracing"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestObservabilityPipeline verifies that the centralized logging, metrics,
// and distributed tracing standards are properly enforced.
func TestObservabilityPipeline(t *testing.T) {
	// 1. Verify W3C distributed trace context generation and propagation
	sc := tracing.NewSpanContext("corr-obs-test")
	if len(sc.TraceID) != 32 || len(sc.SpanID) != 16 {
		t.Errorf("Invalid trace/span ID length: %s, %s", sc.TraceID, sc.SpanID)
	}

	ctx := tracing.WithTraceContext(context.Background(), sc)
	extracted := tracing.FromContext(ctx)
	if extracted.CorrelationID != "corr-obs-test" {
		t.Errorf("Expected correlation ID corr-obs-test, got %s", extracted.CorrelationID)
	}

	// 2. Verify sensitive secret redaction in logging
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(logging.NewRedactingCore(core))

	logger.Info("User authentication attempted",
		zap.String("username", "security_analyst"),
		zap.String("password", "SuperSecret123!"),
		zap.String("authorization", "Bearer eyJhbGciOiJIUzI1Ni..."),
	)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 log entry, found %d", len(entries))
	}

	fields := entries[0].ContextMap()
	if fields["password"] != logging.MaskedValue {
		t.Errorf("Expected password to be masked as %s, got %v", logging.MaskedValue, fields["password"])
	}
	if fields["authorization"] != logging.MaskedValue {
		t.Errorf("Expected authorization to be masked as %s, got %v", logging.MaskedValue, fields["authorization"])
	}

	// 3. Verify operational documentation exists
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	docPath := filepath.Join(repoRoot, "docs", "observability", "CENTRALIZED_LOGGING_METRICS_AND_TRACING.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing CENTRALIZED_LOGGING_METRICS_AND_TRACING.md documentation")
	}
}
