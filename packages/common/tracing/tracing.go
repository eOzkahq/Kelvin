// Package tracing provides distributed trace context propagation and correlation
// compliant with W3C TraceContext standards and KELVIN observability baselines.
package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type contextKey int

const (
	traceContextKey contextKey = iota
)

// SpanContext represents immutable W3C-compliant distributed trace metadata.
type SpanContext struct {
	TraceID       string
	SpanID        string
	ParentSpanID  string
	Sampled       bool
	CorrelationID string
	StartTime     time.Time
}

// NewSpanContext generates a new root or child distributed trace context.
func NewSpanContext(correlationID string) SpanContext {
	if correlationID == "" {
		correlationID = generateHex(16)
	}
	return SpanContext{
		TraceID:       generateHex(16), // 32 hex chars (128-bit)
		SpanID:        generateHex(8),  // 16 hex chars (64-bit)
		Sampled:       true,
		CorrelationID: correlationID,
		StartTime:     time.Now().UTC(),
	}
}

// Traceparent formats the SpanContext into standard W3C 'traceparent' header (00-traceid-spanid-flags).
func (sc SpanContext) Traceparent() string {
	flags := "01"
	if !sc.Sampled {
		flags = "00"
	}
	return fmt.Sprintf("00-%s-%s-%s", sc.TraceID, sc.SpanID, flags)
}

// WithTraceContext injects SpanContext into a Go context.
func WithTraceContext(ctx context.Context, sc SpanContext) context.Context {
	return context.WithValue(ctx, traceContextKey, sc)
}

// FromContext extracts SpanContext from context, or initializes a new one if missing.
func FromContext(ctx context.Context) SpanContext {
	if ctx == nil {
		return NewSpanContext("")
	}
	if sc, ok := ctx.Value(traceContextKey).(SpanContext); ok {
		return sc
	}
	return NewSpanContext("")
}

// ExtractFromHeader parses W3C 'traceparent' or 'X-Correlation-ID' headers from HTTP requests.
func ExtractFromHeader(r *http.Request) SpanContext {
	correlationID := r.Header.Get("X-Correlation-ID")
	traceparent := r.Header.Get("traceparent")

	if traceparent != "" {
		parts := strings.Split(traceparent, "-")
		if len(parts) == 4 && len(parts[1]) == 32 && len(parts[2]) == 16 {
			return SpanContext{
				TraceID:       parts[1],
				SpanID:        generateHex(8), // Create new child span
				ParentSpanID:  parts[2],
				Sampled:       parts[3] == "01",
				CorrelationID: correlationID,
				StartTime:     time.Now().UTC(),
			}
		}
	}

	return NewSpanContext(correlationID)
}

// InjectHeader injects traceparent and X-Correlation-ID headers into outbound HTTP requests.
func InjectHeader(sc SpanContext, req *http.Request) {
	req.Header.Set("traceparent", sc.Traceparent())
	if sc.CorrelationID != "" {
		req.Header.Set("X-Correlation-ID", sc.CorrelationID)
	}
}

func generateHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
