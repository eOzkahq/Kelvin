package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTraceContextLifecycle(t *testing.T) {
	corrID := "test-corr-12345"
	sc := NewSpanContext(corrID)

	if len(sc.TraceID) != 32 {
		t.Errorf("Expected 32-char hex TraceID, got %s", sc.TraceID)
	}
	if len(sc.SpanID) != 16 {
		t.Errorf("Expected 16-char hex SpanID, got %s", sc.SpanID)
	}
	if sc.CorrelationID != corrID {
		t.Errorf("Expected correlation ID %s, got %s", corrID, sc.CorrelationID)
	}

	tp := sc.Traceparent()
	if !strings.HasPrefix(tp, "00-") {
		t.Errorf("Expected W3C traceparent prefix 00-, got %s", tp)
	}

	// Context injection & extraction
	ctx := WithTraceContext(context.Background(), sc)
	extracted := FromContext(ctx)
	if extracted.TraceID != sc.TraceID {
		t.Errorf("Extracted trace ID mismatch: %s vs %s", extracted.TraceID, sc.TraceID)
	}

	// HTTP Header extraction
	req := httptest.NewRequest("GET", "/api/v1/assessments", nil)
	req.Header.Set("traceparent", tp)
	req.Header.Set("X-Correlation-ID", corrID)

	childSC := ExtractFromHeader(req)
	if childSC.TraceID != sc.TraceID {
		t.Errorf("Child span trace ID mismatch: expected %s, got %s", sc.TraceID, childSC.TraceID)
	}
	if childSC.ParentSpanID != sc.SpanID {
		t.Errorf("Expected ParentSpanID %s, got %s", sc.SpanID, childSC.ParentSpanID)
	}
	if childSC.CorrelationID != corrID {
		t.Errorf("Expected CorrelationID %s, got %s", corrID, childSC.CorrelationID)
	}

	// Outbound header injection
	outboundReq, _ := http.NewRequest("POST", "https://api.internal/dispatch", nil)
	InjectHeader(childSC, outboundReq)
	if outboundReq.Header.Get("traceparent") == "" {
		t.Errorf("Expected traceparent header on outbound request")
	}
	if outboundReq.Header.Get("X-Correlation-ID") != corrID {
		t.Errorf("Expected X-Correlation-ID header on outbound request")
	}
}
