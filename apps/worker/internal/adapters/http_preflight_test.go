package adapters

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

type preflightResolver struct{ ip netip.Addr }

func (r preflightResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}

func TestHTTPPreflightAdapterCapturesHTTPResponse(t *testing.T) {
	withLabMode(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodHead {
			t.Errorf("method = %q, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	policy := preflightPolicy(t, []string{"preflight.test"}, nil, netip.MustParseAddr("127.0.0.1"))
	task := preflightTask(t, "http://preflight.test"+strings.TrimPrefix(server.URL, "http://127.0.0.1"))
	result := executePreflight(t, policy, task)
	if result.Status != StatusCompleted || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("unexpected result status/exit: %s / %v", result.Status, result.ExitCode)
	}
	observation := decodeObservation(t, result)
	if observation.Outcome != "HTTP_RESPONDED" || observation.StatusCode != http.StatusNoContent || observation.Protocol == "" {
		t.Fatalf("response was not captured: %+v", observation)
	}
	if observation.LatencyMS < 0 || requests != 1 {
		t.Fatalf("latency=%d requests=%d; want one bounded request", observation.LatencyMS, requests)
	}
}

func TestHTTPPreflightAdapterRejectsOutOfScopeRedirect(t *testing.T) {
	withLabMode(t)
	var outsideRequests int
	outside := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { outsideRequests++ }))
	defer outside.Close()
	outsideURL, err := url.Parse(outside.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://outside.test:"+outsideURL.Port()+"/", http.StatusFound)
	}))
	defer server.Close()
	policy := preflightPolicy(t, []string{"preflight.test"}, nil, netip.MustParseAddr("127.0.0.1"))
	target := "http://preflight.test" + strings.TrimPrefix(server.URL, "http://127.0.0.1")
	result := executePreflight(t, policy, preflightTask(t, target))
	if result.Status != StatusCompletedWithWarnings {
		t.Fatalf("redirect result status = %s, want warning outcome", result.Status)
	}
	observation := decodeObservation(t, result)
	if observation.Error != "redirect_rejected_by_scope" || !observation.Redirected || observation.StatusCode != http.StatusFound || outsideRequests != 0 {
		t.Fatalf("out-of-scope redirect was followed or misclassified: observation=%+v outside requests=%d", observation, outsideRequests)
	}
}

func TestHTTPPreflightAdapterClassifiesTLSFailure(t *testing.T) {
	withLabMode(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := preflightPolicy(t, nil, []string{"127.0.0.1/32"}, netip.MustParseAddr("127.0.0.1"))
	target := "https://" + net.JoinHostPort("127.0.0.1", parsed.Port())
	result := executePreflight(t, policy, preflightTask(t, target))
	if result.Status != StatusCompletedWithWarnings {
		t.Fatalf("TLS failure status = %s, want completed with warnings", result.Status)
	}
	if got := decodeObservation(t, result).Error; got != "tls_error" {
		t.Fatalf("TLS error classified as %q", got)
	}
}

func TestHTTPPreflightAdapterClassifiesConnectionRefusal(t *testing.T) {
	withLabMode(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	policy := preflightPolicy(t, []string{"preflight.test"}, nil, netip.MustParseAddr("127.0.0.1"))
	target := fmt.Sprintf("http://preflight.test:%d/", port)
	result := executePreflight(t, policy, preflightTask(t, target))
	if result.Status != StatusCompletedWithWarnings || decodeObservation(t, result).Error != "connection_error" {
		t.Fatalf("connection refusal was not represented as a warning outcome: %+v", result)
	}
}

func TestHTTPPreflightConfigCannotExceedDeclaredLimits(t *testing.T) {
	adapter := NewHTTPPreflightAdapter(func(context.Context, Task) (scope.Policy, error) { return scope.Policy{}, nil })
	config, err := DefaultScannerConfig(ScannerHTTPPreflight)
	if err != nil {
		t.Fatal(err)
	}
	config.RequestsPerSecond = 3
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateConfig(raw); err == nil {
		t.Fatal("config exceeded adapter request-rate capability")
	}
}

func TestHTTPPreflightAdapterBoundsRequestByTaskDeadline(t *testing.T) {
	withLabMode(t)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	policy := preflightPolicy(t, []string{"preflight.test"}, nil, netip.MustParseAddr("127.0.0.1"))
	target := "http://preflight.test" + strings.TrimPrefix(server.URL, "http://127.0.0.1")
	task := preflightTask(t, target)
	task.HardDeadline = 100 * time.Millisecond
	started := time.Now()
	result := executePreflight(t, policy, task)
	if result.Status != StatusTimedOut || time.Since(started) > time.Second {
		t.Fatalf("preflight was not bounded by task deadline: status=%s elapsed=%s", result.Status, time.Since(started))
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "DEADLINE_EXCEEDED" {
		t.Fatalf("timeout diagnostic missing: %+v", result.Diagnostics)
	}
}

func TestHTTPPreflightRejectsMissingScopeProviderAndInvalidTarget(t *testing.T) {
	adapter := NewHTTPPreflightAdapter(nil)
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err == nil {
		t.Fatal("adapter initialized without trusted scope provider")
	}

	withLabMode(t)
	policy := preflightPolicy(t, []string{"preflight.test"}, nil, netip.MustParseAddr("127.0.0.1"))
	adapter = NewHTTPPreflightAdapter(func(context.Context, Task) (scope.Policy, error) { return policy, nil })
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	task := preflightTask(t, "ftp://preflight.test/resource")
	if _, err := adapter.Execute(context.Background(), task); err == nil {
		t.Fatal("adapter accepted non-HTTP target")
	}
}

func executePreflight(t *testing.T, policy scope.Policy, task Task) Result {
	t.Helper()
	adapter := NewHTTPPreflightAdapter(func(context.Context, Task) (scope.Policy, error) { return policy, nil })
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateConfig(task.Payload); err != nil {
		t.Fatalf("default preflight config rejected: %v", err)
	}
	result, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("invalid output envelope: %v", err)
	}
	return result
}

func preflightPolicy(t *testing.T, domains, cidrs []string, resolvedIP netip.Addr) scope.Policy {
	t.Helper()
	policy, err := scope.NewPolicy(domains, cidrs, preflightResolver{ip: resolvedIP})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func preflightTask(t *testing.T, target string) Task {
	t.Helper()
	config, err := DefaultScannerConfig(ScannerHTTPPreflight)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return Task{
		JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID: "33333333-3333-3333-3333-333333333333", CorrelationID: "preflight-correlation",
		Scanner: ScannerHTTPPreflight, Target: target, ProfileID: "kelvin.profile.standard.v1",
		HardDeadline: 5 * time.Second, Payload: raw,
	}
}

func decodeObservation(t *testing.T, result Result) preflightObservation {
	t.Helper()
	var observation preflightObservation
	if err := json.Unmarshal(result.ScannerMetadata["http_preflight.observation"], &observation); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	return observation
}

func withLabMode(t *testing.T) {
	t.Helper()
	key := strings.Repeat("k", 32)
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("kelvin-local-lab:v1"))
	t.Setenv("KELVIN_ENV", "testing")
	t.Setenv("KELVIN_LAB_MODE", "enabled")
	t.Setenv("KELVIN_LAB_MODE_KEY", key)
	t.Setenv("KELVIN_LAB_MODE_SIGNATURE", hex.EncodeToString(mac.Sum(nil)))
}
