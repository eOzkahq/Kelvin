package egress

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

type mockMetricsRecorder struct {
	violations   uint64
	terminations uint64
}

func (m *mockMetricsRecorder) IncResourceViolation(v metrics.ViolationType) {
	if v == metrics.ViolationNetwork {
		atomic.AddUint64(&m.violations, 1)
	}
}

func (m *mockMetricsRecorder) IncTermination(c metrics.TerminationCause) {
	if c == metrics.CauseNetwork {
		atomic.AddUint64(&m.terminations, 1)
	}
}

func TestEgressProxy_PermittedHTTPForwarding(t *testing.T) {
	// 1. Mock Target Server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"target_reached"}`))
	}))
	defer targetServer.Close()

	targetURL, err := url.Parse(targetServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetHost, targetPortStr, _ := net.SplitHostPort(targetURL.Host)
	targetPort, _ := strconv.Atoi(targetPortStr)

	// In test, targetServer runs on 127.0.0.1. We configure a mock resolver and lab mode
	// so the target itself is reachable for this test.
	targetIP := netip.MustParseAddr(targetHost)

	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"app.test": {targetIP},
		},
	}
	scopePol, err := scope.NewPolicy([]string{"app.test"}, []string{"127.0.0.0/8"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	scopePol = scopePol.WithLabMode(true)

	policy, err := PolicyForScanner(ScannerZAPBaseline, fmt.Sprintf("http://app.test:%d", targetPort), scopePol)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	// Allow 127.0.0.1 in the egress filter solely for the mock loopback target
	policy.Filter.AllowInternal()

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Close()

	// 2. Client configured with proxy
	proxyURL, err := url.Parse(proxy.Endpoint())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://app.test:%d/api/v1/health", targetPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status":"target_reached"}` {
		t.Errorf("unexpected body: %s", string(body))
	}

	if proxy.ViolationsCount() != 0 {
		t.Errorf("expected 0 violations, got %d", proxy.ViolationsCount())
	}
}

func TestEgressProxy_PermittedCONNECTForwarding(t *testing.T) {
	// 1. Mock TLS Target Server
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls_tunnel_ok"))
	}))
	defer targetServer.Close()

	targetURL, err := url.Parse(targetServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetHost, targetPortStr, _ := net.SplitHostPort(targetURL.Host)
	targetPort, _ := strconv.Atoi(targetPortStr)
	targetIP := netip.MustParseAddr(targetHost)

	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"secure.test": {targetIP},
		},
	}
	scopePol, err := scope.NewPolicy([]string{"secure.test"}, []string{"127.0.0.0/8"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	scopePol = scopePol.WithLabMode(true)

	policy, err := PolicyForScanner(ScannerNuclei, fmt.Sprintf("https://secure.test:%d", targetPort), scopePol)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	policy.Filter.AllowInternal()

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Close()

	// 2. Client configured with proxy and trusted root cert
	proxyURL, err := url.Parse(proxy.Endpoint())
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // test self-signed cert
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://secure.test:%d/test", targetPort))
	if err != nil {
		t.Fatalf("HTTPS request via CONNECT proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tls_tunnel_ok" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestEgressProxy_BlocksRFC1918Destinations(t *testing.T) {
	resolver := &mockResolver{}
	scopePol, _ := scope.NewPolicy([]string{"example.com"}, []string{"93.184.216.0/24"}, resolver)
	policy, err := PolicyForScanner(ScannerZAPBaseline, "https://example.com", scopePol)
	if err != nil {
		t.Fatal(err)
	}

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.Endpoint())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}

	// Try reaching private IP 10.0.0.1
	resp, err := client.Get("http://10.0.0.1:80/secret")
	if err != nil {
		t.Fatalf("expected HTTP error response, got network failure: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Kelvin-Egress-Blocked") != "true" {
		t.Errorf("expected X-Kelvin-Egress-Blocked header")
	}

	if proxy.ViolationsCount() != 1 {
		t.Errorf("expected 1 violation, got %d", proxy.ViolationsCount())
	}
	if atomic.LoadUint64(&mr.violations) != 1 {
		t.Errorf("expected metrics counter to be 1, got %d", mr.violations)
	}
}

func TestEgressProxy_BlocksCloudMetadata(t *testing.T) {
	resolver := &mockResolver{}
	scopePol, _ := scope.NewPolicy([]string{"example.com"}, []string{"93.184.216.0/24"}, resolver)
	policy, err := PolicyForScanner(ScannerNuclei, "https://example.com", scopePol)
	if err != nil {
		t.Fatal(err)
	}

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.Endpoint())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}

	// Try reaching AWS metadata 169.254.169.254
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		t.Fatalf("expected HTTP error response, got %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
	if proxy.ViolationsCount() != 1 {
		t.Errorf("expected 1 violation, got %d", proxy.ViolationsCount())
	}
}

func TestEgressProxy_BlocksOutOfScopeDestinations(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"unapproved-host.org": {netip.MustParseAddr("8.8.8.8")},
		},
	}
	scopePol, _ := scope.NewPolicy([]string{"example.com"}, []string{"93.184.216.0/24"}, resolver)
	policy, err := PolicyForScanner(ScannerZAPBaseline, "https://example.com", scopePol)
	if err != nil {
		t.Fatal(err)
	}

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.Endpoint())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}

	resp, err := client.Get("http://unapproved-host.org/malicious")
	if err != nil {
		t.Fatalf("expected HTTP response, got %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

func TestEgressProxy_ObservabilityAndEventBroadcasting(t *testing.T) {
	resolver := &mockResolver{}
	scopePol, _ := scope.NewPolicy([]string{"example.com"}, []string{"93.184.216.0/24"}, resolver)
	policy, err := PolicyForScanner(ScannerNuclei, "https://example.com", scopePol)
	if err != nil {
		t.Fatal(err)
	}

	var receivedEvents []ViolationEvent
	var mu sync.Mutex

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxy.AddViolationListener(func(v ViolationEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, v)
	})

	proxyURL, _ := url.Parse(proxy.Endpoint())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}

	// Trigger two distinct violations
	_, _ = client.Get("http://192.168.1.1:80/admin")
	_, _ = client.Get("http://169.254.169.254/meta-data")

	if proxy.ViolationsCount() != 2 {
		t.Fatalf("expected 2 violations, got %d", proxy.ViolationsCount())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 received events via listener, got %d", len(receivedEvents))
	}

	if receivedEvents[0].Scanner != ScannerNuclei {
		t.Errorf("expected scanner %s, got %s", ScannerNuclei, receivedEvents[0].Scanner)
	}
	if receivedEvents[0].RequestedDestination != "192.168.1.1" {
		t.Errorf("expected requested destination 192.168.1.1, got %s", receivedEvents[0].RequestedDestination)
	}
	if receivedEvents[1].RequestedDestination != "169.254.169.254" {
		t.Errorf("expected requested destination 169.254.169.254, got %s", receivedEvents[1].RequestedDestination)
	}
}
