package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

func createScopedProxy(t *testing.T, scanner string, targetURL string, allowedHosts []string, labMode bool) (*Proxy, *mockMetricsRecorder) {
	t.Helper()
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"target.example": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	scopePol, err := scope.NewPolicy(allowedHosts, []string{}, resolver)
	if err != nil {
		t.Fatalf("failed to create scope policy: %v", err)
	}
	if labMode {
		scopePol = scopePol.WithLabMode(true)
	}

	policy, err := PolicyForScanner(scanner, targetURL, scopePol)
	if err != nil {
		t.Fatalf("failed to create policy for %s: %v", scanner, err)
	}

	mr := &mockMetricsRecorder{}
	proxy, err := NewProxy(policy, zap.NewNop(), mr)
	if err != nil {
		t.Fatalf("failed to initialize proxy: %v", err)
	}
	return proxy, mr
}

func makeProxyClient(proxyEndpoint string) *http.Client {
	proxyURL, _ := url.Parse(proxyEndpoint)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}
}

func testAllowAllPolicy(t *testing.T) scope.Policy {
	t.Helper()
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"target.example": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	p, err := scope.NewPolicy([]string{"target.example"}, []string{}, resolver)
	if err != nil {
		t.Fatalf("failed to create scope policy: %v", err)
	}
	return p
}

// 1. Direct connection without proxy fails when destination is isolated
func TestNetworkBypass_DirectConnectionWithoutProxy(t *testing.T) {
	// A scanner specification without proxy must fail validation
	policy, err := PolicyForScanner(ScannerNuclei, "https://target.example", testAllowAllPolicy(t))
	if err != nil {
		t.Fatalf("unexpected policy error: %v", err)
	}
	if !policy.RequiresProxy {
		t.Fatal("expected Nuclei to require an egress proxy")
	}
}

// 2. Localhost & Loopback denial (127.0.0.1, ::1)
func TestNetworkBypass_LoopbackDenial(t *testing.T) {
	proxy, mr := createScopedProxy(t, ScannerNuclei, "https://target.example", []string{"target.example"}, false)
	defer proxy.Close()

	client := makeProxyClient(proxy.Endpoint())
	for _, dest := range []string{"http://127.0.0.1:8080", "http://127.0.0.2:80", "http://localhost:8080"} {
		resp, err := client.Get(dest)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("expected 403 Forbidden for %s, got %d", dest, resp.StatusCode)
			}
			if resp.Header.Get("X-Kelvin-Egress-Blocked") != "true" {
				t.Errorf("expected X-Kelvin-Egress-Blocked header for %s", dest)
			}
		}
	}
	if mr.violations == 0 {
		t.Error("expected loopback violation alarms to be recorded")
	}
}

// 3. RFC1918 Private range denial (10/8, 172.16/12, 192.168/16)
func TestNetworkBypass_RFC1918Denial(t *testing.T) {
	proxy, mr := createScopedProxy(t, ScannerNuclei, "https://target.example", []string{"target.example"}, false)
	defer proxy.Close()

	client := makeProxyClient(proxy.Endpoint())
	privateIPs := []string{
		"http://10.0.0.1:80",
		"http://10.254.254.254:443",
		"http://172.16.0.1:80",
		"http://172.31.255.255:80",
		"http://192.168.1.1:80",
		"http://192.168.100.50:8080",
	}

	for _, dest := range privateIPs {
		resp, err := client.Get(dest)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden for RFC1918 dest %s, got %d", dest, resp.StatusCode)
			}
		}
	}
	if mr.violations < uint64(len(privateIPs)) {
		t.Errorf("expected at least %d violations recorded, got %d", len(privateIPs), mr.violations)
	}
}

// 4. Cloud metadata endpoint denial (169.254.169.254)
func TestNetworkBypass_CloudMetadataDenial(t *testing.T) {
	proxy, mr := createScopedProxy(t, ScannerNuclei, "https://target.example", []string{"target.example"}, false)
	defer proxy.Close()

	client := makeProxyClient(proxy.Endpoint())
	metadataDest := "http://169.254.169.254/latest/meta-data/"

	resp, err := client.Get(metadataDest)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for cloud metadata, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Kelvin-Egress-Blocked") != "true" {
			t.Error("expected X-Kelvin-Egress-Blocked header for cloud metadata")
		}
	}
	if mr.violations == 0 {
		t.Error("expected security alarm on cloud metadata access attempt")
	}
}

// 5. Out-of-scope targets & unauthorized external destinations
func TestNetworkBypass_OutOfScopeTargets(t *testing.T) {
	proxy, _ := createScopedProxy(t, ScannerNuclei, "https://target.example", []string{"target.example"}, false)
	defer proxy.Close()

	client := makeProxyClient(proxy.Endpoint())
	resp, err := client.Get("http://unauthorized.evil.org/steal")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for out-of-scope target, got %d", resp.StatusCode)
		}
	}
}

// 6. Disallowed ports (e.g. SSH 22, SMTP 25, RDP 3389)
func TestNetworkBypass_DisallowedPorts(t *testing.T) {
	proxy, _ := createScopedProxy(t, ScannerNuclei, "https://target.example", []string{"target.example"}, false)
	defer proxy.Close()

	client := makeProxyClient(proxy.Endpoint())
	for _, port := range []int{22, 25, 3389, 8080} {
		resp, err := client.Get(fmt.Sprintf("http://target.example:%d/test", port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("expected 403 for disallowed port %d, got %d", port, resp.StatusCode)
			}
		}
	}
}

// 7. Disallowed protocols
func TestNetworkBypass_DisallowedProtocols(t *testing.T) {
	resolver := &mockResolver{mapping: map[string][]netip.Addr{"target.example": {netip.MustParseAddr("93.184.216.34")}}}
	scopePol, _ := scope.NewPolicy([]string{"target.example"}, []string{}, resolver)
	policy, err := PolicyForScanner(ScannerNuclei, "https://target.example", scopePol)
	if err != nil {
		t.Fatal(err)
	}

	for _, proto := range []string{"ftp", "ssh", "smtp", "gopher", "file"} {
		_, err := policy.ValidateDestination(context.Background(), "target.example", 443, proto)
		if err == nil || !strings.Contains(err.Error(), "protocol not permitted") {
			t.Errorf("expected protocol %q to be disallowed, got err: %v", proto, err)
		}
	}
}

// 8. Outbound callback / out-of-band infrastructure denial
func TestNetworkBypass_OutboundCallbackDenial(t *testing.T) {
	resolver := &mockResolver{mapping: map[string][]netip.Addr{"target.example": {netip.MustParseAddr("93.184.216.34")}}}
	scopePol, err := scope.NewPolicy([]string{"target.example"}, []string{}, resolver)
	if err != nil {
		t.Fatalf("failed to create scope policy: %v", err)
	}
	policy, err := PolicyForScanner(ScannerNuclei, "https://target.example", scopePol)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	callbacks := []string{
		"xyz.interactsh.com",
		"sub.oast.fun",
		"target.burpcollaborator.net",
		"test.canarytokens.com",
		"probe.dnslog.cn",
	}

	for _, cb := range callbacks {
		_, err := policy.ValidateDestination(context.Background(), cb, 443, "https")
		if err == nil || !strings.Contains(err.Error(), "callback infrastructure") {
			t.Errorf("expected callback %s to be blocked, got: %v", cb, err)
		}
	}
}

// 9. DNS Rebinding defense (hostname resolving to private IP fails closed)
func TestNetworkBypass_DNSRebindingDefense(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"rebind.target.example": {
				netip.MustParseAddr("93.184.216.34"),
			},
		},
	}
	scopePol, err := scope.NewPolicy([]string{"rebind.target.example"}, []string{}, resolver)
	if err != nil {
		t.Fatalf("failed to create scope policy: %v", err)
	}
	policy, err := PolicyForScanner(ScannerNuclei, "https://rebind.target.example", scopePol)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Hostname rebinds to both a valid public IP and an injected private IP
	resolver.mapping["rebind.target.example"] = []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("10.0.0.1"),
	}

	_, err = policy.ValidateDestination(context.Background(), "rebind.target.example", 443, "https")
	if err == nil || !strings.Contains(err.Error(), "prohibited IP") {
		t.Fatalf("expected DNS rebinding multi-A-record to fail closed, got: %v", err)
	}
}

// 10. Config tampering rejection (--no-proxy, 169.254.169.254 in config)
func TestNetworkBypass_ConfigTamperingRejection(t *testing.T) {
	policy, _ := PolicyForScanner(ScannerNuclei, "https://target.example", testAllowAllPolicy(t))

	tamperedConfigs := []string{
		`{"flags": ["--no-proxy"]}`,
		`{"env": {"NO_PROXY": "*"}}`,
		`{"http_proxy": "http://evil.com"}`,
		`{"target": "http://169.254.169.254"}`,
		`{"callback": "interactsh"}`,
	}

	for _, cfgStr := range tamperedConfigs {
		err := policy.ValidateConfig(json.RawMessage(cfgStr))
		if err == nil || !strings.Contains(err.Error(), "prohibited egress directive") {
			t.Errorf("expected config %s to be rejected for tampering, got: %v", cfgStr, err)
		}
	}
}

// 11. Proxy shutdown during execution terminates cleanly
func TestNetworkBypass_ProxyShutdownDuringExecution(t *testing.T) {
	proxy, _ := createScopedProxy(t, ScannerNuclei, "https://target.example", []string{"target.example"}, false)

	if err := proxy.Close(); err != nil {
		t.Fatalf("expected graceful close, got: %v", err)
	}
	// Calling close a second time is safe and idempotent
	if err := proxy.Close(); err != nil {
		t.Fatalf("expected idempotent close, got: %v", err)
	}
}

// 12. Custom bind address and advertised host
func TestNetworkBypass_CustomBindAddressAndAdvertisedHost(t *testing.T) {
	resolver := &mockResolver{mapping: map[string][]netip.Addr{"target.example": {netip.MustParseAddr("93.184.216.34")}}}
	scopePol, _ := scope.NewPolicy([]string{"target.example"}, []string{}, resolver)
	policy, _ := PolicyForScanner(ScannerNuclei, "https://target.example", scopePol)

	// Test custom advertised host
	_ = os.Setenv("KELVIN_EGRESS_PROXY_ADVERTISED_HOST", "10.89.10.1")
	defer os.Unsetenv("KELVIN_EGRESS_PROXY_ADVERTISED_HOST")

	proxy, err := NewProxyWithBindAddr(policy, "127.0.0.1:0", zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("failed to bind proxy: %v", err)
	}
	defer proxy.Close()

	if !strings.HasPrefix(proxy.Endpoint(), "http://10.89.10.1:") {
		t.Errorf("expected proxy endpoint to use advertised host 10.89.10.1, got: %s", proxy.Endpoint())
	}
}
