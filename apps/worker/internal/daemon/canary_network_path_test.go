package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/egress"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

type staticResolver struct {
	mapping map[string][]netip.Addr
}

func (r *staticResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ips, ok := r.mapping[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host}
}

// TestCanaryNetworkPathAndHarmlessHealthCheck comprehensively resolves the
// target network-path ambiguity for Milestone 6 Approval Gate A.
func TestCanaryNetworkPathAndHarmlessHealthCheck(t *testing.T) {
	// 1. Instantiate the mock target server (matches mock-target/main.go)
	mockTarget := setupMockTargetServer(t)
	defer mockTarget.Close()

	mockTargetURL, err := url.Parse(mockTarget.URL)
	if err != nil {
		t.Fatalf("failed to parse mock target URL: %v", err)
	}
	mockPort := mockTargetURL.Port()

	// 2. Establish DNS resolution for scanner-mock.kelvin.internal to mock-target loopback IP
	targetHost := "scanner-mock.kelvin.internal"
	resolver := &staticResolver{
		mapping: map[string][]netip.Addr{
			targetHost: {netip.MustParseAddr("127.0.0.1")},
		},
	}

	// 3. Verify Canary Allowlist enforcement
	allowed := []string{
		"scanner-mock.kelvin.internal",
		"mock-target.kelvin.internal",
		"127.0.0.1",
		"localhost",
	}
	if !isCanaryTargetAllowed("http://"+targetHost+":"+mockPort, allowed) {
		t.Errorf("expected %s to be permitted by canary allowlist", targetHost)
	}
	if isCanaryTargetAllowed("https://external-target.com", allowed) {
		t.Errorf("expected external target to be rejected by canary allowlist")
	}

	// 4. Configure Scope Policy with LabMode enabled for controlled staging mock verification
	scopePol, err := scope.NewPolicy([]string{targetHost}, []string{}, resolver)
	if err != nil {
		t.Fatalf("failed to create scope policy: %v", err)
	}
	scopePol = scopePol.WithLabMode(true) // Permits loopback routing to local mock-target

	canonicalTarget := "http://" + targetHost + ":" + mockPort
	policy, err := egress.PolicyForScanner(egress.ScannerNuclei, canonicalTarget, scopePol)
	if err != nil {
		t.Fatalf("failed to create scanner egress policy: %v", err)
	}

	// 5. Instantiate the isolated Egress Proxy
	proxy, err := egress.NewProxy(policy, zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("failed to instantiate egress proxy: %v", err)
	}
	defer proxy.Close()

	// 6. Demonstrate that without LabMode, direct loopback 127.0.0.1 is rejected
	strictPol, _ := scope.NewPolicy([]string{"example.com"}, []string{}, resolver)
	strictPolicy, err := egress.PolicyForScanner(egress.ScannerNuclei, "https://example.com", strictPol)
	if err == nil {
		strictProxy, err := egress.NewProxy(strictPolicy, zap.NewNop(), nil)
		if err == nil {
			defer strictProxy.Close()
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(mustParseURL(strictProxy.Endpoint())),
				},
				Timeout: 2 * time.Second,
			}
			resp, err := client.Get("http://127.0.0.1:" + mockPort)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("expected 403 Forbidden for direct loopback access in strict mode, got %d", resp.StatusCode)
				}
			}
		}
	}

	// 7. Perform harmless HTTP healthcheck and fixture verification THROUGH the proxy
	proxyClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxy.Endpoint())),
		},
		Timeout: 5 * time.Second,
	}

	// Check 7a: /healthz
	respHealth, err := proxyClient.Get(canonicalTarget + "/healthz")
	if err != nil {
		t.Fatalf("healthcheck through proxy failed: %v", err)
	}
	defer respHealth.Body.Close()
	if respHealth.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /healthz, got %d", respHealth.StatusCode)
	}
	var healthData map[string]interface{}
	if err := json.NewDecoder(respHealth.Body).Decode(&healthData); err != nil {
		t.Fatalf("failed to decode /healthz JSON: %v", err)
	}
	if healthData["service"] != "kelvin-mock-target" || healthData["status"] != "healthy" {
		t.Errorf("unexpected healthcheck payload: %+v", healthData)
	}

	// Check 7b: /.env (Confirm it is an intentional mock fixture, not real host secrets)
	respEnv, err := proxyClient.Get(canonicalTarget + "/.env")
	if err != nil {
		t.Fatalf("failed to fetch /.env fixture: %v", err)
	}
	defer respEnv.Body.Close()
	bodyEnv, _ := io.ReadAll(respEnv.Body)
	envStr := string(bodyEnv)
	if !strings.Contains(envStr, "DB_PASSWORD=mock_insecure_password_123") {
		t.Errorf("expected mock password fixture in /.env, got: %s", envStr)
	}
	// Verify no real host environment variables or sensitive keys exist in fixture
	if strings.Contains(envStr, "REPLACE_WITH") || strings.Contains(envStr, "eyJ") {
		t.Errorf("SECURITY ALERT: /.env fixture contains suspect tokens: %s", envStr)
	}

	// Check 7c: /robots.txt (Confirm intentional mock fixture)
	respRobots, err := proxyClient.Get(canonicalTarget + "/robots.txt")
	if err != nil {
		t.Fatalf("failed to fetch /robots.txt fixture: %v", err)
	}
	defer respRobots.Body.Close()
	bodyRobots, _ := io.ReadAll(respRobots.Body)
	robotsStr := string(bodyRobots)
	if !strings.Contains(robotsStr, "Disallow: /admin") || !strings.Contains(robotsStr, "Disallow: /vulnerable/") {
		t.Errorf("unexpected /robots.txt fixture content: %s", robotsStr)
	}

	// Check 7d: Redirect validation - ensure redirect to IMDS is blocked
	respRedirect, err := proxyClient.Get(canonicalTarget + "/vulnerable/redirect-imds")
	if err == nil {
		defer respRedirect.Body.Close()
		// Egress proxy must block the redirect target (169.254.169.254)
		if respRedirect.StatusCode != http.StatusForbidden && respRedirect.StatusCode != http.StatusBadGateway {
			t.Errorf("expected redirect to IMDS to be blocked by egress proxy, got status: %d", respRedirect.StatusCode)
		}
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
