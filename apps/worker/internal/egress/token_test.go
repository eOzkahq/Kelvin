package egress

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

func TestGenerateExecutionToken(t *testing.T) {
	t1, err := GenerateExecutionToken("job-1", "tenant-1", "assess-1", "nuclei", 5*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	if t1.Token == "" || !strings.HasPrefix(t1.Token, TokenPrefix) {
		t.Errorf("expected token prefix %s, got %s", TokenPrefix, t1.Token)
	}
	if t1.JobID != "job-1" || t1.TenantID != "tenant-1" || t1.AssessmentID != "assess-1" || t1.Scanner != "nuclei" {
		t.Errorf("token fields mismatch: %+v", t1)
	}
	if t1.IsExpired() {
		t.Errorf("token should not be expired immediately")
	}

	// Uniqueness
	t2, _ := GenerateExecutionToken("job-1", "tenant-1", "assess-1", "nuclei", 5*time.Minute)
	if t1.Token == t2.Token {
		t.Errorf("tokens must be unique, got duplicate: %s", t1.Token)
	}

	// Expiration check
	expiredToken := &ExecutionToken{
		Token:     "test-expired",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	if !expiredToken.IsExpired() {
		t.Errorf("expected expiredToken.IsExpired() to be true")
	}
}

func TestTokenManager_Lifecycle(t *testing.T) {
	tm := NewTokenManager()

	tok, err := tm.Issue("job-100", "tenant-A", "assess-X", "zap", 10*time.Minute)
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}

	if tm.ActiveCount() != 1 {
		t.Errorf("expected 1 active token, got %d", tm.ActiveCount())
	}

	// Validate valid token
	validated, err := tm.Validate(tok.Token)
	if err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}
	if validated.JobID != "job-100" {
		t.Errorf("expected job-100, got %s", validated.JobID)
	}

	// Validate invalid token
	_, err = tm.Validate("invalid-token")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}

	// Validate empty token
	_, err = tm.Validate("")
	if err != ErrMissingToken {
		t.Errorf("expected ErrMissingToken, got %v", err)
	}

	// Revoke by token
	tm.Revoke(tok.Token)
	_, err = tm.Validate(tok.Token)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken after revoke, got %v", err)
	}

	// Revoke by job
	tokA, _ := tm.Issue("job-200", "tenant-A", "assess-X", "nuclei", 10*time.Minute)
	tokB, _ := tm.Issue("job-200", "tenant-A", "assess-X", "zap", 10*time.Minute)
	tokC, _ := tm.Issue("job-300", "tenant-A", "assess-X", "nmap", 10*time.Minute)

	if tm.ActiveCount() != 3 {
		t.Errorf("expected 3 active tokens, got %d", tm.ActiveCount())
	}

	tm.RevokeJob("job-200")
	if tm.ActiveCount() != 1 {
		t.Errorf("expected 1 active token after RevokeJob, got %d", tm.ActiveCount())
	}
	_, err = tm.Validate(tokA.Token)
	if err != ErrInvalidToken {
		t.Errorf("expected tokA to be revoked")
	}
	_, err = tm.Validate(tokB.Token)
	if err != ErrInvalidToken {
		t.Errorf("expected tokB to be revoked")
	}
	valC, err := tm.Validate(tokC.Token)
	if err != nil || valC.JobID != "job-300" {
		t.Errorf("expected tokC to remain valid")
	}
}

func TestProxy_ExecutionTokenEnforcement(t *testing.T) {
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
	targetIP := netip.MustParseAddr(targetHost)

	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			targetHost: {targetIP},
		},
	}
	scopePolicy := scope.Policy{
		Domains:  []string{targetHost},
		Prefixes: []netip.Prefix{netip.PrefixFrom(targetIP, targetIP.BitLen())},
		Resolver: resolver,
	}.WithLabMode(true)

	policy, err := PolicyForScanner(ScannerNuclei, targetServer.URL, scopePolicy)
	if err != nil {
		t.Fatal(err)
	}

	tm := NewTokenManager()
	tok, err := tm.Issue("job-auth-test", "tenant-1", "assess-1", "nuclei", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	metricsRec := &mockMetricsRecorder{}
	proxy, err := NewProxyWithBindAddr(policy, "127.0.0.1:0", zap.NewNop(), metricsRec)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxy.SetTokenManager(tm)

	proxyURL, _ := url.Parse(proxy.Endpoint())

	// Case 1: Unauthenticated request rejected with 407
	{
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		resp, err := client.Get(targetServer.URL)
		if err != nil {
			t.Fatalf("unexpected client error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("expected status 407 Proxy Authentication Required, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Kelvin-Egress-Blocked") != "true" {
			t.Errorf("expected X-Kelvin-Egress-Blocked header on auth rejection")
		}
	}

	// Case 2: Request with invalid Bearer token rejected with 407
	{
		req, _ := http.NewRequest(http.MethodGet, targetServer.URL, nil)
		req.Header.Set("Proxy-Authorization", "Bearer invalid-token-value")

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("unexpected client error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("expected status 407 for invalid token, got %d", resp.StatusCode)
		}
	}

	// Case 3: Request with valid Proxy-Authorization: Bearer <token> succeeds
	{
		req, _ := http.NewRequest(http.MethodGet, targetServer.URL, nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+tok.Token)

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("unexpected client error with valid token: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK with valid token, got %d: %s", resp.StatusCode, string(body))
		}
	}

	// Case 4: Request with valid Basic auth credentials in Proxy URL succeeds
	{
		authProxyURL, _ := url.Parse(fmt.Sprintf("http://token:%s@%s", tok.Token, proxyURL.Host))
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(authProxyURL),
			},
		}

		resp, err := client.Get(targetServer.URL)
		if err != nil {
			t.Fatalf("unexpected client error with basic auth: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK with basic auth in proxy URL, got %d: %s", resp.StatusCode, string(body))
		}
	}

	// Case 5: Expired token rejected with 407
	{
		expiredTok := &ExecutionToken{
			Token:        "kelvin-egress-expired-token",
			JobID:        "job-expired",
			TenantID:     "tenant-1",
			AssessmentID: "assess-1",
			Scanner:      "nuclei",
			CreatedAt:    time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:    time.Now().UTC().Add(-1 * time.Hour),
		}
		tm.Register(expiredTok)
		req, _ := http.NewRequest(http.MethodGet, targetServer.URL, nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+expiredTok.Token)

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("unexpected client error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("expected 407 for expired token, got %d", resp.StatusCode)
		}
	}

	// Case 6: CONNECT tunnel with valid token succeeds, without token rejected with 407
	{
		// CONNECT without auth
		conn, err := net.Dial("tcp", proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", targetHost, targetPort, targetHost, targetPort)
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Close()
		respStr := string(buf[:n])
		if !strings.Contains(respStr, "407 Proxy Authentication Required") {
			t.Errorf("expected 407 for unauthenticated CONNECT, got: %s", respStr)
		}

		// CONNECT with valid auth
		connAuth, err := net.Dial("tcp", proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		basicAuth := base64.StdEncoding.EncodeToString([]byte("token:" + tok.Token))
		_, _ = fmt.Fprintf(connAuth, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n", targetHost, targetPort, targetHost, targetPort, basicAuth)
		n, _ = connAuth.Read(buf)
		connAuth.Close()
		respAuthStr := string(buf[:n])
		if !strings.Contains(respAuthStr, "200 Connection Established") {
			t.Errorf("expected 200 Connection Established for authenticated CONNECT, got: %s", respAuthStr)
		}
	}
}
