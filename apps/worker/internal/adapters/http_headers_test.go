package adapters

import (
	"context"
	"encoding/json"
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

func TestHTTPSecurityHeadersAdapterExecutesScopedHEADAndEmitsEnvelope(t *testing.T) {
	withLabMode(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodHead {
			t.Errorf("method=%q, want HEAD", r.Method)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Add("Set-Cookie", "session=secret-value; HttpOnly; SameSite=Lax")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	policy, err := scope.NewPolicy([]string{"headers.test"}, nil, preflightResolver{ip: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	config, err := DefaultScannerConfig(ScannerHTTPHeaders)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	task := Task{
		JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID: "33333333-3333-3333-3333-333333333333", CorrelationID: "headers-correlation",
		Scanner: ScannerHTTPHeaders, Target: "http://headers.test" + strings.TrimPrefix(server.URL, "http://127.0.0.1"),
		ProfileID: "kelvin.profile.standard.v1", HardDeadline: 5 * time.Second, Payload: raw,
	}
	adapter := NewHTTPSecurityHeadersAdapter(func(context.Context, Task) (scope.Policy, error) { return policy, nil })
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("invalid result envelope: %v", err)
	}
	if result.Status != StatusCompleted || len(result.Findings) != 0 || requests != 1 {
		t.Fatalf("unexpected response audit: status=%s findings=%d requests=%d", result.Status, len(result.Findings), requests)
	}
	if !strings.Contains(string(result.ScannerMetadata["http_headers.rule_set_version"]), HTTPHeaderRuleSetVersion) {
		t.Fatalf("rule set version missing: %s", result.ScannerMetadata["http_headers.rule_set_version"])
	}
}

func TestSecurityHeaderRulesAndCookieEvidenceAreRedacted(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{
		"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Security-Policy":   {"default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'"},
		"X-Content-Type-Options":    {"nosniff"},
		"X-Frame-Options":           {"SAMEORIGIN"},
		"Referrer-Policy":           {"strict-origin-when-cross-origin"},
		"Permissions-Policy":        {"camera=*, microphone=()"},
		"Set-Cookie":                {"session=do-not-leak-this; HttpOnly; SameSite=None"},
	}}
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].SameSite != http.SameSiteNoneMode || cookies[0].Secure {
		t.Fatalf("fixture cookie was not parsed as insecure SameSite=None: %+v", cookies)
	}
	endpoint, err := url.Parse("https://headers.example/account?token=private")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := evaluateHTTPSecurityHeaders("headers.example", endpoint, response, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings=%d, want CSP, Permissions-Policy, cookie Secure, and cookie SameSite findings: %s", len(findings), findings)
	}
	joined := strings.Join(rawFindingsToStrings(findings), "\n")
	for _, expected := range []string{"csp_unsafe_script", "permissions_policy", "cookie_secure", "cookie_samesite"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("expected finding %q missing: %s", expected, joined)
		}
	}
	if strings.Contains(joined, "do-not-leak-this") || strings.Contains(joined, "session=") || strings.Contains(joined, "?token=") {
		t.Fatalf("cookie value or query leaked into findings: %s", joined)
	}
	if !strings.Contains(joined, "response.header.set-cookie.value") {
		t.Fatalf("cookie evidence does not attest redaction: %s", joined)
	}
	if !strings.Contains(joined, "HTTP status: 200") || !strings.Contains(joined, "Content-Type: text/html") {
		t.Fatalf("finding evidence omits response context: %s", joined)
	}
}

func TestSecurityHeaderRulesAvoidContextInsensitiveFindings(t *testing.T) {
	response := &http.Response{Header: http.Header{
		"Content-Type": {"application/json"},
		"Set-Cookie":   {"preference=client-readable; SameSite=Lax"},
	}}
	endpoint, err := url.Parse("http://headers.example/api")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := evaluateHTTPSecurityHeaders("headers.example", endpoint, response, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rawFindingsToStrings(findings), "\n")
	for _, suppressed := range []string{"hsts_missing", "csp_missing", "frame_protection", "referrer_policy", "cookie_secure", "cookie_httponly", "cookie_samesite"} {
		if strings.Contains(joined, suppressed) {
			t.Errorf("context-insensitive finding %q emitted: %s", suppressed, joined)
		}
	}
	if !strings.Contains(joined, "content_type_options") {
		t.Fatalf("applicable generic header check missing: %s", joined)
	}
}

func rawFindingsToStrings(findings []json.RawMessage) []string {
	values := make([]string, len(findings))
	for i, finding := range findings {
		values[i] = string(finding)
	}
	return values
}
