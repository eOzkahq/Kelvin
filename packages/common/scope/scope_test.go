package scope

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestCanonicalObfuscatedAndAmbiguousTargets(t *testing.T) {
	tests := map[string]string{
		"0177.0.0.1": "127.0.0.1", "0x7f.0.0.1": "127.0.0.1", "0x7f000001": "127.0.0.1",
		"2130706433": "127.0.0.1", "0177.1": "127.0.0.1", "127.1": "127.0.0.1",
		"[::ffff:127.0.0.1]": "127.0.0.1", "http://[::1]/": "http://[::1]/",
		"EXAMPLE.COM.": "https://example.com", "https://example.com:443/a": "https://example.com:443/a",
	}
	for raw, want := range tests {
		got, err := Normalize(raw)
		if err != nil {
			t.Errorf("Normalize(%q): %v", raw, err)
			continue
		}
		if got.Canonical != want {
			t.Errorf("Normalize(%q)=%q, want %q", raw, got.Canonical, want)
		}
	}
	for _, raw := range []string{"http://legit@127.0.0.1", "ftp://example.com", "http://0x100000000", "http://0178.0.0.1", "http://[fe80::1%25eth0]"} {
		if _, err := Normalize(raw); err == nil {
			t.Errorf("Normalize(%q) accepted", raw)
		}
	}
}

func TestMoreThanFiftyProhibitedAddressVectors(t *testing.T) {
	vectors := []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "ff02::1"}
	for i := 1; i <= 20; i++ {
		vectors = append(vectors, "10.2.3."+strconv.Itoa(i))
		vectors = append(vectors, "192.168.10."+strconv.Itoa(i))
		vectors = append(vectors, "172.20.4."+strconv.Itoa(i))
	}
	for i, raw := range vectors {
		target, err := Normalize(raw)
		if err != nil {
			t.Fatalf("vector %d normalization %q: %v", i, raw, err)
		}
		if !target.IP.IsValid() || !IsProhibited(target.IP) {
			t.Errorf("vector %d was not prohibited: %s", i, raw)
		}
	}
	if len(vectors) < 50 {
		t.Fatalf("expected >=50 test vectors, got %d", len(vectors))
	}
}

func TestPolicyBlocksProhibitedAndOutOfScopeTargets(t *testing.T) {
	policy := Policy{Domains: []string{"allowed.example"}, Prefixes: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}, Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})}
	for _, raw := range []string{"http://127.0.0.1", "http://10.0.0.1", "http://169.254.169.254", "http://[::1]"} {
		if _, _, err := policy.Validate(context.Background(), raw); !errors.Is(err, ErrProhibited) {
			t.Errorf("%q error=%v", raw, err)
		}
	}
	if _, _, err := policy.Validate(context.Background(), "https://outside.example"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("out of scope error=%v", err)
	}
	if _, _, err := policy.Validate(context.Background(), "https://allowed.example"); err != nil {
		t.Fatalf("in-scope public host rejected: %v", err)
	}
}

func TestDNSRebindingAbortedAtDialTime(t *testing.T) {
	lookups := 0
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	policy := Policy{Domains: []string{"rebind.example"}, Resolver: resolver}
	if _, _, err := policy.Validate(context.Background(), "https://rebind.example"); err != nil {
		t.Fatalf("public initial resolution rejected: %v", err)
	}
	transport := policy.NewTransport()
	_, err := transport.DialContext(context.Background(), "tcp", "rebind.example:443")
	if !errors.Is(err, ErrProhibited) {
		t.Fatalf("rebinding result=%v", err)
	}
	if lookups != 2 {
		t.Fatalf("expected fresh connect-time resolution, lookups=%d", lookups)
	}
}

func TestDialRejectsDirectOutOfScopeIP(t *testing.T) {
	policy := Policy{Prefixes: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}}
	_, err := policy.NewTransport().DialContext(context.Background(), "tcp", "1.1.1.1:443")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("direct unapproved IP error=%v", err)
	}
}

func TestRedirectScopeIsRevalidated(t *testing.T) {
	var client *http.Client
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://outside.example/", http.StatusFound)
	}))
	defer server.Close()
	ip := strings.TrimPrefix(server.URL, "http://")
	policy := Policy{labMode: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	client = policy.NewHTTPClient()
	_, err := client.Get("http://" + ip)
	if err == nil || !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("redirect should be blocked as out of scope: %v", err)
	}
}

func TestRedirectLoopIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := "/a"
		if r.URL.Path == "/a" {
			next = "/b"
		}
		http.Redirect(w, r, next, http.StatusFound)
	}))
	defer server.Close()
	policy := Policy{labMode: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	_, err := policy.NewHTTPClient().Get(server.URL + "/a")
	if !errors.Is(err, ErrRedirectLoop) {
		t.Fatalf("redirect loop error=%v, want ErrRedirectLoop", err)
	}
}

func TestRedirectHopLimitIsEnforced(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		hop, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if hop < MaxRedirectHops+2 {
			http.Redirect(w, r, "/"+strconv.Itoa(hop+1), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	policy := Policy{labMode: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	_, err := policy.NewHTTPClient().Get(server.URL + "/0")
	if !errors.Is(err, ErrRedirectLimit) {
		t.Fatalf("redirect limit error=%v, want ErrRedirectLimit", err)
	}
	if requests != MaxRedirectHops+1 {
		t.Fatalf("requests=%d, want initial request plus exactly %d redirects", requests, MaxRedirectHops)
	}
}

func TestRedirectToUnapprovedPortIsRejectedBeforeFollow(t *testing.T) {
	var destinationRequests int
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationRequests++ }))
	defer destination.Close()
	destinationURL, err := url.Parse(destination.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:"+destinationURL.Port()+"/target", http.StatusFound)
	}))
	defer server.Close()
	policy := Policy{labMode: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	_, err = policy.NewHTTPClient().Get(server.URL)
	if !errors.Is(err, ErrRedirectPort) {
		t.Fatalf("redirect port error=%v, want ErrRedirectPort", err)
	}
	if destinationRequests != 0 {
		t.Fatalf("unapproved redirect destination received %d requests", destinationRequests)
	}
}

func TestRedirectToUnsupportedSchemeIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://127.0.0.1/resource", http.StatusFound)
	}))
	defer server.Close()
	policy := Policy{labMode: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	_, err := policy.NewHTTPClient().Get(server.URL)
	if !errors.Is(err, ErrRedirectScheme) {
		t.Fatalf("redirect scheme error=%v, want ErrRedirectScheme", err)
	}
}

func TestLabModeRequiresValidSignature(t *testing.T) {
	t.Setenv("KELVIN_ENV", "testing")
	key := "01234567890123456789012345678901"
	t.Setenv("KELVIN_LAB_MODE", "enabled")
	t.Setenv("KELVIN_LAB_MODE_KEY", key)
	t.Setenv("KELVIN_LAB_MODE_SIGNATURE", "bad")
	if LabModeFromEnv() {
		t.Fatal("invalid lab signature accepted")
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("kelvin-local-lab:v1"))
	t.Setenv("KELVIN_LAB_MODE_SIGNATURE", hex.EncodeToString(mac.Sum(nil)))
	if !LabModeFromEnv() {
		t.Fatal("valid lab signature rejected")
	}
	t.Setenv("KELVIN_ENV", "production")
	if LabModeFromEnv() {
		t.Fatal("lab override accepted in production")
	}
	t.Setenv("KELVIN_LAB_MODE", "disabled")
	if LabModeFromEnv() {
		t.Fatal("disabled lab mode accepted")
	}
}

func TestCIDRPolicyRejectsProhibitedOverlap(t *testing.T) {
	policy := Policy{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	_, _, err := policy.Validate(context.Background(), "10.0.0.0/8")
	if !errors.Is(err, ErrProhibited) {
		t.Fatalf("private CIDR error=%v", err)
	}
	_, _, err = policy.Validate(context.Background(), "8.8.8.0/24")
	if err != nil {
		t.Fatalf("approved public CIDR rejected: %v", err)
	}
}

func TestSSRF_CloudMetadataAndRebinding(t *testing.T) {
	// 1. Cloud metadata IPs strictly prohibited
	metadataIPs := []string{
		"169.254.169.254",
		"169.254.170.2",
		"100.100.100.200",
		"255.255.255.255",
	}
	for _, ipStr := range metadataIPs {
		addr := netip.MustParseAddr(ipStr)
		if !IsProhibited(addr) {
			t.Errorf("expected cloud metadata IP %s to be prohibited", ipStr)
		}
	}

	// 2. Cloud metadata hostnames rejected
	policy := Policy{Domains: []string{"metadata.google.internal", "instance-data", "localhost"}}
	for _, host := range []string{"http://metadata.google.internal", "http://instance-data", "http://localhost"} {
		_, _, err := policy.Validate(context.Background(), host)
		if !errors.Is(err, ErrProhibited) {
			t.Errorf("expected ErrProhibited for %s, got: %v", host, err)
		}
	}

	// 3. Multi-homed DNS resolution containing one internal IP fails closed
	multiResolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("93.184.216.34"), // public
			netip.MustParseAddr("10.0.0.1"),      // private RFC 1918
		}, nil
	})
	multiPolicy := Policy{Domains: []string{"multihomed.example"}, Resolver: multiResolver}
	_, _, err := multiPolicy.Validate(context.Background(), "https://multihomed.example")
	if !errors.Is(err, ErrProhibited) {
		t.Fatalf("expected ErrProhibited on multi-homed resolution with internal IP, got: %v", err)
	}

	// 4. IPv6 link-local and ULA
	ipv6Targets := []string{
		"fe80::1",
		"fd00::1",
		"fc00::1",
		"::1",
	}
	for _, ip6 := range ipv6Targets {
		addr := netip.MustParseAddr(ip6)
		if !IsProhibited(addr) {
			t.Errorf("expected IPv6 address %s to be prohibited", ip6)
		}
	}
}

func TestWildcardDomainMatching_StrictBoundaries(t *testing.T) {
	policy, err := NewPolicy([]string{"*.example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("failed to create wildcard policy: %v", err)
	}

	// 1. Valid subdomains match
	validSubs := []string{"api.example.com", "sub.api.example.com", "test-app.example.com"}
	for _, sub := range validSubs {
		if !policy.HostAllowed(sub) {
			t.Errorf("expected valid subdomain %q to be allowed", sub)
		}
	}

	// 2. Root domain without explicit entry is NOT allowed by *.example.com
	if policy.HostAllowed("example.com") {
		t.Errorf("expected root domain example.com to be rejected when only *.example.com is in policy")
	}

	// 3. Suffix collision attempts are strictly rejected
	collisions := []string{
		"fake-example.com",
		"notexample.com",
		"evilexample.com",
		"attackerexample.com",
		"myexample.com",
	}
	for _, c := range collisions {
		if policy.HostAllowed(c) {
			t.Errorf("expected suffix collision %q to be rejected", c)
		}
	}
}

func TestNewPolicy_RejectsLaxWildcards(t *testing.T) {
	badWildcards := []string{
		"*.com",       // TLD wildcard
		"*.net",       // TLD wildcard
		"*.org",       // TLD wildcard
		"*example.com", // missing dot
		"example.*",   // postfix wildcard
		"*",           // single star
	}

	for _, bad := range badWildcards {
		_, err := NewPolicy([]string{bad}, nil, nil)
		if err == nil {
			t.Errorf("expected lax wildcard %q to be rejected, got nil error", bad)
		}
	}
}

func TestPolicyForTenant_TargetManifest(t *testing.T) {
	// 1. Missing tenant ID fails
	_, err := PolicyForTenant(TenantTargetManifest{}, nil)
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	// 2. AllowSubdomains=true generates both root and wildcard subdomains
	manifest := TenantTargetManifest{
		TenantID:        "tenant-corp-123",
		AllowedDomains:  []string{"kelvin.security"},
		AllowedCIDRs:    []string{"93.184.216.0/24"},
		AllowSubdomains: true,
	}

	p, err := PolicyForTenant(manifest, nil)
	if err != nil {
		t.Fatalf("PolicyForTenant failed: %v", err)
	}

	if !p.HostAllowed("kelvin.security") {
		t.Error("expected root domain kelvin.security to be allowed")
	}
	if !p.HostAllowed("api.kelvin.security") {
		t.Error("expected subdomain api.kelvin.security to be allowed")
	}
	if p.HostAllowed("other.com") {
		t.Error("expected unrelated domain other.com to be rejected")
	}
	if !p.HostAllowed("93.184.216.34") {
		t.Error("expected IP within approved CIDR to be allowed")
	}
}
