package egress

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/kelvin/kelvin/packages/common/scope"
)

type mockResolver struct {
	mapping map[string][]netip.Addr
}

func (m *mockResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if m != nil && m.mapping != nil {
		if addrs, ok := m.mapping[host]; ok {
			return addrs, nil
		}
	}
	if host == "example.com" {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	return nil, errors.New("host not found in mock resolver")
}

func testScopePolicy(resolver scope.Resolver) scope.Policy {
	p, err := scope.NewPolicy([]string{"example.com", "*.example.com", "app.test"}, []string{"93.184.216.0/24"}, resolver)
	if err != nil {
		panic(err)
	}
	return p
}

func TestPolicyForScanner_PredefinedConfigurations(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	policy := testScopePolicy(resolver)

	scanners := []struct {
		name          string
		expectedProto []string
		requiresProxy bool
	}{
		{ScannerHTTPPreflight, []string{"http", "https"}, false},
		{ScannerHTTPHeaders, []string{"http", "https"}, false},
		{ScannerHTTPSecurityHeaders, []string{"http", "https"}, false},
		{ScannerTLSAssessment, []string{"tls", "tcp", "https"}, false},
		{ScannerTLSAssessor, []string{"tls", "tcp", "https"}, false},
		{ScannerZAPBaseline, []string{"http", "https"}, true},
		{ScannerZAP, []string{"http", "https"}, true},
		{ScannerNuclei, []string{"http", "https"}, true},
	}

	for _, sc := range scanners {
		t.Run(sc.name, func(t *testing.T) {
			p, err := PolicyForScanner(sc.name, "https://example.com", policy)
			if err != nil {
				t.Fatalf("PolicyForScanner failed for %s: %v", sc.name, err)
			}
			if p.AllowCallbacks {
				t.Errorf("%s: callbacks should be disabled by default", sc.name)
			}
			if !p.BlockPrivateRanges {
				t.Errorf("%s: RFC 1918 blocking must be enabled", sc.name)
			}
			if !p.BlockCloudMetadata {
				t.Errorf("%s: Cloud metadata blocking must be enabled", sc.name)
			}
			if p.RequiresProxy != sc.requiresProxy {
				t.Errorf("%s: expected RequiresProxy=%v, got %v", sc.name, sc.requiresProxy, p.RequiresProxy)
			}
			if len(p.AllowedProtocols) != len(sc.expectedProto) {
				t.Errorf("%s: expected protocols %v, got %v", sc.name, sc.expectedProto, p.AllowedProtocols)
			}
		})
	}

	// Unknown scanner must fail closed
	if _, err := PolicyForScanner("unknown_scanner", "https://example.com", policy); !errors.Is(err, ErrUnknownScanner) {
		t.Errorf("expected ErrUnknownScanner, got %v", err)
	}
}

func TestValidateDestination_PermittedInScope(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerZAPBaseline, "https://example.com:443", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Test valid hostname and port
	addr, err := p.ValidateDestination(context.Background(), "example.com", 443, "https")
	if err != nil {
		t.Fatalf("expected valid destination to succeed, got %v", err)
	}
	if addr.String() != "93.184.216.34" {
		t.Errorf("expected 93.184.216.34, got %s", addr)
	}

	// Test valid approved IP within allowed CIDR
	ipAddr, err := p.ValidateDestination(context.Background(), "93.184.216.50", 80, "http")
	if err != nil {
		t.Fatalf("expected in-scope IP destination to succeed, got %v", err)
	}
	if ipAddr.String() != "93.184.216.50" {
		t.Errorf("expected 93.184.216.50, got %s", ipAddr)
	}
}

func TestValidateDestination_BlocksRFC1918AndProhibitedAddresses(t *testing.T) {
	resolver := &mockResolver{}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerNuclei, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	blocked := []string{
		"10.0.0.1",
		"10.255.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"127.0.0.1",
		"169.254.169.254", // Cloud metadata
		"169.254.1.1",     // Link local
		"::1",             // IPv6 loopback
		"fc00::1",         // IPv6 unique local
		"fe80::1",         // IPv6 link local
	}

	for _, target := range blocked {
		t.Run(target, func(t *testing.T) {
			_, err := p.ValidateDestination(context.Background(), target, 80, "http")
			if !errors.Is(err, ErrProhibitedAddress) {
				t.Errorf("expected ErrProhibitedAddress for %s, got %v", target, err)
			}
		})
	}
}

func TestValidateDestination_BlocksOutOfScopeTarget(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"unauthorized.org": {netip.MustParseAddr("8.8.8.8")},
		},
	}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerHTTPPreflight, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Out of scope hostname
	_, err = p.ValidateDestination(context.Background(), "unauthorized.org", 443, "https")
	if !errors.Is(err, ErrOutOfScopeTarget) {
		t.Errorf("expected ErrOutOfScopeTarget for unauthorized.org, got %v", err)
	}

	// Out of scope IP
	_, err = p.ValidateDestination(context.Background(), "8.8.8.8", 443, "https")
	if !errors.Is(err, ErrOutOfScopeTarget) {
		t.Errorf("expected ErrOutOfScopeTarget for 8.8.8.8, got %v", err)
	}
}

func TestValidateDestination_PortRestrictions(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerHTTPHeaders, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Permitted ports
	for _, port := range []int{80, 443} {
		if _, err := p.ValidateDestination(context.Background(), "example.com", port, "http"); err != nil {
			t.Errorf("port %d should be allowed: %v", port, err)
		}
	}

	// Prohibited ports (SSH, MySQL, Redis, invalid)
	for _, port := range []int{22, 3306, 6379, 0, 70000} {
		if _, err := p.ValidateDestination(context.Background(), "example.com", port, "http"); !errors.Is(err, ErrDisallowedPort) {
			t.Errorf("port %d should be rejected with ErrDisallowedPort, got %v", port, err)
		}
	}
}

func TestValidateDestination_ProtocolRestrictions(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerZAPBaseline, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	for _, proto := range []string{"ftp", "gopher", "ssh", "file", "ldap"} {
		if _, err := p.ValidateDestination(context.Background(), "example.com", 80, proto); !errors.Is(err, ErrDisallowedProtocol) {
			t.Errorf("expected ErrDisallowedProtocol for %q, got %v", proto, err)
		}
	}
}

func TestValidateDestination_BlocksCallbacks(t *testing.T) {
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"c123.oast.fun":           {netip.MustParseAddr("1.2.3.4")},
			"xyz.interactsh.com":      {netip.MustParseAddr("1.2.3.4")},
			"canarytokens.com":        {netip.MustParseAddr("1.2.3.4")},
			"sub.ceye.io":             {netip.MustParseAddr("1.2.3.4")},
			"target.burpcollaborator.net": {netip.MustParseAddr("1.2.3.4")},
		},
	}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerNuclei, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	callbacks := []string{
		"c123.oast.fun",
		"xyz.interactsh.com",
		"canarytokens.com",
		"sub.ceye.io",
		"target.burpcollaborator.net",
	}

	for _, cb := range callbacks {
		if _, err := p.ValidateDestination(context.Background(), cb, 443, "https"); !errors.Is(err, ErrCallbackProhibited) {
			t.Errorf("expected ErrCallbackProhibited for callback %s, got %v", cb, err)
		}
	}
}

func TestValidateDestination_AntiRebindDNSResolution(t *testing.T) {
	// Attacker configures DNS for in-scope domain to point to AWS metadata or RFC 1918
	resolver := &mockResolver{
		mapping: map[string][]netip.Addr{
			"rebind-metadata.example.com": {netip.MustParseAddr("169.254.169.254")},
			"rebind-private.example.com":  {netip.MustParseAddr("10.0.0.1")},
			"rebind-multi.example.com":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("192.168.1.1")},
		},
	}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerNuclei, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Rebinding to cloud metadata
	_, err = p.ValidateDestination(context.Background(), "rebind-metadata.example.com", 80, "http")
	if !errors.Is(err, ErrProhibitedAddress) {
		t.Errorf("expected ErrProhibitedAddress for metadata rebind, got %v", err)
	}

	// Rebinding to RFC 1918
	_, err = p.ValidateDestination(context.Background(), "rebind-private.example.com", 80, "http")
	if !errors.Is(err, ErrProhibitedAddress) {
		t.Errorf("expected ErrProhibitedAddress for private rebind, got %v", err)
	}

	// Multi-address rebind (one public, one private) - must fail closed
	_, err = p.ValidateDestination(context.Background(), "rebind-multi.example.com", 80, "http")
	if !errors.Is(err, ErrProhibitedAddress) {
		t.Errorf("expected ErrProhibitedAddress for multi-IP rebind, got %v", err)
	}
}

func TestValidateConfig_RejectsPolicyTampering(t *testing.T) {
	resolver := &mockResolver{}
	policy := testScopePolicy(resolver)
	p, err := PolicyForScanner(ScannerNuclei, "https://example.com", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	tamperingConfigs := []string{
		`{"flags": ["--interactsh-server", "evil.com"]}`,
		`{"oast": "enabled"}`,
		`{"options": {"no_proxy": true}}`,
		`{"custom_proxy": "http://169.254.169.254"}`,
		`{"proxy": "http_proxy=http://attacker.com"}`,
		`{"callback_url": "https://webhook.site/abc-123"}`,
		`{"pipeline": "https://pipedream.net/v1"}`,
		`{"token": "http://canarytokens.com/static/token.png"}`,
	}

	for _, raw := range tamperingConfigs {
		err := p.ValidateConfig(json.RawMessage(raw))
		if !errors.Is(err, ErrPolicyTampering) {
			t.Errorf("expected ErrPolicyTampering for config %q, got %v", raw, err)
		}
	}

	// Benign config should validate
	validConfig := json.RawMessage(`{"scanner_id": "nuclei", "max_concurrency": 2}`)
	if err := p.ValidateConfig(validConfig); err != nil {
		t.Errorf("expected benign config to pass, got %v", err)
	}
}
