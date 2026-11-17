package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kelvin/kelvin/packages/common/scope"
)

var (
	ErrDisallowedProtocol = errors.New("egress: protocol not permitted by scanner egress policy")
	ErrDisallowedPort     = errors.New("egress: destination port not permitted by scanner egress policy")
	ErrOutOfScopeTarget   = errors.New("egress: destination host is outside approved assessment scope")
	ErrProhibitedAddress  = errors.New("egress: destination resolved to prohibited address (RFC 1918 / cloud metadata / loopback)")
	ErrCallbackProhibited = errors.New("egress: outbound callbacks and out-of-band channels are prohibited")
	ErrUnknownScanner     = errors.New("egress: unknown scanner identifier")
	ErrPolicyTampering    = errors.New("egress: scanner configuration attempts to weaken network policy")
)

const (
	ScannerHTTPPreflight       = "http_preflight"
	ScannerHTTPSecurityHeaders = "http_security_headers"
	ScannerHTTPHeaders         = "http_headers"
	ScannerTLSAssessment       = "tls_assessment"
	ScannerTLSAssessor         = "tls_assessor"
	ScannerZAPBaseline         = "zap_baseline"
	ScannerZAP                 = "zap"
	ScannerNuclei              = "nuclei"
	ScannerSSLScan             = "sslscan"
	ScannerNmap                = "nmap"
	ScannerWhatWeb             = "whatweb"
	ScannerSubfinder           = "subfinder"
)

var knownCallbackSuffixes = []string{
	"interactsh.com",
	"interact.sh",
	"oast.fun",
	"oast.live",
	"oast.site",
	"oast.online",
	"oast.pro",
	"oast.me",
	"canarytokens.com",
	"canarytokens.org",
	"ceye.io",
	"burpcollaborator.net",
	"dnslog.cn",
	"requestbin.net",
	"requestbin.com",
	"webhook.site",
	"pipedream.net",
	"ngrok.io",
	"ngrok-free.app",
	"localtunnel.me",
	"beeceptor.com",
	"mockbin.org",
	"postb.in",
}

// ScannerEgressPolicy defines the explicit network constraints for a scanner execution.
type ScannerEgressPolicy struct {
	Scanner                string       `json:"scanner"`
	Target                 string       `json:"target"`
	TargetHost             string       `json:"target_host"`
	TargetPort             int          `json:"target_port"`
	AllowedProtocols       []string     `json:"allowed_protocols"`
	AllowedPorts           []int        `json:"allowed_ports"`
	AllowCallbacks         bool         `json:"allow_callbacks"`
	AllowArbitraryEgress   bool         `json:"allow_arbitrary_egress"`
	BlockPrivateRanges     bool         `json:"block_private_ranges"`
	BlockCloudMetadata     bool         `json:"block_cloud_metadata"`
	RequireDNSVerification bool         `json:"require_dns_verification"`
	RequiresProxy          bool         `json:"requires_proxy"`
	ExecutionToken         string       `json:"execution_token,omitempty"`
	ScopePolicy            scope.Policy `json:"-"`
	Filter                 *Filter      `json:"-"`
}

// PolicyForScanner constructs the authoritative egress policy for a given scanner and target.
func PolicyForScanner(scanner, target string, scopePolicy scope.Policy) (*ScannerEgressPolicy, error) {
	canonicalScanner := canonicalizeScanner(scanner)
	if canonicalScanner == "" {
		return nil, fmt.Errorf("%w: %q", ErrUnknownScanner, scanner)
	}

	filter, err := NewFilter()
	if err != nil {
		return nil, fmt.Errorf("egress: initialize default deny filter: %w", err)
	}
	if scopePolicy.LabMode() {
		filter.AllowInternal()
	}

	// Validate target against scope policy to establish initial approved context
	normalizedTarget, resolvedIPs, err := scopePolicy.Validate(context.Background(), target)
	if err != nil {
		return nil, fmt.Errorf("egress: target validation failed against scope policy: %w", err)
	}

	targetHost := normalizedTarget.Host
	if targetHost == "" && normalizedTarget.IP.IsValid() {
		targetHost = normalizedTarget.IP.String()
	}

	targetPort := 0
	if normalizedTarget.Port != "" {
		if p, err := strconv.Atoi(normalizedTarget.Port); err == nil && p > 0 {
			targetPort = p
		}
	}

	if targetPort == 0 && normalizedTarget.URL != nil {
		if normalizedTarget.URL.Scheme == "https" {
			targetPort = 443
		} else if normalizedTarget.URL.Scheme == "http" {
			targetPort = 80
		}
	}

	allowedPorts := make([]int, 0, 4)
	if targetPort > 0 {
		allowedPorts = append(allowedPorts, targetPort)
	}

	policy := &ScannerEgressPolicy{
		Scanner:                canonicalScanner,
		Target:                 normalizedTarget.Canonical,
		TargetHost:             targetHost,
		TargetPort:             targetPort,
		AllowCallbacks:         false,
		AllowArbitraryEgress:   false,
		BlockPrivateRanges:     true,
		BlockCloudMetadata:     true,
		RequireDNSVerification: true,
		ScopePolicy:            scopePolicy,
		Filter:                 filter,
	}

	// Populate scanner-specific network egress parameters
	switch canonicalScanner {
	case ScannerHTTPPreflight, ScannerHTTPHeaders:
		policy.AllowedProtocols = []string{"http", "https"}
		policy.RequiresProxy = false
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 80, 443)

	case ScannerTLSAssessment:
		policy.AllowedProtocols = []string{"tls", "tcp", "https"}
		policy.RequiresProxy = false
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 443)

	case ScannerZAPBaseline:
		policy.AllowedProtocols = []string{"http", "https"}
		policy.RequiresProxy = true
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 80, 443)

	case ScannerNuclei:
		policy.AllowedProtocols = []string{"http", "https"}
		policy.RequiresProxy = true
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 80, 443)

	case ScannerSSLScan:
		policy.AllowedProtocols = []string{"tls", "tcp", "https"}
		policy.RequiresProxy = false
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 443)

	case ScannerNmap:
		policy.AllowedProtocols = []string{"tcp"}
		policy.RequiresProxy = false
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 80, 443)

	case ScannerWhatWeb:
		policy.AllowedProtocols = []string{"http", "https"}
		policy.RequiresProxy = true
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 80, 443)

	case ScannerSubfinder:
		policy.AllowedProtocols = []string{"https"}
		policy.RequiresProxy = true
		policy.AllowedPorts = appendUniquePorts(allowedPorts, 443)

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownScanner, scanner)
	}

	_ = resolvedIPs
	return policy, nil
}

// ValidateDestination verifies that an outbound connection request to host:port
// strictly adheres to this scanner's egress policy and scope boundaries.
func (p *ScannerEgressPolicy) ValidateDestination(ctx context.Context, hostOrAddr string, port int, scheme string) (netip.Addr, error) {
	if p == nil {
		return netip.Addr{}, errors.New("egress: nil policy")
	}

	// 1. Protocol Validation
	if scheme != "" {
		normalizedScheme := strings.ToLower(strings.TrimSuffix(scheme, "://"))
		if len(p.AllowedProtocols) == 0 {
			return netip.Addr{}, fmt.Errorf("%w: no protocols allowed (default-deny)", ErrDisallowedProtocol)
		}
		allowed := false
		for _, proto := range p.AllowedProtocols {
			if strings.EqualFold(proto, normalizedScheme) {
				allowed = true
				break
			}
		}
		if !allowed {
			return netip.Addr{}, fmt.Errorf("%w: %q not allowed for %s", ErrDisallowedProtocol, scheme, p.Scanner)
		}
	}

	// 2. Port Validation
	if port <= 0 || port > 65535 {
		return netip.Addr{}, fmt.Errorf("%w: invalid port %d", ErrDisallowedPort, port)
	}
	if len(p.AllowedPorts) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: no ports allowed (default-deny)", ErrDisallowedPort)
	}
	portAllowed := false
	for _, allowed := range p.AllowedPorts {
		if allowed == port {
			portAllowed = true
			break
		}
	}
	if !portAllowed {
		return netip.Addr{}, fmt.Errorf("%w: port %d not permitted for scanner %s (allowed: %v)", ErrDisallowedPort, port, p.Scanner, p.AllowedPorts)
	}

	// 3. Callback / Out-of-band Target Check
	cleanHost := strings.ToLower(strings.TrimSpace(hostOrAddr))
	cleanHost = strings.TrimPrefix(cleanHost, "[")
	cleanHost = strings.TrimSuffix(cleanHost, "]")

	if !p.AllowCallbacks {
		for _, suffix := range knownCallbackSuffixes {
			if cleanHost == suffix || strings.HasSuffix(cleanHost, "."+suffix) {
				return netip.Addr{}, fmt.Errorf("%w: callback infrastructure %q is forbidden", ErrCallbackProhibited, hostOrAddr)
			}
		}
	}

	// 4. IP Literal or Hostname Evaluation
	ip, err := netip.ParseAddr(cleanHost)
	if err == nil {
		ip = ip.Unmap()
		// Check prohibited addresses (RFC 1918, 169.254.169.254, loopback, etc.)
		if p.Filter != nil && p.Filter.Blocked(ip) {
			return netip.Addr{}, fmt.Errorf("%w: IP %s blocked by filter", ErrProhibitedAddress, ip)
		}
		if scope.IsProhibited(ip) && !p.ScopePolicy.LabMode() {
			return netip.Addr{}, fmt.Errorf("%w: IP %s prohibited by scope invariants", ErrProhibitedAddress, ip)
		}

		// Must fall within approved scope
		if !p.ScopePolicy.HostAllowed(ip.String()) {
			return netip.Addr{}, fmt.Errorf("%w: IP %s not approved in assessment scope", ErrOutOfScopeTarget, ip)
		}
		return ip, nil
	}

	// Hostname resolution and scope verification
	if !p.ScopePolicy.HostAllowed(cleanHost) {
		return netip.Addr{}, fmt.Errorf("%w: destination host %q is not approved in assessment scope", ErrOutOfScopeTarget, cleanHost)
	}

	// Resolve destination using the verified resolver (anti-rebind)
	resolved, err := p.resolveNetIP(ctx, cleanHost)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egress: failed to resolve host %q: %w", cleanHost, err)
	}
	if len(resolved) == 0 {
		return netip.Addr{}, fmt.Errorf("egress: host %q has no resolved IP addresses", cleanHost)
	}

	// Every resolved address must be evaluated. If ANY address is prohibited,
	// fail-closed to prevent DNS rebinding attacks.
	for _, addr := range resolved {
		addr = addr.Unmap()
		if p.Filter != nil && p.Filter.Blocked(addr) {
			return netip.Addr{}, fmt.Errorf("%w: host %q resolved to prohibited IP %s", ErrProhibitedAddress, cleanHost, addr)
		}
		if scope.IsProhibited(addr) && !p.ScopePolicy.LabMode() {
			return netip.Addr{}, fmt.Errorf("%w: host %q resolved to prohibited IP %s", ErrProhibitedAddress, cleanHost, addr)
		}
	}

	return resolved[0].Unmap(), nil
}

// ValidateConfig verifies that operator- or scanner-supplied configuration does
// not attempt to weaken network egress restrictions.
func (p *ScannerEgressPolicy) ValidateConfig(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}

	str := strings.ToLower(string(raw))

	// Block any attempt to enable arbitrary callbacks or third-party proxies
	prohibitedSubstrings := []string{
		"interactsh",
		"oast",
		"burpcollaborator",
		"canarytokens",
		"webhook.site",
		"pipedream",
		"requestbin",
		"dnslog",
		"ceye.io",
		"--no-proxy",
		"no_proxy",
		"http_proxy",
		"https_proxy",
		"169.254.169.254",
	}

	for _, sub := range prohibitedSubstrings {
		if strings.Contains(str, sub) {
			return fmt.Errorf("%w: configuration contains prohibited egress directive %q", ErrPolicyTampering, sub)
		}
	}

	return nil
}

func (p *ScannerEgressPolicy) resolveNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if p.ScopePolicy.Resolver != nil {
		return p.ScopePolicy.Resolver.LookupNetIP(ctx, "ip", host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func canonicalizeScanner(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case ScannerHTTPPreflight:
		return ScannerHTTPPreflight
	case ScannerHTTPSecurityHeaders, ScannerHTTPHeaders:
		return ScannerHTTPHeaders
	case ScannerTLSAssessment, ScannerTLSAssessor:
		return ScannerTLSAssessment
	case ScannerZAPBaseline, ScannerZAP:
		return ScannerZAPBaseline
	case ScannerNuclei:
		return ScannerNuclei
	case ScannerSSLScan:
		return ScannerSSLScan
	case ScannerNmap:
		return ScannerNmap
	case ScannerWhatWeb:
		return ScannerWhatWeb
	case ScannerSubfinder:
		return ScannerSubfinder
	default:
		return ""
	}
}

func appendUniquePorts(ports []int, extra ...int) []int {
	seen := make(map[int]bool, len(ports)+len(extra))
	result := make([]int, 0, len(ports)+len(extra))
	for _, p := range ports {
		if !seen[p] && p > 0 {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range extra {
		if !seen[p] && p > 0 {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}
