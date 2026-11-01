// Package scope canonicalizes scan targets and enforces scope at resolution,
// connection, and redirect time. Workers should use PinnedTransport rather
// than a default HTTP transport for requests to assessed targets.
package scope

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrTarget = errors.New("invalid target")
var ErrProhibited = errors.New("prohibited target address")
var ErrOutOfScope = errors.New("target is outside approved scope")
var ErrRedirectLoop = errors.New("redirect loop detected")
var ErrRedirectLimit = errors.New("redirect hop limit exceeded")
var ErrRedirectPort = errors.New("redirect port is not permitted")
var ErrRedirectScheme = errors.New("redirect scheme is not permitted")

const MaxRedirectHops = 10

type Target struct {
	Canonical string
	Host      string
	Port      string
	IP        netip.Addr
	Prefix    netip.Prefix
	URL       *url.URL
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Policy struct {
	Domains  []string
	Prefixes []netip.Prefix
	Resolver Resolver
	labMode  bool
	Dialer   net.Dialer
}

func NewPolicy(domains, cidrs []string, resolver Resolver) (Policy, error) {
	p := Policy{Domains: append([]string(nil), domains...), Resolver: resolver, labMode: LabModeFromEnv()}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return Policy{}, fmt.Errorf("invalid approved CIDR %q: %w", cidr, err)
		}
		p.Prefixes = append(p.Prefixes, prefix.Masked())
	}
	return p, nil
}

var prohibited = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("::ffff:0:0/96"),
}

func Normalize(raw string) (Target, error) {
	input := strings.TrimSpace(raw)
	if input == "" || len(input) > 4096 || strings.ContainsAny(input, "\r\n\x00\\") {
		return Target{}, fmt.Errorf("%w: empty, oversized, or invalid characters", ErrTarget)
	}
	if p, err := netip.ParsePrefix(input); err == nil {
		p = p.Masked()
		return Target{Canonical: p.String(), Prefix: p}, nil
	}
	if addr, err := netip.ParseAddr(strings.Trim(input, "[]")); err == nil {
		addr = addr.Unmap()
		return Target{Canonical: addr.String(), IP: addr}, nil
	}
	if candidate, looks := parseObfuscatedIPv4(input); looks {
		if candidate.IsValid() {
			return Target{Canonical: candidate.String(), IP: candidate}, nil
		}
		return Target{}, fmt.Errorf("%w: malformed numeric IP notation", ErrTarget)
	}
	var u *url.URL
	var err error
	if strings.Contains(input, "://") {
		u, err = url.Parse(input)
	} else {
		u, err = url.Parse("https://" + input)
	}
	if err != nil || u == nil {
		return Target{}, fmt.Errorf("%w: malformed URL", ErrTarget)
	}
	if u.User != nil {
		return Target{}, fmt.Errorf("%w: URL credentials are forbidden", ErrTarget)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fmt.Errorf("%w: only HTTP and HTTPS targets are supported", ErrTarget)
	}
	if u.Fragment != "" || u.Opaque != "" {
		return Target{}, fmt.Errorf("%w: fragments and opaque URLs are forbidden", ErrTarget)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || strings.Contains(host, "%") {
		return Target{}, fmt.Errorf("%w: invalid host", ErrTarget)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return Target{Canonical: canonicalIPURL(u, ip), Host: ip.String(), IP: ip, Port: portFor(u)}, nil
	}
	if numericIPHost(host) {
		if ip, looks := parseObfuscatedIPv4(host); looks && ip.IsValid() {
			return Target{Canonical: canonicalIPURL(u, ip), Host: ip.String(), IP: ip, Port: portFor(u)}, nil
		}
		return Target{}, fmt.Errorf("%w: malformed numeric IP notation", ErrTarget)
	}
	if err := validDNSName(host); err != nil {
		return Target{}, err
	}
	port := portFor(u)
	hasExplicitPort := u.Port() != ""
	if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
		return Target{}, fmt.Errorf("%w: invalid port", ErrTarget)
	}
	u.Host = host
	if hasExplicitPort {
		u.Host = net.JoinHostPort(host, port)
	}
	return Target{Canonical: u.String(), Host: host, Port: port, URL: u}, nil
}

func canonicalIPURL(u *url.URL, ip netip.Addr) string {
	host := ip.String()
	if ip.Is6() {
		host = "[" + host + "]"
	}
	port := portFor(u)
	if explicitPort(u) {
		host = net.JoinHostPort(ip.String(), port)
	}
	u.Host = host
	return u.String()
}
func explicitPort(u *url.URL) bool { return u.Port() != "" }
func portFor(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}
func validDNSName(h string) error {
	if len(h) > 253 {
		return fmt.Errorf("%w: hostname too long", ErrTarget)
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: invalid hostname", ErrTarget)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("%w: hostname must use ASCII DNS labels", ErrTarget)
			}
		}
	}
	return nil
}

// parseObfuscatedIPv4 accepts the legacy numeric forms interpreted as IPv4 by
// browsers and some socket stacks (octal, hex, and one-component dword).
func parseObfuscatedIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(strings.ToLower(s), ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		base := 10
		digits := p
		if strings.HasPrefix(p, "0x") {
			base = 16
			digits = p[2:]
		} else if len(p) > 1 && p[0] == '0' {
			base = 8
			digits = p[1:]
		}
		if digits == "" {
			if base == 8 {
				digits = "0"
			} else {
				return netip.Addr{}, false
			}
		}
		for _, r := range digits {
			valid := r >= '0' && r <= '9' || base == 16 && r >= 'a' && r <= 'f'
			if !valid {
				return netip.Addr{}, false
			}
		}
		n, e := strconv.ParseUint(digits, base, 32)
		if e != nil {
			return netip.Addr{}, true
		}
		nums[i] = n
	}
	for i := 0; i < len(nums)-1; i++ {
		if nums[i] > 255 {
			return netip.Addr{}, true
		}
	}
	lastBits := uint(8 * (5 - len(nums)))
	if nums[len(nums)-1] >= uint64(1)<<lastBits {
		return netip.Addr{}, true
	}
	value := nums[len(nums)-1]
	for i := 0; i < len(nums)-1; i++ {
		value |= nums[i] << uint(8*(3-i))
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}), true
}
func numericIPHost(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r == 'x' || r == '.') {
			return false
		}
	}
	return strings.ContainsAny(s, "0123456789")
}

func IsProhibited(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() {
		return true
	}
	for _, p := range prohibited {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func prefixProhibited(p netip.Prefix) bool {
	for _, bad := range prohibited {
		if p.Addr().Is4() == bad.Addr().Is4() && (p.Contains(bad.Addr()) || bad.Contains(p.Addr())) {
			return true
		}
	}
	return false
}

func (p Policy) resolver() Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}
func (p Policy) hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range p.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if strings.HasPrefix(d, "*.") {
			suffix := strings.TrimPrefix(d, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
		} else if host == d {
			return true
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, prefix := range p.Prefixes {
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}

func (p Policy) Validate(ctx context.Context, raw string) (Target, []netip.Addr, error) {
	t, err := Normalize(raw)
	if err != nil {
		return Target{}, nil, err
	}
	if t.Prefix.IsValid() {
		if prefixProhibited(t.Prefix) && !p.labMode {
			return Target{}, nil, fmt.Errorf("%w: CIDR intersects a prohibited range", ErrProhibited)
		}
		for _, approved := range p.Prefixes {
			if approved.Contains(t.Prefix.Addr()) && approved.Bits() <= t.Prefix.Bits() {
				return t, nil, nil
			}
		}
		return Target{}, nil, ErrOutOfScope
	}
	if t.IP.IsValid() {
		if IsProhibited(t.IP) && !p.labMode {
			return Target{}, nil, ErrProhibited
		}
		if !p.hostAllowed(t.IP.String()) {
			return Target{}, nil, ErrOutOfScope
		}
		return t, []netip.Addr{t.IP}, nil
	}
	if !p.hostAllowed(t.Host) {
		return Target{}, nil, ErrOutOfScope
	}
	ips, err := p.resolver().LookupNetIP(ctx, "ip", t.Host)
	if err != nil {
		return Target{}, nil, fmt.Errorf("resolve target: %w", err)
	}
	if len(ips) == 0 {
		return Target{}, nil, errors.New("target hostname has no addresses")
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if IsProhibited(ip) && !p.labMode {
			return Target{}, nil, fmt.Errorf("%w: DNS resolved to %s", ErrProhibited, ip)
		}
	}
	return t, ips, nil
}

type PinnedTransport struct {
	Policy Policy
	Dialer net.Dialer
	Base   *http.Transport
	init   sync.Once
}

func (p *Policy) NewTransport() *PinnedTransport {
	dialer := p.Dialer
	if dialer.Timeout == 0 {
		dialer.Timeout = 10 * time.Second
	}
	if dialer.KeepAlive == 0 {
		dialer.KeepAlive = 30 * time.Second
	}
	return &PinnedTransport{Policy: *p, Dialer: dialer}
}
func (t *PinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.init.Do(func() {
		if t.Base == nil {
			t.Base = &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true}
		}
		t.Base.DialContext = t.DialContext
	})
	return t.Base.RoundTrip(req)
}
func (t *PinnedTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("scope dial: invalid address: %w", err)
	}
	target, err := Normalize(host)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if target.IP.IsValid() {
		if !t.Policy.hostAllowed(target.IP.String()) {
			return nil, ErrOutOfScope
		}
		ips = []netip.Addr{target.IP}
	} else {
		if !t.Policy.hostAllowed(target.Host) {
			return nil, ErrOutOfScope
		}
		ips, err = t.Policy.resolver().LookupNetIP(ctx, "ip", target.Host)
		if err != nil {
			return nil, fmt.Errorf("resolve at connect: %w", err)
		}
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if IsProhibited(ip) && !t.Policy.labMode {
			return nil, fmt.Errorf("%w: DNS resolved to %s", ErrProhibited, ip)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("scope dial: hostname has no addresses")
	}
	var last error
	for _, ip := range ips {
		dialer := t.Dialer
		if dialer.Timeout == 0 && t.Policy.Dialer.Timeout > 0 {
			dialer = t.Policy.Dialer
		}
		if dialer.Timeout == 0 {
			dialer.Timeout = 10 * time.Second
		}
		conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}

func (p Policy) NewHTTPClient() *http.Client {
	transport := p.NewTransport()
	return &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > MaxRedirectHops {
			return fmt.Errorf("%w: maximum is %d", ErrRedirectLimit, MaxRedirectHops)
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("%w: %s", ErrRedirectScheme, req.URL.Scheme)
		}
		if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("%w: HTTPS redirect downgrade is prohibited", ErrRedirectScheme)
		}
		if len(via) > 0 && !redirectPortAllowed(via[0].URL, req.URL) {
			return fmt.Errorf("%w: %s", ErrRedirectPort, effectivePort(req.URL))
		}
		canonical := redirectCanonical(req.URL)
		for _, previous := range via {
			if redirectCanonical(previous.URL) == canonical {
				return fmt.Errorf("%w: %s", ErrRedirectLoop, canonical)
			}
		}
		_, _, err := p.Validate(req.Context(), req.URL.String())
		if err != nil {
			return fmt.Errorf("redirect destination rejected: %w", err)
		}
		return nil
	}}
}

// redirectPortAllowed permits the original target's port and standard web
// ports. A redirect cannot pivot an approved host onto an unrelated service.
func redirectPortAllowed(initial, destination *url.URL) bool {
	port := effectivePort(destination)
	return port == effectivePort(initial) ||
		(destination.Scheme == "http" && port == "80") ||
		(destination.Scheme == "https" && port == "443")
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

func redirectCanonical(u *url.URL) string {
	copyURL := *u
	copyURL.Fragment = ""
	if copyURL.Path == "" {
		copyURL.Path = "/"
	}
	port := copyURL.Port()
	if (copyURL.Scheme == "http" && port == "80") || (copyURL.Scheme == "https" && port == "443") {
		copyURL.Host = copyURL.Hostname()
		if strings.Contains(copyURL.Hostname(), ":") {
			copyURL.Host = "[" + copyURL.Hostname() + "]"
		}
	}
	copyURL.Scheme = strings.ToLower(copyURL.Scheme)
	copyURL.Host = strings.ToLower(copyURL.Host)
	return copyURL.String()
}

// LabModeFromEnv enables isolated local-lab exceptions only when a dedicated
// key signs the fixed v1 activation statement with HMAC-SHA256.
func LabModeFromEnv() bool {
	env := strings.ToLower(os.Getenv("KELVIN_ENV"))
	if env != "development" && env != "testing" {
		return false
	}
	if os.Getenv("KELVIN_LAB_MODE") != "enabled" {
		return false
	}
	key := os.Getenv("KELVIN_LAB_MODE_KEY")
	sig := os.Getenv("KELVIN_LAB_MODE_SIGNATURE")
	if len(key) < 32 || sig == "" {
		return false
	}
	provided, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("kelvin-local-lab:v1"))
	return hmac.Equal(provided, mac.Sum(nil))
}
