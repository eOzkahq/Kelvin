// Package egress provides a network egress filter for sandboxed scanner
// workers. It enforces a default-deny posture toward internal and cloud
// metadata destinations so a compromised or misconfigured scanner cannot
// reach RFC 1918 private space, loopback, link-local addresses, or cloud
// metadata endpoints (e.g. 169.254.169.254) (P1-29).
//
// This is the enforcement complement to packages/common/scope (target
// normalization and DNS pinning). The filter is applied at socket-connect
// time inside the sandbox executor and by scanner adapters before any
// outbound request.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var (
	// ErrDestinationBlocked is returned when a destination address is denied by
	// the egress filter.
	ErrDestinationBlocked = errors.New("egress: destination blocked by egress policy")
)

// blockedPrefixes are the absolute deny-list enforced on all worker outbound
// traffic. RFC 1918 private space, loopback, link-local, documentation /
// benchmarking ranges, multicast, and cloud metadata are never reachable from
// a scanner container.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // includes 169.254.169.254 cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("::ffff:0:0/96"),
}

// Filter decides whether a destination IP/hostname may be reached by a
// sandboxed worker. It holds the blocked prefixes plus any operator-supplied
// allow-list. Zero value blocks everything that is not explicitly allowed.
type Filter struct {
	blocked []netip.Prefix
	allowed []netip.Prefix
	// denyInternal, when true (default), applies the standard blockedPrefixes.
	denyInternal bool
}

// NewFilter builds a default-deny egress filter with the standard internal /
// cloud-metadata blocklist. If allowed CIDRs are supplied, only destinations
// matching them (and not blocked) are reachable.
func NewFilter(allowedCIDRs ...string) (*Filter, error) {
	f := &Filter{
		blocked:      append([]netip.Prefix{}, blockedPrefixes...),
		denyInternal: true,
	}
	for _, cidr := range allowedCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("egress: invalid allowed CIDR %q: %w", cidr, err)
		}
		f.allowed = append(f.allowed, p.Masked())
	}
	return f, nil
}

// AllowInternal relaxes the default-deny of RFC 1918 / loopback / link-local
// space for isolated lab environments. It does NOT unblock cloud metadata
// (169.254.0.0/16), which remains denied unconditionally. Intended for
// KELVIN_LAB_MODE only.
func (f *Filter) AllowInternal() {
	f.denyInternal = false
}

// Blocked reports whether the IP is denied by the filter.
func (f *Filter) Blocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	// Cloud metadata is never reachable, even in lab mode.
	if metadataPrefix.Contains(ip) {
		return true
	}
	if f.denyInternal {
		for _, p := range f.blocked {
			if p.Contains(ip) {
				return true
			}
		}
	}
	// If an allow-list is configured, only allowed destinations pass.
	if len(f.allowed) > 0 {
		for _, p := range f.allowed {
			if p.Contains(ip) {
				return false
			}
		}
		return true // not in allow-list
	}
	return false
}

// BlockedHost reports whether a hostname (after DNS resolution) is denied.
// It resolves via the standard resolver and blocks if ANY resolved address is
// blocked (anti-rebind: a resolving-to-private result is treated as blocked).
func (f *Filter) BlockedHost(host string) bool {
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if !f.Blocked(ip.Unmap()) {
			return false
		}
	}
	return true
}

// Check returns ErrDestinationBlocked if the IP is denied, nil otherwise. It
// is the call-site enforcement primitive used by the sandbox executor and
// scanner adapters before opening a connection.
func (f *Filter) Check(ip netip.Addr) error {
	if f.Blocked(ip) {
		return fmt.Errorf("%w: %s", ErrDestinationBlocked, ip)
	}
	return nil
}

// metadataPrefix is cloud metadata (169.254.0.0/16), denied unconditionally.
var metadataPrefix = netip.MustParsePrefix("169.254.0.0/16")
