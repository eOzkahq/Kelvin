package egress

import (
	"errors"
	"net/netip"
	"testing"
)

func ip(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestDefaultFilterBlocksPrivateRanges(t *testing.T) {
	f, err := NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	private := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"127.0.0.1",
		"169.254.169.254", // cloud metadata
		"169.254.0.1",     // link-local
		"::1",             // loopback v6
		"fc00::1",         // unique local v6
		"fe80::1",         // link-local v6
		"224.0.0.1",       // multicast
	}
	for _, s := range private {
		if !f.Blocked(ip(s)) {
			t.Errorf("expected %q to be blocked", s)
		}
		if err := f.Check(ip(s)); !errors.Is(err, ErrDestinationBlocked) {
			t.Errorf("expected Check(%q) to return ErrDestinationBlocked, got %v", s, err)
		}
	}
}

func TestDefaultFilterAllowsPublicTargets(t *testing.T) {
	f, err := NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2001:4860:4860::8888"}
	for _, s := range public {
		if f.Blocked(ip(s)) {
			t.Errorf("expected %q to be allowed", s)
		}
		if err := f.Check(ip(s)); err != nil {
			t.Errorf("expected Check(%q) to succeed, got %v", s, err)
		}
	}
}

func TestCloudMetadataNeverReachable(t *testing.T) {
	f, err := NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	// Even in lab mode, cloud metadata must remain blocked.
	f.AllowInternal()
	if !f.Blocked(ip("169.254.169.254")) {
		t.Error("cloud metadata 169.254.169.254 must remain blocked in lab mode")
	}
	if err := f.Check(ip("169.254.169.254")); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("expected metadata Check to return ErrDestinationBlocked, got %v", err)
	}
}

func TestAllowInternalUnblocksPrivateRanges(t *testing.T) {
	f, err := NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	f.AllowInternal()
	// Private ranges become reachable (lab mode only).
	if f.Blocked(ip("10.0.0.1")) {
		t.Error("expected 10.0.0.1 to be allowed in lab mode")
	}
	if f.Blocked(ip("172.16.0.1")) {
		t.Error("expected 172.16.0.1 to be allowed in lab mode")
	}
	if f.Blocked(ip("192.168.0.1")) {
		t.Error("expected 192.168.0.1 to be allowed in lab mode")
	}
}

func TestAllowListRestrictsReachability(t *testing.T) {
	f, err := NewFilter("93.184.216.34/32")
	if err != nil {
		t.Fatal(err)
	}
	if f.Blocked(ip("93.184.216.34")) {
		t.Error("expected allow-listed IP to be reachable")
	}
	if !f.Blocked(ip("1.1.1.1")) {
		t.Error("expected non-allow-listed public IP to be blocked")
	}
	// Cloud metadata stays blocked even if explicitly allow-listed.
	f2, err := NewFilter("169.254.169.254/32")
	if err != nil {
		t.Fatal(err)
	}
	if !f2.Blocked(ip("169.254.169.254")) {
		t.Error("cloud metadata must remain blocked even if explicitly allow-listed")
	}
}
