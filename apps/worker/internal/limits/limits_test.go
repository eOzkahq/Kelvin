package limits

import (
	"testing"
	"time"
)

func TestDefaultLimitsAreValid(t *testing.T) {
	l := DefaultLimits()
	if err := l.Validate(); err != nil {
		t.Fatalf("default limits should be valid: %v", err)
	}
}

func TestValidateRejectsInvalidLimits(t *testing.T) {
	cases := []struct {
		name string
		l    Limits
	}{
		{"empty cpu", Limits{MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 10 * time.Minute}},
		{"empty memory", Limits{CPUQuota: "1", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 10 * time.Minute}},
		{"zero max_pids", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 0, HardDeadline: 10 * time.Minute}},
		{"excessive pids", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 2000, HardDeadline: 10 * time.Minute}},
		{"zero deadline", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 0}},
		{"deadline too short", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 30 * time.Second}},
		{"deadline too long", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 48 * time.Hour}},
		{"excessive conns", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 10 * time.Minute, MaxConcurrentConns: 200}},
		{"excessive requests/target", Limits{CPUQuota: "1", MemoryLimit: "512m", DiskLimit: "2g", MaxPIDs: 64, HardDeadline: 10 * time.Minute, MaxRequestsPerTarget: 200000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.l.Validate(); err == nil {
				t.Errorf("expected validation failure for %s", tc.name)
			}
		})
	}
}

func TestValidateAcceptsBoundaryValues(t *testing.T) {
	l := Limits{
		CPUQuota:             MaxCPUQuota,
		MemoryLimit:          MaxMemoryLimit,
		DiskLimit:            MaxDiskLimit,
		MaxPIDs:              MaxPIDLimit,
		MaxConcurrentConns:   MaxConcurrentConns,
		MaxRequestsPerTarget: MaxRequestsPerTarget,
		HardDeadline:         MaxHardDeadline,
	}
	if err := l.Validate(); err != nil {
		t.Fatalf("boundary values should be valid: %v", err)
	}
}

func TestStringSummary(t *testing.T) {
	l := DefaultLimits()
	s := l.String()
	for _, want := range []string{"cpu=1", "mem=512m", "disk=2g", "pids=64", "deadline=30m0s"} {
		if !contains(s, want) {
			t.Errorf("summary %q should contain %q", s, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
