package limits

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultLimitsAreValid(t *testing.T) {
	l := DefaultLimits()
	if err := l.Validate(); err != nil {
		t.Fatalf("default limits should be valid: %v", err)
	}
}

func TestForScanner_AllScanners(t *testing.T) {
	scanners := []string{
		"http_preflight",
		"http_security_headers",
		"http_headers",
		"tls_assessment",
		"tls_assessor",
		"zap_baseline",
		"zap",
		"nuclei",
	}

	for _, sc := range scanners {
		t.Run(sc, func(t *testing.T) {
			l, err := ForScanner(sc)
			if err != nil {
				t.Fatalf("ForScanner(%q) failed: %v", sc, err)
			}
			if err := l.Validate(); err != nil {
				t.Fatalf("limits for %q are invalid: %v", sc, err)
			}
		})
	}
}

func TestForScanner_RejectsUnknownScanner(t *testing.T) {
	_, err := ForScanner("non_existent_scanner")
	if !errors.Is(err, ErrUnknownScanner) {
		t.Errorf("expected ErrUnknownScanner, got %v", err)
	}
}

func TestValidateAgainstCeiling_Enforcement(t *testing.T) {
	ceiling := PlatformCeiling

	// Within ceiling
	validReq := Limits{
		CPUQuota:             "1.0",
		MemoryLimit:          "1g",
		DiskLimit:            "1g",
		MaxPIDs:              64,
		MaxConcurrentConns:   10,
		MaxRequestsPerTarget: 5000,
		HardDeadline:         10 * time.Minute,
	}
	if err := ValidateAgainstCeiling(validReq, ceiling); err != nil {
		t.Fatalf("expected validReq to pass ceiling validation: %v", err)
	}

	// Exceeding CPU
	badCPU := validReq
	badCPU.CPUQuota = "4.0"
	if err := ValidateAgainstCeiling(badCPU, ceiling); !errors.Is(err, ErrExceedsCeiling) {
		t.Errorf("expected ErrExceedsCeiling for CPU 4.0 vs 2.0, got %v", err)
	}

	// Exceeding Memory
	badMem := validReq
	badMem.MemoryLimit = "4g"
	if err := ValidateAgainstCeiling(badMem, ceiling); !errors.Is(err, ErrExceedsCeiling) {
		t.Errorf("expected ErrExceedsCeiling for Memory 4g vs 2g, got %v", err)
	}

	// Exceeding PIDs
	badPIDs := validReq
	badPIDs.MaxPIDs = 512
	if err := ValidateAgainstCeiling(badPIDs, ceiling); !errors.Is(err, ErrExceedsCeiling) {
		t.Errorf("expected ErrExceedsCeiling for PIDs 512 vs 256, got %v", err)
	}

	// Exceeding Hard Deadline
	badDeadline := validReq
	badDeadline.HardDeadline = 2 * time.Hour
	if err := ValidateAgainstCeiling(badDeadline, ceiling); !errors.Is(err, ErrExceedsCeiling) {
		t.Errorf("expected ErrExceedsCeiling for deadline 2h vs 30m, got %v", err)
	}
}

func TestParseMemoryBytes(t *testing.T) {
	cases := []struct {
		input string
		want  int64
		err   bool
	}{
		{"128m", 128 * 1024 * 1024, false},
		{"1g", 1024 * 1024 * 1024, false},
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"64k", 64 * 1024, false},
		{"", 0, true},
		{"invalid", 0, true},
		{"-5m", 0, true},
	}

	for _, tc := range cases {
		got, err := ParseMemoryBytes(tc.input)
		if tc.err && err == nil {
			t.Errorf("ParseMemoryBytes(%q) expected error, got nil", tc.input)
		}
		if !tc.err && err != nil {
			t.Errorf("ParseMemoryBytes(%q) unexpected error: %v", tc.input, err)
		}
		if !tc.err && got != tc.want {
			t.Errorf("ParseMemoryBytes(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseCPUQuota(t *testing.T) {
	cases := []struct {
		input string
		want  float64
		err   bool
	}{
		{"0.5", 0.5, false},
		{"1", 1.0, false},
		{"2.0", 2.0, false},
		{"", 0, true},
		{"-1", 0, true},
		{"zero", 0, true},
	}

	for _, tc := range cases {
		got, err := ParseCPUQuota(tc.input)
		if tc.err && err == nil {
			t.Errorf("ParseCPUQuota(%q) expected error, got nil", tc.input)
		}
		if !tc.err && err != nil {
			t.Errorf("ParseCPUQuota(%q) unexpected error: %v", tc.input, err)
		}
		if !tc.err && got != tc.want {
			t.Errorf("ParseCPUQuota(%q) = %f, want %f", tc.input, got, tc.want)
		}
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
