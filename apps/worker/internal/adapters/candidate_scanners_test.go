package adapters

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

type candidateMockResolver struct {
	mapping map[string][]netip.Addr
}

func (m *candidateMockResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if ips, ok := m.mapping[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

func TestCandidateScannersScopeEnforcement(t *testing.T) {
	authorizedTarget := "https://authorized.example.com"
	unauthorizedTarget := "https://unauthorized.evil.org"

	resolver := &candidateMockResolver{
		mapping: map[string][]netip.Addr{
			"authorized.example.com": {netip.MustParseAddr("93.184.216.34")},
		},
	}

	mockProvider := func(_ context.Context, _ Task) (scope.Policy, error) {
		return scope.NewPolicy([]string{"authorized.example.com"}, nil, resolver)
	}

	scanners := []struct {
		name    string
		adapter ScannerAdapter
	}{
		{name: "sslscan", adapter: NewSSLScanAdapter(mockProvider)},
		{name: "nmap", adapter: NewNmapAdapter(mockProvider)},
		{name: "whatweb", adapter: NewWhatWebAdapter(mockProvider)},
		{name: "subfinder", adapter: NewSubfinderAdapter(mockProvider)},
	}

	for _, tc := range scanners {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
				t.Fatalf("failed to initialize %s: %v", tc.name, err)
			}
			task := Task{
				JobID:        uuid.NewString(),
				AssessmentID: uuid.NewString(),
				TenantID:     uuid.NewString(),
				Scanner:      tc.name,
				Target:       authorizedTarget,
				ProfileID:    "standard",
				HardDeadline: time.Minute,
			}

			// Execution against authorized target should succeed
			res, err := tc.adapter.(Executable).Execute(context.Background(), task)
			if err != nil {
				t.Fatalf("expected success on authorized target for %s, got: %v", tc.name, err)
			}
			if res.Status != StatusCompleted {
				t.Errorf("expected status COMPLETED, got: %s", res.Status)
			}
			if res.Metadata.ScannerID != tc.name {
				t.Errorf("expected scanner ID %s, got: %s", tc.name, res.Metadata.ScannerID)
			}

			// Execution against unauthorized target must be rejected
			unauthTask := task
			unauthTask.Target = unauthorizedTarget
			_, err = tc.adapter.(Executable).Execute(context.Background(), unauthTask)
			if err == nil || !strings.Contains(err.Error(), "not authorized by scope policy") {
				t.Fatalf("expected scope rejection for %s on %s, got: %v", tc.name, unauthorizedTarget, err)
			}
		})
	}
}

func TestSubfinderPassiveOnlyEnforcement(t *testing.T) {
	subfinder := NewSubfinderAdapter(nil)
	caps := subfinder.Capabilities()

	if !caps.PassiveOnly {
		t.Error("subfinder must enforce PassiveOnly = true")
	}
	if caps.ActiveScanning {
		t.Error("subfinder must enforce ActiveScanning = false")
	}
}
