package adapters

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

func TestZAPBaselineAdapter_InitializationAndVerification(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	validVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: "2.16.0",
			AdapterVersion: "1.0.0",
			ImageReference: "kelvin/scanner-zap:2.16.0",
			ImageDigest:    "sha256:4b94f923b320d7be7d25e0a6d05fca1c676b772c679b380bf9cfd5ac5bbf6c41",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return []byte(`{"@version":"2.16.0","site":[{"@name":"http://target.internal","alerts":[]}]}`), nil
	}

	adapter := NewVerifiedZAPBaselineAdapter(validVerifier, dummyRunner)
	if err := adapter.Initialize(ctx, logger); err != nil {
		t.Fatalf("adapter.Initialize failed: %v", err)
	}

	// Verify adapter capabilities
	caps := adapter.Capabilities()
	if !caps.PassiveOnly {
		t.Errorf("ZAP baseline adapter must be passive only")
	}
	if caps.ActiveScanning {
		t.Errorf("ZAP baseline adapter must not perform active scanning")
	}
	if !caps.RequiresSandbox {
		t.Errorf("ZAP baseline adapter must require sandbox execution")
	}
	if caps.MaxConcurrency > 2 {
		t.Errorf("ZAP baseline adapter max concurrency cannot exceed 2")
	}
}

func TestZAPBaselineAdapter_RejectsMissingRuntimeInfo(t *testing.T) {
	ctx := context.Background()

	invalidVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: "", // Missing version
			ImageDigest:    "",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return nil, nil
	}

	adapter := NewVerifiedZAPBaselineAdapter(invalidVerifier, dummyRunner)
	_, err := adapter.VerifyRuntimeVersion(ctx)
	if err == nil {
		t.Fatalf("expected error for incomplete runtime version info, got nil")
	}
}

func TestZAPActiveScan_AuthorizationGate(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	validVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: "2.16.0",
			AdapterVersion: "1.0.0",
			ImageReference: "kelvin/scanner-zap:2.16.0",
			ImageDigest:    "sha256:4b94f923b320d7be7d25e0a6d05fca1c676b772c679b380bf9cfd5ac5bbf6c41",
		}, nil
	}

	executedCmd := ""
	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		executedCmd = "executed"
		return []byte(`{"@version":"2.16.0","site":[{"@name":"http://target.internal","alerts":[]}]}`), nil
	}

	adapter := NewVerifiedZAPBaselineAdapter(validVerifier, dummyRunner)
	if err := adapter.Initialize(ctx, logger); err != nil {
		t.Fatalf("adapter.Initialize failed: %v", err)
	}

	activeCfg := ScannerConfigV1{
		SchemaVersion:         ScannerConfigVersion,
		ScannerID:             ScannerZAPBaseline,
		ExecutionMode:         "ACTIVE",
		RequestTimeoutSeconds: 10,
		MaxDurationSeconds:    120,
		RequestsPerSecond:     1,
		MaxConcurrency:        1,
		ZAP: &ZAPSettings{
			SafetyProfile: ZAPSafetyProfileVersion,
			MaxChildren:   5,
			MaxDepth:      2,
			ActiveScan:    true,
		},
	}
	rawActiveCfg, _ := json.Marshal(activeCfg)

	// 1. Rejection under standard (non-active) profile
	taskStandard := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Target:       "https://target.internal",
		ProfileID:    ProfileStandard,
		Scanner:      ScannerZAPBaseline,
		Payload:      rawActiveCfg,
		HardDeadline: 5 * time.Minute,
	}

	_, err := adapter.Execute(ctx, taskStandard)
	if err == nil || !strings.Contains(err.Error(), "requires explicit authorization") {
		t.Fatalf("expected active scan rejection under standard profile, got: %v", err)
	}
	if executedCmd != "" {
		t.Fatal("runner should not have executed on unauthorized active scan")
	}

	// 2. Permission under deep profile (active traffic + admin signoff)
	taskDeep := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Target:       "https://target.internal",
		ProfileID:    ProfileDeep,
		Scanner:      ScannerZAPBaseline,
		Payload:      rawActiveCfg,
		HardDeadline: 15 * time.Minute,
	}

	res, err := adapter.Execute(ctx, taskDeep)
	if err != nil {
		t.Fatalf("expected authorized active scan under deep profile, got: %v", err)
	}
	if res.Status != StatusCompleted {
		t.Errorf("expected COMPLETED status, got: %s", res.Status)
	}
}

func TestOCIZAPRunnerWithScope_ModeSelection(t *testing.T) {
	ctx := context.Background()
	fakeExec := sandbox.NewFake()
	resolver := &candidateMockResolver{
		mapping: map[string][]netip.Addr{
			"target.internal": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	provider := func(_ context.Context, _ Task) (scope.Policy, error) {
		return scope.NewPolicy([]string{"target.internal"}, nil, resolver)
	}
	runner := NewOCIZAPRunnerWithScope(fakeExec, provider)

	// 1. Passive baseline task selects /zap/zap-baseline.py
	taskBaseline := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Target:       "https://target.internal",
		ProfileID:    ProfileStandard,
		Scanner:      ScannerZAPBaseline,
		HardDeadline: 5 * time.Minute,
	}
	_, err := runner(ctx, taskBaseline)
	if err != nil {
		t.Fatalf("unexpected runner error: %v", err)
	}
	if fakeExec.Last.Invocation.Executable != "/zap/zap-baseline.py" {
		t.Errorf("expected executable /zap/zap-baseline.py, got: %s", fakeExec.Last.Invocation.Executable)
	}

	activeCfg := ScannerConfigV1{
		SchemaVersion:         ScannerConfigVersion,
		ScannerID:             ScannerZAPBaseline,
		ExecutionMode:         "ACTIVE",
		RequestTimeoutSeconds: 10,
		MaxDurationSeconds:    120,
		RequestsPerSecond:     1,
		MaxConcurrency:        1,
		ZAP: &ZAPSettings{
			SafetyProfile: ZAPSafetyProfileVersion,
			MaxChildren:   5,
			MaxDepth:      2,
			ActiveScan:    true,
		},
	}
	rawActiveCfg, _ := json.Marshal(activeCfg)

	// 2. Active scan under standard profile is rejected
	taskActiveStd := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Target:       "https://target.internal",
		ProfileID:    ProfileStandard,
		Scanner:      ScannerZAPBaseline,
		Payload:      rawActiveCfg,
		HardDeadline: 5 * time.Minute,
	}
	_, err = runner(ctx, taskActiveStd)
	if err == nil || !strings.Contains(err.Error(), "requires explicit authorization") {
		t.Fatalf("expected active scan rejection in OCI runner, got: %v", err)
	}

	// 3. Active scan under deep profile is permitted and selects /zap/zap-full-scan.py
	taskActiveDeep := Task{
		JobID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID:     "33333333-3333-3333-3333-333333333333",
		Target:       "https://target.internal",
		ProfileID:    ProfileDeep,
		Scanner:      ScannerZAPBaseline,
		Payload:      rawActiveCfg,
		HardDeadline: 15 * time.Minute,
	}
	_, err = runner(ctx, taskActiveDeep)
	if err != nil {
		t.Fatalf("expected active scan to succeed in OCI runner under deep profile, got: %v", err)
	}
	if fakeExec.Last.Invocation.Executable != "/zap/zap-full-scan.py" {
		t.Errorf("expected executable /zap/zap-full-scan.py, got: %s", fakeExec.Last.Invocation.Executable)
	}
}
