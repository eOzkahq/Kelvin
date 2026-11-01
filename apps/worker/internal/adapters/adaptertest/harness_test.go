package adaptertest

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/packages/common/scope"
)

type fixedResolver struct{}

func (fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

func TestConformanceHarnessBuiltInAndExternalStyleAdapters(t *testing.T) {
	tests := []struct {
		name      string
		scannerID string
	}{
		{"built-in reference adapter", adapters.ScannerHTTPPreflight},
		{"external ZAP-style adapter", adapters.ScannerZAPBaseline},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config, err := adapters.DefaultScannerConfig(tc.scannerID)
			if err != nil {
				t.Fatal(err)
			}
			validConfig, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			invalid := config
			invalid.ExecutionMode = "ACTIVE"
			invalidConfig, err := json.Marshal(invalid)
			if err != nil {
				t.Fatal(err)
			}
			baseTask := conformanceTask(tc.scannerID, "/valid", validConfig)
			started := make(chan struct{})
			var processCalls int
			process := FakeProcessFunc(func(ctx context.Context, task adapters.Task) (ProcessOutput, error) {
				processCalls++
				if strings.HasSuffix(task.Target, "/cancel") {
					close(started)
					<-ctx.Done()
					return ProcessOutput{}, ctx.Err()
				}
				fixture := "valid-output.json"
				switch {
				case strings.HasSuffix(task.Target, "/malformed"):
					fixture = "malformed-output.json"
				case strings.HasSuffix(task.Target, "/empty"):
					fixture = "empty-output.json"
				case strings.HasSuffix(task.Target, "/partial"):
					fixture = "partial-output.json"
				case strings.HasSuffix(task.Target, "/failure"):
					fixture = "scanner-failure.json"
				}
				stdout, err := PreparedFixture(fixture, task, "1.0.0", "1.0.0")
				if err != nil {
					return ProcessOutput{}, err
				}
				exitCode := 0
				if fixture == "scanner-failure.json" || fixture == "malformed-output.json" {
					exitCode = 2
				}
				return ProcessOutput{Stdout: stdout, ExitCode: exitCode}, nil
			})
			adapter := &adapters.ReferenceAdapter{
				AdapterName: tc.scannerID,
				Caps: adapters.Capabilities{
					CheckCategories: []string{"passive"}, SupportedTargetTypes: []string{"url"},
					SupportedProtocols: []string{"http", "https"}, PassiveOnly: true,
					SupportsCancel: true, RequiresSandbox: tc.scannerID == adapters.ScannerZAPBaseline,
				},
				Run: EnvelopeRunner(process),
			}
			policy, err := scope.NewPolicy([]string{"example.test"}, nil, fixedResolver{})
			if err != nil {
				t.Fatal(err)
			}
			guard := func(ctx context.Context, task adapters.Task) error {
				_, _, err := policy.Validate(ctx, task.Target)
				return err
			}
			outOfScope := conformanceTask(tc.scannerID, "/outside", validConfig)
			outOfScope.Target = "https://outside.test/outside"
			scenarios := []Scenario{
				{Name: "valid envelope and correlation", Task: baseTask, ExpectedStatus: adapters.StatusCompleted},
				{Name: "malformed output", Task: conformanceTask(tc.scannerID, "/malformed", validConfig), ExpectedError: adapters.ErrMalformedOutput},
				{Name: "empty output", Task: conformanceTask(tc.scannerID, "/empty", validConfig), ExpectedError: adapters.ErrMalformedOutput},
				{Name: "partial output", Task: conformanceTask(tc.scannerID, "/partial", validConfig), ExpectedStatus: adapters.StatusPartial},
				{Name: "scanner failure envelope", Task: conformanceTask(tc.scannerID, "/failure", validConfig), ExpectedStatus: adapters.StatusFailed},
				{Name: "out-of-scope target", Task: outOfScope, ExpectScopeReject: true},
			}
			Run(t, Suite{
				Adapter: adapter, ValidConfig: validConfig, InvalidConfig: invalidConfig,
				Task: baseTask, Scenarios: scenarios, ScopeGuard: guard,
				ScopeError: scope.ErrOutOfScope, OutOfScope: &outOfScope,
				Cancellation: &CancellationCase{Task: conformanceTask(tc.scannerID, "/cancel", validConfig), Started: started},
				Timeout:      2 * time.Second,
			})
			if processCalls != 6 { // 5 executed output cases plus one cancellation attempt.
				t.Fatalf("fake process calls = %d, out-of-scope task must not reach scanner", processCalls)
			}
		})
	}
}

func TestFixtureSetContainsValidMalformedEmptyPartialAndFailureOutputs(t *testing.T) {
	for _, name := range []string{"valid-output.json", "partial-output.json", "scanner-failure.json"} {
		raw, err := Fixture(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adapters.DecodeOutputEnvelope(raw); err != nil {
			t.Errorf("fixture %s should be a valid envelope: %v", name, err)
		}
	}
	raw, err := Fixture("malformed-output.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapters.DecodeOutputEnvelope(raw); !errors.Is(err, adapters.ErrMalformedOutput) {
		t.Fatalf("malformed fixture error = %v, want ErrMalformedOutput", err)
	}
	empty, err := Fixture("empty-output.json")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty output fixture has bytes or failed to load: len=%d err=%v", len(empty), err)
	}
}

func conformanceTask(scannerID, path string, config []byte) adapters.Task {
	return adapters.Task{
		JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID: "33333333-3333-3333-3333-333333333333", CorrelationID: "conformance-correlation",
		Scanner: scannerID, Target: "https://example.test" + path, ProfileID: "kelvin.profile.standard.v1",
		HardDeadline: time.Minute, Payload: append(json.RawMessage(nil), config...),
	}
}
