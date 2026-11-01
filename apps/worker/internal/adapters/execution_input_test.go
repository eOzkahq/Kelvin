package adapters

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/packages/common/scope"
)

type fixedResolver struct{ ips []netip.Addr }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.ips...), nil
}

func validExecutionInput(t *testing.T) ExecutionInput {
	t.Helper()
	task := validTask()
	task.Target = "https://example.com/"
	task.Payload = []byte(`{"severity":"low"}`)
	policy, err := scope.NewPolicy([]string{"example.com"}, nil, fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := BuildExecutionInput(context.Background(), task,
		InvocationAuthorization{ScopeID: "44444444-4444-4444-4444-444444444444", AuthorizationID: "55555555-5555-5555-5555-555555555555"},
		policy, "kelvin.resource.standard.v1", limits.DefaultLimits(), 25, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func TestBuildExecutionInputValidatesAndPinsTarget(t *testing.T) {
	in := validExecutionInput(t)
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if in.Target.Canonical != "https://example.com/" || len(in.Target.PinnedIPs) != 1 || in.Target.PinnedIPs[0] != "93.184.216.34" {
		t.Fatalf("unexpected target context: %+v", in.Target)
	}
	if in.Scope.Target != in.Target.Canonical || in.Execution.RequestsPerSecond != 25 {
		t.Fatalf("scope or resource context mismatch: %+v", in)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExecutionInput(raw)
	if err != nil || decoded.Target.Canonical != in.Target.Canonical {
		t.Fatalf("DecodeExecutionInput() = %+v, %v", decoded, err)
	}
}

func TestDecodeExecutionInputRejectsUnknownAndTrailingFields(t *testing.T) {
	raw, err := json.Marshal(validExecutionInput(t))
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"untrusted":true}`)...)
	if _, err := DecodeExecutionInput(unknown); err == nil {
		t.Fatal("DecodeExecutionInput accepted unknown field")
	}
	if _, err := DecodeExecutionInput(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("DecodeExecutionInput accepted trailing JSON")
	}
}

func TestBuildExecutionInputAllowsOpaqueSecretReference(t *testing.T) {
	task := validTask()
	task.Target = "https://example.com/"
	task.Payload = []byte(`{"credential_ref":"vault://tenant/scan-account"}`)
	policy, err := scope.NewPolicy([]string{"example.com"}, nil, fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildExecutionInput(context.Background(), task,
		InvocationAuthorization{ScopeID: "44444444-4444-4444-4444-444444444444"},
		policy, "kelvin.resource.standard.v1", limits.DefaultLimits(), 25, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestBuildExecutionInputRejectsOutOfScopeAndUnsafeConfig(t *testing.T) {
	cases := []struct {
		name   string
		target string
		config []byte
	}{
		{name: "out of scope", target: "https://outside.example/", config: []byte(`{}`)},
		{name: "arbitrary args", target: "https://example.com/", config: []byte(`{"args":["-target","evil.example"]}`)},
		{name: "environment injection", target: "https://example.com/", config: []byte(`{"env_vars":{"K":"V"}}`)},
		{name: "nested credential", target: "https://example.com/", config: []byte(`{"options":{"api_key":"secret-value"}}`)},
		{name: "non object config", target: "https://example.com/", config: []byte(`[]`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task := validTask()
			task.Target, task.Payload = tc.target, tc.config
			policy, err := scope.NewPolicy([]string{"example.com"}, nil, fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = BuildExecutionInput(context.Background(), task,
				InvocationAuthorization{ScopeID: "44444444-4444-4444-4444-444444444444"},
				policy, "kelvin.resource.standard.v1", limits.DefaultLimits(), 25, time.Now())
			if err == nil {
				t.Fatal("BuildExecutionInput accepted invalid input")
			}
		})
	}
}

func TestExecutionInputValidateRejectsTamperingAndIncompleteFields(t *testing.T) {
	base := validExecutionInput(t)
	cases := []struct {
		name   string
		mutate func(*ExecutionInput)
	}{
		{"unsupported version", func(in *ExecutionInput) { in.SchemaVersion = "2.0" }},
		{"scope target mismatch", func(in *ExecutionInput) { in.Scope.Target = "https://attacker.example/" }},
		{"missing pinned IP", func(in *ExecutionInput) { in.Target.PinnedIPs = nil }},
		{"prohibited pinned IP", func(in *ExecutionInput) { in.Target.PinnedIPs = []string{"127.0.0.1"} }},
		{"missing resource ref", func(in *ExecutionInput) { in.Execution.ResourcePolicyID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.Target.PinnedIPs = append([]string(nil), base.Target.PinnedIPs...)
			tc.mutate(&in)
			if err := in.Validate(); err == nil {
				t.Fatal("Validate accepted invalid input")
			}
		})
	}
}
