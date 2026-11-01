package adapter

import (
	"errors"
	"testing"
	"time"
)

func validInvocationInput() InvocationInput {
	return InvocationInput{
		SchemaVersion: InputSchemaVersion,
		TaskID:        "11111111-1111-1111-1111-111111111111",
		AssessmentID:  "22222222-2222-2222-2222-222222222222",
		TenantID:      "33333333-3333-3333-3333-333333333333",
		CorrelationID: "corr-xyz",
		Target: CanonicalTarget{
			Raw:    "https://example.com/api",
			Scheme: "https",
			Host:   "example.com",
			Port:   443,
		},
		Scope: ApprovedScope{
			ScopeID:      "scope-1",
			AllowedHosts: []string{"example.com", "*.example.com"},
		},
		Profile: ProfileContext{
			ProfileID:         "standard-v1",
			Name:              "Standard Profile",
			MaxRequestRate:    50,
			MaxTargetRequests: 1000,
			TimeoutPerRequest: 5 * time.Second,
			HardDeadline:      10 * time.Minute,
			AllowedEngines:    []string{"zap", "nuclei", "preflight"},
		},
		ResourcePolicy: ResourcePolicyRef{
			PolicyID:       "pol-default",
			MaxMemoryBytes: 512 * 1024 * 1024,
			CPUCores:       1.0,
			ReadOnlyRootFS: true,
		},
		Scanner: ScannerConfig{
			Engine:      "nuclei",
			PassiveOnly: false,
			SafeFlags: map[string]string{
				"severity": "medium,high",
			},
		},
		ExecutionDeadline: 5 * time.Minute,
		CreatedAt:         time.Now(),
	}
}

func TestValidateInvocationInputValid(t *testing.T) {
	in := validInvocationInput()
	if err := ValidateInvocationInput(in); err != nil {
		t.Fatalf("expected valid invocation input to pass: %v", err)
	}

	execIn, err := in.ToExecutionInput()
	if err != nil {
		t.Fatalf("expected ToExecutionInput to succeed: %v", err)
	}
	if execIn.TaskID != in.TaskID {
		t.Fatalf("expected TaskID %s, got %s", in.TaskID, execIn.TaskID)
	}
}

func TestValidateInvocationInputSchemaVersion(t *testing.T) {
	in := validInvocationInput()
	in.SchemaVersion = "2.0"
	if err := ValidateInvocationInput(in); !errors.Is(err, ErrInvalidSchemaVersion) {
		t.Fatalf("expected ErrInvalidSchemaVersion, got %v", err)
	}
}

func TestValidateInvocationInputUUIDs(t *testing.T) {
	in := validInvocationInput()
	in.TaskID = "invalid-uuid"
	if err := ValidateInvocationInput(in); !errors.Is(err, ErrInvalidUUID) {
		t.Fatalf("expected ErrInvalidUUID for TaskID, got %v", err)
	}

	in = validInvocationInput()
	in.TenantID = ""
	if err := ValidateInvocationInput(in); !errors.Is(err, ErrMissingRequiredField) {
		t.Fatalf("expected ErrMissingRequiredField for TenantID, got %v", err)
	}
}

func TestValidateInvocationInputScopeEnforcement(t *testing.T) {
	in := validInvocationInput()
	in.Target.Host = "unauthorized.attacker.com"
	in.Target.Raw = "https://unauthorized.attacker.com"
	if err := ValidateInvocationInput(in); !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("expected ErrScopeViolation, got %v", err)
	}

	// Wildcard matching should succeed
	in = validInvocationInput()
	in.Target.Host = "subdomain.example.com"
	in.Target.Raw = "https://subdomain.example.com"
	if err := ValidateInvocationInput(in); err != nil {
		t.Fatalf("expected wildcard host match to pass: %v", err)
	}
}

func TestValidateInvocationInputRejectsCommandInjection(t *testing.T) {
	in := validInvocationInput()
	in.Target.Raw = "example.com; rm -rf /"
	if err := ValidateInvocationInput(in); !errors.Is(err, ErrUnsafeInput) {
		t.Fatalf("expected ErrUnsafeInput on injection target, got %v", err)
	}

	in = validInvocationInput()
	in.Scanner.SafeFlags["bad_flag"] = "test; whoami"
	if err := ValidateInvocationInput(in); !errors.Is(err, ErrUnsafeInput) {
		t.Fatalf("expected ErrUnsafeInput on metacharacter in flag value, got %v", err)
	}
}
