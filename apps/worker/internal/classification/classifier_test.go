package classification

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestClassificationCategoriesAndRetryability(t *testing.T) {
	cases := []struct {
		category  FailureCategory
		retryable bool
	}{
		{CategoryTargetUnreachable, true},
		{CategoryTimeout, true},
		{CategoryInfrastructureFault, true},
		{CategoryInvalidConfig, false},
		{CategoryUnsupportedVersion, false},
		{CategoryScopeViolation, false},
		{CategoryResourceExhaustion, false},
		{CategoryOutputParseError, false},
		{CategoryProcessCrash, false},
		{CategoryUnknown, false},
	}

	for _, tc := range cases {
		if tc.category.IsRetryable() != tc.retryable {
			t.Errorf("category %s IsRetryable() = %v; want %v", tc.category, tc.category.IsRetryable(), tc.retryable)
		}
	}
}

func TestClassifyOOM(t *testing.T) {
	// Case 1: OOMKilled flag
	cf1 := Classify(context.Background(), ClassificationInput{
		Scanner:   "nuclei",
		ExitCode:  137,
		OOMKilled: true,
	})
	if cf1.Category != CategoryResourceExhaustion || cf1.Code != "ERR_OOM" {
		t.Fatalf("expected CategoryResourceExhaustion / ERR_OOM, got: %s / %s", cf1.Category, cf1.Code)
	}
	if cf1.Retryable {
		t.Errorf("OOM should not be retryable")
	}

	// Case 2: Stderr contains out of memory
	cf2 := Classify(context.Background(), ClassificationInput{
		Scanner:  "zap",
		ExitCode: 1,
		Stderr:   "fatal error: runtime: out of memory",
	})
	if cf2.Category != CategoryResourceExhaustion {
		t.Fatalf("expected CategoryResourceExhaustion from stderr, got: %s", cf2.Category)
	}
}

func TestClassifyTimeout(t *testing.T) {
	// Case 1: Context deadline exceeded error
	cf1 := Classify(context.Background(), ClassificationInput{
		Scanner: "zap",
		Err:     context.DeadlineExceeded,
	})
	if cf1.Category != CategoryTimeout || cf1.Code != "ERR_DEADLINE_EXCEEDED" {
		t.Fatalf("expected CategoryTimeout / ERR_DEADLINE_EXCEEDED, got: %s / %s", cf1.Category, cf1.Code)
	}
	if !cf1.Retryable {
		t.Errorf("timeout should be retryable")
	}

	// Case 2: Exit code 124
	cf2 := Classify(context.Background(), ClassificationInput{
		Scanner:  "nuclei",
		ExitCode: 124,
	})
	if cf2.Category != CategoryTimeout {
		t.Fatalf("expected CategoryTimeout from exit code 124, got: %s", cf2.Category)
	}
}

func TestClassifyScopeViolation(t *testing.T) {
	cf := Classify(context.Background(), ClassificationInput{
		Scanner:       "nuclei",
		EgressBlocked: true,
		Stderr:        "egress: destination blocked by policy: RFC 1918 address 10.0.0.1 forbidden",
	})
	if cf.Category != CategoryScopeViolation || cf.Code != "ERR_SCOPE_BLOCKED" {
		t.Fatalf("expected CategoryScopeViolation / ERR_SCOPE_BLOCKED, got: %s / %s", cf.Category, cf.Code)
	}
	if cf.Retryable {
		t.Errorf("scope violations must never be retryable")
	}
}

func TestClassifyTargetUnreachable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		text string
	}{
		{"connection refused", errors.New("dial tcp 93.184.216.34:443: connect: connection refused"), ""},
		{"DNS failure", nil, "dial: lookup nonexistent.domain: no such host"},
		{"network unreachable", errors.New("connect: network is unreachable"), ""},
		{"TLS handshake failure", nil, "remote error: tls: handshake failure"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cf := Classify(context.Background(), ClassificationInput{
				Scanner: "http_preflight",
				Err:     tc.err,
				Stderr:  tc.text,
			})
			if cf.Category != CategoryTargetUnreachable {
				t.Fatalf("expected CategoryTargetUnreachable, got: %s", cf.Category)
			}
			if !cf.Retryable {
				t.Fatalf("target unreachable should be marked retryable")
			}
		})
	}
}

func TestClassifyInvalidConfigAndVersion(t *testing.T) {
	// Invalid config
	cfConfig := Classify(context.Background(), ClassificationInput{
		Scanner: "zap",
		Err:     errors.New("adapters: invalid scanner config: requests_per_second must be in 1..5"),
	})
	if cfConfig.Category != CategoryInvalidConfig {
		t.Fatalf("expected CategoryInvalidConfig, got: %s", cfConfig.Category)
	}

	// Unsupported version
	cfVersion := Classify(context.Background(), ClassificationInput{
		Scanner: "nuclei",
		Stderr:  "adapters: unsupported runtime version v2.8.0, minimum is v3.0.0",
	})
	if cfVersion.Category != CategoryUnsupportedVersion {
		t.Fatalf("expected CategoryUnsupportedVersion, got: %s", cfVersion.Category)
	}
}

func TestClassifyOutputParseError(t *testing.T) {
	cf := Classify(context.Background(), ClassificationInput{
		Scanner: "nuclei",
		Stderr:  "failed to parse scanner output: unexpected end of JSON input",
	})
	if cf.Category != CategoryOutputParseError {
		t.Fatalf("expected CategoryOutputParseError, got: %s", cf.Category)
	}
	if cf.Retryable {
		t.Errorf("output parse errors are terminal and should not be retryable")
	}
}

func TestClassifyProcessCrash(t *testing.T) {
	cf := Classify(context.Background(), ClassificationInput{
		Scanner:  "nuclei",
		ExitCode: 2,
		Stderr:   "fatal: segmentation fault (core dumped)",
	})
	if cf.Category != CategoryProcessCrash || cf.Code != "ERR_PROCESS_EXIT_2" {
		t.Fatalf("expected CategoryProcessCrash / ERR_PROCESS_EXIT_2, got: %s / %s", cf.Category, cf.Code)
	}
}

func TestRedactSecrets(t *testing.T) {
	raw := "Request failed: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret and apikey=secret_api_123456 with token=token_xyz"
	redacted := RedactSecrets(raw)

	if strings.Contains(redacted, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret") {
		t.Errorf("bearer token was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "secret_api_123456") {
		t.Errorf("apikey was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "token_xyz") {
		t.Errorf("token was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "Bearer [REDACTED]") {
		t.Errorf("expected Bearer [REDACTED], got: %s", redacted)
	}
}
