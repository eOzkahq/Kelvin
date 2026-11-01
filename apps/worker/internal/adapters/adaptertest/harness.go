// Package adaptertest contains reusable, offline conformance helpers for
// ScannerAdapter implementations and their fake scanner processes.
package adaptertest

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"go.uber.org/zap"
)

//go:embed testdata/*.json
var fixtureFiles embed.FS

type Scenario struct {
	Name              string
	Task              adapters.Task
	ExpectedStatus    adapters.ExecutionStatus
	ExpectedError     error
	ExpectScopeReject bool
}

type CancellationCase struct {
	Task    adapters.Task
	Started <-chan struct{}
}

// Suite describes scanner-specific inputs while the harness owns common
// lifecycle, config, version, output, correlation, and cancellation checks.
type Suite struct {
	Adapter       adapters.ScannerAdapter
	ValidConfig   []byte
	InvalidConfig []byte
	Task          adapters.Task
	Scenarios     []Scenario
	ScopeGuard    func(context.Context, adapters.Task) error
	ScopeError    error
	OutOfScope    *adapters.Task
	Cancellation  *CancellationCase
	Timeout       time.Duration
}

// Run executes the common adapter contract assertions. It never registers or
// certifies an adapter for production; it only reports test failures.
func Run(t *testing.T, suite Suite) {
	t.Helper()
	if suite.Adapter == nil {
		t.Fatal("adaptertest: Adapter is required")
	}
	if suite.Timeout <= 0 {
		suite.Timeout = 3 * time.Second
	}
	adapter := suite.Adapter
	if adapter.Name() == "" || adapter.Version() == "" {
		t.Fatal("adaptertest: adapter name and version are required")
	}
	if len(suite.ValidConfig) == 0 || len(suite.InvalidConfig) == 0 {
		t.Fatal("adaptertest: valid and invalid config fixtures are required")
	}
	if err := adapter.ValidateConfig(suite.ValidConfig); err != nil {
		t.Fatalf("adaptertest: valid config rejected: %v", err)
	}
	if err := adapter.ValidateConfig(suite.InvalidConfig); err == nil {
		t.Fatal("adaptertest: invalid config was accepted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), suite.Timeout)
	defer cancel()
	if err := adapter.Initialize(ctx, zap.NewNop()); err != nil {
		t.Fatalf("adaptertest: Initialize failed: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Cancel() })
	if err := adapter.Health(ctx); err != nil {
		t.Fatalf("adaptertest: Health failed after initialization: %v", err)
	}
	caps := adapter.Capabilities()
	if len(caps.SupportedTargetTypes) == 0 || len(caps.CheckCategories) == 0 {
		t.Fatal("adaptertest: capabilities must declare target types and check categories")
	}
	runtime, err := adapter.VerifyRuntimeVersion(ctx)
	if err != nil {
		t.Fatalf("adaptertest: VerifyRuntimeVersion failed: %v", err)
	}
	if runtime.ScannerVersion == "" || runtime.AdapterVersion != adapter.Version() {
		t.Fatalf("adaptertest: runtime version identity is incomplete or inconsistent: %+v", runtime)
	}
	if len(suite.Scenarios) == 0 {
		t.Fatal("adaptertest: at least one execution scenario is required")
	}
	if err := adapters.ValidateTask(suite.Task); err != nil {
		t.Fatalf("adaptertest: baseline task is invalid: %v", err)
	}
	if suite.Task.Scanner != adapter.Name() {
		t.Fatalf("adaptertest: task scanner %q does not match adapter %q", suite.Task.Scanner, adapter.Name())
	}
	if suite.ScopeGuard != nil {
		if err := suite.ScopeGuard(ctx, suite.Task); err != nil {
			t.Fatalf("adaptertest: in-scope task rejected by scope guard: %v", err)
		}
		if suite.OutOfScope == nil || suite.ScopeError == nil {
			t.Fatal("adaptertest: scope guard requires an out-of-scope task and expected error")
		}
	} else if suite.OutOfScope != nil {
		t.Fatal("adaptertest: out-of-scope task requires a scope guard")
	}

	for _, scenario := range suite.Scenarios {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			task := scenario.Task
			if task.JobID == "" {
				task = suite.Task
			}
			if task.Scanner != adapter.Name() {
				t.Fatalf("scenario scanner %q does not match adapter %q", task.Scanner, adapter.Name())
			}
			if suite.ScopeGuard != nil {
				guardErr := suite.ScopeGuard(ctx, task)
				if scenario.ExpectScopeReject {
					if !errors.Is(guardErr, suite.ScopeError) {
						t.Fatalf("scope guard error = %v, want %v", guardErr, suite.ScopeError)
					}
					return
				}
				if guardErr != nil {
					t.Fatalf("scope guard rejected scenario: %v", guardErr)
				}
			}
			if err := adapters.ValidateTask(task); err != nil {
				t.Fatalf("scenario task invalid: %v", err)
			}
			execCtx, execCancel := context.WithTimeout(ctx, minDuration(task.HardDeadline, suite.Timeout))
			defer execCancel()
			result, err := adapter.Execute(execCtx, task)
			if scenario.ExpectedError != nil {
				if !errors.Is(err, scenario.ExpectedError) {
					t.Fatalf("Execute error = %v, want errors.Is(_, %v)", err, scenario.ExpectedError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Execute failed: %v", err)
			}
			assertEnvelope(t, result, task, adapter, runtime, scenario.ExpectedStatus)
			stored, err := adapter.Result()
			if err != nil {
				t.Fatalf("Result after successful execution failed: %v", err)
			}
			assertEnvelope(t, stored, task, adapter, runtime, scenario.ExpectedStatus)
		})
	}

	if suite.ScopeGuard != nil {
		if err := suite.ScopeGuard(ctx, *suite.OutOfScope); !errors.Is(err, suite.ScopeError) {
			t.Fatalf("scope guard accepted/rejected incorrectly: got %v, want %v", err, suite.ScopeError)
		}
	}
	if suite.Cancellation != nil {
		runCancellation(t, adapter, *suite.Cancellation, suite.Timeout)
	}
}

func assertEnvelope(t *testing.T, result adapters.Result, task adapters.Task, adapter adapters.ScannerAdapter, runtime adapters.RuntimeVersionInfo, expected adapters.ExecutionStatus) {
	t.Helper()
	if err := result.Validate(); err != nil {
		t.Fatalf("output envelope is invalid: %v", err)
	}
	if result.Status != expected {
		t.Fatalf("output status = %q, want %q", result.Status, expected)
	}
	if result.Metadata.AssessmentID != task.AssessmentID || result.Metadata.CorrelationID != task.CorrelationID {
		t.Fatalf("assessment/correlation identifiers were not preserved: %+v", result.Metadata)
	}
	if result.Metadata.ScannerID != adapter.Name() || result.Metadata.ScannerVersion != runtime.ScannerVersion || result.Metadata.AdapterVersion != runtime.AdapterVersion {
		t.Fatalf("scanner runtime identity mismatch: %+v; expected runtime %+v", result.Metadata, runtime)
	}
}

func runCancellation(t *testing.T, adapter adapters.ScannerAdapter, test CancellationCase, timeout time.Duration) {
	t.Helper()
	if !adapter.Capabilities().SupportsCancel {
		t.Fatal("adaptertest: cancellation scenario requires SupportsCancel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct {
		result adapters.Result
		err    error
	}, 1)
	go func() {
		result, err := adapter.Execute(ctx, test.Task)
		done <- struct {
			result adapters.Result
			err    error
		}{result, err}
	}()
	select {
	case <-test.Started:
	case <-ctx.Done():
		t.Fatalf("cancellation scenario did not start: %v", ctx.Err())
	}
	if err := adapter.Cancel(); err != nil {
		t.Fatalf("Cancel failed: %v", err)
	}
	select {
	case got := <-done:
		if errors.Is(got.err, context.Canceled) {
			return
		}
		if got.err == nil && got.result.Status == adapters.StatusCancelled {
			if err := got.result.Validate(); err == nil {
				return
			}
		}
		t.Fatalf("cancelled Execute returned result=%+v error=%v", got.result, got.err)
	case <-ctx.Done():
		t.Fatalf("Execute did not stop after Cancel: %v", ctx.Err())
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

type ProcessOutput struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type FakeProcess interface {
	Run(context.Context, adapters.Task) (ProcessOutput, error)
}

type FakeProcessFunc func(context.Context, adapters.Task) (ProcessOutput, error)

func (f FakeProcessFunc) Run(ctx context.Context, task adapters.Task) (ProcessOutput, error) {
	return f(ctx, task)
}

// EnvelopeRunner adapts fake process bytes through the same strict output
// envelope decoder used by scanner adapters.
func EnvelopeRunner(process FakeProcess) adapters.Runner {
	return func(ctx context.Context, task adapters.Task) (adapters.Result, error) {
		output, err := process.Run(ctx, task)
		if err != nil {
			return adapters.Result{}, err
		}
		if len(output.Stdout) == 0 {
			return adapters.Result{}, fmt.Errorf("%w: scanner returned empty stdout", adapters.ErrMalformedOutput)
		}
		result, err := adapters.DecodeOutputEnvelope(output.Stdout)
		if err != nil {
			return adapters.Result{}, err
		}
		if result.Metadata.AssessmentID != task.AssessmentID || result.Metadata.CorrelationID != task.CorrelationID || result.Metadata.ScannerID != task.Scanner {
			return adapters.Result{}, fmt.Errorf("%w: assessment, correlation, or scanner identity mismatch", adapters.ErrMalformedOutput)
		}
		if result.ExitCode != nil && output.ExitCode != *result.ExitCode {
			return adapters.Result{}, fmt.Errorf("%w: process exit code disagrees with output envelope", adapters.ErrMalformedOutput)
		}
		return result, nil
	}
}

// Fixture returns an embedded output fixture. Names are restricted to the
// checked-in testdata directory; callers cannot read arbitrary paths.
func Fixture(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, fmt.Errorf("adaptertest: invalid fixture path")
	}
	return fixtureFiles.ReadFile("testdata/" + name)
}

// PreparedFixture makes a valid fixture specific to one test task and adapter.
// Malformed and empty fixtures are returned byte-for-byte for rejection tests.
func PreparedFixture(name string, task adapters.Task, scannerVersion, adapterVersion string) ([]byte, error) {
	raw, err := Fixture(name)
	if err != nil || len(raw) == 0 {
		return raw, err
	}
	result, err := adapters.DecodeOutputEnvelope(raw)
	if err != nil {
		return raw, nil
	}
	result.Metadata.AssessmentID = task.AssessmentID
	result.Metadata.ScannerID = task.Scanner
	result.Metadata.ScannerVersion = scannerVersion
	result.Metadata.AdapterVersion = adapterVersion
	result.Metadata.CorrelationID = task.CorrelationID
	return adapters.EncodeOutputEnvelope(result)
}
