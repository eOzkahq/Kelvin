package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

func validContractTask() Task {
	return Task{
		JobID: "22222222-2222-2222-2222-222222222222", AssessmentID: "33333333-3333-3333-3333-333333333333",
		TenantID: "123e4567-e89b-12d3-a456-426614174000", Scanner: "reference", Target: "https://example.test",
		ProfileID: "standard", HardDeadline: time.Minute,
	}
}

func TestReferenceAdapterLifecycle(t *testing.T) {
	want := validOutputEnvelope()
	want := Result{ExitCode: 0, Findings: []byte(`{"sample":true}`)}
	a := &ReferenceAdapter{AdapterName: "reference", Caps: Capabilities{CheckCategories: []string{"passive"}}, Run: func(context.Context, Task) (Result, error) { return want, nil }}
	if _, err := a.Result(); !errors.Is(err, ErrNoResult) {
		t.Fatalf("Result before Execute error = %v, want ErrNoResult", err)
	}
	if err := a.Health(context.Background()); err == nil {
		t.Fatal("Health before Initialize succeeded")
	}
	if err := a.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := a.ValidateConfig(json.RawMessage(`{"mode":"baseline"}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.ValidateConfig(json.RawMessage(`[]`)); err == nil {
		t.Fatal("ValidateConfig accepted a non-object")
	}
	caps := a.Capabilities()
	caps.CheckCategories[0] = "mutated"
	if got := a.Capabilities().CheckCategories[0]; got != "passive" {
		t.Fatalf("Capabilities leaked mutable slice: %q", got)
	}
	got, err := a.Execute(context.Background(), validContractTask())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusCompleted {
	if got.ExitCode != 0 {
		t.Fatalf("Execute result = %+v", got)
	}
	stored, err := a.Result()
	if err != nil {
		t.Fatal(err)
	}
	stored.Findings[0][0] = 'x'
	stored.Findings[0] = 'x'
	storedAgain, err := a.Result()
	if err != nil {
		t.Fatal(err)
	}
	if string(storedAgain.Findings[0]) != string(want.Findings[0]) {
	if string(storedAgain.Findings) != string(want.Findings) {
		t.Fatalf("Result returned aliased findings: %q", storedAgain.Findings)
	}
	if err := a.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceAdapterCancel(t *testing.T) {
	started := make(chan struct{})
	a := &ReferenceAdapter{AdapterName: "reference", Run: func(ctx context.Context, _ Task) (Result, error) {
		close(started)
		<-ctx.Done()
		return Result{}, ctx.Err()
	}}
	if err := a.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := a.Execute(context.Background(), validContractTask())
		done <- err
	}()
	<-started
	if err := a.Cancel(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Execute error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Execute did not stop after Cancel")
	}
}

func TestReferenceAdapterRejectsConcurrentExecute(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	a := &ReferenceAdapter{AdapterName: "reference", Run: func(context.Context, Task) (Result, error) {
		close(started)
		<-release
		return Result{}, nil
	}}
	if err := a.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.Execute(context.Background(), validContractTask())
	}()
	<-started
	if _, err := a.Execute(context.Background(), validContractTask()); err == nil {
		t.Fatal("concurrent Execute succeeded")
	}
	close(release)
	<-done
}
