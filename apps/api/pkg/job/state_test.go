package job

import (
	"errors"
	"testing"
)

func TestPermittedTransitions(t *testing.T) {
	tests := []struct{ from, to State }{
		{Queued, Validating}, {Validating, Running}, {Validating, Failed}, {Validating, Cancelled},
		{Running, Completed}, {Running, Failed}, {Running, Cancelled}, {Running, TimedOut},
	}
	for _, tt := range tests {
		if err := ValidateTransition(tt.from, tt.to); err != nil {
			t.Errorf("%s -> %s rejected: %v", tt.from, tt.to, err)
		}
	}
}

func TestRejectsIllegalTransitions(t *testing.T) {
	states := []State{Queued, Validating, Running, Completed, Failed, Cancelled, TimedOut}
	allowed := map[[2]State]bool{
		{Queued, Validating}: true, {Validating, Running}: true, {Validating, Failed}: true, {Validating, Cancelled}: true,
		{Running, Completed}: true, {Running, Failed}: true, {Running, Cancelled}: true, {Running, TimedOut}: true,
	}
	for _, from := range states {
		for _, to := range states {
			err := ValidateTransition(from, to)
			if allowed[[2]State{from, to}] && err != nil {
				t.Errorf("allowed %s -> %s rejected: %v", from, to, err)
			}
			if !allowed[[2]State{from, to}] && !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("illegal %s -> %s error = %v", from, to, err)
			}
		}
	}
}

func TestUnknownStateRejected(t *testing.T) {
	if err := ValidateTransition("BROKEN", Running); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("got %v", err)
	}
}
