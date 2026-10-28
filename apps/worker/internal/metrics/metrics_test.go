package metrics

import (
	"testing"
)

func TestIncResourceViolationAndTermination(t *testing.T) {
	r := Default()
	// Reset counters for a deterministic check.
	r.mu.Lock()
	r.resourceViolations = map[ViolationType]uint64{}
	r.terminations = map[TerminationCause]uint64{}
	r.mu.Unlock()

	r.IncResourceViolation(ViolationDeadline)
	r.IncResourceViolation(ViolationDeadline)
	r.IncResourceViolation(ViolationOOM)
	r.IncTermination(CauseDeadline)
	r.IncTermination(CauseOOM)
	r.IncTermination(CauseCompleted)

	snap := r.Snapshot()
	if snap.ResourceViolations[ViolationDeadline] != 2 {
		t.Errorf("expected 2 deadline violations, got %d", snap.ResourceViolations[ViolationDeadline])
	}
	if snap.ResourceViolations[ViolationOOM] != 1 {
		t.Errorf("expected 1 OOM violation, got %d", snap.ResourceViolations[ViolationOOM])
	}
	if snap.Terminations[CauseDeadline] != 1 {
		t.Errorf("expected 1 deadline termination, got %d", snap.Terminations[CauseDeadline])
	}
	if snap.Terminations[CauseOOM] != 1 {
		t.Errorf("expected 1 OOM termination, got %d", snap.Terminations[CauseOOM])
	}
	if snap.Terminations[CauseCompleted] != 1 {
		t.Errorf("expected 1 completed termination, got %d", snap.Terminations[CauseCompleted])
	}
	if snap.UptimeSeconds < 0 {
		t.Error("uptime must not be negative")
	}
}

func TestSnapshotIsIsolated(t *testing.T) {
	r := Default()
	r.mu.Lock()
	r.resourceViolations = map[ViolationType]uint64{}
	r.terminations = map[TerminationCause]uint64{}
	r.mu.Unlock()

	r.IncResourceViolation(ViolationPIDs)
	snap := r.Snapshot()
	snap.ResourceViolations[ViolationCPU] = 999 // mutate snapshot
	snap2 := r.Snapshot()
	if _, ok := snap2.ResourceViolations[ViolationCPU]; ok {
		t.Error("snapshot mutation leaked into registry")
	}
}
