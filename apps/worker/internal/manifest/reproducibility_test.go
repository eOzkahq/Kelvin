package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type ReproducibilityLock struct {
	SchemaVersion        string `json:"schema_version"`
	Policy               string `json:"policy"`
	ReproducibilityEpoch struct {
		SourceDateEpoch int64 `json:"SOURCE_DATE_EPOCH"`
	} `json:"reproducibility_epoch"`
	CompilerNormalization struct {
		CgoEnabled int      `json:"cgo_enabled"`
		GoFlags    []string `json:"go_flags"`
	} `json:"compiler_normalization"`
	NonDeterministicFields []struct {
		Field      string `json:"field"`
		Mitigation string `json:"mitigation"`
	} `json:"non_deterministic_fields"`
}

func TestScannerReproducibility_LockfileInvariants(t *testing.T) {
	lockPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "reproducibility.lock")

	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read reproducibility.lock: %v", err)
	}

	var lock ReproducibilityLock
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("failed to parse reproducibility.lock: %v", err)
	}

	if lock.ReproducibilityEpoch.SourceDateEpoch <= 0 {
		t.Errorf("SOURCE_DATE_EPOCH must be positive integer, got %d", lock.ReproducibilityEpoch.SourceDateEpoch)
	}

	if lock.CompilerNormalization.CgoEnabled != 0 {
		t.Errorf("CGO_ENABLED must be 0 for reproducible hermetic builds")
	}

	hasTrimpath := false
	hasBuildID := false
	for _, flag := range lock.CompilerNormalization.GoFlags {
		if flag == "-trimpath" {
			hasTrimpath = true
		}
		if flag == "-ldflags=-s -w -buildid=" {
			hasBuildID = true
		}
	}

	if !hasTrimpath || !hasBuildID {
		t.Errorf("expected -trimpath and -buildid= in compiler flags, got %v", lock.CompilerNormalization.GoFlags)
	}

	if len(lock.NonDeterministicFields) < 3 {
		t.Errorf("expected at least 3 documented non-deterministic fields, got %d", len(lock.NonDeterministicFields))
	}
}
