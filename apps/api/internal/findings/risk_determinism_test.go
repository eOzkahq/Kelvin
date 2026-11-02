package findings

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRiskEngineDeterminismAcrossIterations(t *testing.T) {
	engine := NewRiskEngine()
	if engine.Version() != "v1" {
		t.Fatalf("expected engine version v1, got %s", engine.Version())
	}

	finding := &PersistentFinding{
		ID:         uuid.New(),
		Title:      "SQL Injection in /api/v1/users",
		Severity:   "HIGH",
		Confidence: 0.9,
		ScannerData: map[string]any{
			"exposure":    "PUBLIC_INTERNET",
			"criticality": "TIER_1_CRITICAL",
		},
		CreatedAt: time.Now().UTC(),
	}

	firstRes, err := engine.Compute(finding)
	if err != nil {
		t.Fatalf("compute failed: %v", err)
	}

	firstHash := sha256.Sum256([]byte(fmt.Sprintf("%f:%s:%s", firstRes.RiskScore, firstRes.PriorityBand, firstRes.Explanation)))

	// Execute 1,000 iterations to verify strict determinism
	for i := 0; i < 1000; i++ {
		res, err := engine.Compute(finding)
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		if res.RiskScore != firstRes.RiskScore {
			t.Fatalf("non-deterministic score on iteration %d: %v != %v", i, res.RiskScore, firstRes.RiskScore)
		}
		if res.PriorityBand != firstRes.PriorityBand {
			t.Fatalf("non-deterministic priority band on iteration %d: %v != %v", i, res.PriorityBand, firstRes.PriorityBand)
		}
		currentHash := sha256.Sum256([]byte(fmt.Sprintf("%f:%s:%s", res.RiskScore, res.PriorityBand, res.Explanation)))
		if currentHash != firstHash {
			t.Fatalf("hash mismatch on iteration %d", i)
		}
	}
}

func TestRiskEngineMissingContextGracefulDefaults(t *testing.T) {
	engine := NewRiskEngine()

	// Finding with nil ScannerData and nil CVSS
	finding := &PersistentFinding{
		ID:          uuid.New(),
		Severity:    "MEDIUM",
		Confidence:  0.8,
		ScannerData: nil,
	}

	res, err := engine.Compute(finding)
	if err != nil {
		t.Fatalf("compute failed on missing context: %v", err)
	}

	if res.ExposureMultiplier != 1.0 {
		t.Errorf("expected default exposure multiplier 1.0, got %v", res.ExposureMultiplier)
	}
	if res.CriticalityMultiplier != 1.0 {
		t.Errorf("expected default criticality multiplier 1.0, got %v", res.CriticalityMultiplier)
	}
	if res.PriorityBand != RiskBandMedium {
		t.Errorf("expected MEDIUM priority band, got %s", res.PriorityBand)
	}
}

func TestRiskEngineNilFindingError(t *testing.T) {
	engine := NewRiskEngine()
	if _, err := engine.Compute(nil); err == nil {
		t.Errorf("expected error when finding is nil")
	}
}
