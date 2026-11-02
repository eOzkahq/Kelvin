package findings

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenerateRiskExplanation(t *testing.T) {
	findingID := uuid.New()
	tenantID := uuid.New()
	projectID := uuid.New()
	score := 8.5
	cvss := 8.0

	// 1. Nil finding returns error
	if _, err := GenerateRiskExplanation(nil); err == nil {
		t.Errorf("expected error for nil finding")
	}

	// 2. Finding with measured and manual context attributes
	f := &PersistentFinding{
		ID:               findingID,
		TenantID:         tenantID,
		ProjectID:        projectID,
		Title:            "SQL Injection in Customer Portal",
		Severity:         "HIGH",
		Confidence:       0.95,
		CVSSScore:        &cvss,
		Status:           StatusOpen,
		RiskScore:        &score,
		RiskPriorityBand: RiskBandHigh,
		ScannerData: map[string]any{
			"exposure":        "PUBLIC_INTERNET",
			"criticality":     "TIER_1_CRITICAL",
			"known_exploited": true,
		},
		UpdatedAt: time.Now().UTC(),
	}

	expl, err := GenerateRiskExplanation(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if expl.FindingID != findingID {
		t.Errorf("expected finding ID %v, got %v", findingID, expl.FindingID)
	}
	if expl.RiskScore != score {
		t.Errorf("expected risk score %v, got %v", score, expl.RiskScore)
	}
	if expl.PriorityBand != RiskBandHigh {
		t.Errorf("expected priority band HIGH, got %v", expl.PriorityBand)
	}
	if expl.ModelVersion != RiskModelVersion {
		t.Errorf("expected model version %q, got %q", RiskModelVersion, expl.ModelVersion)
	}
	if expl.Summary == "" {
		t.Errorf("expected non-empty summary narrative")
	}

	// Verify distinction between MEASURED and MANUAL_CONTEXT
	hasMeasured := false
	hasManual := false
	for _, factor := range expl.Factors {
		if factor.Category == CategoryMeasured {
			hasMeasured = true
		}
		if factor.Category == CategoryManualContext {
			hasManual = true
		}
	}
	if !hasMeasured {
		t.Errorf("expected at least one MEASURED factor")
	}
	if !hasManual {
		t.Errorf("expected at least one MANUAL_CONTEXT factor")
	}
}

func TestGenerateRiskExplanationDefaults(t *testing.T) {
	findingID := uuid.New()
	f := &PersistentFinding{
		ID:         findingID,
		Severity:   "MEDIUM",
		Confidence: 0.0, // Should default to conservative baseline
	}

	expl, err := GenerateRiskExplanation(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if expl.PriorityBand == "" {
		t.Errorf("expected non-empty priority band")
	}

	// Verify unknown exposure/criticality categorized as HEURISTIC
	hasHeuristic := false
	for _, factor := range expl.Factors {
		if factor.Category == CategoryHeuristic {
			hasHeuristic = true
			break
		}
	}
	if !hasHeuristic {
		t.Errorf("expected HEURISTIC category for unknown context factors")
	}
}

