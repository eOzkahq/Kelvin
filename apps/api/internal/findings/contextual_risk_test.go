package findings

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestValidateTargetRiskContext(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	// 1. Nil context
	if err := ValidateTargetRiskContext(nil); err == nil {
		t.Errorf("expected error for nil context")
	}

	// 2. Missing tenant ID
	err := ValidateTargetRiskContext(&TargetRiskContext{
		ProjectID:   projectID,
		TargetAsset: "api.example.com",
	})
	if !errors.Is(err, ErrTenantRequired) {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// 3. Missing project ID
	err = ValidateTargetRiskContext(&TargetRiskContext{
		TenantID:    tenantID,
		TargetAsset: "api.example.com",
	})
	if !errors.Is(err, ErrProjectRequired) {
		t.Errorf("expected ErrProjectRequired, got %v", err)
	}

	// 4. Missing target asset
	err = ValidateTargetRiskContext(&TargetRiskContext{
		TenantID:    tenantID,
		ProjectID:   projectID,
		TargetAsset: "   ",
	})
	if !errors.Is(err, ErrTargetAssetRequired) {
		t.Errorf("expected ErrTargetAssetRequired, got %v", err)
	}

	// 5. Invalid environment
	err = ValidateTargetRiskContext(&TargetRiskContext{
		TenantID:    tenantID,
		ProjectID:   projectID,
		TargetAsset: "api.example.com",
		Environment: "INVALID_ENV",
	})
	if !errors.Is(err, ErrInvalidEnvironment) {
		t.Errorf("expected ErrInvalidEnvironment, got %v", err)
	}

	// 6. Invalid criticality
	err = ValidateTargetRiskContext(&TargetRiskContext{
		TenantID:            tenantID,
		ProjectID:           projectID,
		TargetAsset:         "api.example.com",
		BusinessCriticality: "INVALID_CRIT",
	})
	if !errors.Is(err, ErrInvalidCriticality) {
		t.Errorf("expected ErrInvalidCriticality, got %v", err)
	}

	// 7. Valid target context normalizes asset and sets defaults
	valid := &TargetRiskContext{
		TenantID:    tenantID,
		ProjectID:   projectID,
		TargetAsset: "  https://API.Example.com:443/v1  ",
	}
	if err := ValidateTargetRiskContext(valid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid.Environment != EnvUnknown {
		t.Errorf("expected default EnvUnknown, got %q", valid.Environment)
	}
	if valid.BusinessCriticality != CritUnknown {
		t.Errorf("expected default CritUnknown, got %q", valid.BusinessCriticality)
	}
	if valid.Source != "MANUAL_ANALYST" {
		t.Errorf("expected default Source MANUAL_ANALYST, got %q", valid.Source)
	}
}

func TestCalculateContextualMultiplier(t *testing.T) {
	// 1. Nil context yields 1.0 (neutral)
	mult, signals := CalculateContextualMultiplier(nil)
	if mult != 1.0 {
		t.Errorf("expected 1.0 for nil context, got %v", mult)
	}
	if len(signals) == 0 {
		t.Errorf("expected signals explanation for nil context")
	}

	// 2. High impact context: PRODUCTION, Internet-facing, Contains PII, MISSION_CRITICAL
	highContext := &TargetRiskContext{
		Environment:         EnvProduction,
		InternetFacing:      true,
		ContainsPII:         true,
		BusinessCriticality: CritMissionCritical,
	}
	highMult, highSignals := CalculateContextualMultiplier(highContext)
	// Expected: 1.20 * 1.15 * 1.25 * 1.30 = 2.2425
	if highMult < 2.24 || highMult > 2.25 {
		t.Errorf("expected high multiplier ~2.24, got %v", highMult)
	}
	if len(highSignals) != 4 {
		t.Errorf("expected 4 signals for high context, got %d", len(highSignals))
	}

	// 3. Low impact context: DEVELOPMENT, Internal, No PII, NON_CRITICAL
	lowContext := &TargetRiskContext{
		Environment:         EnvDevelopment,
		InternetFacing:      false,
		ContainsPII:         false,
		BusinessCriticality: CritNonCritical,
	}
	lowMult, _ := CalculateContextualMultiplier(lowContext)
	// Expected: 0.70 * 0.90 * 0.80 = 0.504
	if lowMult < 0.50 || lowMult > 0.51 {
		t.Errorf("expected low multiplier ~0.504, got %v", lowMult)
	}
}

func TestCalculateRiskScoreWithContext(t *testing.T) {
	findingID := uuid.New()

	baseInput := RiskAssessmentInput{
		FindingID:       findingID,
		ScannerSeverity: "HIGH",
		Confidence:      1.0,
	}

	// Score without context
	neutralRes, err := CalculateRiskScore(baseInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Score with nil Context should match exactly (no fabricated risk)
	baseInput.Context = nil
	nilContextRes, err := CalculateRiskScore(baseInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if neutralRes.RiskScore != nilContextRes.RiskScore {
		t.Errorf("expected identical score with nil context: %v != %v", neutralRes.RiskScore, nilContextRes.RiskScore)
	}

	// Score with High Impact Context should increase risk score
	highInput := baseInput
	highInput.Context = &TargetRiskContext{
		Environment:         EnvProduction,
		InternetFacing:      true,
		ContainsPII:         true,
		BusinessCriticality: CritMissionCritical,
	}
	highRes, err := CalculateRiskScore(highInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if highRes.RiskScore <= neutralRes.RiskScore {
		t.Errorf("expected higher score with critical target context: got %v, base %v", highRes.RiskScore, neutralRes.RiskScore)
	}
}
