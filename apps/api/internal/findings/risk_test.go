package findings

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestDeriveBaseSeverity(t *testing.T) {
	cvss := 7.5
	if got := DeriveBaseSeverity("LOW", &cvss); got != 7.5 {
		t.Errorf("expected CVSS override 7.5, got %v", got)
	}

	tests := []struct {
		severity string
		want     float64
	}{
		{"CRITICAL", 9.5},
		{"HIGH", 8.0},
		{"MEDIUM", 5.5},
		{"LOW", 2.5},
		{"INFO", 0.0},
		{"UNKNOWN", 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := DeriveBaseSeverity(tt.severity, nil); got != tt.want {
				t.Errorf("DeriveBaseSeverity(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestMapPriorityBand(t *testing.T) {
	tests := []struct {
		score float64
		want  RiskPriorityBand
	}{
		{10.0, RiskBandCritical},
		{9.0, RiskBandCritical},
		{8.9, RiskBandHigh},
		{7.0, RiskBandHigh},
		{6.9, RiskBandMedium},
		{4.0, RiskBandMedium},
		{3.9, RiskBandLow},
		{0.1, RiskBandLow},
		{0.0, RiskBandInfo},
	}

	for _, tt := range tests {
		if got := MapPriorityBand(tt.score); got != tt.want {
			t.Errorf("MapPriorityBand(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestCalculateRiskScore(t *testing.T) {
	findingID := uuid.New()

	// 1. Missing scanner severity error
	_, err := CalculateRiskScore(RiskAssessmentInput{
		FindingID:       findingID,
		ScannerSeverity: "",
	})
	if !errors.Is(err, ErrScannerSeverityRequired) {
		t.Errorf("expected ErrScannerSeverityRequired, got %v", err)
	}

	// 2. Informational finding yields INFO band and 0.0 score
	resInfo, err := CalculateRiskScore(RiskAssessmentInput{
		FindingID:       findingID,
		ScannerSeverity: "INFO",
	})
	if err != nil {
		t.Fatalf("unexpected error for INFO: %v", err)
	}
	if resInfo.RiskScore != 0.0 || resInfo.PriorityBand != RiskBandInfo {
		t.Errorf("expected 0.0 / INFO, got %v / %v", resInfo.RiskScore, resInfo.PriorityBand)
	}

	// 3. High severity public internet tier 1 asset with CISA KEV boost
	resCritical, err := CalculateRiskScore(RiskAssessmentInput{
		FindingID:       findingID,
		ScannerSeverity: "CRITICAL",
		Confidence:      1.0,
		Exposure:        ExposurePublicInternet,
		Criticality:     CriticalityTier1,
		Vulnerability: VulnerabilityMetadata{
			KnownExploited: true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resCritical.RiskScore != 10.0 || resCritical.PriorityBand != RiskBandCritical {
		t.Errorf("expected 10.0 / CRITICAL, got %v / %v", resCritical.RiskScore, resCritical.PriorityBand)
	}
	if resCritical.Explanation == "" {
		t.Errorf("expected non-empty explanation")
	}

	// 4. Isolated target attenuates medium finding to low risk
	resAttenuated, err := CalculateRiskScore(RiskAssessmentInput{
		FindingID:       findingID,
		ScannerSeverity: "MEDIUM",
		Confidence:      0.5,
		Exposure:        ExposureIsolated,
		Criticality:     CriticalityTier4,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resAttenuated.PriorityBand != RiskBandLow {
		t.Errorf("expected LOW priority band for isolated tier 4 asset, got %v (score: %v)", resAttenuated.PriorityBand, resAttenuated.RiskScore)
	}
}
