package findings

import (
	"testing"
)

func TestInterpretFindingPreservesOriginals(t *testing.T) {
	origSev := "3"
	origConf := "2"
	res := InterpretFinding("zap", origSev, origConf, nil)

	if res.OriginalSeverity != origSev {
		t.Errorf("expected original severity %q, got %q", origSev, res.OriginalSeverity)
	}
	if res.OriginalConfidence != origConf {
		t.Errorf("expected original confidence %q, got %q", origConf, res.OriginalConfidence)
	}
	if res.CanonicalSeverity != CanonicalSeverityHigh {
		t.Errorf("expected canonical severity HIGH for ZAP 3, got %q", res.CanonicalSeverity)
	}
	if res.CanonicalConfidence != 0.70 {
		t.Errorf("expected canonical confidence 0.70 for ZAP 2, got %v", res.CanonicalConfidence)
	}
	if res.ConfidenceBand != ConfidenceBandFirm {
		t.Errorf("expected FIRM confidence band, got %q", res.ConfidenceBand)
	}
	if res.RuleVersion != InterpretationRuleVersion {
		t.Errorf("expected rule version %q, got %q", InterpretationRuleVersion, res.RuleVersion)
	}
}

func TestInterpretFindingOrthogonalDimensions(t *testing.T) {
	// Case 1: High Severity + Low / Tentative Confidence
	highSevTentative := InterpretFinding("zap", "high", "low", nil)
	if highSevTentative.CanonicalSeverity != CanonicalSeverityHigh {
		t.Errorf("expected HIGH severity, got %q", highSevTentative.CanonicalSeverity)
	}
	if highSevTentative.ConfidenceBand != ConfidenceBandTentative {
		t.Errorf("expected TENTATIVE confidence band, got %q", highSevTentative.ConfidenceBand)
	}
	if !highSevTentative.DimensionsDistinct {
		t.Errorf("expected dimensions to be strictly distinct")
	}

	// Case 2: Low Severity + Certain Confidence
	lowSevCertain := InterpretFinding("builtin-http", "LOW", "", nil)
	if lowSevCertain.CanonicalSeverity != CanonicalSeverityLow {
		t.Errorf("expected LOW severity, got %q", lowSevCertain.CanonicalSeverity)
	}
	if lowSevCertain.ConfidenceBand != ConfidenceBandCertain {
		t.Errorf("expected CERTAIN confidence band, got %q", lowSevCertain.ConfidenceBand)
	}

	// Case 3: Nuclei Critical + CVSS override
	cvss := 9.8
	nucleiCrit := InterpretFinding("nuclei", "medium", "certain", &cvss)
	if nucleiCrit.CanonicalSeverity != CanonicalSeverityCritical {
		t.Errorf("expected CVSS override to CRITICAL, got %q", nucleiCrit.CanonicalSeverity)
	}
	if nucleiCrit.OriginalSeverity != "medium" {
		t.Errorf("expected original severity 'medium' preserved, got %q", nucleiCrit.OriginalSeverity)
	}
	if nucleiCrit.ConfidenceBand != ConfidenceBandCertain {
		t.Errorf("expected CERTAIN confidence band, got %q", nucleiCrit.ConfidenceBand)
	}
}

func TestInterpretFindingMissingConfidence(t *testing.T) {
	// Generic scanner with missing confidence
	res := InterpretFinding("custom-audit", "HIGH", "", nil)
	if !res.ConfidenceUnspecified {
		t.Errorf("expected ConfidenceUnspecified to be true")
	}
	if res.ConfidenceBand != ConfidenceBandUnspecified {
		t.Errorf("expected band UNSPECIFIED, got %q", res.ConfidenceBand)
	}
	if res.CanonicalConfidence <= 0.0 {
		t.Errorf("expected positive conservative baseline confidence, got %v", res.CanonicalConfidence)
	}
}

func TestComputeConfidenceAttenuation(t *testing.T) {
	tests := []struct {
		conf float64
		want float64
	}{
		{1.0, 1.00},
		{0.9, 0.95},
		{0.7, 0.85},
		{0.5, 0.75},
		{0.0, 0.50},
		{-0.5, 0.50}, // Bounded below
		{1.5, 1.00},  // Bounded above
	}

	for _, tt := range tests {
		got := ComputeConfidenceAttenuation(tt.conf)
		if got != tt.want {
			t.Errorf("ComputeConfidenceAttenuation(%v) = %v, want %v", tt.conf, got, tt.want)
		}
	}
}

func TestMapCVSSScoreToSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, CanonicalSeverityCritical},
		{9.0, CanonicalSeverityCritical},
		{8.9, CanonicalSeverityHigh},
		{7.0, CanonicalSeverityHigh},
		{6.9, CanonicalSeverityMedium},
		{4.0, CanonicalSeverityMedium},
		{3.9, CanonicalSeverityLow},
		{0.1, CanonicalSeverityLow},
		{0.0, CanonicalSeverityInformational},
	}

	for _, tt := range tests {
		got := MapCVSSScoreToSeverity(tt.score)
		if got != tt.want {
			t.Errorf("MapCVSSScoreToSeverity(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
