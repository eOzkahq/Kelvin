package normalization

import (
	"testing"
)

func TestMapCVSSScoreToSeverityBands(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{10.0, SeverityCritical},
		{9.8, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0.0, SeverityInformational},
	}

	for _, tc := range tests {
		got := MapCVSSScoreToSeverity(tc.score)
		if got != tc.expected {
			t.Errorf("score %f: expected %s, got %s", tc.score, tc.expected, got)
		}
	}
}

func TestMapZAPSeverityAndConfidence(t *testing.T) {
	tests := []struct {
		risk     string
		conf     string
		wantSev  string
		wantConf float64
	}{
		{"3", "High", SeverityHigh, 0.9},
		{"2", "Medium", SeverityMedium, 0.7},
		{"1", "Low", SeverityLow, 0.5},
		{"0", "False Positive", SeverityInformational, 0.2},
		{"high", "4", SeverityHigh, 1.0},
		{"informational", "0", SeverityInformational, 0.2},
	}

	for _, tc := range tests {
		sev, conf, nativeSev, nativeConf, err := MapZAPSeverityAndConfidence(tc.risk, tc.conf)
		if err != nil {
			t.Fatalf("unexpected error for risk=%s, conf=%s: %v", tc.risk, tc.conf, err)
		}
		if sev != tc.wantSev {
			t.Errorf("risk %s: expected severity %s, got %s", tc.risk, tc.wantSev, sev)
		}
		if conf != tc.wantConf {
			t.Errorf("conf %s: expected confidence %f, got %f", tc.conf, tc.wantConf, conf)
		}
		if nativeSev == "" || nativeConf == "" {
			t.Errorf("native severity and confidence must be preserved")
		}
	}

	// Invalid risk code should fail
	if _, _, _, _, err := MapZAPSeverityAndConfidence("99", "High"); err == nil {
		t.Errorf("expected error for invalid risk code")
	}
}

func TestMapNucleiSeverityAndConfidenceWithCVSSOverride(t *testing.T) {
	// Case 1: Standard mapping without CVSS score
	sev, conf, nativeSev, err := MapNucleiSeverityAndConfidence("critical", 0.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sev != SeverityCritical || conf != 0.95 || nativeSev != "critical" {
		t.Errorf("unexpected critical mapping: sev=%s, conf=%f, native=%s", sev, conf, nativeSev)
	}

	// Case 2: Authoritative CVSS override (Native medium, but CVSS 9.8 -> CRITICAL)
	sevOverride, _, nativeSev2, err := MapNucleiSeverityAndConfidence("medium", 9.8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sevOverride != SeverityCritical {
		t.Errorf("expected CVSS override to CRITICAL, got %s", sevOverride)
	}
	if nativeSev2 != "medium" {
		t.Errorf("expected native severity 'medium' preserved, got %s", nativeSev2)
	}

	// Case 3: Unknown severity maps safely to INFORMATIONAL
	sevUnknown, confUnknown, _, err := MapNucleiSeverityAndConfidence("unknown", 0.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sevUnknown != SeverityInformational || confUnknown != 0.50 {
		t.Errorf("expected unknown -> INFORMATIONAL with 0.50 conf, got sev=%s, conf=%f", sevUnknown, confUnknown)
	}
}

func TestConfidenceFloatToLevel(t *testing.T) {
	if got := ConfidenceFloatToLevel(0.98); got != ConfidenceLevelCertain {
		t.Errorf("expected CERTAIN, got %s", got)
	}
	if got := ConfidenceFloatToLevel(0.75); got != ConfidenceLevelFirm {
		t.Errorf("expected FIRM, got %s", got)
	}
	if got := ConfidenceFloatToLevel(0.30); got != ConfidenceLevelTentative {
		t.Errorf("expected TENTATIVE, got %s", got)
	}
	if got := ConfidenceFloatToLevel(0.0); got != ConfidenceLevelUnknown {
		t.Errorf("expected UNKNOWN, got %s", got)
	}
}
