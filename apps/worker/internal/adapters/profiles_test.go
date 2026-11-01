package adapters

import (
	"testing"
	"time"
)

func TestAssessmentProfilesApprovedList(t *testing.T) {
	profiles := ListAssessmentProfiles()
	if len(profiles) != 3 {
		t.Fatalf("expected 3 MVP assessment profiles, got %d", len(profiles))
	}

	for _, p := range profiles {
		if p.ProfileID == "" || p.Version == "" || p.DisplayName == "" {
			t.Errorf("profile missing essential fields: %+v", p)
		}
		if p.Budget.RequestsPerSecond < 1 || p.Budget.MaxConcurrency < 1 || p.Budget.MaxDuration < time.Minute {
			t.Errorf("profile %s has invalid budget: %+v", p.ProfileID, p.Budget)
		}
	}
}

func TestGetAssessmentProfileLookup(t *testing.T) {
	// Full canonical ID
	p, err := GetAssessmentProfile(ProfileStandard)
	if err != nil {
		t.Fatalf("unexpected error looking up standard profile: %v", err)
	}
	if p.ProfileID != ProfileStandard {
		t.Errorf("expected %s, got %s", ProfileStandard, p.ProfileID)
	}

	// Short alias lookup
	pShort, err := GetAssessmentProfile("standard")
	if err != nil {
		t.Fatalf("unexpected error looking up standard alias: %v", err)
	}
	if pShort.ProfileID != ProfileStandard {
		t.Errorf("expected %s, got %s", ProfileStandard, pShort.ProfileID)
	}

	// Unknown profile lookup
	if _, err := GetAssessmentProfile("unknown.profile.v1"); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestValidateProfileSelectionPermittedScanners(t *testing.T) {
	// Preflight under standard
	p, err := ValidateProfileSelection(ProfileStandard, ScannerHTTPPreflight)
	if err != nil {
		t.Fatalf("expected preflight allowed under standard profile: %v", err)
	}
	if p.ProfileID != ProfileStandard {
		t.Errorf("unexpected profile ID: %s", p.ProfileID)
	}

	// Nuclei under standard
	if _, err := ValidateProfileSelection(ProfileStandard, ScannerNuclei); err != nil {
		t.Fatalf("expected nuclei allowed under standard profile: %v", err)
	}

	// Disallowed scanner under passive profile
	if _, err := ValidateProfileSelection(ProfilePassive, ScannerNuclei); err == nil {
		t.Fatal("expected nuclei rejected under passive profile")
	}

	// Disallowed scanner under passive profile (preflight)
	if _, err := ValidateProfileSelection(ProfilePassive, ScannerHTTPPreflight); err == nil {
		t.Fatal("expected preflight rejected under passive profile")
	}

	// Unknown scanner under standard profile
	if _, err := ValidateProfileSelection(ProfileStandard, "malicious_scanner"); err == nil {
		t.Fatal("expected unknown scanner rejected")
	}
}

func TestStandardProfileScannerDependenciesAndPhases(t *testing.T) {
	p, err := GetAssessmentProfile(ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}

	if len(p.DefaultScannerOrder) != 3 {
		t.Fatalf("expected 3 phases in standard profile execution order, got %d", len(p.DefaultScannerOrder))
	}

	phase1 := p.DefaultScannerOrder[0]
	if phase1.PhaseName != "preflight_and_reachability" || len(phase1.Scanners) != 1 || phase1.Scanners[0] != ScannerHTTPPreflight {
		t.Errorf("phase 1 should be preflight check: %+v", phase1)
	}
	if phase1.RequirePrev {
		t.Errorf("phase 1 should not require previous phase")
	}

	phase2 := p.DefaultScannerOrder[1]
	if !phase2.RequirePrev || !phase2.Parallel {
		t.Errorf("phase 2 should run in parallel and require phase 1 success: %+v", phase2)
	}

	phase3 := p.DefaultScannerOrder[2]
	if !phase3.RequirePrev || !phase3.Parallel {
		t.Errorf("phase 3 should run in parallel and require previous phase success: %+v", phase3)
	}
}
