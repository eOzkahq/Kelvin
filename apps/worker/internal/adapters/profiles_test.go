package adapters

import (
	"testing"
	"time"
)

func TestAssessmentProfilesApprovedList(t *testing.T) {
	profiles := ListAssessmentProfiles()
	if len(profiles) != 4 {
		t.Fatalf("expected 4 MVP assessment profiles, got %d", len(profiles))
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

	// SafeWeb profile lookup
	pSafe, err := GetAssessmentProfile(ProfileSafeWeb)
	if err != nil {
		t.Fatalf("unexpected error looking up safeweb profile: %v", err)
	}
	if pSafe.ProfileID != ProfileSafeWeb {
		t.Errorf("expected %s, got %s", ProfileSafeWeb, pSafe.ProfileID)
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

func TestDeepProfilePhasesAndScanners(t *testing.T) {
	p, err := GetAssessmentProfile(ProfileDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(p.DefaultScannerOrder) != 4 {
		t.Fatalf("expected 4 phases in deep profile execution order, got %d", len(p.DefaultScannerOrder))
	}

	// Verify all 6 candidate scanners are permitted under deep profile
	expectedPermitted := map[string]bool{
		ScannerHTTPPreflight: true,
		ScannerNmap:          true,
		ScannerTLSAssessor:   true,
		ScannerHTTPHeaders:   true,
		ScannerZAPBaseline:   true,
		ScannerNuclei:        true,
	}
	for _, sc := range p.PermittedScanners {
		delete(expectedPermitted, sc)
	}
	if len(expectedPermitted) != 0 {
		t.Errorf("missing permitted scanners in deep profile: %v", expectedPermitted)
	}

	phase2 := p.DefaultScannerOrder[1]
	if phase2.PhaseName != "network_and_service_discovery" || len(phase2.Scanners) != 1 || phase2.Scanners[0] != ScannerNmap {
		t.Errorf("phase 2 should be nmap service discovery: %+v", phase2)
	}
}
