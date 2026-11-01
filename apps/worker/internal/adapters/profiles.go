package adapters

import (
	"fmt"
	"strings"
	"time"
)

// Standard Profile IDs
const (
	ProfilePassive  = "kelvin.profile.passive.v1"
	ProfileStandard = "kelvin.profile.standard.v1"
	ProfileDeep     = "kelvin.profile.deep.v1"
)

// ScannerExecutionOrder defines sequential phases and concurrency for an assessment profile.
type ScannerPhase struct {
	PhaseIndex  int      `json:"phase_index"`
	PhaseName   string   `json:"phase_name"`
	Scanners    []string `json:"scanners"`
	Parallel    bool     `json:"parallel"`
	RequirePrev bool     `json:"require_previous_phase_success"`
}

// AssessmentProfile represents a versioned, immutable profile definition for MVP assessments.
type AssessmentProfile struct {
	ProfileID           string         `json:"profile_id"`
	Version             string         `json:"version"`
	DisplayName         string         `json:"display_name"`
	Description         string         `json:"description"`
	ImpactLevel         string         `json:"impact_level"` // "low", "medium", "high"
	TrafficLevel        string         `json:"traffic_level"` // "none", "limited", "active"
	CheckCategories     []string       `json:"check_categories"`
	Budget              ProfileBudget  `json:"budget"`
	PermittedScanners   []string       `json:"permitted_scanners"`
	DefaultScannerOrder []ScannerPhase `json:"default_scanner_order"`
	AdminSignoffRequired bool          `json:"admin_signoff_required"`
}

var mvpProfiles = map[string]AssessmentProfile{
	ProfilePassive: {
		ProfileID:       ProfilePassive,
		Version:         "1.0.0",
		DisplayName:     "Passive Discovery",
		Description:     "Zero-network-traffic discovery using external sources without touching the target.",
		ImpactLevel:     "low",
		TrafficLevel:    "none",
		CheckCategories: []string{"discovery", "passive"},
		Budget: ProfileBudget{
			RequestsPerSecond:    1,
			MaxConcurrency:       1,
			MaxRequestsPerTarget: 10,
			MaxDuration:          5 * time.Minute,
		},
		PermittedScanners: []string{}, // No MVP active/HTTP scanners permitted
		DefaultScannerOrder: []ScannerPhase{},
		AdminSignoffRequired: false,
	},
	ProfileStandard: {
		ProfileID:       ProfileStandard,
		Version:         "1.0.0",
		DisplayName:     "Standard Automated Baseline",
		Description:     "Non-destructive, rate-limited baseline assessment for verified targets.",
		ImpactLevel:     "medium",
		TrafficLevel:    "limited",
		CheckCategories: []string{"discovery", "passive", "passive_web_application_security", "misconfiguration"},
		Budget: ProfileBudget{
			RequestsPerSecond:    2,
			MaxConcurrency:       2,
			MaxRequestsPerTarget: 500,
			MaxDuration:          10 * time.Minute,
		},
		PermittedScanners: []string{
			ScannerHTTPPreflight,
			ScannerTLSAssessor,
			ScannerHTTPHeaders,
			ScannerZAPBaseline,
			ScannerNuclei,
		},
		DefaultScannerOrder: []ScannerPhase{
			{
				PhaseIndex:  1,
				PhaseName:   "preflight_and_reachability",
				Scanners:    []string{ScannerHTTPPreflight},
				Parallel:    false,
				RequirePrev: false,
			},
			{
				PhaseIndex:  2,
				PhaseName:   "protocol_and_header_observation",
				Scanners:    []string{ScannerTLSAssessor, ScannerHTTPHeaders},
				Parallel:    true,
				RequirePrev: true,
			},
			{
				PhaseIndex:  3,
				PhaseName:   "safe_content_and_crawl_inspection",
				Scanners:    []string{ScannerNuclei, ScannerZAPBaseline},
				Parallel:    true,
				RequirePrev: true,
			},
		},
		AdminSignoffRequired: false,
	},
	ProfileDeep: {
		ProfileID:       ProfileDeep,
		Version:         "1.0.0",
		DisplayName:     "Deep Authorized Assessment",
		Description:     "Authorized assessment requiring explicit admin signoff and scheduled window.",
		ImpactLevel:     "high",
		TrafficLevel:    "active",
		CheckCategories: []string{"discovery", "passive", "active", "vulnerability_scanning"},
		Budget: ProfileBudget{
			RequestsPerSecond:    5,
			MaxConcurrency:       2,
			MaxRequestsPerTarget: 2000,
			MaxDuration:          30 * time.Minute,
		},
		PermittedScanners: []string{
			ScannerHTTPPreflight,
			ScannerTLSAssessor,
			ScannerHTTPHeaders,
			ScannerZAPBaseline,
			ScannerNuclei,
		},
		DefaultScannerOrder: []ScannerPhase{
			{
				PhaseIndex:  1,
				PhaseName:   "preflight",
				Scanners:    []string{ScannerHTTPPreflight},
				Parallel:    false,
				RequirePrev: false,
			},
			{
				PhaseIndex:  2,
				PhaseName:   "passive_analysis",
				Scanners:    []string{ScannerTLSAssessor, ScannerHTTPHeaders, ScannerZAPBaseline},
				Parallel:    true,
				RequirePrev: true,
			},
			{
				PhaseIndex:  3,
				PhaseName:   "vulnerability_inspection",
				Scanners:    []string{ScannerNuclei},
				Parallel:    false,
				RequirePrev: true,
			},
		},
		AdminSignoffRequired: true,
	},
}

// GetAssessmentProfile retrieves an approved assessment profile by ID.
func GetAssessmentProfile(profileID string) (AssessmentProfile, error) {
	canonicalID := strings.TrimSpace(profileID)
	// Handle short names for backward compatibility
	switch canonicalID {
	case "passive":
		canonicalID = ProfilePassive
	case "standard":
		canonicalID = ProfileStandard
	case "deep":
		canonicalID = ProfileDeep
	}

	profile, ok := mvpProfiles[canonicalID]
	if !ok {
		return AssessmentProfile{}, fmt.Errorf("adapters: unknown or unsupported assessment profile %q", profileID)
	}
	return profile, nil
}

// ValidateProfileSelection validates that a requested profile and scanner combination is permitted.
func ValidateProfileSelection(profileID, scannerID string) (AssessmentProfile, error) {
	profile, err := GetAssessmentProfile(profileID)
	if err != nil {
		return AssessmentProfile{}, err
	}

	scannerAllowed := false
	for _, permitted := range profile.PermittedScanners {
		if permitted == scannerID {
			scannerAllowed = true
			break
		}
	}

	if !scannerAllowed {
		return AssessmentProfile{}, fmt.Errorf("adapters: scanner %q is not permitted under profile %q", scannerID, profile.ProfileID)
	}

	return profile, nil
}

// ListAssessmentProfiles returns all registered MVP assessment profiles.
func ListAssessmentProfiles() []AssessmentProfile {
	return []AssessmentProfile{
		mvpProfiles[ProfilePassive],
		mvpProfiles[ProfileStandard],
		mvpProfiles[ProfileDeep],
	}
}
