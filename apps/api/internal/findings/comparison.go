// Package findings provides assessment-to-assessment delta comparison,
// scanner coverage evaluation, and vulnerability mutation tracking.
//
// See docs/architecture/ASSESSMENT_TO_ASSESSMENT_COMPARISON.md.
package findings

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// FindingDeltaCategory classifies the differential state of a finding between two assessments.
type FindingDeltaCategory string

const (
	DeltaNew                 FindingDeltaCategory = "NEW"
	DeltaPersistent          FindingDeltaCategory = "PERSISTENT"
	DeltaUnobserved          FindingDeltaCategory = "UNOBSERVED"
	DeltaMutated             FindingDeltaCategory = "MUTATED"
	DeltaCoverageGapUntested FindingDeltaCategory = "COVERAGE_GAP_UNTESTED"
)

// FindingDeltaItem represents a single comparative delta between base and target observations.
type FindingDeltaItem struct {
	Fingerprint       string               `json:"fingerprint"`
	Title             string               `json:"title"`
	Category          FindingDeltaCategory `json:"category"`
	BaseObservation   *FindingObservation  `json:"base_observation,omitempty"`
	TargetObservation *FindingObservation  `json:"target_observation,omitempty"`
	BaseSeverity      string               `json:"base_severity,omitempty"`
	TargetSeverity    string               `json:"target_severity,omitempty"`
	Explanation       string               `json:"explanation"`
}

// CoverageComparison analyzes differences in scanner engine coverage between assessments.
type CoverageComparison struct {
	BaseScanners    []string `json:"base_scanners"`
	TargetScanners  []string `json:"target_scanners"`
	CommonScanners  []string `json:"common_scanners"`
	OmittedScanners []string `json:"omitted_scanners"`
	CoverageRatio   float64  `json:"coverage_ratio"`
	CoverageWarning string   `json:"coverage_warning,omitempty"`
}

// AssessmentComparisonResult holds the complete comparative diff between two assessments.
type AssessmentComparisonResult struct {
	TenantID            uuid.UUID          `json:"tenant_id"`
	BaseAssessmentID    uuid.UUID          `json:"base_assessment_id"`
	TargetAssessmentID  uuid.UUID          `json:"target_assessment_id"`
	TotalBaseFindings   int                `json:"total_base_findings"`
	TotalTargetFindings int                `json:"total_target_findings"`
	NewCount            int                `json:"new_count"`
	PersistentCount     int                `json:"persistent_count"`
	UnobservedCount     int                `json:"unobserved_count"`
	MutatedCount        int                `json:"mutated_count"`
	CoverageGapCount    int                `json:"coverage_gap_count"`
	Coverage            CoverageComparison `json:"coverage"`
	Deltas              []FindingDeltaItem `json:"deltas"`
	ComparedAt          time.Time          `json:"compared_at"`
}

// CompareAssessments evaluates finding observations and scanner coverage between base and target assessments.
func CompareAssessments(
	tenantID uuid.UUID,
	baseID, targetID uuid.UUID,
	baseObs, targetObs []*FindingObservation,
	baseScanners, targetScanners []string,
) (*AssessmentComparisonResult, error) {
	cov := computeCoverage(baseScanners, targetScanners)

	targetScannerMap := make(map[string]bool, len(targetScanners))
	for _, s := range targetScanners {
		targetScannerMap[s] = true
	}

	baseMap := make(map[string]*FindingObservation, len(baseObs))
	for _, o := range baseObs {
		fp := extractFingerprint(o)
		baseMap[fp] = o
	}

	targetMap := make(map[string]*FindingObservation, len(targetObs))
	for _, o := range targetObs {
		fp := extractFingerprint(o)
		targetMap[fp] = o
	}

	res := &AssessmentComparisonResult{
		TenantID:            tenantID,
		BaseAssessmentID:    baseID,
		TargetAssessmentID:  targetID,
		TotalBaseFindings:   len(baseObs),
		TotalTargetFindings: len(targetObs),
		Coverage:            cov,
		Deltas:              make([]FindingDeltaItem, 0),
		ComparedAt:          time.Now().UTC(),
	}

	// 1. Process base observations against target
	for fp, b := range baseMap {
		t, presentInTarget := targetMap[fp]

		if presentInTarget {
			// Check for mutations (e.g. severity changed)
			bSev := extractSeverity(b)
			tSev := extractSeverity(t)

			if bSev != "" && tSev != "" && bSev != tSev {
				res.MutatedCount++
				res.Deltas = append(res.Deltas, FindingDeltaItem{
					Fingerprint:       fp,
					Title:             extractTitle(t),
					Category:          DeltaMutated,
					BaseObservation:   b,
					TargetObservation: t,
					BaseSeverity:      bSev,
					TargetSeverity:    tSev,
					Explanation:       fmt.Sprintf("Vulnerability persisted with modified severity: %s -> %s", bSev, tSev),
				})
			} else {
				res.PersistentCount++
				res.Deltas = append(res.Deltas, FindingDeltaItem{
					Fingerprint:       fp,
					Title:             extractTitle(t),
					Category:          DeltaPersistent,
					BaseObservation:   b,
					TargetObservation: t,
					BaseSeverity:      bSev,
					TargetSeverity:    tSev,
					Explanation:       "Vulnerability re-confirmed in target assessment",
				})
			}
		} else {
			// Disappeared in target: check if scanner was actually run in target assessment
			scannerRan := targetScannerMap[b.ScannerID]
			if !scannerRan && len(targetScanners) > 0 {
				res.CoverageGapCount++
				res.Deltas = append(res.Deltas, FindingDeltaItem{
					Fingerprint:     fp,
					Title:           extractTitle(b),
					Category:        DeltaCoverageGapUntested,
					BaseObservation: b,
					BaseSeverity:    extractSeverity(b),
					Explanation:     fmt.Sprintf("Scanner %q was omitted in target assessment; unresolved status preserved", b.ScannerID),
				})
			} else {
				res.UnobservedCount++
				res.Deltas = append(res.Deltas, FindingDeltaItem{
					Fingerprint:     fp,
					Title:           extractTitle(b),
					Category:        DeltaUnobserved,
					BaseObservation: b,
					BaseSeverity:    extractSeverity(b),
					Explanation:     "Vulnerability was not observed in target assessment (verification re-test advised)",
				})
			}
		}
	}

	// 2. Identify new findings present only in target
	for fp, t := range targetMap {
		if _, presentInBase := baseMap[fp]; !presentInBase {
			res.NewCount++
			res.Deltas = append(res.Deltas, FindingDeltaItem{
				Fingerprint:       fp,
				Title:             extractTitle(t),
				Category:          DeltaNew,
				TargetObservation: t,
				TargetSeverity:    extractSeverity(t),
				Explanation:       "Newly discovered vulnerability not observed in base assessment",
			})
		}
	}

	// Sort deltas deterministically by fingerprint
	sort.Slice(res.Deltas, func(i, j int) bool {
		return res.Deltas[i].Fingerprint < res.Deltas[j].Fingerprint
	})

	return res, nil
}

func computeCoverage(baseScanners, targetScanners []string) CoverageComparison {
	baseSet := make(map[string]bool, len(baseScanners))
	for _, s := range baseScanners {
		baseSet[s] = true
	}

	targetSet := make(map[string]bool, len(targetScanners))
	for _, s := range targetScanners {
		targetSet[s] = true
	}

	var common, omitted []string
	for _, s := range baseScanners {
		if targetSet[s] {
			common = append(common, s)
		} else {
			omitted = append(omitted, s)
		}
	}

	ratio := 1.0
	warning := ""
	if len(baseScanners) > 0 {
		ratio = float64(len(common)) / float64(len(baseScanners))
		if len(omitted) > 0 {
			warning = fmt.Sprintf("Coverage mismatch: %d scanner(s) omitted in target assessment (%v)", len(omitted), omitted)
		}
	}

	return CoverageComparison{
		BaseScanners:    baseScanners,
		TargetScanners:  targetScanners,
		CommonScanners:  common,
		OmittedScanners: omitted,
		CoverageRatio:   ratio,
		CoverageWarning: warning,
	}
}

func extractFingerprint(obs *FindingObservation) string {
	if obs.RawMetadata != nil {
		if fp, ok := obs.RawMetadata["fingerprint"].(string); ok && fp != "" {
			return fp
		}
	}
	return obs.ID.String()
}

func extractTitle(obs *FindingObservation) string {
	if obs.RawMetadata != nil {
		if t, ok := obs.RawMetadata["title"].(string); ok && t != "" {
			return t
		}
	}
	return "Vulnerability Observation"
}

func extractSeverity(obs *FindingObservation) string {
	if obs.RawMetadata != nil {
		if s, ok := obs.RawMetadata["severity"].(string); ok && s != "" {
			return s
		}
	}
	return "MEDIUM"
}
