package findings_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/findings"
)

func TestCompareAssessments_DeltaCategories(t *testing.T) {
	tenantID := uuid.New()
	baseID := uuid.New()
	targetID := uuid.New()

	baseObs := []*findings.FindingObservation{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: baseID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC().AddDate(0, 0, -5),
			RawMetadata: map[string]any{
				"fingerprint": "fp-persistent",
				"title":       "Missing X-Frame-Options",
				"severity":    "MEDIUM",
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: baseID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC().AddDate(0, 0, -5),
			RawMetadata: map[string]any{
				"fingerprint": "fp-mutated",
				"title":       "SQL Injection in Search",
				"severity":    "HIGH",
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: baseID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC().AddDate(0, 0, -5),
			RawMetadata: map[string]any{
				"fingerprint": "fp-unobserved",
				"title":       "Information Disclosure",
				"severity":    "LOW",
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: baseID,
			ScannerID:    "tls_scanner",
			ObservedAt:   time.Now().UTC().AddDate(0, 0, -5),
			RawMetadata: map[string]any{
				"fingerprint": "fp-coverage-gap",
				"title":       "TLS 1.0 Supported",
				"severity":    "MEDIUM",
			},
		},
	}

	targetObs := []*findings.FindingObservation{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: targetID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC(),
			RawMetadata: map[string]any{
				"fingerprint": "fp-persistent",
				"title":       "Missing X-Frame-Options",
				"severity":    "MEDIUM",
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: targetID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC(),
			RawMetadata: map[string]any{
				"fingerprint": "fp-mutated",
				"title":       "SQL Injection in Search",
				"severity":    "CRITICAL", // Mutated from HIGH -> CRITICAL
			},
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			AssessmentID: targetID,
			ScannerID:    "zap",
			ObservedAt:   time.Now().UTC(),
			RawMetadata: map[string]any{
				"fingerprint": "fp-new",
				"title":       "Remote Code Execution",
				"severity":    "CRITICAL",
			},
		},
	}

	baseScanners := []string{"zap", "tls_scanner"}
	targetScanners := []string{"zap"} // tls_scanner omitted!

	res, err := findings.CompareAssessments(tenantID, baseID, targetID, baseObs, targetObs, baseScanners, targetScanners)
	require.NoError(t, err)

	assert.Equal(t, 1, res.NewCount)
	assert.Equal(t, 1, res.PersistentCount)
	assert.Equal(t, 1, res.MutatedCount)
	assert.Equal(t, 1, res.UnobservedCount)
	assert.Equal(t, 1, res.CoverageGapCount)

	// Verify coverage diff
	assert.Equal(t, 0.5, res.Coverage.CoverageRatio)
	assert.Contains(t, res.Coverage.CoverageWarning, "tls_scanner")
	assert.ElementsMatch(t, []string{"tls_scanner"}, res.Coverage.OmittedScanners)

	// Verify specific delta items
	deltaMap := make(map[string]findings.FindingDeltaItem)
	for _, d := range res.Deltas {
		deltaMap[d.Fingerprint] = d
	}

	assert.Equal(t, findings.DeltaPersistent, deltaMap["fp-persistent"].Category)
	assert.Equal(t, findings.DeltaMutated, deltaMap["fp-mutated"].Category)
	assert.Equal(t, "HIGH", deltaMap["fp-mutated"].BaseSeverity)
	assert.Equal(t, "CRITICAL", deltaMap["fp-mutated"].TargetSeverity)

	assert.Equal(t, findings.DeltaUnobserved, deltaMap["fp-unobserved"].Category)
	assert.Equal(t, findings.DeltaCoverageGapUntested, deltaMap["fp-coverage-gap"].Category)
	assert.Equal(t, findings.DeltaNew, deltaMap["fp-new"].Category)
}
