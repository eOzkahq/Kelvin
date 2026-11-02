package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryFindingSearchEngine(t *testing.T) {
	ctx := context.Background()
	engine := NewMemoryFindingSearchEngine()

	tenant1 := uuid.New()
	tenant2 := uuid.New()
	asmtID := uuid.New()

	scoreCritical := 95.0
	scoreHigh := 82.0
	scoreLow := 20.0

	now := time.Now().UTC()

	f1 := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenant1,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-001",
		Title:            "Remote Code Execution in Spring",
		Severity:         "CRITICAL",
		Status:           StatusConfirmed,
		RiskScore:        &scoreCritical,
		RiskPriorityBand: RiskBandCritical,
		AffectedEndpoint: "https://api.kelvin.internal/login",
		ScannerData:      map[string]any{"scanner_type": "nuclei"},
		CWEID:            "CWE-94",
		CVEIDs:           []string{"CVE-2022-22965"},
		FirstSeenAt:      now.Add(-48 * time.Hour),
		LastSeenAt:       now,
	}

	f2 := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenant1,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-002",
		Title:            "SQL Injection in Search Query",
		Severity:         "HIGH",
		Status:           StatusConfirmed,
		RiskScore:        &scoreHigh,
		RiskPriorityBand: RiskBandHigh,
		AffectedEndpoint: "https://api.kelvin.internal/search",
		ScannerData:      map[string]any{"scanner_type": "zap"},
		CWEID:            "CWE-89",
		CVEIDs:           []string{"CVE-2023-1111"},
		FirstSeenAt:      now.Add(-24 * time.Hour),
		LastSeenAt:       now,
	}

	f3 := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenant1,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-003",
		Title:            "Missing Strict-Transport-Security Header",
		Severity:         "LOW",
		Status:           StatusResolved,
		RiskScore:        &scoreLow,
		RiskPriorityBand: RiskBandLow,
		AffectedEndpoint: "https://api.kelvin.internal/about",
		ScannerData:      map[string]any{"scanner_type": "tls"},
		CWEID:            "CWE-319",
		FirstSeenAt:      now.Add(-72 * time.Hour),
		LastSeenAt:       now.Add(-12 * time.Hour),
	}

	// Finding for tenant2 (must be isolated)
	fOther := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenant2,
		AssessmentID:     uuid.New(),
		Fingerprint:      "fp-other",
		Title:            "Information Disclosure",
		Severity:         "HIGH",
		Status:           StatusConfirmed,
		AffectedEndpoint: "https://other.com/secret",
	}

	engine.IndexFinding(f1)
	engine.IndexFinding(f2)
	engine.IndexFinding(f3)
	engine.IndexFinding(fOther)

	t.Run("tenant boundary isolation", func(t *testing.T) {
		res, err := engine.SearchFindings(ctx, FindingSearchQuery{TenantID: tenant1})
		require.NoError(t, err)
		assert.Equal(t, 3, res.TotalCount)
		assert.Len(t, res.Items, 3)

		resOther, err := engine.SearchFindings(ctx, FindingSearchQuery{TenantID: tenant2})
		require.NoError(t, err)
		assert.Equal(t, 1, resOther.TotalCount)
		assert.Equal(t, "Information Disclosure", resOther.Items[0].Title)
	})

	t.Run("filter by severity and status", func(t *testing.T) {
		res, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Severity: "CRITICAL",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, res.TotalCount)
		assert.Equal(t, f1.ID, res.Items[0].ID)

		resResolved, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Status:   StatusResolved,
		})
		require.NoError(t, err)
		assert.Equal(t, 1, resResolved.TotalCount)
		assert.Equal(t, f3.ID, resResolved.Items[0].ID)
	})

	t.Run("filter by scanner and endpoint target", func(t *testing.T) {
		res, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Scanner:  "zap",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, res.TotalCount)
		assert.Equal(t, f2.ID, res.Items[0].ID)

		resTarget, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Target:   "search",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, resTarget.TotalCount)
		assert.Equal(t, f2.ID, resTarget.Items[0].ID)
	})

	t.Run("text search by query q", func(t *testing.T) {
		res, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Query:    "spring",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, res.TotalCount)
		assert.Equal(t, f1.ID, res.Items[0].ID)

		resCVE, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Query:    "CVE-2023-1111",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, resCVE.TotalCount)
		assert.Equal(t, f2.ID, resCVE.Items[0].ID)
	})

	t.Run("pagination and limit bounds", func(t *testing.T) {
		res, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Limit:    2,
			Offset:   0,
		})
		require.NoError(t, err)
		assert.Equal(t, 3, res.TotalCount)
		assert.Len(t, res.Items, 2)

		resPage2, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Limit:    2,
			Offset:   2,
		})
		require.NoError(t, err)
		assert.Equal(t, 3, resPage2.TotalCount)
		assert.Len(t, resPage2.Items, 1)

		// Exceeding max limit
		_, err = engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Limit:    150,
		})
		assert.ErrorIs(t, err, ErrInvalidLimit)

		// Negative offset
		_, err = engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID: tenant1,
			Offset:   -1,
		})
		assert.ErrorIs(t, err, ErrInvalidOffset)
	})

	t.Run("sorting by severity and risk score", func(t *testing.T) {
		res, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID:  tenant1,
			SortBy:    "severity",
			SortOrder: "desc",
		})
		require.NoError(t, err)
		assert.Equal(t, "CRITICAL", res.Items[0].Severity)
		assert.Equal(t, "HIGH", res.Items[1].Severity)
		assert.Equal(t, "LOW", res.Items[2].Severity)

		resAsc, err := engine.SearchFindings(ctx, FindingSearchQuery{
			TenantID:  tenant1,
			SortBy:    "severity",
			SortOrder: "asc",
		})
		require.NoError(t, err)
		assert.Equal(t, "LOW", resAsc.Items[0].Severity)
	})

	t.Run("dashboard metrics aggregation", func(t *testing.T) {
		metrics, err := engine.GetDashboardMetrics(ctx, tenant1)
		require.NoError(t, err)

		assert.Equal(t, 3, metrics.TotalFindings)
		assert.Equal(t, 2, metrics.OpenFindings)
		assert.Equal(t, 1, metrics.ResolvedFindings)
		assert.Equal(t, 1, metrics.SeverityBreakdown["CRITICAL"])
		assert.Equal(t, 1, metrics.SeverityBreakdown["HIGH"])
		assert.Equal(t, 1, metrics.SeverityBreakdown["LOW"])
		assert.Equal(t, 2, metrics.StatusBreakdown["CONFIRMED"])
		assert.Equal(t, 1, metrics.StatusBreakdown["RESOLVED"])
	})
}
