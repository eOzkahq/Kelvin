package governance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataRetentionPolicy_PlatformEnforcedBounds(t *testing.T) {
	svc := NewRetentionService()
	tenantID := uuid.New()

	// 1. Evidence retention below 30 days must be rejected
	err := svc.SetPolicy(DataRetentionPolicy{
		TenantID:       tenantID,
		EvidenceDays:   15, // Below 30
		AssessmentDays: 365,
		FindingDays:    730,
		ReportDays:     365,
		AuditDays:      365,
	})
	assert.ErrorIs(t, err, ErrRetentionBelowPlatformMinimum)

	// 2. Audit log retention below 365 days must be rejected (ADR-0002 compliance)
	err = svc.SetPolicy(DataRetentionPolicy{
		TenantID:       tenantID,
		EvidenceDays:   60,
		AssessmentDays: 365,
		FindingDays:    730,
		ReportDays:     365,
		AuditDays:      90, // Below 365
	})
	assert.ErrorIs(t, err, ErrRetentionBelowPlatformMinimum)

	// 3. Valid policy within platform bounds
	validPolicy := DataRetentionPolicy{
		TenantID:       tenantID,
		EvidenceDays:   45,
		AssessmentDays: 180,
		FindingDays:    365,
		ReportDays:     180,
		AuditDays:      365,
	}
	err = svc.SetPolicy(validPolicy)
	require.NoError(t, err)

	retrieved := svc.GetPolicy(tenantID)
	assert.Equal(t, 45, retrieved.EvidenceDays)
	assert.Equal(t, 180, retrieved.AssessmentDays)
}

func TestRetentionPurge_LegalHoldPrecedenceAndPurgeExecution(t *testing.T) {
	svc := NewRetentionService()
	tenantID := uuid.New()

	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	oldTime := now.Add(-100 * 24 * time.Hour)    // 100 days old (exceeds default 90-day evidence retention)
	recentTime := now.Add(-10 * 24 * time.Hour) // 10 days old (within 90-day retention)

	records := []*RetentionRecord{
		{
			ID:        "ev-old-1",
			Category:  CategoryEvidence,
			ProjectID: "proj-alpha",
			SizeBytes: 1024 * 1024, // 1MB
			CreatedAt: oldTime,
		},
		{
			ID:        "ev-old-held",
			Category:  CategoryEvidence,
			ProjectID: "proj-held", // Under legal hold
			SizeBytes: 2048 * 1024, // 2MB
			CreatedAt: oldTime,
		},
		{
			ID:        "ev-recent",
			Category:  CategoryEvidence,
			ProjectID: "proj-alpha",
			SizeBytes: 512 * 1024,
			CreatedAt: recentTime,
		},
	}

	// Apply Legal Hold to "proj-held"
	hold, err := svc.ApplyLegalHold(LegalHold{
		TenantID:   tenantID,
		Name:       "Litigation Hold Alpha",
		Reason:     "Regulatory inquiry",
		TargetType: HoldTargetProject,
		TargetID:   "proj-held",
		CreatedBy:  "legal-counsel",
	})
	require.NoError(t, err)
	assert.Equal(t, HoldStatusActive, hold.Status)

	// Execute purge
	exec, err := svc.ExecutePurge(context.Background(), tenantID, records, now)
	require.NoError(t, err)
	assert.Equal(t, 3, exec.RecordsScanned)
	assert.Equal(t, 1, exec.RecordsPurged) // ev-old-1 purged
	assert.Equal(t, 1, exec.RecordsHeld)   // ev-old-held preserved
	assert.Equal(t, int64(1024*1024), exec.EvidenceBytesReclaimed)

	assert.True(t, records[0].IsPurged)
	assert.False(t, records[1].IsPurged) // Preserved by hold
	assert.False(t, records[2].IsPurged) // Preserved by retention window

	// Release Legal Hold
	err = svc.ReleaseLegalHold(tenantID, hold.ID)
	require.NoError(t, err)

	// Re-run purge -> ev-old-held should now be purged
	exec2, err := svc.ExecutePurge(context.Background(), tenantID, records, now)
	require.NoError(t, err)
	assert.Equal(t, 1, exec2.RecordsPurged)
	assert.Equal(t, 0, exec2.RecordsHeld)
	assert.True(t, records[1].IsPurged)
}
