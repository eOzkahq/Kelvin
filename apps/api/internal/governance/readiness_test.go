package governance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
	"github.com/kelvin/kelvin/apps/api/internal/notifications"
	"github.com/kelvin/kelvin/apps/api/internal/orchestrator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPhase4_FullEnterpriseReadinessIntegrationSuite validates the interoperability
// of all Phase 4 enterprise systems across Workstreams A, B, C, D, and E.
func TestPhase4_FullEnterpriseReadinessIntegrationSuite(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("Workstream E & B: Audit Search and Tamper-Evidence Verification", func(t *testing.T) {
		// 1. RBAC Check on Audit Access
		principal := audit.Principal{
			UserID:      userID,
			TenantID:    tenantID,
			Role:        "SECURITY_OFFICER",
			Permissions: []string{"audit:read"},
		}
		require.NoError(t, audit.CheckAuditAccess(principal))

		// 2. Cryptographic Chain & Checkpoint Integrity
		engine := audit.NewIntegrityEngine("phase4-readiness-hmac-key")
		e1 := engine.AppendChainedEvent(nil, audit.ChainedEvent{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Action:      "policy.created",
			EntityType:  "policy",
			CreatedAt:   time.Now().UTC(),
		})
		e2 := engine.AppendChainedEvent(&e1, audit.ChainedEvent{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Action:      "scan.executed",
			EntityType:  "scan",
			CreatedAt:   time.Now().UTC().Add(1 * time.Second),
		})

		cp, err := engine.CreateCheckpoint(context.Background(), tenantID, 1, []audit.ChainedEvent{e1, e2})
		require.NoError(t, err)

		verifyRes, err := engine.VerifyChain(context.Background(), []audit.ChainedEvent{e1, e2}, cp)
		require.NoError(t, err)
		assert.True(t, verifyRes.Valid)
	})

	t.Run("Workstream D: Central Notifications and Redaction", func(t *testing.T) {
		router := notifications.NewRouter()
		event := notifications.Event{
			OrganizationID: tenantID,
			EventType:      "findings.critical",
			Severity:       "CRITICAL",
			ResourceID:     "prod-db-1",
			Title:          "Critical finding with password=SuperSecret!",
			Message:        "Leaked Bearer secret-auth-token-99999",
		}

		logs := router.Dispatch(context.Background(), event)
		require.NotEmpty(t, logs)
		for _, l := range logs {
			assert.NotContains(t, l.SanitizedContent, "SuperSecret!")
			assert.NotContains(t, l.SanitizedContent, "secret-auth-token-99999")
		}
	})

	t.Run("Workstream E: Data Governance Exports and Retention Precedence", func(t *testing.T) {
		// 1. Export Clearance
		assert.True(t, AuthorizeExport("SECURITY_OFFICER", nil, ClassificationConfidential))

		// 2. Retention Policy Bounds
		retSvc := NewRetentionService()
		err := retSvc.SetPolicy(DataRetentionPolicy{
			TenantID:       tenantID,
			EvidenceDays:   60,
			AssessmentDays: 180,
			FindingDays:    365,
			ReportDays:     180,
			AuditDays:      365, // Complies with ADR-0002 min 365
		})
		require.NoError(t, err)

		// 3. Legal Hold Precedence
		_, err = retSvc.ApplyLegalHold(LegalHold{
			TenantID:   tenantID,
			Name:       "Litigation Hold 2026",
			TargetType: HoldTargetTenant,
		})
		require.NoError(t, err)
		assert.True(t, retSvc.IsUnderLegalHold(tenantID, "p-1", "a-1"))
	})

	t.Run("Workstream E: Quota Gatekeeping and Fair-Share Scheduling", func(t *testing.T) {
		// 1. Quota Gatekeeper
		quotaMgr := NewQuotaManager()
		_ = quotaMgr.SetQuota(TenantQuota{
			TenantID:             tenantID,
			MaxConcurrentScans:   2,
			MaxMonthlyScanHours:  100,
			MaxStorageGB:         50,
			MaxServiceIdentities: 10,
			MaxMonthlyEvents:     1000,
		})

		rel, err := quotaMgr.AcquireConcurrentScan(context.Background(), tenantID)
		require.NoError(t, err)
		rel()

		// 2. Fair-Share Orchestration
		scheduler := orchestrator.NewFairShareScheduler()
		err = scheduler.Enqueue(context.Background(), &orchestrator.WorkloadJob{
			TenantID: tenantID,
			JobType:  "SCAN",
			Priority: 1,
		})
		require.NoError(t, err)

		job, err := scheduler.DispatchNext(context.Background(), "worker-readiness")
		require.NoError(t, err)
		assert.Equal(t, tenantID, job.TenantID)
		scheduler.CompleteJob(tenantID)

		// 3. Rate Limiting
		limiter := middleware.NewRateLimiter(10, 2)
		res := limiter.Allow("tenant:"+tenantID.String(), middleware.OpCategoryStandard, time.Now().UTC())
		assert.True(t, res.Allowed)
	})
}
