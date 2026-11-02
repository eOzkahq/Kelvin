package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAuditAccess(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	// 1. Regular user without audit permission -> Denied
	regularUser := Principal{
		UserID:      userID,
		TenantID:    tenantID,
		Role:        "DEVELOPER",
		Permissions: []string{"scans:read", "findings:read"},
	}
	assert.ErrorIs(t, CheckAuditAccess(regularUser), ErrAuditForbidden)

	// 2. User with audit:read permission -> Allowed
	auditorUser := Principal{
		UserID:      userID,
		TenantID:    tenantID,
		Role:        "DEVELOPER",
		Permissions: []string{"audit:read"},
	}
	assert.NoError(t, CheckAuditAccess(auditorUser))

	// 3. Org Owner role -> Allowed
	ownerUser := Principal{
		UserID:      userID,
		TenantID:    tenantID,
		Role:        "ORG_OWNER",
		Permissions: []string{},
	}
	assert.NoError(t, CheckAuditAccess(ownerUser))

	// 4. Compliance Auditor role -> Allowed
	complianceUser := Principal{
		UserID:      userID,
		TenantID:    tenantID,
		Role:        "COMPLIANCE_AUDITOR",
		Permissions: []string{},
	}
	assert.NoError(t, CheckAuditAccess(complianceUser))
}

func TestAuditSearch_TenantIsolationAndFiltering(t *testing.T) {
	svc := NewSearchService(nil)
	tenant1 := uuid.New()
	tenant2 := uuid.New()
	actor1 := uuid.New()
	actor2 := uuid.New()

	baseTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	events := []Event{
		{
			ID:            uuid.New(),
			TenantID:      &tenant1,
			ActorUserID:   &actor1,
			ActorType:     ActorUser,
			Action:        "scan.created",
			EntityType:    "scan",
			Payload:       json.RawMessage(`{"status": "scheduled", "token": "Bearer secret-1234567890"}`),
			CorrelationID: "corr-101",
			CreatedAt:     baseTime.Add(1 * time.Minute),
		},
		{
			ID:            uuid.New(),
			TenantID:      &tenant1,
			ActorUserID:   &actor2,
			ActorType:     ActorUser,
			Action:        "policy.updated",
			EntityType:    "policy",
			Payload:       json.RawMessage(`{"policy_name": "SLA-Critical", "password": "superSecretPassword!"}`),
			CorrelationID: "corr-102",
			CreatedAt:     baseTime.Add(2 * time.Minute),
		},
		{
			ID:            uuid.New(),
			TenantID:      &tenant2, // Different tenant
			ActorUserID:   &actor1,
			ActorType:     ActorUser,
			Action:        "scan.created",
			EntityType:    "scan",
			Payload:       json.RawMessage(`{"status": "scheduled"}`),
			CorrelationID: "corr-201",
			CreatedAt:     baseTime.Add(3 * time.Minute),
		},
	}

	// 1. Search for Tenant 1 -> Should never return Tenant 2 events
	res, err := svc.FilterEventsInMemory(events, SearchFilter{
		TenantID: tenant1,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res.TotalCount)
	for _, e := range res.Events {
		assert.Equal(t, tenant1, *e.TenantID)
	}

	// 2. Sensitive data redaction in returned payloads
	assert.NotContains(t, string(res.Events[0].Payload), "superSecretPassword!")
	assert.NotContains(t, string(res.Events[1].Payload), "secret-1234567890")

	// 3. Filter by Action
	actionRes, err := svc.FilterEventsInMemory(events, SearchFilter{
		TenantID: tenant1,
		Action:   "policy.updated",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, actionRes.TotalCount)
	assert.Equal(t, "policy.updated", actionRes.Events[0].Action)

	// 4. Filter by Actor
	actorRes, err := svc.FilterEventsInMemory(events, SearchFilter{
		TenantID:    tenant1,
		ActorUserID: &actor1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, actorRes.TotalCount)
	assert.Equal(t, actor1, *actorRes.Events[0].ActorUserID)
}

func TestAuditSearch_PaginationAndLimits(t *testing.T) {
	svc := NewSearchService(nil)
	tenantID := uuid.New()

	var events []Event
	baseTime := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		events = append(events, Event{
			ID:            uuid.New(),
			TenantID:      &tenantID,
			ActorType:     ActorService,
			Action:        "finding.detected",
			EntityType:    "finding",
			Payload:       json.RawMessage(`{"index": ` + string(rune('0'+i)) + `}`),
			CorrelationID: "corr-bulk",
			CreatedAt:     baseTime.Add(time.Duration(i) * time.Minute),
		})
	}

	// Limit 10, Offset 0 -> returns first 10, newest first
	p1, err := svc.FilterEventsInMemory(events, SearchFilter{
		TenantID: tenantID,
		Limit:    10,
		Offset:   0,
	})
	require.NoError(t, err)
	assert.Equal(t, 25, p1.TotalCount)
	assert.Len(t, p1.Events, 10)
	assert.True(t, p1.HasMore)
	assert.True(t, p1.Events[0].CreatedAt.After(p1.Events[1].CreatedAt)) // Ordered DESC

	// Limit 10, Offset 20 -> returns last 5
	p3, err := svc.FilterEventsInMemory(events, SearchFilter{
		TenantID: tenantID,
		Limit:    10,
		Offset:   20,
	})
	require.NoError(t, err)
	assert.Len(t, p3.Events, 5)
	assert.False(t, p3.HasMore)

	// Limit > 100 -> rejected
	_, err = svc.FilterEventsInMemory(events, SearchFilter{
		TenantID: tenantID,
		Limit:    150,
	})
	assert.ErrorIs(t, err, ErrLimitExceeded)

	// Invalid time range -> rejected
	tFrom := time.Now()
	tTo := tFrom.Add(-1 * time.Hour)
	_, err = svc.FilterEventsInMemory(events, SearchFilter{
		TenantID: tenantID,
		FromTime: &tFrom,
		ToTime:   &tTo,
	})
	assert.ErrorIs(t, err, ErrInvalidTimeRange)
}

func TestAuditSearch_SQLQueryBuilder(t *testing.T) {
	svc := NewSearchService(nil)
	tenantID := uuid.New()
	actorID := uuid.New()

	query, countQuery, args := svc.BuildSearchQuery(SearchFilter{
		TenantID:       tenantID,
		ActorUserID:    &actorID,
		Action:         "user.invited",
		CorrelationID:  "corr-abc",
		MetadataFilter: map[string]any{"status": "success"},
	})

	assert.Contains(t, query, "tenant_id = $1")
	assert.Contains(t, query, "actor_user_id = $2")
	assert.Contains(t, query, "action ILIKE $3")
	assert.Contains(t, query, "correlation_id = $4")
	assert.Contains(t, query, "payload @> $5::jsonb")
	assert.Contains(t, countQuery, "SELECT COUNT(*)")
	assert.Equal(t, 5, len(args))
}
