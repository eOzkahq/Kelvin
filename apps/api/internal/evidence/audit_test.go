package evidence_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

func TestEvidenceAuditRecorder_LifecycleEvents(t *testing.T) {
	ctx := context.Background()
	memRecorder := evidence.NewMemoryAuditRecorder()
	auditService := evidence.NewEvidenceAuditRecorder(memRecorder)

	tenantID := uuid.New().String()
	evidenceID := uuid.New().String()
	findingID := uuid.New().String()
	userID := uuid.New().String()

	// 1. Record Creation
	err := auditService.RecordCreation(ctx, tenantID, evidenceID, &userID, evidence.TypeHTTPObservation, 1024, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	require.NoError(t, err)

	// 2. Record Association
	err = auditService.RecordAssociation(ctx, tenantID, findingID, evidenceID, &userID, true)
	require.NoError(t, err)

	// 3. Record Retrieval
	err = auditService.RecordRetrieval(ctx, tenantID, findingID, evidenceID, &userID, false)
	require.NoError(t, err)

	// 4. Record Download
	err = auditService.RecordDownload(ctx, tenantID, findingID, evidenceID, &userID, 300)
	require.NoError(t, err)

	// 5. Record Legal Hold
	err = auditService.RecordLegalHold(ctx, tenantID, evidenceID, &userID, true, "Regulatory review")
	require.NoError(t, err)
	err = auditService.RecordLegalHold(ctx, tenantID, evidenceID, &userID, false, "Hold lifted")
	require.NoError(t, err)

	// 6. Record Purge
	err = auditService.RecordPurge(ctx, tenantID, evidenceID, &userID, &findingID, time.Now().UTC())
	require.NoError(t, err)

	events := memRecorder.GetEvents()
	require.Len(t, events, 7)

	assert.Equal(t, evidence.ActionEvidenceCreated, events[0].Action)
	assert.Equal(t, evidence.ActionEvidenceAssociated, events[1].Action)
	assert.Equal(t, evidence.ActionEvidenceRetrieved, events[2].Action)
	assert.Equal(t, evidence.ActionEvidenceDownloaded, events[3].Action)
	assert.Equal(t, evidence.ActionEvidenceLegalHoldSet, events[4].Action)
	assert.Equal(t, evidence.ActionEvidenceLegalHoldRemoved, events[5].Action)
	assert.Equal(t, evidence.ActionEvidencePurged, events[6].Action)

	for _, e := range events {
		assert.Equal(t, "EVIDENCE", e.EntityType)
		assert.Equal(t, evidenceID, e.EntityID.String())
		assert.Equal(t, tenantID, e.TenantID.String())
	}
}

func TestEvidenceAuditRecorder_IntegrityAndTamperEvents(t *testing.T) {
	ctx := context.Background()
	memRecorder := evidence.NewMemoryAuditRecorder()
	auditService := evidence.NewEvidenceAuditRecorder(memRecorder)

	tenantID := uuid.New().String()
	evidenceID := uuid.New().String()

	// 1. Successful verification
	err := auditService.RecordIntegrityOutcome(ctx, tenantID, evidenceID, nil, true, "calculated_hash_abc")
	require.NoError(t, err)

	// 2. Tampering alert
	err = auditService.RecordIntegrityOutcome(ctx, tenantID, evidenceID, nil, false, "mismatched_hash_xyz")
	require.NoError(t, err)

	events := memRecorder.GetEvents()
	require.Len(t, events, 2)

	assert.Equal(t, evidence.ActionEvidenceIntegrityVerified, events[0].Action)
	assert.Equal(t, evidence.ActionEvidenceTamperAlert, events[1].Action)
}

func TestEvidenceAuditRecorder_AccessDeniedEvent(t *testing.T) {
	ctx := context.Background()
	memRecorder := evidence.NewMemoryAuditRecorder()
	auditService := evidence.NewEvidenceAuditRecorder(memRecorder)

	tenantID := uuid.New().String()
	evidenceID := uuid.New().String()
	findingID := uuid.New().String()
	userID := uuid.New().String()

	err := auditService.RecordAccessDenied(ctx, tenantID, findingID, evidenceID, &userID, "IDOR cross-finding mismatch")
	require.NoError(t, err)

	events := memRecorder.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, evidence.ActionEvidenceAccessDenied, events[0].Action)
	assert.Contains(t, string(events[0].Payload), "ACCESS_DENIED")
}

func TestEvidenceAuditRecorder_NoSensitivePayloadLeaked(t *testing.T) {
	ctx := context.Background()
	memRecorder := evidence.NewMemoryAuditRecorder()
	auditService := evidence.NewEvidenceAuditRecorder(memRecorder)

	tenantID := uuid.New().String()
	evidenceID := uuid.New().String()
	findingID := uuid.New().String()

	_ = auditService.RecordCreation(ctx, tenantID, evidenceID, nil, evidence.TypeHTTPObservation, 512, "abc123")
	_ = auditService.RecordRetrieval(ctx, tenantID, findingID, evidenceID, nil, false)
	_ = auditService.RecordDownload(ctx, tenantID, findingID, evidenceID, nil, 300)

	for _, e := range memRecorder.GetEvents() {
		rawStr := strings.ToLower(string(e.Payload))
		assert.NotContains(t, rawStr, "bearer")
		assert.NotContains(t, rawStr, "password")
		assert.NotContains(t, rawStr, "cookie")
		assert.NotContains(t, rawStr, "token")
		assert.NotContains(t, rawStr, "secret")
	}
}
