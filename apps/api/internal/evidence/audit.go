// Package evidence provides audit logging adapters and schema definitions for tracking
// evidence lifecycle transitions, access grants, integrity checks, and secure purges.
//
// See docs/architecture/EVIDENCE_ACCESS_AND_LIFECYCLE_AUDIT_EVENTS.md.
package evidence

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

// Evidence audit actions conforming to ADR-0002 / DATA_MODEL.md §5.12.
const (
	ActionEvidenceCreated           = "evidence.created"
	ActionEvidenceAssociated        = "evidence.associated"
	ActionEvidenceRetrieved         = "evidence.retrieved"
	ActionEvidenceDownloaded        = "evidence.downloaded"
	ActionEvidenceIntegrityVerified = "evidence.integrity_verified"
	ActionEvidenceTamperAlert       = "evidence.tamper_alert"
	ActionEvidenceArchived          = "evidence.archived"
	ActionEvidenceLegalHoldSet      = "evidence.legal_hold_set"
	ActionEvidenceLegalHoldRemoved  = "evidence.legal_hold_removed"
	ActionEvidencePurged            = "evidence.purged"
	ActionEvidenceAccessDenied      = "evidence.access_denied"
)

// EvidenceAuditRecorder orchestrates security and compliance audit logging for evidence.
type EvidenceAuditRecorder struct {
	recorder audit.Recorder
}

// NewEvidenceAuditRecorder creates a new EvidenceAuditRecorder.
func NewEvidenceAuditRecorder(recorder audit.Recorder) *EvidenceAuditRecorder {
	return &EvidenceAuditRecorder{
		recorder: recorder,
	}
}

func parseUUID(s string) *uuid.UUID {
	if u, err := uuid.Parse(s); err == nil {
		return &u
	}
	return nil
}

// RecordCreation audits the ingestion of a new evidence object.
func (r *EvidenceAuditRecorder) RecordCreation(
	ctx context.Context,
	tenantID, evidenceID string,
	actorID *string,
	evType EvidenceType,
	size int64,
	checksum string,
) error {
	payload, _ := json.Marshal(map[string]any{
		"evidence_type":   evType,
		"size_bytes":      size,
		"checksum_sha256": checksum,
		"status":          "SUCCESS",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, ActionEvidenceCreated, payload)
}

// RecordAssociation audits linking an evidence item to a persistent finding.
func (r *EvidenceAuditRecorder) RecordAssociation(
	ctx context.Context,
	tenantID, findingID, evidenceID string,
	actorID *string,
	isPrimary bool,
) error {
	payload, _ := json.Marshal(map[string]any{
		"finding_id": findingID,
		"is_primary": isPrimary,
		"status":     "SUCCESS",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, ActionEvidenceAssociated, payload)
}

// RecordRetrieval audits evidence inspection or detail view.
func (r *EvidenceAuditRecorder) RecordRetrieval(
	ctx context.Context,
	tenantID, findingID, evidenceID string,
	actorID *string,
	isUnredacted bool,
) error {
	payload, _ := json.Marshal(map[string]any{
		"finding_id":    findingID,
		"is_unredacted": isUnredacted,
		"status":        "SUCCESS",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, ActionEvidenceRetrieved, payload)
}

// RecordDownload audits the issuance of short-lived download URLs.
func (r *EvidenceAuditRecorder) RecordDownload(
	ctx context.Context,
	tenantID, findingID, evidenceID string,
	actorID *string,
	ttlSeconds int,
) error {
	payload, _ := json.Marshal(map[string]any{
		"finding_id":  findingID,
		"ttl_seconds": ttlSeconds,
		"status":      "SUCCESS",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, ActionEvidenceDownloaded, payload)
}

// RecordIntegrityOutcome audits cryptographic verification results.
func (r *EvidenceAuditRecorder) RecordIntegrityOutcome(
	ctx context.Context,
	tenantID, evidenceID string,
	actorID *string,
	verified bool,
	calculatedDigest string,
) error {
	action := ActionEvidenceIntegrityVerified
	status := "VERIFIED"
	if !verified {
		action = ActionEvidenceTamperAlert
		status = "TAMPER_DETECTED"
	}

	payload, _ := json.Marshal(map[string]any{
		"status":            status,
		"calculated_digest": calculatedDigest,
	})
	return r.record(ctx, tenantID, evidenceID, actorID, action, payload)
}

// RecordLegalHold audits legal hold placement or release.
func (r *EvidenceAuditRecorder) RecordLegalHold(
	ctx context.Context,
	tenantID, evidenceID string,
	actorID *string,
	hold bool,
	reason string,
) error {
	action := ActionEvidenceLegalHoldSet
	if !hold {
		action = ActionEvidenceLegalHoldRemoved
	}

	payload, _ := json.Marshal(map[string]any{
		"is_legal_hold": hold,
		"reason":        reason,
		"status":        "SUCCESS",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, action, payload)
}

// RecordPurge audits the cryptographic erasure of an evidence item.
func (r *EvidenceAuditRecorder) RecordPurge(
	ctx context.Context,
	tenantID, evidenceID string,
	actorID *string,
	findingID *string,
	wipedAt time.Time,
) error {
	payload, _ := json.Marshal(map[string]any{
		"finding_id": findingID,
		"wiped_at":   wipedAt.Format(time.RFC3339),
		"status":     "SECURELY_PURGED",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, ActionEvidencePurged, payload)
}

// RecordAccessDenied audits unauthorized or IDOR attempts to access evidence.
func (r *EvidenceAuditRecorder) RecordAccessDenied(
	ctx context.Context,
	tenantID, findingID, evidenceID string,
	actorID *string,
	reason string,
) error {
	payload, _ := json.Marshal(map[string]any{
		"finding_id": findingID,
		"reason":     reason,
		"status":     "ACCESS_DENIED",
	})
	return r.record(ctx, tenantID, evidenceID, actorID, ActionEvidenceAccessDenied, payload)
}

func (r *EvidenceAuditRecorder) record(
	ctx context.Context,
	tenantID, evidenceID string,
	actorID *string,
	action string,
	payload json.RawMessage,
) error {
	if r.recorder == nil {
		return nil
	}

	tUUID := parseUUID(tenantID)
	eUUID := parseUUID(evidenceID)
	var aUUID *uuid.UUID
	actorType := audit.ActorSystem
	if actorID != nil && *actorID != "" {
		aUUID = parseUUID(*actorID)
		if aUUID != nil {
			actorType = audit.ActorUser
		}
	}

	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    tUUID,
		ActorUserID: aUUID,
		ActorType:   actorType,
		Action:      action,
		EntityType:  "EVIDENCE",
		EntityID:    eUUID,
		Payload:     payload,
		CreatedAt:   time.Now().UTC(),
	}

	return r.recorder.Record(ctx, evt)
}

// MemoryAuditRecorder provides an in-memory audit store for testing.
type MemoryAuditRecorder struct {
	mu     sync.RWMutex
	events []audit.Event
}

// NewMemoryAuditRecorder creates a new MemoryAuditRecorder.
func NewMemoryAuditRecorder() *MemoryAuditRecorder {
	return &MemoryAuditRecorder{
		events: make([]audit.Event, 0),
	}
}

// Record appends an audit event to memory.
func (m *MemoryAuditRecorder) Record(_ context.Context, evt audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, evt)
	return nil
}

// GetEvents returns all captured audit events.
func (m *MemoryAuditRecorder) GetEvents() []audit.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]audit.Event, len(m.events))
	copy(copied, m.events)
	return copied
}

// FindByEvidenceID filters recorded events by entity ID.
func (m *MemoryAuditRecorder) FindByEvidenceID(evidenceID string) []audit.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matched []audit.Event
	for _, e := range m.events {
		if e.EntityID != nil && e.EntityID.String() == evidenceID {
			matched = append(matched, e)
		}
	}
	return matched
}
