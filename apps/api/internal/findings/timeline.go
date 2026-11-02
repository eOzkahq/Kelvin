package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/redaction"
)

// Timeline event type constants
const (
	TimelineEventFindingCreated      = "FINDING_CREATED"
	TimelineEventObservationRecorded = "OBSERVATION_RECORDED"
	TimelineEventStatusTransitioned  = "STATUS_TRANSITIONED"
	TimelineEventSeverityChanged     = "SEVERITY_CHANGED"
	TimelineEventFalsePositiveMarked = "FALSE_POSITIVE_MARKED"
	TimelineEventAcceptedRiskMarked  = "ACCEPTED_RISK_MARKED"
	TimelineEventRemediationUpdated  = "REMEDIATION_UPDATED"
	TimelineEventEvidenceAdded       = "EVIDENCE_ADDED"
	TimelineEventEvidenceRemoved     = "EVIDENCE_REMOVED"
	TimelineEventFalsePositiveReopened = "FALSE_POSITIVE_REOPENED"
	TimelineEventFalsePositiveReviewFlagged = "FALSE_POSITIVE_REVIEW_FLAGGED"
	TimelineEventSuppressionCreated = "SUPPRESSION_CREATED"
	TimelineEventSuppressionRevoked = "SUPPRESSION_REVOKED"
	TimelineEventSuppressionExpired = "SUPPRESSION_EXPIRED"
	TimelineEventBulkTriageApplied = "BULK_TRIAGE_APPLIED"
)

var (
	// ErrEventTypeRequired indicates an event was submitted without an event_type.
	ErrEventTypeRequired = errors.New("findings: event_type is required")
)

// TimelineEntry represents an immutable chronological event in a finding's activity history.
type TimelineEntry struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	FindingID     uuid.UUID      `json:"finding_id"`
	ActorID       *uuid.UUID     `json:"actor_id,omitempty"`
	EventType     string         `json:"event_type"`
	Payload       map[string]any `json:"payload"`
	CorrelationID uuid.UUID      `json:"correlation_id"`
	CreatedAt     time.Time      `json:"created_at"`
}

// SanitizePayload recursively redacts sensitive strings within the timeline payload.
func SanitizePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	redactor := redaction.NewDefaultRedactor()
	sanitized := make(map[string]any, len(payload))
	for k, v := range payload {
		sanitized[k] = sanitizeValue(v, redactor)
	}
	return sanitized
}

func sanitizeValue(v any, r *redaction.Redactor) any {
	switch val := v.(type) {
	case string:
		return r.RedactString(val)
	case map[string]any:
		res := make(map[string]any, len(val))
		for k, child := range val {
			// Proactively redact known sensitive keys
			lowerKey := strings.ToLower(k)
			if strings.Contains(lowerKey, "password") ||
				strings.Contains(lowerKey, "token") ||
				strings.Contains(lowerKey, "secret") ||
				strings.Contains(lowerKey, "cookie") ||
				strings.Contains(lowerKey, "authorization") {
				res[k] = "[REDACTED]"
			} else {
				res[k] = sanitizeValue(child, r)
			}
		}
		return res
	case []any:
		res := make([]any, len(val))
		for i, child := range val {
			res[i] = sanitizeValue(child, r)
		}
		return res
	default:
		return val
	}
}

// RecordTimelineEvent inserts an immutable event record into the timeline.
func (r *PostgresFindingRepository) RecordTimelineEvent(ctx context.Context, entry *TimelineEntry) error {
	if entry == nil {
		return errors.New("findings: timeline entry cannot be nil")
	}
	if entry.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if entry.FindingID == uuid.Nil {
		return ErrFindingIDRequired
	}
	if strings.TrimSpace(entry.EventType) == "" {
		return ErrEventTypeRequired
	}

	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	sanitizedPayload := SanitizePayload(entry.Payload)
	payloadBytes, err := json.Marshal(sanitizedPayload)
	if err != nil {
		return fmt.Errorf("findings: marshal timeline payload: %w", err)
	}

	const query = `
		INSERT INTO finding_activity_timeline (
			id, tenant_id, finding_id, actor_id, event_type, payload, correlation_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	`

	_, err = r.db.Exec(ctx, query,
		entry.ID,
		entry.TenantID,
		entry.FindingID,
		entry.ActorID,
		entry.EventType,
		payloadBytes,
		entry.CorrelationID,
		entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: record timeline event failed: %w", err)
	}

	return nil
}

// GetTimelineByFinding retrieves the chronological activity timeline for a finding within tenant boundaries.
func (r *PostgresFindingRepository) GetTimelineByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	limit, offset int,
) ([]*TimelineEntry, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	// Verify finding ownership / anti-IDOR
	_, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	const query = `
		SELECT
			id, tenant_id, finding_id, actor_id, event_type, payload, correlation_id, created_at
		FROM finding_activity_timeline
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4;
	`

	rows, err := r.db.Query(ctx, query, tenantID, findingID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("findings: query timeline failed: %w", err)
	}
	defer rows.Close()

	var entries []*TimelineEntry
	for rows.Next() {
		var entry TimelineEntry
		var payloadBytes []byte
		if err := rows.Scan(
			&entry.ID,
			&entry.TenantID,
			&entry.FindingID,
			&entry.ActorID,
			&entry.EventType,
			&payloadBytes,
			&entry.CorrelationID,
			&entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan timeline row: %w", err)
		}

		if len(payloadBytes) > 0 {
			if err := json.Unmarshal(payloadBytes, &entry.Payload); err != nil {
				entry.Payload = map[string]any{}
			}
		} else {
			entry.Payload = map[string]any{}
		}

		entries = append(entries, &entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: iterate timeline rows: %w", err)
	}

	if entries == nil {
		entries = []*TimelineEntry{}
	}

	return entries, nil
}
