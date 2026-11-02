package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// MaxBulkBatchSize defines the strict upper bound on findings per bulk request.
	MaxBulkBatchSize = 100

	BulkActionTransition = "TRANSITION"
	BulkActionSuppress   = "SUPPRESS"
)

var (
	ErrBulkBatchEmpty         = errors.New("findings: bulk operation requires at least 1 finding ID")
	ErrBulkBatchLimitExceeded = errors.New("findings: bulk batch size exceeds limit of 100 items")
	ErrInvalidBulkAction      = errors.New("findings: invalid bulk action; must be TRANSITION or SUPPRESS")
	ErrBulkReasonRequired     = errors.New("findings: reason is required for sensitive bulk operations")
)

// BulkTriageRequest encapsulates a batch operation across multiple findings.
type BulkTriageRequest struct {
	FindingIDs   []uuid.UUID   `json:"finding_ids"`
	Action       string        `json:"action"` // TRANSITION, SUPPRESS
	TargetStatus FindingStatus `json:"target_status,omitempty"`
	Reason       string        `json:"reason,omitempty"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty"`
	ActorID      *uuid.UUID    `json:"actor_id,omitempty"`
}

// BulkTriageItemFailure describes an individual finding failure within a bulk operation.
type BulkTriageItemFailure struct {
	FindingID uuid.UUID `json:"finding_id"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
}

// BulkTriageResult encapsulates the aggregated multi-status outcome of a bulk triage request.
type BulkTriageResult struct {
	BatchID        uuid.UUID               `json:"batch_id"`
	Action         string                  `json:"action"`
	Total          int                     `json:"total"`
	SucceededCount int                     `json:"succeeded_count"`
	FailedCount    int                     `json:"failed_count"`
	Succeeded      []uuid.UUID             `json:"succeeded"`
	Failed         []BulkTriageItemFailure `json:"failed"`
}

// ValidateBulkTriageRequest enforces batch size constraints and required operation parameters.
func ValidateBulkTriageRequest(req *BulkTriageRequest) error {
	if req == nil {
		return errors.New("findings: bulk triage request cannot be nil")
	}
	if len(req.FindingIDs) == 0 {
		return ErrBulkBatchEmpty
	}
	if len(req.FindingIDs) > MaxBulkBatchSize {
		return ErrBulkBatchLimitExceeded
	}

	normAction := strings.ToUpper(strings.TrimSpace(req.Action))
	switch normAction {
	case BulkActionTransition:
		if strings.TrimSpace(string(req.TargetStatus)) == "" {
			return ErrTargetStatusRequired
		}
		targetStatus := CanonicalStatus(req.TargetStatus)
		if targetStatus == StatusFalsePositive || targetStatus == StatusAcceptedRisk {
			if strings.TrimSpace(req.Reason) == "" {
				return ErrBulkReasonRequired
			}
		}
	case BulkActionSuppress:
		if strings.TrimSpace(req.Reason) == "" {
			return ErrSuppressionReasonRequired
		}
		if req.ExpiresAt == nil || !req.ExpiresAt.After(time.Now().UTC()) {
			return ErrSuppressionExpiryRequired
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidBulkAction, req.Action)
	}

	return nil
}

// ExecuteBulkTriage processes a bounded batch of findings with independent transactional validation.
func (r *PostgresFindingRepository) ExecuteBulkTriage(
	ctx context.Context,
	tenantID uuid.UUID,
	req *BulkTriageRequest,
	corrID uuid.UUID,
) (*BulkTriageResult, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if err := ValidateBulkTriageRequest(req); err != nil {
		return nil, err
	}

	batchID := uuid.New()
	normAction := strings.ToUpper(strings.TrimSpace(req.Action))

	result := &BulkTriageResult{
		BatchID:        batchID,
		Action:         normAction,
		Total:          len(req.FindingIDs),
		SucceededCount: 0,
		FailedCount:    0,
		Succeeded:      make([]uuid.UUID, 0, len(req.FindingIDs)),
		Failed:         make([]BulkTriageItemFailure, 0),
	}

	for _, findingID := range req.FindingIDs {
		var itemErr error

		switch normAction {
		case BulkActionTransition:
			_, _, itemErr = r.UpdateFindingStatus(
				ctx,
				tenantID,
				findingID,
				req.TargetStatus,
				req.ActorID,
				req.Reason,
				corrID,
			)

		case BulkActionSuppress:
			_, itemErr = r.CreateSuppressionRule(
				ctx,
				tenantID,
				findingID,
				req.ActorID,
				req.Reason,
				*req.ExpiresAt,
				corrID,
			)
		}

		if itemErr != nil {
			var code string
			switch {
			case errors.Is(itemErr, ErrFindingNotFound):
				code = "not_found"
			case errors.Is(itemErr, ErrIllegalTransition):
				code = "illegal_transition"
			case errors.Is(itemErr, ErrSuppressionAlreadyActive):
				code = "already_suppressed"
			default:
				code = "operation_failed"
			}

			result.Failed = append(result.Failed, BulkTriageItemFailure{
				FindingID: findingID,
				Code:      code,
				Message:   itemErr.Error(),
			})
			result.FailedCount++
		} else {
			// Record bulk timeline event for auditability per item
			_ = r.RecordTimelineEvent(ctx, &TimelineEntry{
				ID:        uuid.New(),
				TenantID:  tenantID,
				FindingID: findingID,
				ActorID:   req.ActorID,
				EventType: TimelineEventBulkTriageApplied,
				Payload: map[string]any{
					"batch_id": batchID.String(),
					"action":   normAction,
					"reason":   req.Reason,
				},
				CorrelationID: corrID,
				CreatedAt:     time.Now().UTC(),
			})

			result.Succeeded = append(result.Succeeded, findingID)
			result.SucceededCount++
		}
	}

	return result, nil
}
