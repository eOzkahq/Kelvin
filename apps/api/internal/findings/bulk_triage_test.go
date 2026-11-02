package findings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateBulkTriageRequest(t *testing.T) {
	findingID := uuid.New()
	future := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name    string
		req     *BulkTriageRequest
		wantErr error
	}{
		{
			name: "valid transition request",
			req: &BulkTriageRequest{
				FindingIDs:   []uuid.UUID{findingID},
				Action:       BulkActionTransition,
				TargetStatus: StatusConfirmed,
				Reason:       "Confirmed in audit",
			},
			wantErr: nil,
		},
		{
			name: "valid suppression request",
			req: &BulkTriageRequest{
				FindingIDs: []uuid.UUID{findingID},
				Action:     BulkActionSuppress,
				Reason:     "Maintenance",
				ExpiresAt:  &future,
			},
			wantErr: nil,
		},
		{
			name: "empty finding ids",
			req: &BulkTriageRequest{
				FindingIDs:   []uuid.UUID{},
				Action:       BulkActionTransition,
				TargetStatus: StatusConfirmed,
			},
			wantErr: ErrBulkBatchEmpty,
		},
		{
			name: "exceeds maximum batch size (> 100)",
			req: func() *BulkTriageRequest {
				ids := make([]uuid.UUID, 101)
				for i := range ids {
					ids[i] = uuid.New()
				}
				return &BulkTriageRequest{
					FindingIDs:   ids,
					Action:       BulkActionTransition,
					TargetStatus: StatusConfirmed,
				}
			}(),
			wantErr: ErrBulkBatchLimitExceeded,
		},
		{
			name: "invalid bulk action",
			req: &BulkTriageRequest{
				FindingIDs: []uuid.UUID{findingID},
				Action:     "INVALID_ACTION",
			},
			wantErr: ErrInvalidBulkAction,
		},
		{
			name: "sensitive transition missing reason",
			req: &BulkTriageRequest{
				FindingIDs:   []uuid.UUID{findingID},
				Action:       BulkActionTransition,
				TargetStatus: StatusFalsePositive,
				Reason:       "",
			},
			wantErr: ErrBulkReasonRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBulkTriageRequest(tt.req)
			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExecuteBulkTriageValidation(t *testing.T) {
	repo := NewPostgresFindingRepository(nil)
	ctx := context.Background()

	_, err := repo.ExecuteBulkTriage(ctx, uuid.Nil, &BulkTriageRequest{
		FindingIDs: []uuid.UUID{uuid.New()},
		Action:     BulkActionTransition,
	}, uuid.New())

	if !errors.Is(err, ErrTenantRequired) {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}
}
