package findings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

func TestValidateFalsePositiveDecision(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	actorID := uuid.New()

	tests := []struct {
		name    string
		review  *FalsePositiveReview
		wantErr error
	}{
		{
			name: "valid false positive decision",
			review: &FalsePositiveReview{
				ID:            uuid.New(),
				TenantID:      tenantID,
				FindingID:     findingID,
				ActorID:       &actorID,
				Action:        ActionMarkedFalsePositive,
				Justification: "Parameter is protected by strict WAF regex rules; verified non-exploitable.",
				CreatedAt:     time.Now().UTC(),
			},
			wantErr: nil,
		},
		{
			name: "justification too short (< 20 chars)",
			review: &FalsePositiveReview{
				ID:            uuid.New(),
				TenantID:      tenantID,
				FindingID:     findingID,
				ActorID:       &actorID,
				Action:        ActionMarkedFalsePositive,
				Justification: "Not a bug.",
				CreatedAt:     time.Now().UTC(),
			},
			wantErr: ErrRationaleTooShort,
		},
		{
			name: "missing actor id",
			review: &FalsePositiveReview{
				ID:            uuid.New(),
				TenantID:      tenantID,
				FindingID:     findingID,
				ActorID:       nil,
				Action:        ActionMarkedFalsePositive,
				Justification: "Parameter is protected by strict WAF regex rules; verified non-exploitable.",
				CreatedAt:     time.Now().UTC(),
			},
			wantErr: ErrActorRequired,
		},
		{
			name: "invalid action",
			review: &FalsePositiveReview{
				ID:            uuid.New(),
				TenantID:      tenantID,
				FindingID:     findingID,
				ActorID:       &actorID,
				Action:        "INVALID_ACTION",
				Justification: "Parameter is protected by strict WAF regex rules; verified non-exploitable.",
				CreatedAt:     time.Now().UTC(),
			},
			wantErr: ErrInvalidAction,
		},
		{
			name: "nil review",
			review: nil,
			wantErr: errors.New("findings: false positive review cannot be nil"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFalsePositiveDecision(tt.review)
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

func TestDetectMaterialChange(t *testing.T) {
	prev := []normalization.Evidence{
		{
			Type:           "http_request_response",
			ChecksumSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	// Identical evidence
	currSame := []normalization.Evidence{
		{
			Type:           "http_request_response",
			ChecksumSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	if DetectMaterialChange(prev, currSame) {
		t.Errorf("expected no material change for identical evidence")
	}

	// Different payload/evidence checksum
	currDiff := []normalization.Evidence{
		{
			Type:           "http_request_response",
			ChecksumSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	if !DetectMaterialChange(prev, currDiff) {
		t.Errorf("expected material change when new checksum introduced")
	}

	// Empty previous evidence with new evidence
	if !DetectMaterialChange(nil, currDiff) {
		t.Errorf("expected material change when prior evidence was empty")
	}
}

func TestFalsePositiveRepositoryValidation(t *testing.T) {
	repo := NewPostgresFindingRepository(nil)
	ctx := context.Background()

	// Missing tenant
	_, err := repo.MarkFindingFalsePositive(ctx, uuid.Nil, uuid.New(), uuid.New(), "valid justification with >= 20 characters here", "", uuid.New())
	if !errors.Is(err, ErrTenantRequired) {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing finding
	_, err = repo.MarkFindingFalsePositive(ctx, uuid.New(), uuid.Nil, uuid.New(), "valid justification with >= 20 characters here", "", uuid.New())
	if !errors.Is(err, ErrFindingIDRequired) {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}

	// Reversal missing target status
	_, err = repo.ReverseFalsePositive(ctx, uuid.New(), uuid.New(), uuid.New(), "", "valid justification with >= 20 characters here", uuid.New())
	if !errors.Is(err, ErrTargetStatusRequired) {
		t.Errorf("expected ErrTargetStatusRequired, got %v", err)
	}
}
