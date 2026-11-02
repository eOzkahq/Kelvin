package findings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateSuppressionRule(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	tests := []struct {
		name    string
		rule    *SuppressionRule
		wantErr error
	}{
		{
			name: "valid suppression rule",
			rule: &SuppressionRule{
				ID:        uuid.New(),
				TenantID:  tenantID,
				FindingID: findingID,
				Reason:    "Internal dev environment; non-production testing target.",
				Status:    SuppressionActive,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: nil,
		},
		{
			name: "missing reason",
			rule: &SuppressionRule{
				ID:        uuid.New(),
				TenantID:  tenantID,
				FindingID: findingID,
				Reason:    "   ",
				Status:    SuppressionActive,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: ErrSuppressionReasonRequired,
		},
		{
			name: "past expiry date",
			rule: &SuppressionRule{
				ID:        uuid.New(),
				TenantID:  tenantID,
				FindingID: findingID,
				Reason:    "Temporary exclusion",
				Status:    SuppressionActive,
				ExpiresAt: past,
				CreatedAt: now,
			},
			wantErr: ErrSuppressionExpiryRequired,
		},
		{
			name: "zero expiry date",
			rule: &SuppressionRule{
				ID:        uuid.New(),
				TenantID:  tenantID,
				FindingID: findingID,
				Reason:    "Temporary exclusion",
				Status:    SuppressionActive,
				ExpiresAt: time.Time{},
				CreatedAt: now,
			},
			wantErr: ErrSuppressionExpiryRequired,
		},
		{
			name: "missing tenant",
			rule: &SuppressionRule{
				ID:        uuid.New(),
				TenantID:  uuid.Nil,
				FindingID: findingID,
				Reason:    "Temporary exclusion",
				ExpiresAt: future,
			},
			wantErr: ErrTenantRequired,
		},
		{
			name: "missing finding",
			rule: &SuppressionRule{
				ID:        uuid.New(),
				TenantID:  tenantID,
				FindingID: uuid.Nil,
				Reason:    "Temporary exclusion",
				ExpiresAt: future,
			},
			wantErr: ErrFindingIDRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSuppressionRule(tt.rule, now)
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

func TestSuppressionRuleIsActive(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	activeFuture := &SuppressionRule{
		Status:    SuppressionActive,
		ExpiresAt: future,
	}
	if !activeFuture.IsActive(now) {
		t.Errorf("expected activeFuture to be active")
	}

	activePast := &SuppressionRule{
		Status:    SuppressionActive,
		ExpiresAt: past,
	}
	if activePast.IsActive(now) {
		t.Errorf("expected activePast to be inactive")
	}

	revokedFuture := &SuppressionRule{
		Status:    SuppressionRevoked,
		ExpiresAt: future,
	}
	if revokedFuture.IsActive(now) {
		t.Errorf("expected revoked rule to be inactive")
	}
}

func TestSuppressionRepositoryValidation(t *testing.T) {
	repo := NewPostgresFindingRepository(nil)
	ctx := context.Background()

	// Missing tenant
	_, err := repo.CreateSuppressionRule(ctx, uuid.Nil, uuid.New(), nil, "reason", time.Now().Add(time.Hour), uuid.New())
	if !errors.Is(err, ErrTenantRequired) {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing finding
	_, err = repo.CreateSuppressionRule(ctx, uuid.New(), uuid.Nil, nil, "reason", time.Now().Add(time.Hour), uuid.New())
	if !errors.Is(err, ErrFindingIDRequired) {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}

	// Revocation missing reason
	_, err = repo.RevokeSuppressionRule(ctx, uuid.New(), uuid.New(), nil, "", uuid.New())
	if !errors.Is(err, ErrRevocationReasonRequired) {
		t.Errorf("expected ErrRevocationReasonRequired, got %v", err)
	}
}
