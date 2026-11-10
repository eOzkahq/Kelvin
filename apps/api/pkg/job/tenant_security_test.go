package job

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

func TestTransitionForTenant_RequiresTenantID(t *testing.T) {
	store := Store{} // nil pool for validation checks
	err := store.TransitionForTenant(context.Background(), "", "job-123", Running, "worker-1")
	if err == nil {
		t.Fatal("expected error when tenant ID is empty, got nil")
	}
}

func TestSetDeadlineForTenant_RequiresTenantID(t *testing.T) {
	store := Store{}
	err := store.SetDeadlineForTenant(context.Background(), "", "job-123", 10*time.Minute)
	if err == nil {
		t.Fatal("expected error when tenant ID is empty, got nil")
	}
}

func TestRecordHeartbeatForTenant_RequiresTenantID(t *testing.T) {
	store := Store{}
	err := store.RecordHeartbeatForTenant(context.Background(), "", "job-123", "worker-1", 30*time.Second)
	if err == nil {
		t.Fatal("expected error when tenant ID is empty, got nil")
	}
}

func TestTenantContextIsolationExtraction(t *testing.T) {
	tenantID := uuid.New()
	ctx, err := tenant.WithID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("failed to create tenant context: %v", err)
	}

	extracted, err := tenant.ID(ctx)
	if err != nil {
		t.Fatalf("failed to extract tenant ID: %v", err)
	}
	if extracted != tenantID {
		t.Fatalf("expected tenant %s, got %s", tenantID, extracted)
	}
}
