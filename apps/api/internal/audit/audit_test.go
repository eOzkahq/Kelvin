package audit

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

func TestService_Record_MockDB(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}
	defer db.Close()

	service := NewService(db, zap.NewNop())

	tenantID := uuid.New()
	userID := uuid.New()
	targetID := uuid.New()

	evt := Event{
		TenantID:    &tenantID,
		ActorUserID: &userID,
		ActorType:   ActorUser,
		Action:      "scan.create",
		EntityType:  "assessment",
		EntityID:    &targetID,
		Payload:     json.RawMessage(`{"target":"192.168.1.100","profile":"full_scan"}`),
	}

	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL ROLE kelvin_audit_writer").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('app.tenant_id', $1, true)")).WithArgs(tenantID.String()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_log").
		WithArgs(
			sqlmock.AnyArg(), // id
			tenantID,
			userID,
			"USER",
			"scan.create",
			"assessment",
			targetID,
			[]byte(evt.Payload),
			sqlmock.AnyArg(), // correlation_id
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	ctx, err := tenant.WithID(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectCommit()
	if err := service.Record(ctx, evt); err != nil {
		t.Fatalf("expected successful audit insertion, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestServiceRejectsTenantMismatchBeforeWriting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, zap.NewNop())
	contextID, eventID := uuid.New(), uuid.New()
	ctx, err := tenant.WithID(context.Background(), contextID)
	if err != nil {
		t.Fatal(err)
	}
	err = service.Record(ctx, Event{TenantID: &eventID, ActorType: ActorUser, Action: "finding.read", EntityType: "finding"})
	if err == nil {
		t.Fatal("cross-tenant audit event accepted")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestService_Record_Validation(t *testing.T) {
	service := NewService(nil, zap.NewNop())
	ctx := context.Background()

	// Missing action
	err := service.Record(ctx, Event{EntityType: "finding"})
	if err == nil {
		t.Fatal("expected error on missing action, got nil")
	}

	// Missing entity_type
	err = service.Record(ctx, Event{Action: "finding.create"})
	if err == nil {
		t.Fatal("expected error on missing entity_type, got nil")
	}

	// Valid in-memory fallback
	err = service.Record(ctx, Event{
		Action:     "report.export",
		EntityType: "report",
		CreatedAt:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("expected successful in-memory record, got: %v", err)
	}
}
