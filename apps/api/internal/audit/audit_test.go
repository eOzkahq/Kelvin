package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
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

	ctx := context.Background()
	if err := service.Record(ctx, evt); err != nil {
		t.Fatalf("expected successful audit insertion, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
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

