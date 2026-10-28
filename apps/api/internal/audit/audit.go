// Package audit provides the immutable, append-only security audit logging service
// for recording compliance and security events in PostgreSQL (ADR-0002 / T-05).
// In accordance with ADR-0002, the application role possesses INSERT-only permissions;
// no UPDATE or DELETE privileges exist on the audit_log table.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/logging"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

// ActorType identifies the source category of an audited action.
type ActorType string

const (
	ActorUser    ActorType = "USER"
	ActorService ActorType = "SERVICE"
	ActorWorker  ActorType = "WORKER"
	ActorSystem  ActorType = "SYSTEM"
)

// Event represents an immutable audit entry matching DATA_MODEL.md §5.12.
type Event struct {
	ID            uuid.UUID       `json:"id"`
	TenantID      *uuid.UUID      `json:"tenant_id,omitempty"`
	ActorUserID   *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorType     ActorType       `json:"actor_type"`
	Action        string          `json:"action"`
	EntityType    string          `json:"entity_type"`
	EntityID      *uuid.UUID      `json:"entity_id,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	CorrelationID string          `json:"correlation_id"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Recorder defines the contract for recording audit events.
type Recorder interface {
	Record(ctx context.Context, evt Event) error
}

// Service records audit events into PostgreSQL.
type Service struct {
	db  *sql.DB
	log *zap.Logger
}

// NewService creates a new audit Service.
func NewService(db *sql.DB, log *zap.Logger) *Service {
	return &Service{
		db:  db,
		log: log,
	}
}

// Record persists an immutable audit event into the PostgreSQL audit_log table.
func (s *Service) Record(ctx context.Context, evt Event) error {
	if evt.Action == "" {
		return errors.New("audit: action must not be empty")
	}
	if evt.EntityType == "" {
		return errors.New("audit: entity_type must not be empty")
	}
	if evt.ActorType == "" {
		evt.ActorType = ActorSystem
	}
	contextTenant, tenantErr := tenant.ID(ctx)
	if tenantErr == nil {
		if evt.TenantID != nil && *evt.TenantID != contextTenant {
			return errors.New("audit: event tenant does not match authenticated tenant context")
		}
		if evt.TenantID == nil {
			evt.TenantID = &contextTenant
		}
	} else if evt.TenantID != nil || evt.ActorType == ActorUser || evt.ActorType == ActorWorker {
		return errors.New("audit: tenant context required for tenant-owned event")
	}
	if evt.ID == uuid.Nil {
		evt.ID = uuid.New()
	}
	if evt.CreatedAt.IsZero() {
		evt.CreatedAt = time.Now().UTC()
	}
	if evt.CorrelationID == "" {
		evt.CorrelationID = logging.CorrelationFromContext(ctx)
		if evt.CorrelationID == "" {
			evt.CorrelationID = uuid.New().String()
		}
	}
	if len(evt.Payload) == 0 {
		evt.Payload = json.RawMessage("{}")
	}

	// If no DB pool is provided (e.g. testing/dry-run), log structured audit event
	if s.db == nil {
		s.log.Info("audit event recorded (in-memory/mock)",
			zap.String("audit_id", evt.ID.String()),
			zap.String("action", evt.Action),
			zap.String("entity_type", evt.EntityType),
			zap.String("actor_type", string(evt.ActorType)),
			zap.String("correlation_id", evt.CorrelationID),
		)
		return nil
	}

	query := `
		INSERT INTO audit_log (
			id,
			tenant_id,
			actor_user_id,
			actor_type,
			action,
			entity_type,
			entity_id,
			payload,
			correlation_id,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE kelvin_audit_writer"); err != nil {
		return fmt.Errorf("audit: assume append-only writer role: %w", err)
	}
	tenantValue := ""
	if evt.TenantID != nil {
		tenantValue = evt.TenantID.String()
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantValue); err != nil {
		return fmt.Errorf("audit: set tenant context: %w", err)
	}
	_, err = tx.ExecContext(
		ctx,
		query,
		evt.ID,
		evt.TenantID,
		evt.ActorUserID,
		string(evt.ActorType),
		evt.Action,
		evt.EntityType,
		evt.EntityID,
		[]byte(evt.Payload),
		evt.CorrelationID,
		evt.CreatedAt,
	)
	if err != nil {
		s.log.Error("failed to record audit event to database",
			zap.Error(err),
			zap.String("action", evt.Action),
			zap.String("correlation_id", evt.CorrelationID),
		)
		return fmt.Errorf("audit: failed to insert audit record: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit event: %w", err)
	}
	return nil
}
