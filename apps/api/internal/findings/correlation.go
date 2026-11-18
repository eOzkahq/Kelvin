package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CorrelationType represents the classification basis of a finding correlation group.
type CorrelationType string

const (
	CorrelationSharedVulnClass CorrelationType = "SHARED_VULNERABILITY_CLASS"
	CorrelationSameTarget      CorrelationType = "SAME_TARGET_CLUSTER"
	CorrelationCommonID        CorrelationType = "COMMON_IDENTIFIER"
	CorrelationAnalystCurated  CorrelationType = "ANALYST_CURATED"
)

var (
	ErrGroupNotFound          = errors.New("findings: correlation group not found")
	ErrGroupIDRequired        = errors.New("findings: correlation group_id is required")
	ErrGroupNameRequired      = errors.New("findings: correlation group name is required")
	ErrInvalidCorrelationType = errors.New("findings: invalid correlation group type")
	ErrFindingAlreadyInGroup  = errors.New("findings: finding is already a member of this correlation group")
	ErrMemberNotFound         = errors.New("findings: correlation group membership not found")
)

var validCorrelationTypes = map[CorrelationType]bool{
	CorrelationSharedVulnClass: true,
	CorrelationSameTarget:      true,
	CorrelationCommonID:        true,
	CorrelationAnalystCurated:  true,
}

// CorrelationGroup models a logical clustering of related findings without collapsing identities.
type CorrelationGroup struct {
	ID              uuid.UUID       `json:"id"`
	TenantID        uuid.UUID       `json:"tenant_id"`
	Name            string          `json:"name"`
	CorrelationType CorrelationType `json:"correlation_type"`
	Description     string          `json:"description,omitempty"`
	RulePattern     string          `json:"rule_pattern,omitempty"`
	Metadata        map[string]any  `json:"metadata"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// CorrelationGroupMember records membership of a persistent finding in a correlation group.
type CorrelationGroupMember struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	GroupID   uuid.UUID  `json:"group_id"`
	FindingID uuid.UUID  `json:"finding_id"`
	AddedBy   *uuid.UUID `json:"added_by,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// CorrelationRepository defines persistence operations for finding correlation groups.
type CorrelationRepository interface {
	CreateCorrelationGroup(ctx context.Context, group *CorrelationGroup) error
	GetCorrelationGroupByID(ctx context.Context, tenantID, groupID uuid.UUID) (*CorrelationGroup, error)
	AddFindingToGroup(ctx context.Context, member *CorrelationGroupMember) error
	RemoveFindingFromGroup(ctx context.Context, tenantID, groupID, findingID uuid.UUID) error
	GetGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID) ([]*CorrelationGroupMember, error)
	GetFindingGroups(ctx context.Context, tenantID, findingID uuid.UUID) ([]*CorrelationGroup, error)
}

// CreateCorrelationGroup persists a new correlation group within tenant boundaries.
func (r *PostgresFindingRepository) CreateCorrelationGroup(ctx context.Context, group *CorrelationGroup) error {
	if group == nil {
		return errors.New("findings: correlation group cannot be nil")
	}
	if group.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if strings.TrimSpace(group.Name) == "" {
		return ErrGroupNameRequired
	}
	if !validCorrelationTypes[group.CorrelationType] {
		return fmt.Errorf("%w: %q", ErrInvalidCorrelationType, group.CorrelationType)
	}

	if group.ID == uuid.Nil {
		group.ID = uuid.New()
	}
	now := time.Now().UTC()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}
	if group.Metadata == nil {
		group.Metadata = make(map[string]any)
	}

	metaBytes, err := json.Marshal(group.Metadata)
	if err != nil {
		return fmt.Errorf("findings: marshal group metadata: %w", err)
	}

	const query = `
		INSERT INTO finding_correlation_groups (
			id, tenant_id, name, correlation_type, description, rule_pattern, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	`

	_, err = r.db.Exec(ctx, query,
		group.ID,
		group.TenantID,
		group.Name,
		string(group.CorrelationType),
		group.Description,
		group.RulePattern,
		metaBytes,
		group.CreatedAt,
		group.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: insert correlation group failed: %w", err)
	}

	return nil
}

// GetCorrelationGroupByID retrieves a correlation group by ID enforcing tenant isolation.
func (r *PostgresFindingRepository) GetCorrelationGroupByID(ctx context.Context, tenantID, groupID uuid.UUID) (*CorrelationGroup, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if groupID == uuid.Nil {
		return nil, ErrGroupIDRequired
	}

	const query = `
		SELECT
			id, tenant_id, name, correlation_type, description, rule_pattern, metadata, created_at, updated_at
		FROM finding_correlation_groups
		WHERE tenant_id = $1 AND id = $2;
	`

	var group CorrelationGroup
	var cType string
	var metaBytes []byte

	err := r.db.QueryRow(ctx, query, tenantID, groupID).Scan(
		&group.ID,
		&group.TenantID,
		&group.Name,
		&cType,
		&group.Description,
		&group.RulePattern,
		&metaBytes,
		&group.CreatedAt,
		&group.UpdatedAt,
	)
	if err != nil {
		return nil, ErrGroupNotFound
	}

	group.CorrelationType = CorrelationType(cType)
	if len(metaBytes) > 0 {
		if err := json.Unmarshal(metaBytes, &group.Metadata); err != nil {
			group.Metadata = make(map[string]any)
		}
	} else {
		group.Metadata = make(map[string]any)
	}

	return &group, nil
}

// AddFindingToGroup associates a persistent finding with a correlation group.
func (r *PostgresFindingRepository) AddFindingToGroup(ctx context.Context, member *CorrelationGroupMember) error {
	if member == nil {
		return errors.New("findings: member cannot be nil")
	}
	if member.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if member.GroupID == uuid.Nil {
		return ErrGroupIDRequired
	}
	if member.FindingID == uuid.Nil {
		return ErrFindingIDRequired
	}

	// Verify group exists in tenant
	if _, err := r.GetCorrelationGroupByID(ctx, member.TenantID, member.GroupID); err != nil {
		return err
	}

	// Verify finding exists in tenant
	if _, err := r.GetFindingByID(ctx, member.TenantID, member.FindingID); err != nil {
		return err
	}

	if member.ID == uuid.Nil {
		member.ID = uuid.New()
	}
	if member.CreatedAt.IsZero() {
		member.CreatedAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO finding_correlation_group_members (
			id, tenant_id, group_id, finding_id, added_by, reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (group_id, finding_id) DO NOTHING;
	`

	tag, err := r.db.Exec(ctx, query,
		member.ID,
		member.TenantID,
		member.GroupID,
		member.FindingID,
		member.AddedBy,
		member.Reason,
		member.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: add finding to correlation group failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrFindingAlreadyInGroup
	}

	return nil
}

// RemoveFindingFromGroup disassociates a finding from a correlation group.
func (r *PostgresFindingRepository) RemoveFindingFromGroup(ctx context.Context, tenantID, groupID, findingID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if groupID == uuid.Nil {
		return ErrGroupIDRequired
	}
	if findingID == uuid.Nil {
		return ErrFindingIDRequired
	}

	const query = `
		DELETE FROM finding_correlation_group_members
		WHERE tenant_id = $1 AND group_id = $2 AND finding_id = $3;
	`

	tag, err := r.db.Exec(ctx, query, tenantID, groupID, findingID)
	if err != nil {
		return fmt.Errorf("findings: remove finding from group failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMemberNotFound
	}

	return nil
}

// GetGroupMembers retrieves all member finding references for a correlation group.
func (r *PostgresFindingRepository) GetGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID) ([]*CorrelationGroupMember, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if groupID == uuid.Nil {
		return nil, ErrGroupIDRequired
	}

	// Verify group existence / tenant isolation
	if _, err := r.GetCorrelationGroupByID(ctx, tenantID, groupID); err != nil {
		return nil, err
	}

	const query = `
		SELECT
			id, tenant_id, group_id, finding_id, added_by, reason, created_at
		FROM finding_correlation_group_members
		WHERE tenant_id = $1 AND group_id = $2
		ORDER BY created_at ASC;
	`

	rows, err := r.db.Query(ctx, query, tenantID, groupID)
	if err != nil {
		return nil, fmt.Errorf("findings: query group members failed: %w", err)
	}
	defer rows.Close()

	var members []*CorrelationGroupMember
	for rows.Next() {
		var m CorrelationGroupMember
		if err := rows.Scan(
			&m.ID,
			&m.TenantID,
			&m.GroupID,
			&m.FindingID,
			&m.AddedBy,
			&m.Reason,
			&m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan group member row: %w", err)
		}
		members = append(members, &m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: iterate group members failed: %w", err)
	}

	if members == nil {
		members = []*CorrelationGroupMember{}
	}

	return members, nil
}

// GetFindingGroups retrieves all correlation groups a finding belongs to.
func (r *PostgresFindingRepository) GetFindingGroups(ctx context.Context, tenantID, findingID uuid.UUID) ([]*CorrelationGroup, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	// Verify finding exists in tenant
	if _, err := r.GetFindingByID(ctx, tenantID, findingID); err != nil {
		return nil, err
	}

	const query = `
		SELECT
			g.id, g.tenant_id, g.name, g.correlation_type, g.description, g.rule_pattern, g.metadata, g.created_at, g.updated_at
		FROM finding_correlation_groups g
		JOIN finding_correlation_group_members m ON g.id = m.group_id AND g.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.finding_id = $2
		ORDER BY g.created_at DESC;
	`

	rows, err := r.db.Query(ctx, query, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("findings: query finding groups failed: %w", err)
	}
	defer rows.Close()

	var groups []*CorrelationGroup
	for rows.Next() {
		var g CorrelationGroup
		var cType string
		var metaBytes []byte

		if err := rows.Scan(
			&g.ID,
			&g.TenantID,
			&g.Name,
			&cType,
			&g.Description,
			&g.RulePattern,
			&metaBytes,
			&g.CreatedAt,
			&g.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan finding group row: %w", err)
		}

		g.CorrelationType = CorrelationType(cType)
		if len(metaBytes) > 0 {
			if err := json.Unmarshal(metaBytes, &g.Metadata); err != nil {
				g.Metadata = make(map[string]any)
			}
		} else {
			g.Metadata = make(map[string]any)
		}

		groups = append(groups, &g)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: iterate finding groups failed: %w", err)
	}

	if groups == nil {
		groups = []*CorrelationGroup{}
	}

	return groups, nil
}
