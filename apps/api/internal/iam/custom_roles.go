package iam

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrCustomRoleNotFound          = errors.New("custom role not found")
	ErrCustomRoleArchived          = errors.New("custom role is archived: modifications or assignments prohibited")
	ErrBuiltInRoleImmutable        = errors.New("built-in system roles cannot be modified or deleted")
	ErrForbiddenCustomPermission    = errors.New("custom role contains forbidden root/platform-only permission")
	ErrDuplicateRoleSlug           = errors.New("role with this slug already exists in organization")
)

const (
	ActionCustomRoleCreated  = "custom_role.created"
	ActionCustomRoleUpdated  = "custom_role.updated"
	ActionCustomRoleArchived = "custom_role.archived"
)

// CustomRole represents an enterprise-defined RBAC role tailored to specific team personas.
type CustomRole struct {
	ID             uuid.UUID    `json:"id"`
	OrganizationID uuid.UUID    `json:"organization_id"`
	Name           string       `json:"name"`
	Slug           string       `json:"slug"`
	Description    string       `json:"description"`
	Scope          ScopeLevel   `json:"scope"`
	Permissions    []Permission `json:"permissions"`
	Version        int          `json:"version"`
	Status         string       `json:"status"` // ACTIVE, ARCHIVED
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// forbiddenCustomPermissions lists actions strictly reserved for built-in root roles.
var forbiddenCustomPermissions = map[Permission]bool{
	PermissionOrgBillingManage: true,
	PermissionOrgSSOManage:     true,
	PermissionEvidencePurge:    true,
}

// CustomRoleRepository defines storage operations for custom enterprise roles.
type CustomRoleRepository interface {
	SaveCustomRole(ctx context.Context, role *CustomRole) error
	GetCustomRole(ctx context.Context, id uuid.UUID) (*CustomRole, error)
	GetCustomRoleBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*CustomRole, error)
	UpdateCustomRole(ctx context.Context, role *CustomRole) error
	ListCustomRoles(ctx context.Context, orgID uuid.UUID) ([]*CustomRole, error)
}

// MemoryCustomRoleRepository provides an in-memory thread-safe implementation of CustomRoleRepository.
type MemoryCustomRoleRepository struct {
	mu    sync.RWMutex
	roles map[uuid.UUID]*CustomRole
}

func NewMemoryCustomRoleRepository() *MemoryCustomRoleRepository {
	return &MemoryCustomRoleRepository{
		roles: make(map[uuid.UUID]*CustomRole),
	}
}

func (m *MemoryCustomRoleRepository) SaveCustomRole(ctx context.Context, role *CustomRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roles[role.ID] = role
	return nil
}

func (m *MemoryCustomRoleRepository) GetCustomRole(ctx context.Context, id uuid.UUID) (*CustomRole, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.roles[id]
	if !ok {
		return nil, ErrCustomRoleNotFound
	}
	return r, nil
}

func (m *MemoryCustomRoleRepository) GetCustomRoleBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*CustomRole, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.roles {
		if r.OrganizationID == orgID && r.Slug == slug {
			return r, nil
		}
	}
	return nil, ErrCustomRoleNotFound
}

func (m *MemoryCustomRoleRepository) UpdateCustomRole(ctx context.Context, role *CustomRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[role.ID]; !ok {
		return ErrCustomRoleNotFound
	}
	m.roles[role.ID] = role
	return nil
}

func (m *MemoryCustomRoleRepository) ListCustomRoles(ctx context.Context, orgID uuid.UUID) ([]*CustomRole, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*CustomRole
	for _, r := range m.roles {
		if r.OrganizationID == orgID {
			result = append(result, r)
		}
	}
	return result, nil
}

// CustomRoleService manages custom role creation, escalation defense, and resolution.
type CustomRoleService struct {
	repo  CustomRoleRepository
	audit audit.Recorder
}

func NewCustomRoleService(repo CustomRoleRepository, audit audit.Recorder) *CustomRoleService {
	return &CustomRoleService{
		repo:  repo,
		audit: audit,
	}
}

// ValidateCustomRolePermissions ensures all permissions exist in the catalog and prevents root privilege escalation.
func ValidateCustomRolePermissions(perms []Permission) error {
	if len(perms) == 0 {
		return fmt.Errorf("%w: role must contain at least one permission", ErrPermissionDenied)
	}

	for _, p := range perms {
		if err := ValidatePermission(p); err != nil {
			return err
		}
		if forbiddenCustomPermissions[p] {
			return fmt.Errorf("%w: %q cannot be assigned to custom roles", ErrForbiddenCustomPermission, p)
		}
	}
	return nil
}

// CreateCustomRole provisions an enterprise custom role.
func (s *CustomRoleService) CreateCustomRole(
	ctx context.Context,
	orgID uuid.UUID,
	actorUserID string,
	name string,
	slug string,
	description string,
	scope ScopeLevel,
	permissions []Permission,
) (*CustomRole, error) {
	// Validate permissions
	if err := ValidateCustomRolePermissions(permissions); err != nil {
		return nil, err
	}

	// Check slug collision with built-in roles
	if _, ok := builtInRoles[RoleName(slug)]; ok {
		return nil, ErrBuiltInRoleImmutable
	}

	// Check slug collision within org
	if _, err := s.repo.GetCustomRoleBySlug(ctx, orgID, slug); err == nil {
		return nil, ErrDuplicateRoleSlug
	}

	now := time.Now().UTC()
	role := &CustomRole{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Name:           name,
		Slug:           slug,
		Description:    description,
		Scope:          scope,
		Permissions:    permissions,
		Version:        1,
		Status:         "ACTIVE",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.SaveCustomRole(ctx, role); err != nil {
		return nil, err
	}

	if s.audit != nil {
		_ = s.recordAuditEvent(ctx, ActionCustomRoleCreated, role.ID, orgID, actorUserID)
	}

	return role, nil
}

// UpdateCustomRole modifies an existing custom role and increments its version.
func (s *CustomRoleService) UpdateCustomRole(
	ctx context.Context,
	roleID uuid.UUID,
	actorUserID string,
	name string,
	description string,
	permissions []Permission,
) (*CustomRole, error) {
	role, err := s.repo.GetCustomRole(ctx, roleID)
	if err != nil {
		return nil, err
	}

	if role.Status == "ARCHIVED" {
		return nil, ErrCustomRoleArchived
	}

	if err := ValidateCustomRolePermissions(permissions); err != nil {
		return nil, err
	}

	role.Name = name
	role.Description = description
	role.Permissions = permissions
	role.Version++
	role.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateCustomRole(ctx, role); err != nil {
		return nil, err
	}

	if s.audit != nil {
		_ = s.recordAuditEvent(ctx, ActionCustomRoleUpdated, role.ID, role.OrganizationID, actorUserID)
	}

	return role, nil
}

// ArchiveCustomRole soft-archives a custom role.
func (s *CustomRoleService) ArchiveCustomRole(ctx context.Context, roleID uuid.UUID, actorUserID string) error {
	role, err := s.repo.GetCustomRole(ctx, roleID)
	if err != nil {
		return err
	}

	role.Status = "ARCHIVED"
	role.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateCustomRole(ctx, role); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.recordAuditEvent(ctx, ActionCustomRoleArchived, role.ID, role.OrganizationID, actorUserID)
	}

	return nil
}

// ResolveCustomRolePermissions resolves effective permissions granted by a list of custom roles.
func (s *CustomRoleService) ResolveCustomRolePermissions(ctx context.Context, roleIDs []uuid.UUID) (map[Permission]bool, error) {
	effective := make(map[Permission]bool)
	for _, id := range roleIDs {
		role, err := s.repo.GetCustomRole(ctx, id)
		if err != nil {
			return nil, err
		}
		if role.Status != "ACTIVE" {
			continue // Skip archived roles
		}
		for _, p := range role.Permissions {
			effective[p] = true
		}
	}
	return effective, nil
}

func (s *CustomRoleService) recordAuditEvent(ctx context.Context, action string, roleID uuid.UUID, orgID uuid.UUID, actorUserID string) error {
	var actorUUID *uuid.UUID
	if u, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &u
	}
	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    &orgID,
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "custom_role",
		EntityID:    &roleID,
		CreatedAt:   time.Now().UTC(),
	}
	return s.audit.Record(ctx, evt)
}
