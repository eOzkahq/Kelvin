package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUnauthorizedSubject     = errors.New("unauthorized: invalid or missing security subject")
	ErrResourceNotFound        = errors.New("resource not found") // Anti-IDOR safe error for foreign/non-existent objects
	ErrWorkspaceBoundaryDenied = errors.New("access denied: resource belongs to a different workspace")
	ErrTeamBoundaryDenied      = errors.New("access denied: resource is restricted to a team you are not a member of")
	ErrActionForbidden         = errors.New("forbidden: insufficient permissions for requested action")
)

// Subject represents the authenticated caller (user or service identity) performing an operation.
type Subject struct {
	UserID         string              `json:"user_id"`
	OrganizationID uuid.UUID           `json:"organization_id"`
	TenantID       uuid.UUID           `json:"tenant_id"`
	WorkspaceID    uuid.UUID           `json:"workspace_id"`
	Roles          []RoleName          `json:"roles"`
	Permissions    map[Permission]bool `json:"permissions"`
	TeamIDs        []uuid.UUID         `json:"team_ids"`
}

// ResourceDescriptor describes the tenancy and security metadata of a protected domain object.
type ResourceDescriptor struct {
	Type           string     `json:"type"` // e.g. "finding", "assessment", "evidence", "report", "target", "integration"
	ID             string     `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	WorkspaceID    uuid.UUID  `json:"workspace_id"`
	AssignedTeamID *uuid.UUID `json:"assigned_team_id,omitempty"`
}

// SharingResolver checks whether a cross-workspace or cross-team resource sharing grant exists.
type SharingResolver interface {
	HasActiveSharingGrant(
		ctx context.Context,
		orgID uuid.UUID,
		resourceType string,
		resourceID string,
		targetWorkspaceID uuid.UUID,
		targetTeamIDs []uuid.UUID,
	) bool
}

// BackgroundJobContext preserves the security context for asynchronous processing and worker tasks.
type BackgroundJobContext struct {
	JobID     string    `json:"job_id"`
	Initiator Subject   `json:"initiator"`
	CreatedAt time.Time `json:"created_at"`
}

// ObjectAuthorizer enforces centralized, defense-in-depth resource and object-level authorization.
type ObjectAuthorizer struct {
	sharing SharingResolver
}

// NewObjectAuthorizer instantiates an ObjectAuthorizer with an optional sharing resolver.
func NewObjectAuthorizer(sharing SharingResolver) *ObjectAuthorizer {
	return &ObjectAuthorizer{
		sharing: sharing,
	}
}

// Authorize performs comprehensive server-side checks before granting access to a protected object:
// 1. Subject validation (authenticated identity, tenant, org)
// 2. Multi-tenant boundary & Anti-IDOR check (prevents cross-tenant enumeration)
// 3. Workspace boundary check (org-level role override or active sharing grant)
// 4. Team restriction boundary check (team membership or administrative override)
// 5. Capability & action permission check (RBAC and custom role permissions)
func (a *ObjectAuthorizer) Authorize(
	ctx context.Context,
	subject Subject,
	resource ResourceDescriptor,
	action Permission,
) error {
	// 1. Subject Validation
	if subject.UserID == "" || subject.OrganizationID == uuid.Nil || subject.TenantID == uuid.Nil {
		return ErrUnauthorizedSubject
	}

	// 2. Multi-Tenant Boundary & Anti-IDOR Defense
	// If resource belongs to a foreign organization or tenant, return ErrResourceNotFound
	// to prevent attackers from probing the existence of direct object identifiers across tenants.
	if resource.OrganizationID != subject.OrganizationID || resource.TenantID != subject.TenantID {
		return ErrResourceNotFound
	}

	// 3. Workspace Boundary Check
	if !a.hasOrgWideScope(subject.Roles) {
		if resource.WorkspaceID != uuid.Nil && resource.WorkspaceID != subject.WorkspaceID {
			// Check if resource is explicitly shared across workspaces
			isShared := false
			if a.sharing != nil {
				isShared = a.sharing.HasActiveSharingGrant(
					ctx,
					subject.OrganizationID,
					resource.Type,
					resource.ID,
					subject.WorkspaceID,
					subject.TeamIDs,
				)
			}
			if !isShared {
				return ErrWorkspaceBoundaryDenied
			}
		}
	}

	// 4. Team Boundary Check
	if resource.AssignedTeamID != nil && *resource.AssignedTeamID != uuid.Nil {
		if !a.hasAdminBypass(subject.Roles) {
			isTeamMember := false
			for _, tid := range subject.TeamIDs {
				if tid == *resource.AssignedTeamID {
					isTeamMember = true
					break
				}
			}
			if !isTeamMember {
				return ErrTeamBoundaryDenied
			}
		}
	}

	// 5. Capability / Action Permission Check
	if !a.hasPermission(subject, action) {
		return fmt.Errorf("%w: missing required permission %q", ErrActionForbidden, action)
	}

	return nil
}

// AuthorizeBackgroundJob validates that an asynchronous job maintains authorized object access.
func (a *ObjectAuthorizer) AuthorizeBackgroundJob(
	ctx context.Context,
	jobCtx BackgroundJobContext,
	resource ResourceDescriptor,
	action Permission,
) error {
	if jobCtx.JobID == "" {
		return ErrUnauthorizedSubject
	}
	return a.Authorize(ctx, jobCtx.Initiator, resource, action)
}

func (a *ObjectAuthorizer) hasOrgWideScope(roles []RoleName) bool {
	for _, r := range roles {
		switch r {
		case RoleOrgOwner, RoleOrgAdmin, RoleSecurityAdmin:
			return true
		}
	}
	return false
}

func (a *ObjectAuthorizer) hasAdminBypass(roles []RoleName) bool {
	for _, r := range roles {
		switch r {
		case RoleOrgOwner, RoleOrgAdmin, RoleWorkspaceAdmin:
			return true
		}
	}
	return false
}

func (a *ObjectAuthorizer) hasPermission(subject Subject, action Permission) bool {
	// Direct permission map check (includes resolved custom roles)
	if subject.Permissions != nil && subject.Permissions[action] {
		return true
	}

	// Built-in role permission check
	if HasPermission(subject.Roles, action) {
		return true
	}

	return false
}

// Context helpers for Subject propagation
type subjectContextKey struct{}

func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectContextKey{}, s)
}

func SubjectFromContext(ctx context.Context) (Subject, bool) {
	s, ok := ctx.Value(subjectContextKey{}).(Subject)
	return s, ok
}
