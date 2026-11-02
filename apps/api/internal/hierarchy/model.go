package hierarchy

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// OrgRole represents global roles within an Enterprise Organization.
type OrgRole string

const (
	OrgRoleOwner   OrgRole = "OWNER"
	OrgRoleAdmin   OrgRole = "ADMIN"
	OrgRoleMember  OrgRole = "MEMBER"
	OrgRoleBilling OrgRole = "BILLING"
)

// WorkspaceRole represents environment-scoped operational roles.
type WorkspaceRole string

const (
	WorkspaceRoleAdmin    WorkspaceRole = "ADMIN"
	WorkspaceRoleOperator WorkspaceRole = "OPERATOR"
	WorkspaceRoleViewer   WorkspaceRole = "VIEWER"
)

// TeamRole represents leadership or member roles inside a Team.
type TeamRole string

const (
	TeamRoleLead   TeamRole = "LEAD"
	TeamRoleMember TeamRole = "MEMBER"
)

// ResourceScope indicates whether a resource belongs to an Organization or an isolated Workspace.
type ResourceScope string

const (
	ResourceScopeOrganization ResourceScope = "ORGANIZATION"
	ResourceScopeWorkspace    ResourceScope = "WORKSPACE"
)

// Organization represents the top-level legal, billing, and enterprise governance boundary.
type Organization struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	BillingTier string                 `json:"billing_tier"`
	Status      string                 `json:"status"`
	Settings    map[string]interface{} `json:"settings"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Workspace represents an operational security boundary mapped 1:1 to an underlying Tenant.
type Workspace struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Environment    string    `json:"environment"` // production, staging, development
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Team represents a group of users inside an organization for collaborative access control.
type Team struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// OrganizationMembership records a user's role in an Organization.
type OrganizationMembership struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           OrgRole   `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// WorkspaceMembership records a user's direct role grant in a Workspace.
type WorkspaceMembership struct {
	ID          uuid.UUID     `json:"id"`
	WorkspaceID uuid.UUID     `json:"workspace_id"`
	UserID      string        `json:"user_id"`
	Role        WorkspaceRole `json:"role"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// TeamMembership records a user's membership in a Team.
type TeamMembership struct {
	ID        uuid.UUID `json:"id"`
	TeamID    uuid.UUID `json:"team_id"`
	UserID    string    `json:"user_id"`
	Role      TeamRole  `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// WorkspaceTeamGrant grants a team a collective role on a Workspace.
type WorkspaceTeamGrant struct {
	ID          uuid.UUID     `json:"id"`
	WorkspaceID uuid.UUID     `json:"workspace_id"`
	TeamID      uuid.UUID     `json:"team_id"`
	Role        WorkspaceRole `json:"role"`
	CreatedAt   time.Time     `json:"created_at"`
}

var (
	ErrOrganizationNotFound   = errors.New("organization not found")
	ErrWorkspaceNotFound      = errors.New("workspace not found")
	ErrTeamNotFound           = errors.New("team not found")
	ErrUnauthorized           = errors.New("unauthorized: insufficient hierarchy permissions")
	ErrTenantMismatch         = errors.New("workspace tenant isolation mismatch")
	ErrUnknownResource        = errors.New("unknown resource type for scope classification")
	ErrImplicitAccessForbidden = errors.New("implicit cross-workspace access is forbidden")
)

// ClassifyResourceScope determines whether a security platform resource is Organization-wide or Workspace-isolated.
func ClassifyResourceScope(resourceType string) (ResourceScope, error) {
	switch resourceType {
	case "sso_config", "saml_provider", "enterprise_policy", "billing_account", "audit_export_config", "global_connector":
		return ResourceScopeOrganization, nil
	case "assessment", "scan_profile", "target_asset", "finding", "evidence", "report", "api_token", "remediation_task":
		return ResourceScopeWorkspace, nil
	default:
		return "", ErrUnknownResource
	}
}
