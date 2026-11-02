package hierarchy

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OrgState represents the lifecycle status of an Enterprise Organization.
type OrgState string

const (
	OrgStateProvisioning    OrgState = "PROVISIONING"
	OrgStateActive          OrgState = "ACTIVE"
	OrgStateSuspended       OrgState = "SUSPENDED"
	OrgStatePendingDeletion OrgState = "PENDING_DELETION"
	OrgStatePurged          OrgState = "PURGED"
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
	ID                  uuid.UUID              `json:"id"`
	Name                string                 `json:"name"`
	Slug                string                 `json:"slug"`
	BillingTier         string                 `json:"billing_tier"`
	Status              OrgState               `json:"status"` // PROVISIONING, ACTIVE, SUSPENDED, PENDING_DELETION, PURGED
	Settings            map[string]interface{} `json:"settings"`
	SuspendedAt         *time.Time             `json:"suspended_at,omitempty"`
	SuspensionReason    string                 `json:"suspension_reason,omitempty"`
	DeletionRequestedAt *time.Time             `json:"deletion_requested_at,omitempty"`
	PurgeAfter          *time.Time             `json:"purge_after,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
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
	ErrOrganizationNotFound        = errors.New("organization not found")
	ErrWorkspaceNotFound           = errors.New("workspace not found")
	ErrTeamNotFound                = errors.New("team not found")
	ErrUnauthorized                = errors.New("unauthorized: insufficient hierarchy permissions")
	ErrTenantMismatch              = errors.New("workspace tenant isolation mismatch")
	ErrUnknownResource             = errors.New("unknown resource type for scope classification")
	ErrImplicitAccessForbidden      = errors.New("implicit cross-workspace access is forbidden")
	ErrInvalidOrgStateTransition   = errors.New("invalid organization lifecycle transition")
	ErrOrgSuspended                = errors.New("organization is suspended: operational modifications prohibited")
	ErrOrgPendingDeletion          = errors.New("organization is pending deletion: operational modifications prohibited")
	ErrOrgPurged                   = errors.New("organization has been purged and cannot be accessed")
)

// ValidateOrgStateTransition checks whether a transition between two organization states is permitted.
func ValidateOrgStateTransition(current, target OrgState) error {
	if current == target {
		return nil // Idempotent no-op
	}

	validTransitions := map[OrgState][]OrgState{
		OrgStateProvisioning:    {OrgStateActive, OrgStateSuspended},
		OrgStateActive:          {OrgStateSuspended, OrgStatePendingDeletion},
		OrgStateSuspended:       {OrgStateActive, OrgStatePendingDeletion},
		OrgStatePendingDeletion: {OrgStateActive, OrgStatePurged},
		OrgStatePurged:          {}, // Terminal state
	}

	allowed, ok := validTransitions[current]
	if !ok {
		return fmt.Errorf("%w: unknown current state %q", ErrInvalidOrgStateTransition, current)
	}

	for _, s := range allowed {
		if s == target {
			return nil
		}
	}

	return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidOrgStateTransition, current, target)
}

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
