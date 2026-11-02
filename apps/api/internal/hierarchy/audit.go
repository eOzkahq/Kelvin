package hierarchy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

const (
	ActionOrgCreated           = "org.created"
	ActionOrgSuspended         = "org.suspended"
	ActionOrgReactivated       = "org.reactivated"
	ActionOrgDeletionRequested = "org.deletion_requested"
	ActionOrgDeletionCancelled = "org.deletion_cancelled"
	ActionOrgPurged            = "org.purged"

	ActionTeamCreated       = "team.created"
	ActionTeamUpdated       = "team.updated"
	ActionTeamArchived      = "team.archived"
	ActionTeamMemberAdded   = "team.member_added"
	ActionTeamMemberRemoved = "team.member_removed"

	ActionInvitationCreated  = "org.invitation_created"
	ActionInvitationAccepted = "org.invitation_accepted"
	ActionInvitationRevoked  = "org.invitation_revoked"
	ActionInvitationReissued = "org.invitation_reissued"
	ActionInvitationDeclined = "org.invitation_declined"

	ActionResourceShared   = "resource.shared"
	ActionResourceUnshared = "resource.unshared"

	ActionOrgSettingsUpdated = "org.settings_updated"

	ActionOrgOwnershipTransferred = "org.ownership_transferred"
	ActionOrgMemberRoleUpdated    = "org.member_role_updated"
	ActionOrgMemberRemoved        = "org.member_removed"
	ActionWorkspaceAdminAssigned  = "workspace.admin_assigned"
	ActionWorkspaceAdminRevoked   = "workspace.admin_revoked"
)

// HierarchyAuditRecorder records organization and workspace lifecycle audit events.
type HierarchyAuditRecorder struct {
	recorder audit.Recorder
}

func NewHierarchyAuditRecorder(recorder audit.Recorder) *HierarchyAuditRecorder {
	return &HierarchyAuditRecorder{recorder: recorder}
}

func (r *HierarchyAuditRecorder) RecordOrgLifecycleEvent(ctx context.Context, action string, org *Organization, actorUserID string, details map[string]interface{}) error {
	if r == nil || r.recorder == nil {
		return nil
	}

	payloadMap := map[string]interface{}{
		"org_id":     org.ID.String(),
		"org_name":   org.Name,
		"org_slug":   org.Slug,
		"org_status": string(org.Status),
		"details":    details,
	}
	payloadBytes, _ := json.Marshal(payloadMap)

	var actorUUID *uuid.UUID
	if u, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &u
	}

	evt := audit.Event{
		ID:          uuid.New(),
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "organization",
		EntityID:    &org.ID,
		Payload:     payloadBytes,
		CreatedAt:   time.Now().UTC(),
	}

	return r.recorder.Record(ctx, evt)
}

func (r *HierarchyAuditRecorder) RecordTeamLifecycleEvent(ctx context.Context, action string, team *Team, actorUserID string, details map[string]interface{}) error {
	if r == nil || r.recorder == nil {
		return nil
	}

	payloadMap := map[string]interface{}{
		"team_id":   team.ID.String(),
		"org_id":    team.OrganizationID.String(),
		"team_name": team.Name,
		"team_slug": team.Slug,
		"status":    team.Status,
		"details":   details,
	}
	payloadBytes, _ := json.Marshal(payloadMap)

	var actorUUID *uuid.UUID
	if u, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &u
	}

	evt := audit.Event{
		ID:          uuid.New(),
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "team",
		EntityID:    &team.ID,
		Payload:     payloadBytes,
		CreatedAt:   time.Now().UTC(),
	}

	return r.recorder.Record(ctx, evt)
}

func (r *HierarchyAuditRecorder) RecordInvitationLifecycleEvent(ctx context.Context, action string, invite *OrganizationInvitation, actorUserID string, details map[string]interface{}) error {
	if r == nil || r.recorder == nil {
		return nil
	}

	payloadMap := map[string]interface{}{
		"invitation_id":   invite.ID.String(),
		"org_id":          invite.OrganizationID.String(),
		"invitee_email":   invite.InviteeEmail,
		"assigned_role":   string(invite.Role),
		"status":          string(invite.Status),
		"details":         details,
	}
	payloadBytes, _ := json.Marshal(payloadMap)

	var actorUUID *uuid.UUID
	if u, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &u
	}

	evt := audit.Event{
		ID:          uuid.New(),
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "organization_invitation",
		EntityID:    &invite.ID,
		Payload:     payloadBytes,
		CreatedAt:   time.Now().UTC(),
	}

	return r.recorder.Record(ctx, evt)
}

func (r *HierarchyAuditRecorder) RecordSharingLifecycleEvent(ctx context.Context, action string, grantID uuid.UUID, resourceType string, resourceID uuid.UUID, actorUserID string, details map[string]interface{}) error {
	if r == nil || r.recorder == nil {
		return nil
	}

	payloadMap := map[string]interface{}{
		"grant_id":      grantID.String(),
		"resource_type": resourceType,
		"resource_id":   resourceID.String(),
		"details":       details,
	}
	payloadBytes, _ := json.Marshal(payloadMap)

	var actorUUID *uuid.UUID
	if u, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &u
	}

	evt := audit.Event{
		ID:          uuid.New(),
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "resource_sharing_grant",
		EntityID:    &grantID,
		Payload:     payloadBytes,
		CreatedAt:   time.Now().UTC(),
	}

	return r.recorder.Record(ctx, evt)
}

// MemoryAuditRecorder captures audit events for testing.
type MemoryAuditRecorder struct {
	Events []audit.Event
}

func NewMemoryAuditRecorder() *MemoryAuditRecorder {
	return &MemoryAuditRecorder{Events: make([]audit.Event, 0)}
}

func (m *MemoryAuditRecorder) Record(ctx context.Context, evt audit.Event) error {
	m.Events = append(m.Events, evt)
	return nil
}
