package hierarchy

import (
	"context"
	"testing"
	"time"
)

func TestOrganizationInvitationLifecycle(t *testing.T) {
	repo := NewMemoryHierarchyRepository()
	auditMem := NewMemoryAuditRecorder()
	auditRecorder := NewHierarchyAuditRecorder(auditMem)
	svc := NewHierarchyService(repo).WithAuditRecorder(auditRecorder)
	ctx := context.Background()

	// 1. Setup Org and Team
	org, err := svc.CreateOrganization(ctx, "Avengers Initiative", "avengers", "user-fury")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	team, err := svc.CreateTeam(ctx, org.ID, "user-fury", "Strike Team", "strike", "Strike ops")
	if err != nil {
		t.Fatalf("failed to create team: %v", err)
	}

	// 2. Regular user cannot invite
	_, _, err = svc.CreateInvitation(ctx, org.ID, "user-stranger", "spidey@avengers.io", OrgRoleMember, &team.ID, 24*time.Hour)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for unauthorized inviter, got %v", err)
	}

	// 3. Admin creates invitation with initial team
	invite, rawToken, err := svc.CreateInvitation(ctx, org.ID, "user-fury", "peter.parker@avengers.io", OrgRoleMember, &team.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create invitation: %v", err)
	}

	if rawToken == "" {
		t.Fatalf("expected non-empty raw token")
	}
	if invite.Status != InvitationStatusPending {
		t.Errorf("expected status PENDING, got %s", invite.Status)
	}

	// 4. Accept invitation
	userID := "user-peter"
	mem, err := svc.AcceptInvitation(ctx, rawToken, userID)
	if err != nil {
		t.Fatalf("failed to accept invitation: %v", err)
	}

	if mem.UserID != userID || mem.Role != OrgRoleMember {
		t.Errorf("membership mismatch: got user %s, role %s", mem.UserID, mem.Role)
	}

	// Verify user is also added to team
	teamMembers, _ := repo.GetTeamMembers(ctx, team.ID)
	foundInTeam := false
	for _, tm := range teamMembers {
		if tm.UserID == userID {
			foundInTeam = true
			break
		}
	}
	if !foundInTeam {
		t.Errorf("expected user to be added to initial team upon invitation acceptance")
	}

	// 5. Replay attempt: accepting again must fail
	_, err = svc.AcceptInvitation(ctx, rawToken, "user-imposter")
	if err != ErrInvitationAlreadyUsed {
		t.Errorf("expected ErrInvitationAlreadyUsed on replayed token, got %v", err)
	}

	// 6. Test Expiration
	expiredInvite, expiredToken, _ := svc.CreateInvitation(ctx, org.ID, "user-fury", "expired@avengers.io", OrgRoleMember, nil, -1*time.Hour)
	_ = expiredInvite

	_, err = svc.AcceptInvitation(ctx, expiredToken, "user-late")
	if err != ErrInvitationExpired {
		t.Errorf("expected ErrInvitationExpired, got %v", err)
	}

	// 7. Test Revocation
	revokedInvite, revokedToken, _ := svc.CreateInvitation(ctx, org.ID, "user-fury", "revoked@avengers.io", OrgRoleMember, nil, 24*time.Hour)
	err = svc.RevokeInvitation(ctx, revokedInvite.ID, "user-fury")
	if err != nil {
		t.Fatalf("failed to revoke invitation: %v", err)
	}

	_, err = svc.AcceptInvitation(ctx, revokedToken, "user-revoked")
	if err != ErrInvitationAlreadyUsed {
		t.Errorf("expected ErrInvitationAlreadyUsed on revoked invitation, got %v", err)
	}

	// 8. Test Reissuance
	newRawToken, err := svc.ReissueInvitation(ctx, revokedInvite.ID, "user-fury", 48*time.Hour)
	if err != nil {
		t.Fatalf("failed to reissue invitation: %v", err)
	}

	// Now new token can be accepted
	mem2, err := svc.AcceptInvitation(ctx, newRawToken, "user-reissued")
	if err != nil {
		t.Fatalf("failed to accept reissued invitation: %v", err)
	}
	if mem2.UserID != "user-reissued" {
		t.Errorf("expected user-reissued membership, got %s", mem2.UserID)
	}

	// 9. Verify audit events recorded
	expectedInvitationEvents := []string{
		ActionInvitationCreated,
		ActionInvitationAccepted,
		ActionInvitationCreated,
		ActionInvitationCreated,
		ActionInvitationRevoked,
		ActionInvitationReissued,
		ActionInvitationAccepted,
	}

	var capturedInviteActions []string
	for _, e := range auditMem.Events {
		if e.EntityType == "organization_invitation" {
			capturedInviteActions = append(capturedInviteActions, e.Action)
		}
	}

	if len(capturedInviteActions) != len(expectedInvitationEvents) {
		t.Fatalf("expected %d invitation audit events, got %d", len(expectedInvitationEvents), len(capturedInviteActions))
	}

	for i, action := range expectedInvitationEvents {
		if capturedInviteActions[i] != action {
			t.Errorf("event %d action mismatch: got %s, want %s", i, capturedInviteActions[i], action)
		}
	}
}
