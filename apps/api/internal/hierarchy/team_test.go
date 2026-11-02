package hierarchy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTeamAndGroupManagement(t *testing.T) {
	repo := NewMemoryHierarchyRepository()
	auditMem := NewMemoryAuditRecorder()
	auditRecorder := NewHierarchyAuditRecorder(auditMem)
	svc := NewHierarchyService(repo).WithAuditRecorder(auditRecorder)
	ctx := context.Background()

	// 1. Create Organization Org A and Org B
	orgA, err := svc.CreateOrganization(ctx, "Shield Global", "shield-global", "user-fury")
	if err != nil {
		t.Fatalf("failed to create orgA: %v", err)
	}

	orgB, err := svc.CreateOrganization(ctx, "Hydra Syndicate", "hydra-syndicate", "user-pierce")
	if err != nil {
		t.Fatalf("failed to create orgB: %v", err)
	}

	// 2. Add users to Org A
	userNat := "user-natasha"
	userClint := "user-clint"

	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: orgA.ID,
		UserID:         userNat,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})
	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: orgA.ID,
		UserID:         userClint,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// User Crossbones only in Org B
	userCrossbones := "user-crossbones"
	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: orgB.ID,
		UserID:         userCrossbones,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// 3. Regular member cannot create a team
	_, err = svc.CreateTeam(ctx, orgA.ID, userNat, "Strike Team", "strike-team", "Ops unit")
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized when regular member tries to create team, got %v", err)
	}

	// 4. Org Owner (Fury) creates team
	team, err := svc.CreateTeam(ctx, orgA.ID, "user-fury", "Strike Team", "strike-team", "Special operations unit")
	if err != nil {
		t.Fatalf("failed to create team: %v", err)
	}

	if team.Status != "ACTIVE" {
		t.Errorf("expected team status ACTIVE, got %s", team.Status)
	}

	// 5. Add user-natasha as Team Lead
	err = svc.AddTeamMember(ctx, team.ID, "user-fury", userNat, TeamRoleLead)
	if err != nil {
		t.Fatalf("failed to add team member: %v", err)
	}

	// 6. Natasha (Team Lead) adds Clint as Contributor
	err = svc.AddTeamMember(ctx, team.ID, userNat, userClint, TeamRoleContributor)
	if err != nil {
		t.Fatalf("team lead failed to add member: %v", err)
	}

	// 7. Organization boundary check: Attempt to add userCrossbones (from Org B) into Org A's team
	err = svc.AddTeamMember(ctx, team.ID, userNat, userCrossbones, TeamRoleContributor)
	if err != ErrUserNotInOrganization {
		t.Errorf("expected ErrUserNotInOrganization when adding cross-org user, got %v", err)
	}

	// 8. User can belong to multiple teams
	reconTeam, err := svc.CreateTeam(ctx, orgA.ID, "user-fury", "Reconnaissance", "recon", "Recon group")
	if err != nil {
		t.Fatalf("failed to create recon team: %v", err)
	}

	err = svc.AddTeamMember(ctx, reconTeam.ID, "user-fury", userNat, TeamRoleContributor)
	if err != nil {
		t.Fatalf("failed to add user to second team: %v", err)
	}

	natTeams, err := repo.GetUserTeams(ctx, orgA.ID, userNat)
	if err != nil || len(natTeams) != 2 {
		t.Errorf("expected user-natasha to belong to 2 teams, got %d", len(natTeams))
	}

	// 9. Update team
	updatedTeam, err := svc.UpdateTeam(ctx, team.ID, userNat, "Strike Team Alpha", "Upgraded elite unit")
	if err != nil {
		t.Fatalf("failed to update team: %v", err)
	}
	if updatedTeam.Name != "Strike Team Alpha" {
		t.Errorf("expected name 'Strike Team Alpha', got %s", updatedTeam.Name)
	}

	// 10. Archive team
	err = svc.ArchiveTeam(ctx, team.ID, "user-fury")
	if err != nil {
		t.Fatalf("failed to archive team: %v", err)
	}

	archivedTeam, _ := repo.GetTeam(ctx, team.ID)
	if archivedTeam.Status != "ARCHIVED" {
		t.Errorf("expected status ARCHIVED, got %s", archivedTeam.Status)
	}

	// Cannot add members or modify archived team
	err = svc.AddTeamMember(ctx, team.ID, "user-fury", userClint, TeamRoleMember)
	if err != ErrTeamArchived {
		t.Errorf("expected ErrTeamArchived when adding member to archived team, got %v", err)
	}

	// Archived team is not returned in active user teams
	activeNatTeams, _ := repo.GetUserTeams(ctx, orgA.ID, userNat)
	if len(activeNatTeams) != 1 {
		t.Errorf("expected 1 active team for user-natasha after archival, got %d", len(activeNatTeams))
	}

	// 11. Verify audit events recorded
	expectedTeamEvents := []string{
		ActionTeamCreated,
		ActionTeamMemberAdded,
		ActionTeamMemberAdded,
		ActionTeamCreated,
		ActionTeamMemberAdded,
		ActionTeamUpdated,
		ActionTeamArchived,
	}

	var capturedTeamActions []string
	for _, e := range auditMem.Events {
		if e.EntityType == "team" {
			capturedTeamActions = append(capturedTeamActions, e.Action)
		}
	}

	if len(capturedTeamActions) != len(expectedTeamEvents) {
		t.Fatalf("expected %d team audit events, got %d", len(expectedTeamEvents), len(capturedTeamActions))
	}

	for i, action := range expectedTeamEvents {
		if capturedTeamActions[i] != action {
			t.Errorf("event %d action mismatch: got %s, want %s", i, capturedTeamActions[i], action)
		}
	}
}
