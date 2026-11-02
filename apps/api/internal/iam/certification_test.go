package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type mockAccessRevoker struct {
	revokedItems []*AccessReviewItem
}

func (m *mockAccessRevoker) RevokeAccess(ctx context.Context, item *AccessReviewItem) error {
	m.revokedItems = append(m.revokedItems, item)
	return nil
}

func TestAccessReviewService_CampaignLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryAccessReviewRepository()
	revoker := &mockAccessRevoker{}
	mockAudit := &mockAuditRecorder{}
	service := NewAccessReviewService(repo, revoker, mockAudit)

	orgID := uuid.New()
	adminActorID := "usr_secops_admin"
	reviewerID := "usr_compliance_lead"

	dueDate := time.Now().UTC().Add(30 * 24 * time.Hour)

	items := []*AccessReviewItem{
		{
			TargetUserID:    "usr_developer_1",
			TargetUserEmail: "dev1@corp.example.com",
			ResourceType:    "WORKSPACE_ROLE",
			ResourceID:      "ws_prod_01",
			AssignedRole:    "WORKSPACE_ADMIN",
			IsPrivileged:    true,
		},
		{
			TargetUserID:    reviewerID, // The reviewer itself
			TargetUserEmail: "lead@corp.example.com",
			ResourceType:    "ORG_ROLE",
			ResourceID:      orgID.String(),
			AssignedRole:    "SECURITY_ADMIN",
			IsPrivileged:    true,
		},
		{
			TargetUserID:    "usr_contractor_3",
			TargetUserEmail: "contractor@vendor.com",
			ResourceType:    "CUSTOM_ROLE",
			ResourceID:      "role_temp_auditor",
			AssignedRole:    "Temp Auditor",
			IsPrivileged:    false,
		},
	}

	campaign, err := service.CreateCampaign(
		ctx,
		adminActorID,
		orgID,
		"Q3 2027 Privileged Access Certification",
		"Quarterly review of administrative and custom roles",
		CadenceQuarterly,
		ScopePrivilegedOnly,
		dueDate,
		items,
	)
	if err != nil {
		t.Fatalf("unexpected error creating campaign: %v", err)
	}

	campaignItems, err := repo.ListItemsByCampaign(ctx, campaign.ID)
	if err != nil || len(campaignItems) != 3 {
		t.Fatalf("expected 3 items in campaign, got %d", len(campaignItems))
	}

	t.Run("self-review guard blocks reviewer certifying own access", func(t *testing.T) {
		var ownItem *AccessReviewItem
		for _, it := range campaignItems {
			if it.TargetUserID == reviewerID {
				ownItem = it
				break
			}
		}

		_, err := service.SubmitDecision(ctx, reviewerID, ownItem.ID, DecisionRetain, "Self-approved")
		if !errors.Is(err, ErrSelfReviewProhibited) {
			t.Fatalf("expected ErrSelfReviewProhibited, got %v", err)
		}
	})

	t.Run("mandatory justification on REVOKE decision", func(t *testing.T) {
		var devItem *AccessReviewItem
		for _, it := range campaignItems {
			if it.TargetUserID == "usr_developer_1" {
				devItem = it
				break
			}
		}

		// Empty justification fails
		_, err := service.SubmitDecision(ctx, reviewerID, devItem.ID, DecisionRevoke, "")
		if !errors.Is(err, ErrJustificationRequired) {
			t.Fatalf("expected ErrJustificationRequired, got %v", err)
		}

		// Valid justification succeeds and invokes AccessRevoker
		updated, err := service.SubmitDecision(ctx, reviewerID, devItem.ID, DecisionRevoke, "Developer moved to project B, admin access no longer required")
		if err != nil {
			t.Fatalf("unexpected error submitting REVOKE: %v", err)
		}
		if updated.Decision != DecisionRevoke || !updated.ActionTaken {
			t.Errorf("expected decision REVOKE and ActionTaken true")
		}
		if len(revoker.revokedItems) != 1 || revoker.revokedItems[0].TargetUserID != "usr_developer_1" {
			t.Errorf("expected revoker callback to execute for usr_developer_1")
		}
	})

	t.Run("complete campaign fails when items remain pending", func(t *testing.T) {
		_, err := service.CompleteCampaign(ctx, adminActorID, campaign.ID)
		if !errors.Is(err, ErrCampaignIncomplete) {
			t.Fatalf("expected ErrCampaignIncomplete, got %v", err)
		}
	})

	t.Run("decide remaining items and complete campaign successfully", func(t *testing.T) {
		// Admin reviews the reviewer's item (avoiding self-review)
		var ownItem *AccessReviewItem
		var contractorItem *AccessReviewItem
		for _, it := range campaignItems {
			if it.TargetUserID == reviewerID {
				ownItem = it
			} else if it.TargetUserID == "usr_contractor_3" {
				contractorItem = it
			}
		}

		_, err := service.SubmitDecision(ctx, adminActorID, ownItem.ID, DecisionRetain, "Lead requires Security Admin")
		if err != nil {
			t.Fatalf("failed to decide ownItem: %v", err)
		}

		_, err = service.SubmitDecision(ctx, reviewerID, contractorItem.ID, DecisionInvestigate, "Contract ended; investigate whether credentials active")
		if err != nil {
			t.Fatalf("failed to decide contractorItem: %v", err)
		}

		// Check summary
		summary, err := service.GetCampaignSummary(ctx, campaign.ID)
		if err != nil {
			t.Fatalf("unexpected error getting summary: %v", err)
		}
		if summary.TotalItems != 3 || summary.PendingCount != 0 || summary.PercentComplete != 100.0 {
			t.Errorf("expected 100%% complete summary, got %+v", summary)
		}
		if summary.RevokedCount != 1 || summary.RetainedCount != 1 || summary.InvestigateCount != 1 {
			t.Errorf("unexpected summary counts: %+v", summary)
		}

		// Complete campaign succeeds
		completed, err := service.CompleteCampaign(ctx, adminActorID, campaign.ID)
		if err != nil {
			t.Fatalf("unexpected error completing campaign: %v", err)
		}
		if completed.Status != "COMPLETED" || completed.CompletedAt == nil {
			t.Errorf("expected status COMPLETED with timestamp")
		}
	})
}
