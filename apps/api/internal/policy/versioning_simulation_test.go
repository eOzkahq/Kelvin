package policy

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyVersioning_DraftAndSimulation(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryRiskApproverValidator()
	svc := NewPolicyVersioningService(validator)

	orgID := uuid.New()
	authorID := "policy-author-alice"

	rule1 := PolicyRule{
		ID:         "rule-1",
		Name:       "Allow standard scans",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopeOrganization,
		Precedence: 150,
		Action:     ActionAllow,
		Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
			return eval.TargetID != "forbidden.local", nil
		},
	}

	t.Run("create draft version", func(t *testing.T) {
		draft, err := svc.CreateDraft(ctx, orgID, PolicyTypeScanExecution, authorID, "Initial draft", []PolicyRule{rule1})
		require.NoError(t, err)
		assert.Equal(t, 1, draft.Version)
		assert.Equal(t, StatusDraft, draft.Status)
	})

	t.Run("simulate draft against test corpus without side effects", func(t *testing.T) {
		draft, err := svc.CreateDraft(ctx, orgID, PolicyTypeScanExecution, authorID, "Test draft", []PolicyRule{rule1})
		require.NoError(t, err)

		testCorpus := []EvaluationContext{
			{TargetID: "allowed.local"},
			{TargetID: "forbidden.local"},
		}

		simResult, err := svc.SimulatePolicy(ctx, draft.ID, authorID, testCorpus)
		require.NoError(t, err)
		assert.Equal(t, 2, simResult.TotalEvaluated)
		assert.Equal(t, 1, simResult.AllowedCount)
		assert.Equal(t, 1, simResult.DeniedCount) // forbidden.local matches no allow rule, fails closed
	})

	t.Run("simulation detects contradictory conflicting rules", func(t *testing.T) {
		conflictingRule := PolicyRule{
			ID:         "rule-2",
			Name:       "Contradictory Deny",
			Type:       PolicyTypeScanExecution,
			Scope:      ScopeOrganization,
			Precedence: 150, // Same precedence
			Action:     ActionDeny,
		}

		draft, err := svc.CreateDraft(ctx, orgID, PolicyTypeScanExecution, authorID, "Conflicting draft", []PolicyRule{rule1, conflictingRule})
		require.NoError(t, err)

		simResult, err := svc.SimulatePolicy(ctx, draft.ID, authorID, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, simResult.ConflictsDetected)
		require.NotEmpty(t, simResult.ConflictDetails)
	})
}

func TestPolicyVersioning_PublishAndRollback(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryRiskApproverValidator()
	svc := NewPolicyVersioningService(validator)

	orgID := uuid.New()
	authorID := "author-dan"
	publisherID := "ciso-carol"

	ruleV1 := PolicyRule{
		ID:         "rule-v1",
		Name:       "Version 1 Allow",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopeOrganization,
		Precedence: 150,
		Action:     ActionAllow,
	}

	draftV1, err := svc.CreateDraft(ctx, orgID, PolicyTypeScanExecution, authorID, "v1 spec", []PolicyRule{ruleV1})
	require.NoError(t, err)

	t.Run("unauthorized user cannot publish", func(t *testing.T) {
		_, err := svc.PublishVersion(ctx, draftV1.ID, "junior-dev", "JUNIOR_DEV")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnauthorizedPublisher)
	})

	t.Run("authorized CISO publishes version 1", func(t *testing.T) {
		pubV1, err := svc.PublishVersion(ctx, draftV1.ID, publisherID, "CISO")
		require.NoError(t, err)
		assert.Equal(t, StatusPublished, pubV1.Status)
		assert.NotNil(t, pubV1.PublishedAt)
	})

	t.Run("publishing version 2 archives version 1", func(t *testing.T) {
		ruleV2 := PolicyRule{
			ID:         "rule-v2",
			Name:       "Version 2 Restricted",
			Type:       PolicyTypeScanExecution,
			Scope:      ScopeOrganization,
			Precedence: 100,
			Action:     ActionDeny,
		}
		draftV2, err := svc.CreateDraft(ctx, orgID, PolicyTypeScanExecution, authorID, "v2 spec", []PolicyRule{ruleV2})
		require.NoError(t, err)
		assert.Equal(t, 2, draftV2.Version)

		pubV2, err := svc.PublishVersion(ctx, draftV2.ID, publisherID, "CISO")
		require.NoError(t, err)
		assert.Equal(t, StatusPublished, pubV2.Status)

		// Check v1 is archived
		oldV1, err := svc.GetVersion(draftV1.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusArchived, oldV1.Status)
	})

	t.Run("rollback to version 1 creates new published version 3 with v1 rules", func(t *testing.T) {
		rolledBack, err := svc.RollbackToVersion(ctx, orgID, PolicyTypeScanExecution, 1, publisherID, "CISO", "Reverting v2 regression")
		require.NoError(t, err)
		assert.Equal(t, 3, rolledBack.Version)
		assert.Equal(t, StatusPublished, rolledBack.Status)
		assert.Equal(t, "rule-v1", rolledBack.Rules[0].ID)

		// Audit logs check
		logs := svc.GetAuditLogs(orgID)
		require.NotEmpty(t, logs)
		foundRollback := false
		for _, l := range logs {
			if l.Action == AuditRollback {
				foundRollback = true
				break
			}
		}
		assert.True(t, foundRollback)
	})
}
