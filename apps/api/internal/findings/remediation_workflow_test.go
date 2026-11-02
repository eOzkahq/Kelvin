package findings

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRemediationTransition(t *testing.T) {
	t.Run("valid transitions", func(t *testing.T) {
		assert.NoError(t, ValidateRemediationTransition(RemediationStateOpen, RemediationStatePlanned, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateOpen, RemediationStateInProgress, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStatePlanned, RemediationStateInProgress, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStatePlanned, RemediationStateOpen, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateInProgress, RemediationStateBlocked, "Waiting for cloud provider fix"))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateBlocked, RemediationStateInProgress, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateInProgress, RemediationStateReadyForVerification, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateReadyForVerification, RemediationStateCompleted, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateReadyForVerification, RemediationStateReopened, "Scan re-test still detects flaw"))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateReadyForVerification, RemediationStateInProgress, ""))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateCompleted, RemediationStateReopened, "Regression observed in canary deployment"))
		assert.NoError(t, ValidateRemediationTransition(RemediationStateReopened, RemediationStateInProgress, ""))
	})

	t.Run("invalid transitions", func(t *testing.T) {
		// Jump from Open to Completed directly
		err := ValidateRemediationTransition(RemediationStateOpen, RemediationStateCompleted, "")
		assert.ErrorIs(t, err, ErrInvalidRemediationTransition)

		// Jump from Blocked to Completed
		err = ValidateRemediationTransition(RemediationStateBlocked, RemediationStateCompleted, "")
		assert.ErrorIs(t, err, ErrInvalidRemediationTransition)

		// Transition to same state
		err = ValidateRemediationTransition(RemediationStateOpen, RemediationStateOpen, "")
		assert.ErrorIs(t, err, ErrNoStateChange)

		// Invalid state string
		err = ValidateRemediationTransition("INVALID_STATE", RemediationStateOpen, "")
		assert.ErrorIs(t, err, ErrInvalidRemediationState)
	})

	t.Run("mandatory reason enforcement", func(t *testing.T) {
		// Transition to BLOCKED requires reason
		err := ValidateRemediationTransition(RemediationStateInProgress, RemediationStateBlocked, "")
		assert.ErrorIs(t, err, ErrReasonRequiredForBlocked)

		err = ValidateRemediationTransition(RemediationStateInProgress, RemediationStateBlocked, "   ")
		assert.ErrorIs(t, err, ErrReasonRequiredForBlocked)

		// Transition to REOPENED requires reason
		err = ValidateRemediationTransition(RemediationStateReadyForVerification, RemediationStateReopened, "")
		assert.ErrorIs(t, err, ErrReasonRequiredForReopened)

		err = ValidateRemediationTransition(RemediationStateCompleted, RemediationStateReopened, "   ")
		assert.ErrorIs(t, err, ErrReasonRequiredForReopened)
	})
}

func TestRemediationWorkflowService_TransitionTaskState(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRemediationRepository()
	service := NewRemediationWorkflowService(repo)

	tenantID := uuid.New()
	findingID := uuid.New()
	task, err := NewRemediationTask(tenantID, findingID, "Rotate DB credentials", "Generate new rotation secret", "Vault CLI rotation", "dev-1", nil)
	require.NoError(t, err)
	require.NoError(t, repo.CreateTask(ctx, task))

	t.Run("valid sequential lifecycle execution", func(t *testing.T) {
		// 1. OPEN -> IN_PROGRESS
		res1, err := service.TransitionTaskState(ctx, tenantID, task.ID, "dev-1", RemediationStateInProgress, "Work started", StatusConfirmed)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateInProgress, res1.Task.State)
		assert.Equal(t, StatusConfirmed, res1.FindingStatus)
		assert.False(t, res1.FindingStatusChanged)

		// 2. IN_PROGRESS -> BLOCKED
		res2, err := service.TransitionTaskState(ctx, tenantID, task.ID, "dev-1", RemediationStateBlocked, "Awaiting approval from DBA", StatusConfirmed)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateBlocked, res2.Task.State)

		// 3. BLOCKED -> IN_PROGRESS
		res3, err := service.TransitionTaskState(ctx, tenantID, task.ID, "dev-1", RemediationStateInProgress, "DBA approval granted", StatusConfirmed)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateInProgress, res3.Task.State)

		// 4. IN_PROGRESS -> READY_FOR_VERIFICATION
		res4, err := service.TransitionTaskState(ctx, tenantID, task.ID, "dev-1", RemediationStateReadyForVerification, "Credentials rotated in staging", StatusConfirmed)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateReadyForVerification, res4.Task.State)

		// 5. READY_FOR_VERIFICATION -> COMPLETED
		// Invariant: Finding status does NOT become RESOLVED automatically
		res5, err := service.TransitionTaskState(ctx, tenantID, task.ID, "qa-1", RemediationStateCompleted, "Verified rotated", StatusConfirmed)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateCompleted, res5.Task.State)
		assert.Equal(t, StatusConfirmed, res5.FindingStatus)
		assert.False(t, res5.FindingStatusChanged)
		assert.Contains(t, res5.IndependenceNote, "Finding lifecycle status remains unchanged")

		// 6. Check that all updates were recorded in chronological audit history
		updates, err := repo.ListUpdatesByTask(ctx, tenantID, task.ID)
		require.NoError(t, err)
		assert.Len(t, updates, 5)
		assert.Equal(t, "Work started", updates[0].Comment)
		assert.Equal(t, "Awaiting approval from DBA", updates[1].Comment)
		assert.Equal(t, "Verified rotated", updates[4].Comment)
	})

	t.Run("finding state independence with FalsePositive and AcceptedRisk", func(t *testing.T) {
		fpTask, err := NewRemediationTask(tenantID, findingID, "Document exception", "Docs", "Update wiki", "dev-2", nil)
		require.NoError(t, err)
		require.NoError(t, repo.CreateTask(ctx, fpTask))

		resFP, err := service.TransitionTaskState(ctx, tenantID, fpTask.ID, "dev-2", RemediationStatePlanned, "Scheduled doc update", StatusFalsePositive)
		require.NoError(t, err)
		assert.Equal(t, StatusFalsePositive, resFP.FindingStatus)
		assert.False(t, resFP.FindingStatusChanged)
		assert.Contains(t, resFP.IndependenceNote, "FALSE_POSITIVE")

		riskTask, err := NewRemediationTask(tenantID, findingID, "Compensating control", "Desc", "Add alert rule", "dev-3", nil)
		require.NoError(t, err)
		require.NoError(t, repo.CreateTask(ctx, riskTask))

		resRisk, err := service.TransitionTaskState(ctx, tenantID, riskTask.ID, "dev-3", RemediationStateInProgress, "Adding rule", StatusAcceptedRisk)
		require.NoError(t, err)
		assert.Equal(t, StatusAcceptedRisk, resRisk.FindingStatus)
		assert.False(t, resRisk.FindingStatusChanged)
		assert.Contains(t, resRisk.IndependenceNote, "ACCEPTED")
	})

	t.Run("tenant boundary enforcement", func(t *testing.T) {
		otherTenant := uuid.New()
		_, err := service.TransitionTaskState(ctx, otherTenant, task.ID, "attacker", RemediationStateInProgress, "attempt", StatusConfirmed)
		assert.ErrorIs(t, err, ErrTenantMismatch)
	})

	t.Run("missing author enforcement", func(t *testing.T) {
		_, err := service.TransitionTaskState(ctx, tenantID, task.ID, "", RemediationStateInProgress, "attempt", StatusConfirmed)
		assert.ErrorIs(t, err, ErrMissingAuthorID)
	})
}
