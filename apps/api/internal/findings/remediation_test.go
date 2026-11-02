package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemediationState_IsValid(t *testing.T) {
	validStates := []RemediationState{
		RemediationStateOpen,
		RemediationStatePlanned,
		RemediationStateInProgress,
		RemediationStateBlocked,
		RemediationStateReadyForVerification,
		RemediationStateCompleted,
		RemediationStateReopened,
	}

	for _, s := range validStates {
		assert.True(t, s.IsValid(), "expected state %s to be valid", s)
	}

	invalidStates := []RemediationState{
		"UNKNOWN",
		"DELETED",
		"",
	}
	for _, s := range invalidStates {
		assert.False(t, s.IsValid(), "expected state %s to be invalid", s)
	}
}

func TestNewRemediationTask_Validation(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	t.Run("valid task creation", func(t *testing.T) {
		dueDate := time.Now().Add(48 * time.Hour).UTC()
		task, err := NewRemediationTask(tenantID, findingID, "Patch OpenSSH", "Upgrade to OpenSSH 9.8p1", "Run apt update && apt install openssh-server", "secops-user-1", &dueDate)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, task.ID)
		assert.Equal(t, tenantID, task.TenantID)
		assert.Equal(t, findingID, task.FindingID)
		assert.Equal(t, "Patch OpenSSH", task.Title)
		assert.Equal(t, RemediationStateOpen, task.State)
		assert.Equal(t, "secops-user-1", task.AssignedUserID)
		assert.Equal(t, &dueDate, task.TargetCompletionDate)
		assert.Nil(t, task.VerificationAssessmentID)
		assert.False(t, task.CreatedAt.IsZero())
		assert.False(t, task.UpdatedAt.IsZero())
	})

	t.Run("missing tenant ID", func(t *testing.T) {
		_, err := NewRemediationTask(uuid.Nil, findingID, "Title", "Desc", "Action", "", nil)
		assert.ErrorIs(t, err, ErrMissingTenantID)
	})

	t.Run("missing finding ID", func(t *testing.T) {
		_, err := NewRemediationTask(tenantID, uuid.Nil, "Title", "Desc", "Action", "", nil)
		assert.ErrorIs(t, err, ErrMissingFindingID)
	})

	t.Run("missing title", func(t *testing.T) {
		_, err := NewRemediationTask(tenantID, findingID, "", "Desc", "Action", "", nil)
		assert.ErrorIs(t, err, ErrMissingTaskTitle)
	})
}

func TestRemediationTask_Mutations(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	task, err := NewRemediationTask(tenantID, findingID, "Initial Title", "Desc", "Action", "", nil)
	require.NoError(t, err)

	origUpdated := task.UpdatedAt

	// Assign user
	task.AssignUser("user-42")
	assert.Equal(t, "user-42", task.AssignedUserID)
	assert.True(t, task.UpdatedAt.After(origUpdated) || task.UpdatedAt.Equal(origUpdated))

	// Due date
	newDue := time.Now().Add(24 * time.Hour)
	task.SetTargetCompletionDate(&newDue)
	assert.Equal(t, &newDue, task.TargetCompletionDate)

	// Verification assessment link
	assessmentID := uuid.New()
	task.LinkVerificationAssessment(assessmentID)
	require.NotNil(t, task.VerificationAssessmentID)
	assert.Equal(t, assessmentID, *task.VerificationAssessmentID)

	task.UnlinkVerificationAssessment()
	assert.Nil(t, task.VerificationAssessmentID)

	// Update details
	err = task.UpdateDetails("Updated Title", "New Desc", "New Action")
	require.NoError(t, err)
	assert.Equal(t, "Updated Title", task.Title)

	err = task.UpdateDetails("", "Desc", "Action")
	assert.ErrorIs(t, err, ErrMissingTaskTitle)
}

func TestNewRemediationUpdate_Validation(t *testing.T) {
	tenantID := uuid.New()
	taskID := uuid.New()

	t.Run("valid update", func(t *testing.T) {
		update, err := NewRemediationUpdate(tenantID, taskID, "author-1", "Assigned to backend team", RemediationStateOpen, RemediationStatePlanned)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, update.ID)
		assert.Equal(t, tenantID, update.TenantID)
		assert.Equal(t, taskID, update.TaskID)
		assert.Equal(t, "author-1", update.AuthorID)
		assert.Equal(t, RemediationStateOpen, update.PreviousState)
		assert.Equal(t, RemediationStatePlanned, update.NewState)
	})

	t.Run("missing author", func(t *testing.T) {
		_, err := NewRemediationUpdate(tenantID, taskID, "", "Comment", RemediationStateOpen, RemediationStatePlanned)
		assert.ErrorIs(t, err, ErrMissingAuthorID)
	})

	t.Run("invalid states", func(t *testing.T) {
		_, err := NewRemediationUpdate(tenantID, taskID, "author-1", "Comment", "INVALID", RemediationStatePlanned)
		assert.ErrorIs(t, err, ErrInvalidRemediationState)

		_, err = NewRemediationUpdate(tenantID, taskID, "author-1", "Comment", RemediationStateOpen, "INVALID")
		assert.ErrorIs(t, err, ErrInvalidRemediationState)
	})
}

func TestMemoryRemediationRepository(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRemediationRepository()

	tenant1 := uuid.New()
	tenant2 := uuid.New()
	findingID := uuid.New()

	// 1. Multiple remediation tasks for single finding
	task1, err := NewRemediationTask(tenant1, findingID, "Patch software", "Upgrade package", "Run upgrade", "alice", nil)
	require.NoError(t, err)
	task2, err := NewRemediationTask(tenant1, findingID, "Reconfigure firewall", "Block port 8080", "Update iptables", "bob", nil)
	require.NoError(t, err)

	require.NoError(t, repo.CreateTask(ctx, task1))
	require.NoError(t, repo.CreateTask(ctx, task2))

	// GetTask
	got, err := repo.GetTask(ctx, tenant1, task1.ID)
	require.NoError(t, err)
	assert.Equal(t, "Patch software", got.Title)

	// Tenant boundary isolation
	_, err = repo.GetTask(ctx, tenant2, task1.ID)
	assert.ErrorIs(t, err, ErrTenantMismatch)

	// ListTasksByFinding
	tasks, err := repo.ListTasksByFinding(ctx, tenant1, findingID)
	require.NoError(t, err)
	assert.Len(t, tasks, 2)

	// Cross-tenant list returns empty
	tasksTenant2, err := repo.ListTasksByFinding(ctx, tenant2, findingID)
	require.NoError(t, err)
	assert.Empty(t, tasksTenant2)

	// Update task
	task1.State = RemediationStateInProgress
	require.NoError(t, repo.UpdateTask(ctx, task1))
	gotUpdated, err := repo.GetTask(ctx, tenant1, task1.ID)
	require.NoError(t, err)
	assert.Equal(t, RemediationStateInProgress, gotUpdated.State)

	// Updates history
	update1, err := NewRemediationUpdate(tenant1, task1.ID, "alice", "Started patching", RemediationStateOpen, RemediationStateInProgress)
	require.NoError(t, err)
	require.NoError(t, repo.CreateUpdate(ctx, update1))

	updates, err := repo.ListUpdatesByTask(ctx, tenant1, task1.ID)
	require.NoError(t, err)
	require.Len(t, updates, 1)
	assert.Equal(t, "Started patching", updates[0].Comment)

	// Updates tenant boundary
	_, err = repo.ListUpdatesByTask(ctx, tenant2, task1.ID)
	assert.ErrorIs(t, err, ErrTenantMismatch)

	// Delete task
	require.NoError(t, repo.DeleteTask(ctx, tenant1, task1.ID))
	_, err = repo.GetTask(ctx, tenant1, task1.ID)
	assert.ErrorIs(t, err, ErrTaskNotFound)
}
