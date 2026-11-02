package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemediationAssignmentService(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRemediationRepository()
	validator := NewMemoryUserValidator()
	service := NewRemediationAssignmentService(repo, validator)

	tenant1 := uuid.New()
	tenant2 := uuid.New()
	findingID := uuid.New()

	// Register users
	validator.RegisterUser(tenant1, "alice")
	validator.RegisterUser(tenant1, "bob")
	validator.RegisterUser(tenant2, "eve") // different tenant

	task, err := NewRemediationTask(tenant1, findingID, "Upgrade TLS Cipher Suites", "Disable 3DES and RC4", "Update nginx.conf", "", nil)
	require.NoError(t, err)
	require.NoError(t, repo.CreateTask(ctx, task))

	t.Run("valid initial assignment", func(t *testing.T) {
		dueDate := time.Now().Add(72 * time.Hour).UTC()
		assignedTask, update, err := service.AssignTask(ctx, tenant1, task.ID, "lead-1", "alice", &dueDate, "Assigned for Sprint 14")
		require.NoError(t, err)
		assert.Equal(t, "alice", assignedTask.AssignedUserID)
		require.NotNil(t, assignedTask.TargetCompletionDate)
		assert.Equal(t, &dueDate, assignedTask.TargetCompletionDate)

		require.NotNil(t, update)
		assert.Contains(t, update.Comment, "Task assigned to alice")
		assert.Contains(t, update.Comment, "Sprint 14")
	})

	t.Run("valid reassignment", func(t *testing.T) {
		newDueDate := time.Now().Add(96 * time.Hour).UTC()
		reassignedTask, update, err := service.AssignTask(ctx, tenant1, task.ID, "lead-1", "bob", &newDueDate, "Alice out of office")
		require.NoError(t, err)
		assert.Equal(t, "bob", reassignedTask.AssignedUserID)

		require.NotNil(t, update)
		assert.Contains(t, update.Comment, "Task reassigned from alice to bob")
		assert.Contains(t, update.Comment, "Alice out of office")
	})

	t.Run("due date in past is rejected", func(t *testing.T) {
		pastDueDate := time.Now().Add(-2 * time.Hour)
		_, _, err := service.AssignTask(ctx, tenant1, task.ID, "lead-1", "bob", &pastDueDate, "")
		assert.ErrorIs(t, err, ErrDueDateInPast)
	})

	t.Run("cross-tenant assignment is rejected", func(t *testing.T) {
		// Attempt to assign 'eve' (who belongs to tenant2) to tenant1 task
		_, _, err := service.AssignTask(ctx, tenant1, task.ID, "lead-1", "eve", nil, "cross tenant attempt")
		assert.ErrorIs(t, err, ErrInvalidUserAssignment)
	})

	t.Run("non-existent user is rejected", func(t *testing.T) {
		_, _, err := service.AssignTask(ctx, tenant1, task.ID, "lead-1", "non-existent-user", nil, "")
		assert.ErrorIs(t, err, ErrInvalidUserAssignment)
	})

	t.Run("cross-tenant task access is rejected", func(t *testing.T) {
		_, _, err := service.AssignTask(ctx, tenant2, task.ID, "lead-2", "eve", nil, "")
		assert.ErrorIs(t, err, ErrTenantMismatch)
	})

	t.Run("unassign task", func(t *testing.T) {
		unassignedTask, update, err := service.UnassignTask(ctx, tenant1, task.ID, "lead-1", "Assignee departed organization")
		require.NoError(t, err)
		assert.Empty(t, unassignedTask.AssignedUserID)
		assert.Contains(t, update.Comment, "Task unassigned (previously assigned to: bob)")
	})

	t.Run("add progress notes", func(t *testing.T) {
		noteUpdate, err := service.AddProgressNote(ctx, tenant1, task.ID, "alice", "Created PR #123 on backend repo for review")
		require.NoError(t, err)
		assert.Equal(t, "Created PR #123 on backend repo for review", noteUpdate.Comment)
		assert.Equal(t, task.ID, noteUpdate.TaskID)

		// Empty note rejected
		_, err = service.AddProgressNote(ctx, tenant1, task.ID, "alice", "   ")
		assert.ErrorIs(t, err, ErrEmptyProgressNote)
	})
}
