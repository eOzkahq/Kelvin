package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidUserAssignment = errors.New("remediation: user does not belong to tenant or is not authorized")
	ErrDueDateInPast         = errors.New("remediation: due date cannot be in the past")
	ErrEmptyProgressNote     = errors.New("remediation: progress note cannot be empty")
)

// UserValidator verifies that an assignee identity is active and eligible within the tenant boundary.
type UserValidator interface {
	ValidateUserInTenant(ctx context.Context, tenantID uuid.UUID, userID string) (bool, error)
}

// MemoryUserValidator provides a thread-safe tenant user directory validator for testing and isolation.
type MemoryUserValidator struct {
	mu    sync.RWMutex
	users map[uuid.UUID]map[string]bool
}

// NewMemoryUserValidator initializes an in-memory user eligibility validator.
func NewMemoryUserValidator() *MemoryUserValidator {
	return &MemoryUserValidator{
		users: make(map[uuid.UUID]map[string]bool),
	}
}

// RegisterUser registers a user ID to a tenant.
func (v *MemoryUserValidator) RegisterUser(tenantID uuid.UUID, userID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.users[tenantID]; !exists {
		v.users[tenantID] = make(map[string]bool)
	}
	v.users[tenantID][userID] = true
}

// RevokeUser removes a user's eligibility from a tenant.
func (v *MemoryUserValidator) RevokeUser(tenantID uuid.UUID, userID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if tenantUsers, exists := v.users[tenantID]; exists {
		delete(tenantUsers, userID)
	}
}

// ValidateUserInTenant implements the UserValidator interface.
func (v *MemoryUserValidator) ValidateUserInTenant(_ context.Context, tenantID uuid.UUID, userID string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	tenantUsers, exists := v.users[tenantID]
	if !exists {
		return false, nil
	}
	return tenantUsers[userID], nil
}

// RemediationAssignmentService coordinates user assignment, re-assignment, due dates, and progress tracking.
type RemediationAssignmentService struct {
	repo          RemediationRepository
	userValidator UserValidator
}

// NewRemediationAssignmentService constructs an assignment service.
func NewRemediationAssignmentService(repo RemediationRepository, validator UserValidator) *RemediationAssignmentService {
	return &RemediationAssignmentService{
		repo:          repo,
		userValidator: validator,
	}
}

// AssignTask assigns or reassigns a remediation task to an authorized tenant user and optionally sets a due date.
func (s *RemediationAssignmentService) AssignTask(
	ctx context.Context,
	tenantID, taskID uuid.UUID,
	actorID string,
	newAssigneeID string,
	dueDate *time.Time,
	reason string,
) (*RemediationTask, *RemediationUpdate, error) {
	if tenantID == uuid.Nil {
		return nil, nil, ErrMissingTenantID
	}
	if actorID == "" {
		return nil, nil, ErrMissingAuthorID
	}
	newAssigneeID = strings.TrimSpace(newAssigneeID)
	if newAssigneeID == "" {
		return nil, nil, errors.New("remediation: assignee ID cannot be empty")
	}

	// 1. Fetch task and ensure tenant boundary
	task, err := s.repo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, nil, err
	}

	// 2. Validate tenant-scoped user authorization
	if s.userValidator != nil {
		valid, err := s.userValidator.ValidateUserInTenant(ctx, tenantID, newAssigneeID)
		if err != nil {
			return nil, nil, fmt.Errorf("user validation failed: %w", err)
		}
		if !valid {
			return nil, nil, ErrInvalidUserAssignment
		}
	}

	// 3. Validate due date if specified
	if dueDate != nil {
		now := time.Now().UTC()
		// Allow small 5-minute clock tolerance
		if dueDate.Before(now.Add(-5 * time.Minute)) {
			return nil, nil, ErrDueDateInPast
		}
	}

	previousAssignee := task.AssignedUserID
	previousDueDate := task.TargetCompletionDate

	// 4. Update task fields
	task.AssignUser(newAssigneeID)
	task.SetTargetCompletionDate(dueDate)

	if err := s.repo.UpdateTask(ctx, task); err != nil {
		return nil, nil, fmt.Errorf("failed to persist assigned task: %w", err)
	}

	// 5. Construct audit update history
	var comment string
	dueStr := "none"
	if dueDate != nil {
		dueStr = dueDate.UTC().Format(time.RFC3339)
	}

	if previousAssignee == "" {
		comment = fmt.Sprintf("Task assigned to %s (due: %s)", newAssigneeID, dueStr)
	} else if previousAssignee != newAssigneeID {
		comment = fmt.Sprintf("Task reassigned from %s to %s (due: %s)", previousAssignee, newAssigneeID, dueStr)
	} else {
		comment = fmt.Sprintf("Task assignment updated for %s (due: %s)", newAssigneeID, dueStr)
	}

	if strings.TrimSpace(reason) != "" {
		comment += fmt.Sprintf(" - Reason: %s", reason)
	}

	update, err := NewRemediationUpdate(tenantID, taskID, actorID, comment, task.State, task.State)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct assignment update: %w", err)
	}

	if err := s.repo.CreateUpdate(ctx, update); err != nil {
		return nil, nil, fmt.Errorf("failed to record assignment history: %w", err)
	}

	_ = previousDueDate // preserved for history traceability
	return task, update, nil
}

// UnassignTask unassigns the task (e.g. when an assignee is decommissioned or leaves the team).
func (s *RemediationAssignmentService) UnassignTask(
	ctx context.Context,
	tenantID, taskID uuid.UUID,
	actorID string,
	reason string,
) (*RemediationTask, *RemediationUpdate, error) {
	if tenantID == uuid.Nil {
		return nil, nil, ErrMissingTenantID
	}
	if actorID == "" {
		return nil, nil, ErrMissingAuthorID
	}

	task, err := s.repo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, nil, err
	}

	previousAssignee := task.AssignedUserID
	task.AssignUser("")

	if err := s.repo.UpdateTask(ctx, task); err != nil {
		return nil, nil, fmt.Errorf("failed to update unassigned task: %w", err)
	}

	comment := fmt.Sprintf("Task unassigned (previously assigned to: %s)", previousAssignee)
	if strings.TrimSpace(reason) != "" {
		comment += fmt.Sprintf(" - Reason: %s", reason)
	}

	update, err := NewRemediationUpdate(tenantID, taskID, actorID, comment, task.State, task.State)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct unassign update: %w", err)
	}

	if err := s.repo.CreateUpdate(ctx, update); err != nil {
		return nil, nil, fmt.Errorf("failed to record unassign update: %w", err)
	}

	return task, update, nil
}

// AddProgressNote records a progress note or comment against a remediation task.
func (s *RemediationAssignmentService) AddProgressNote(
	ctx context.Context,
	tenantID, taskID uuid.UUID,
	authorID string,
	note string,
) (*RemediationUpdate, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}
	if authorID == "" {
		return nil, ErrMissingAuthorID
	}
	if strings.TrimSpace(note) == "" {
		return nil, ErrEmptyProgressNote
	}

	task, err := s.repo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}

	update, err := NewRemediationUpdate(tenantID, taskID, authorID, note, task.State, task.State)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateUpdate(ctx, update); err != nil {
		return nil, fmt.Errorf("failed to persist progress note: %w", err)
	}

	return update, nil
}
