package findings

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Standard remediation domain errors
var (
	ErrInvalidRemediationState = errors.New("invalid remediation state")
	ErrMissingTenantID         = errors.New("tenant ID is required")
	ErrMissingFindingID        = errors.New("finding ID is required")
	ErrMissingTaskTitle        = errors.New("remediation task title is required")
	ErrMissingAuthorID         = errors.New("update author ID is required")
	ErrTaskNotFound            = errors.New("remediation task not found")
)

// RemediationState represents the operational status of an action taken to resolve a finding.
type RemediationState string

const (
	RemediationStateOpen                 RemediationState = "OPEN"
	RemediationStatePlanned              RemediationState = "PLANNED"
	RemediationStateInProgress           RemediationState = "IN_PROGRESS"
	RemediationStateBlocked              RemediationState = "BLOCKED"
	RemediationStateReadyForVerification RemediationState = "READY_FOR_VERIFICATION"
	RemediationStateCompleted            RemediationState = "COMPLETED"
	RemediationStateReopened             RemediationState = "REOPENED"
)

// IsValid checks if the state is one of the supported domain states.
func (s RemediationState) IsValid() bool {
	switch s {
	case RemediationStateOpen,
		RemediationStatePlanned,
		RemediationStateInProgress,
		RemediationStateBlocked,
		RemediationStateReadyForVerification,
		RemediationStateCompleted,
		RemediationStateReopened:
		return true
	default:
		return false
	}
}

// RemediationTask represents an actionable item to address a security finding.
// Remediation tasks are tracked separately from persistent finding records, preserving finding identity.
type RemediationTask struct {
	ID                       uuid.UUID        `json:"id"`
	TenantID                 uuid.UUID        `json:"tenant_id"`
	FindingID                uuid.UUID        `json:"finding_id"`
	Title                    string           `json:"title"`
	Description              string           `json:"description"`
	RecommendedAction        string           `json:"recommended_action"`
	State                    RemediationState `json:"state"`
	AssignedUserID           string           `json:"assigned_user_id,omitempty"`
	TargetCompletionDate     *time.Time       `json:"target_completion_date,omitempty"`
	VerificationAssessmentID *uuid.UUID       `json:"verification_assessment_id,omitempty"`
	CreatedAt                time.Time        `json:"created_at"`
	UpdatedAt                time.Time        `json:"updated_at"`
}

// RemediationUpdate models an immutable activity log entry or audit trail item for a task.
type RemediationUpdate struct {
	ID            uuid.UUID        `json:"id"`
	TenantID      uuid.UUID        `json:"tenant_id"`
	TaskID        uuid.UUID        `json:"task_id"`
	AuthorID      string           `json:"author_id"`
	Comment       string           `json:"comment"`
	PreviousState RemediationState `json:"previous_state"`
	NewState      RemediationState `json:"new_state"`
	CreatedAt     time.Time        `json:"created_at"`
}

// NewRemediationTask constructs a validated remediation task initialized in OPEN state.
func NewRemediationTask(
	tenantID, findingID uuid.UUID,
	title, description, recommendedAction string,
	assignedUserID string,
	targetCompletionDate *time.Time,
) (*RemediationTask, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}
	if findingID == uuid.Nil {
		return nil, ErrMissingFindingID
	}
	if title == "" {
		return nil, ErrMissingTaskTitle
	}

	now := time.Now().UTC()
	return &RemediationTask{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		FindingID:            findingID,
		Title:                title,
		Description:          description,
		RecommendedAction:    recommendedAction,
		State:                RemediationStateOpen,
		AssignedUserID:       assignedUserID,
		TargetCompletionDate: targetCompletionDate,
		CreatedAt:            now,
		UpdatedAt:            now,
	}, nil
}

// AssignUser assigns or reassigns the remediation task to a user.
func (t *RemediationTask) AssignUser(userID string) {
	t.AssignedUserID = userID
	t.UpdatedAt = time.Now().UTC()
}

// SetTargetCompletionDate updates the target completion date for the remediation task.
func (t *RemediationTask) SetTargetCompletionDate(dueDate *time.Time) {
	t.TargetCompletionDate = dueDate
	t.UpdatedAt = time.Now().UTC()
}

// LinkVerificationAssessment associates a follow-up assessment used to verify this remediation.
func (t *RemediationTask) LinkVerificationAssessment(assessmentID uuid.UUID) {
	t.VerificationAssessmentID = &assessmentID
	t.UpdatedAt = time.Now().UTC()
}

// UnlinkVerificationAssessment clears the verification assessment reference.
func (t *RemediationTask) UnlinkVerificationAssessment() {
	t.VerificationAssessmentID = nil
	t.UpdatedAt = time.Now().UTC()
}

// UpdateDetails updates the textual details of the remediation task.
func (t *RemediationTask) UpdateDetails(title, description, recommendedAction string) error {
	if title == "" {
		return ErrMissingTaskTitle
	}
	t.Title = title
	t.Description = description
	t.RecommendedAction = recommendedAction
	t.UpdatedAt = time.Now().UTC()
	return nil
}

// NewRemediationUpdate constructs a validated remediation history entry.
func NewRemediationUpdate(
	tenantID, taskID uuid.UUID,
	authorID, comment string,
	previousState, newState RemediationState,
) (*RemediationUpdate, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}
	if taskID == uuid.Nil {
		return nil, errors.New("task ID is required")
	}
	if authorID == "" {
		return nil, ErrMissingAuthorID
	}
	if !previousState.IsValid() || !newState.IsValid() {
		return nil, ErrInvalidRemediationState
	}

	return &RemediationUpdate{
		ID:            uuid.New(),
		TenantID:      tenantID,
		TaskID:        taskID,
		AuthorID:      authorID,
		Comment:       comment,
		PreviousState: previousState,
		NewState:      newState,
		CreatedAt:     time.Now().UTC(),
	}, nil
}

// RemediationRepository defines persistence capabilities for remediation tasks and updates.
type RemediationRepository interface {
	CreateTask(ctx context.Context, task *RemediationTask) error
	GetTask(ctx context.Context, tenantID, taskID uuid.UUID) (*RemediationTask, error)
	ListTasksByFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]RemediationTask, error)
	UpdateTask(ctx context.Context, task *RemediationTask) error
	DeleteTask(ctx context.Context, tenantID, taskID uuid.UUID) error
	CreateUpdate(ctx context.Context, update *RemediationUpdate) error
	ListUpdatesByTask(ctx context.Context, tenantID, taskID uuid.UUID) ([]RemediationUpdate, error)
}

// MemoryRemediationRepository provides a thread-safe in-memory store for testing and isolation.
type MemoryRemediationRepository struct {
	mu      sync.RWMutex
	tasks   map[uuid.UUID]RemediationTask
	updates map[uuid.UUID][]RemediationUpdate
}

// NewMemoryRemediationRepository creates an empty memory repository.
func NewMemoryRemediationRepository() *MemoryRemediationRepository {
	return &MemoryRemediationRepository{
		tasks:   make(map[uuid.UUID]RemediationTask),
		updates: make(map[uuid.UUID][]RemediationUpdate),
	}
}

func (m *MemoryRemediationRepository) CreateTask(_ context.Context, task *RemediationTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if task == nil || task.ID == uuid.Nil {
		return errors.New("invalid task")
	}
	m.tasks[task.ID] = *task
	return nil
}

func (m *MemoryRemediationRepository) GetTask(_ context.Context, tenantID, taskID uuid.UUID) (*RemediationTask, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	task, exists := m.tasks[taskID]
	if !exists {
		return nil, ErrTaskNotFound
	}
	if task.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	copied := task
	return &copied, nil
}

func (m *MemoryRemediationRepository) ListTasksByFinding(_ context.Context, tenantID, findingID uuid.UUID) ([]RemediationTask, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []RemediationTask
	for _, task := range m.tasks {
		if task.TenantID == tenantID && task.FindingID == findingID {
			result = append(result, task)
		}
	}
	return result, nil
}

func (m *MemoryRemediationRepository) UpdateTask(_ context.Context, task *RemediationTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.tasks[task.ID]
	if !exists {
		return ErrTaskNotFound
	}
	if existing.TenantID != task.TenantID {
		return ErrTenantMismatch
	}
	m.tasks[task.ID] = *task
	return nil
}

func (m *MemoryRemediationRepository) DeleteTask(_ context.Context, tenantID, taskID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.tasks[taskID]
	if !exists {
		return ErrTaskNotFound
	}
	if existing.TenantID != tenantID {
		return ErrTenantMismatch
	}
	delete(m.tasks, taskID)
	delete(m.updates, taskID)
	return nil
}

func (m *MemoryRemediationRepository) CreateUpdate(_ context.Context, update *RemediationUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if update == nil || update.ID == uuid.Nil {
		return errors.New("invalid update")
	}
	existingTask, exists := m.tasks[update.TaskID]
	if !exists {
		return ErrTaskNotFound
	}
	if existingTask.TenantID != update.TenantID {
		return ErrTenantMismatch
	}

	m.updates[update.TaskID] = append(m.updates[update.TaskID], *update)
	return nil
}

func (m *MemoryRemediationRepository) ListUpdatesByTask(_ context.Context, tenantID, taskID uuid.UUID) ([]RemediationUpdate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	existingTask, exists := m.tasks[taskID]
	if !exists {
		return nil, ErrTaskNotFound
	}
	if existingTask.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	entries := m.updates[taskID]
	result := make([]RemediationUpdate, len(entries))
	copy(result, entries)
	return result, nil
}
