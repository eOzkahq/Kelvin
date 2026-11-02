package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalidRemediationTransition = errors.New("remediation: invalid state transition")
	ErrReasonRequiredForBlocked     = errors.New("remediation: reason required to block task")
	ErrReasonRequiredForReopened    = errors.New("remediation: reason required to reopen task")
	ErrNoStateChange                = errors.New("remediation: task is already in requested state")
)

// PermittedTransitions defines valid state transitions for the remediation state machine.
var PermittedTransitions = map[RemediationState][]RemediationState{
	RemediationStateOpen: {
		RemediationStatePlanned,
		RemediationStateInProgress,
	},
	RemediationStatePlanned: {
		RemediationStateOpen,
		RemediationStateInProgress,
	},
	RemediationStateInProgress: {
		RemediationStateBlocked,
		RemediationStateReadyForVerification,
		RemediationStatePlanned,
	},
	RemediationStateBlocked: {
		RemediationStateInProgress,
		RemediationStatePlanned,
	},
	RemediationStateReadyForVerification: {
		RemediationStateCompleted,
		RemediationStateReopened,
		RemediationStateInProgress,
	},
	RemediationStateCompleted: {
		RemediationStateReopened,
	},
	RemediationStateReopened: {
		RemediationStateInProgress,
		RemediationStateBlocked,
		RemediationStatePlanned,
	},
}

// ValidateRemediationTransition verifies that the transition from currentState to targetState is permitted
// and validates required rationale where applicable.
func ValidateRemediationTransition(from, to RemediationState, reason string) error {
	if !from.IsValid() || !to.IsValid() {
		return ErrInvalidRemediationState
	}
	if from == to {
		return ErrNoStateChange
	}

	allowed, exists := PermittedTransitions[from]
	if !exists {
		return fmt.Errorf("%w: unknown source state %s", ErrInvalidRemediationTransition, from)
	}

	isAllowed := false
	for _, target := range allowed {
		if target == to {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidRemediationTransition, from, to)
	}

	// Mandatory rationale checks
	if to == RemediationStateBlocked && strings.TrimSpace(reason) == "" {
		return ErrReasonRequiredForBlocked
	}
	if to == RemediationStateReopened && strings.TrimSpace(reason) == "" {
		return ErrReasonRequiredForReopened
	}

	return nil
}

// TransitionResult holds the output of a remediation workflow state transition,
// including notes on finding disposition independence.
type TransitionResult struct {
	Task                 *RemediationTask   `json:"task"`
	Update               *RemediationUpdate `json:"update"`
	FindingStatus        FindingStatus      `json:"finding_status"`
	FindingStatusChanged bool               `json:"finding_status_changed"`
	IndependenceNote     string             `json:"independence_note"`
}

// RemediationWorkflowService manages the lifecycle transitions and audits for remediation tasks.
type RemediationWorkflowService struct {
	repo RemediationRepository
}

// NewRemediationWorkflowService creates a workflow service backed by a remediation repository.
func NewRemediationWorkflowService(repo RemediationRepository) *RemediationWorkflowService {
	return &RemediationWorkflowService{repo: repo}
}

// TransitionTaskState transitions a task to a target state, enforcing transition rules,
// requiring justifications where necessary, persisting audit history, and preserving finding independence.
func (s *RemediationWorkflowService) TransitionTaskState(
	ctx context.Context,
	tenantID, taskID uuid.UUID,
	authorID string,
	targetState RemediationState,
	reason string,
	underlyingFindingStatus FindingStatus,
) (*TransitionResult, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}
	if authorID == "" {
		return nil, ErrMissingAuthorID
	}

	// 1. Fetch task and verify tenant isolation
	task, err := s.repo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}

	// 2. Validate state machine transition
	if err := ValidateRemediationTransition(task.State, targetState, reason); err != nil {
		return nil, err
	}

	previousState := task.State

	// 3. Update task state
	task.State = targetState
	if err := s.repo.UpdateTask(ctx, task); err != nil {
		return nil, fmt.Errorf("failed to update task: %w", err)
	}

	// 4. Create audit update log entry
	comment := reason
	if comment == "" {
		comment = fmt.Sprintf("Remediation state transitioned from %s to %s", previousState, targetState)
	}
	update, err := NewRemediationUpdate(tenantID, taskID, authorID, comment, previousState, targetState)
	if err != nil {
		return nil, fmt.Errorf("failed to construct update entry: %w", err)
	}
	if err := s.repo.CreateUpdate(ctx, update); err != nil {
		return nil, fmt.Errorf("failed to persist update history: %w", err)
	}

	// 5. Evaluate finding status independence invariant:
	// A remediation task marked COMPLETED does NOT automatically resolve the finding.
	// Resolution strictly requires subsequent assessment verification.
	var independenceNote string
	if targetState == RemediationStateCompleted {
		independenceNote = "Remediation marked COMPLETED. Finding lifecycle status remains unchanged until empirically verified by follow-up assessment."
	} else if underlyingFindingStatus == StatusFalsePositive {
		independenceNote = "Finding is categorized as FALSE_POSITIVE; remediation task updated independently."
	} else if underlyingFindingStatus == StatusAcceptedRisk || underlyingFindingStatus == StatusRiskAccepted {
		independenceNote = "Finding risk is ACCEPTED; remediation task updated independently."
	} else {
		independenceNote = "Remediation lifecycle state operates independently from finding status."
	}

	return &TransitionResult{
		Task:                 task,
		Update:               update,
		FindingStatus:        underlyingFindingStatus,
		FindingStatusChanged: false, // Invariant: finding status is NEVER modified by remediation transitions
		IndependenceNote:     independenceNote,
	}, nil
}
