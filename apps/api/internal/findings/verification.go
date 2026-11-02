package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrTaskNotReadyForVerification = errors.New("remediation: task must be in READY_FOR_VERIFICATION state to undergo verification")
	ErrScopeMismatch               = errors.New("remediation: verification assessment target scope mismatch")
	ErrInvalidVerificationOutcome  = errors.New("remediation: invalid verification outcome")
	ErrFindingStoreRequired        = errors.New("remediation: finding store is required")
)

// VerificationOutcome defines the explicit empirical result of a follow-up verification assessment.
type VerificationOutcome string

const (
	VerificationOutcomeVerified         VerificationOutcome = "VERIFIED_RESOLVED"
	VerificationOutcomeFailed           VerificationOutcome = "VERIFICATION_FAILED_STILL_PRESENT"
	VerificationOutcomeInconclusive     VerificationOutcome = "INCONCLUSIVE_INSUFFICIENT_COVERAGE"
	VerificationOutcomeAssessmentFailed VerificationOutcome = "ASSESSMENT_FAILED"
)

// IsValid checks whether an outcome string is a recognized domain verification outcome.
func (v VerificationOutcome) IsValid() bool {
	switch v {
	case VerificationOutcomeVerified,
		VerificationOutcomeFailed,
		VerificationOutcomeInconclusive,
		VerificationOutcomeAssessmentFailed:
		return true
	default:
		return false
	}
}

// VerificationAssessmentData provides the follow-up assessment execution context.
type VerificationAssessmentData struct {
	AssessmentID         uuid.UUID
	Status               string   // e.g. "COMPLETED", "FAILED", "PARTIAL", "CANCELLED"
	Target               string   // host or URL analyzed
	ActiveScanners       []string // scanner adapters executed
	ObservedFingerprints []string // vulnerability fingerprints observed in the run
}

// FindingStore defines the interface required to read and transition findings during verification.
type FindingStore interface {
	GetFindingByID(ctx context.Context, tenantID, findingID uuid.UUID) (*PersistentFinding, error)
	UpdateFindingStatus(
		ctx context.Context,
		tenantID, findingID uuid.UUID,
		newStatus FindingStatus,
		actorUserID *uuid.UUID,
		note string,
		correlationID uuid.UUID,
	) (*PersistentFinding, *FindingEvent, error)
}

// MemoryFindingStore provides an in-memory finding store for testing and isolation.
type MemoryFindingStore struct {
	findings map[uuid.UUID]*PersistentFinding
	events   map[uuid.UUID][]*FindingEvent
}

// NewMemoryFindingStore creates an empty MemoryFindingStore.
func NewMemoryFindingStore() *MemoryFindingStore {
	return &MemoryFindingStore{
		findings: make(map[uuid.UUID]*PersistentFinding),
		events:   make(map[uuid.UUID][]*FindingEvent),
	}
}

// Save stores a persistent finding in the memory store.
func (m *MemoryFindingStore) Save(f *PersistentFinding) {
	m.findings[f.ID] = f
}

// GetFindingByID retrieves a finding by ID and validates tenant boundary.
func (m *MemoryFindingStore) GetFindingByID(_ context.Context, tenantID, findingID uuid.UUID) (*PersistentFinding, error) {
	f, exists := m.findings[findingID]
	if !exists {
		return nil, ErrFindingNotFound
	}
	if f.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return f, nil
}

// UpdateFindingStatus updates the status of a persistent finding and logs an event.
func (m *MemoryFindingStore) UpdateFindingStatus(
	_ context.Context,
	tenantID, findingID uuid.UUID,
	newStatus FindingStatus,
	actorUserID *uuid.UUID,
	note string,
	correlationID uuid.UUID,
) (*PersistentFinding, *FindingEvent, error) {
	f, err := m.GetFindingByID(context.Background(), tenantID, findingID)
	if err != nil {
		return nil, nil, err
	}

	if err := ValidateTransition(f.Status, newStatus); err != nil {
		return nil, nil, err
	}

	fromStatus := f.Status
	f.Status = newStatus
	f.UpdatedAt = time.Now().UTC()

	event := &FindingEvent{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		FromStatus:    &fromStatus,
		ToStatus:      newStatus,
		EventType:     EventTriage,
		ActorUserID:   actorUserID,
		CorrelationID: correlationID,
		Note:          note,
		CreatedAt:     time.Now().UTC(),
	}
	m.events[findingID] = append(m.events[findingID], event)

	return f, event, nil
}

// VerificationResult encapsulates the comprehensive result of a verification assessment.
type VerificationResult struct {
	Outcome              VerificationOutcome `json:"outcome"`
	AssessmentID         uuid.UUID           `json:"assessment_id"`
	TaskID               uuid.UUID           `json:"task_id"`
	FindingID            uuid.UUID           `json:"finding_id"`
	PreviousTaskState    RemediationState    `json:"previous_task_state"`
	NewTaskState         RemediationState    `json:"new_task_state"`
	PreviousFindingState FindingStatus       `json:"previous_finding_state"`
	NewFindingState      FindingStatus       `json:"new_finding_state"`
	Rationale            string              `json:"rationale"`
}

// RemediationVerificationService orchestrates remediation verification workflows.
type RemediationVerificationService struct {
	remediationRepo RemediationRepository
	workflowService *RemediationWorkflowService
	findingStore    FindingStore
}

// NewRemediationVerificationService constructs a verification service.
func NewRemediationVerificationService(
	remediationRepo RemediationRepository,
	workflowService *RemediationWorkflowService,
	findingStore FindingStore,
) *RemediationVerificationService {
	return &RemediationVerificationService{
		remediationRepo: remediationRepo,
		workflowService: workflowService,
		findingStore:    findingStore,
	}
}

// helper to extract scanner name from persistent finding scanner metadata
func getFindingScannerType(f *PersistentFinding) string {
	if f == nil || f.ScannerData == nil {
		return ""
	}
	if s, ok := f.ScannerData["scanner_type"].(string); ok && s != "" {
		return s
	}
	if s, ok := f.ScannerData["tool_name"].(string); ok && s != "" {
		return s
	}
	if s, ok := f.ScannerData["scanner_id"].(string); ok && s != "" {
		return s
	}
	return ""
}

// VerifyRemediation evaluates follow-up assessment results against a remediation task in READY_FOR_VERIFICATION state.
func (s *RemediationVerificationService) VerifyRemediation(
	ctx context.Context,
	tenantID, taskID uuid.UUID,
	assessment VerificationAssessmentData,
	actorID string,
) (*VerificationResult, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}
	if actorID == "" {
		return nil, ErrMissingAuthorID
	}
	if s.findingStore == nil {
		return nil, ErrFindingStoreRequired
	}

	// 1. Fetch remediation task and check tenant boundary
	task, err := s.remediationRepo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}

	// Invariant: Task must be in READY_FOR_VERIFICATION state
	if task.State != RemediationStateReadyForVerification {
		return nil, fmt.Errorf("%w: current state is %s", ErrTaskNotReadyForVerification, task.State)
	}

	// 2. Fetch associated finding
	finding, err := s.findingStore.GetFindingByID(ctx, tenantID, task.FindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve associated finding: %w", err)
	}

	// 3. Target Scope Validation:
	// Verify that the assessment target matches the finding target
	if assessment.Target != "" && finding.AffectedEndpoint != "" {
		cleanAssessmentTarget := strings.ToLower(strings.TrimRight(assessment.Target, "/"))
		cleanFindingTarget := strings.ToLower(strings.TrimRight(finding.AffectedEndpoint, "/"))
		if !strings.Contains(cleanAssessmentTarget, cleanFindingTarget) && !strings.Contains(cleanFindingTarget, cleanAssessmentTarget) {
			return nil, fmt.Errorf("%w: assessment target %q does not match finding endpoint %q", ErrScopeMismatch, assessment.Target, finding.AffectedEndpoint)
		}
	}

	// Associate verification assessment ID with remediation task
	task.LinkVerificationAssessment(assessment.AssessmentID)
	if err := s.remediationRepo.UpdateTask(ctx, task); err != nil {
		return nil, fmt.Errorf("failed to link assessment to remediation task: %w", err)
	}

	prevTaskState := task.State
	prevFindingState := finding.Status

	// 4. Evaluate Assessment Status (Failed / Incomplete)
	statusUpper := strings.ToUpper(assessment.Status)
	if statusUpper == "FAILED" || statusUpper == "CANCELLED" {
		rationale := fmt.Sprintf("Follow-up assessment %s failed with status %s; verification inconclusive", assessment.AssessmentID, statusUpper)
		update, _ := NewRemediationUpdate(tenantID, taskID, actorID, rationale, task.State, task.State)
		_ = s.remediationRepo.CreateUpdate(ctx, update)

		return &VerificationResult{
			Outcome:              VerificationOutcomeAssessmentFailed,
			AssessmentID:         assessment.AssessmentID,
			TaskID:               taskID,
			FindingID:            finding.ID,
			PreviousTaskState:    prevTaskState,
			NewTaskState:         task.State,
			PreviousFindingState: prevFindingState,
			NewFindingState:      finding.Status,
			Rationale:            rationale,
		}, nil
	}

	// 5. Evaluate Scanner Coverage:
	// Verification requires that the scanner capable of detecting the original flaw was executed
	scannerName := getFindingScannerType(finding)
	hasScannerCoverage := false
	if len(assessment.ActiveScanners) > 0 {
		for _, scanner := range assessment.ActiveScanners {
			if strings.EqualFold(scanner, scannerName) || scanner == "all" || scannerName == "" {
				hasScannerCoverage = true
				break
			}
		}
	}

	if !hasScannerCoverage && scannerName != "" {
		rationale := fmt.Sprintf("Follow-up assessment %s lacked coverage for original tool (%s); verification marked inconclusive", assessment.AssessmentID, scannerName)
		update, _ := NewRemediationUpdate(tenantID, taskID, actorID, rationale, task.State, task.State)
		_ = s.remediationRepo.CreateUpdate(ctx, update)

		return &VerificationResult{
			Outcome:              VerificationOutcomeInconclusive,
			AssessmentID:         assessment.AssessmentID,
			TaskID:               taskID,
			FindingID:            finding.ID,
			PreviousTaskState:    prevTaskState,
			NewTaskState:         task.State,
			PreviousFindingState: prevFindingState,
			NewFindingState:      finding.Status,
			Rationale:            rationale,
		}, nil
	}

	// 6. Compare Observations with Original Finding Fingerprint
	flawObserved := false
	for _, fp := range assessment.ObservedFingerprints {
		if fp == finding.Fingerprint {
			flawObserved = true
			break
		}
	}

	if flawObserved {
		// Verification Failed: Flaw still detected!
		rationale := fmt.Sprintf("Vulnerability fingerprint %s still detected in verification assessment %s", finding.Fingerprint, assessment.AssessmentID)

		// Transition remediation task to REOPENED
		_, err := s.workflowService.TransitionTaskState(
			ctx,
			tenantID,
			taskID,
			actorID,
			RemediationStateReopened,
			rationale,
			finding.Status,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to transition task to REOPENED: %w", err)
		}

		// Transition finding if it had been resolved previously
		newFindingStatus := finding.Status
		if finding.Status == StatusResolved {
			updatedFinding, _, err := s.findingStore.UpdateFindingStatus(
				ctx,
				tenantID,
				finding.ID,
				StatusReopened,
				nil,
				rationale,
				assessment.AssessmentID,
			)
			if err == nil {
				newFindingStatus = updatedFinding.Status
			}
		}

		return &VerificationResult{
			Outcome:              VerificationOutcomeFailed,
			AssessmentID:         assessment.AssessmentID,
			TaskID:               taskID,
			FindingID:            finding.ID,
			PreviousTaskState:    prevTaskState,
			NewTaskState:         RemediationStateReopened,
			PreviousFindingState: prevFindingState,
			NewFindingState:      newFindingStatus,
			Rationale:            rationale,
		}, nil
	}

	// 7. Flaw Not Observed and Scanner Coverage Present: Verification Succeeded!
	rationale := fmt.Sprintf("Vulnerability fingerprint %s not detected in verification assessment %s with active scanner coverage; resolved", finding.Fingerprint, assessment.AssessmentID)

	// Transition remediation task to COMPLETED
	_, err = s.workflowService.TransitionTaskState(
		ctx,
		tenantID,
		taskID,
		actorID,
		RemediationStateCompleted,
		rationale,
		finding.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to transition task to COMPLETED: %w", err)
	}

	// Transition finding to RESOLVED
	newFindingStatus := finding.Status
	if finding.Status != StatusResolved {
		updatedFinding, _, err := s.findingStore.UpdateFindingStatus(
			ctx,
			tenantID,
			finding.ID,
			StatusResolved,
			nil,
			rationale,
			assessment.AssessmentID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to transition finding to RESOLVED: %w", err)
		}
		newFindingStatus = updatedFinding.Status
	}

	return &VerificationResult{
		Outcome:              VerificationOutcomeVerified,
		AssessmentID:         assessment.AssessmentID,
		TaskID:               taskID,
		FindingID:            finding.ID,
		PreviousTaskState:    prevTaskState,
		NewTaskState:         RemediationStateCompleted,
		PreviousFindingState: prevFindingState,
		NewFindingState:      newFindingStatus,
		Rationale:            rationale,
	}, nil
}
