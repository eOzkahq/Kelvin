package progress

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Stage denotes a discrete, normalized phase of assessment scanner execution.
type Stage string

const (
	// StagePreflight encompasses readiness verification, scope authorization, and workspace provisioning.
	StagePreflight Stage = "PREFLIGHT"

	// StageScannerInitialization encompasses configuration decoding, container spec synthesis, and proxy setup.
	StageScannerInitialization Stage = "SCANNER_INITIALIZATION"

	// StageScannerExecution encompasses active invocation of the scanner process or container.
	StageScannerExecution Stage = "SCANNER_EXECUTION"

	// StageOutputCollection encompasses gathering raw stdout/stderr, report files, and exit metadata.
	StageOutputCollection Stage = "OUTPUT_COLLECTION"

	// StageResultNormalization encompasses parsing raw output, validating schema, and creating canonical findings.
	StageResultNormalization Stage = "RESULT_NORMALIZATION"

	// StageCompletion encompasses workspace teardown, envelope stamping, and terminal metrics recording.
	StageCompletion Stage = "COMPLETION"
)

// Valid returns true if the stage is one of the recognized normalized execution stages.
func (s Stage) Valid() bool {
	switch s {
	case StagePreflight, StageScannerInitialization, StageScannerExecution,
		StageOutputCollection, StageResultNormalization, StageCompletion:
		return true
	default:
		return false
	}
}

// StageStatus represents the execution state of a specific stage.
type StageStatus string

const (
	StageStatusPending    StageStatus = "PENDING"
	StageStatusInProgress StageStatus = "IN_PROGRESS"
	StageStatusCompleted  StageStatus = "COMPLETED"
	StageStatusFailed     StageStatus = "FAILED"
	StageStatusCancelled  StageStatus = "CANCELLED"
	StageStatusTimedOut   StageStatus = "TIMED_OUT"
)

// Valid returns true if the status is valid.
func (s StageStatus) Valid() bool {
	switch s {
	case StageStatusPending, StageStatusInProgress, StageStatusCompleted,
		StageStatusFailed, StageStatusCancelled, StageStatusTimedOut:
		return true
	default:
		return false
	}
}

// StageTransition records an immutable transition event between execution stages.
type StageTransition struct {
	FromStage Stage         `json:"from_stage,omitempty"`
	ToStage   Stage         `json:"to_stage"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration_ms,omitempty"`
	Details   string        `json:"details,omitempty"`
}

// Tracker maintains observable, traceable stage transitions and progress state.
type Tracker struct {
	assessmentID string
	jobID        string
	tenantID     string
	scanner      string

	mu             sync.RWMutex
	currentStage   Stage
	currentStatus  StageStatus
	stageStartedAt time.Time
	transitions    []StageTransition
	lastProgress   *ScannerProgress

	publisher Publisher
	logger    *zap.Logger
}

// NewTracker constructs an initialized execution stage tracker.
func NewTracker(assessmentID, jobID, tenantID, scanner string, pub Publisher, log *zap.Logger) *Tracker {
	if pub == nil {
		pub = NewNopPublisher()
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Tracker{
		assessmentID: assessmentID,
		jobID:        jobID,
		tenantID:     tenantID,
		scanner:      scanner,
		publisher:    pub,
		logger:       log,
	}
}

// TransitionTo moves the tracker to a new normalized stage, recording timestamped transition history.
func (t *Tracker) TransitionTo(ctx context.Context, to Stage, details string) error {
	t.mu.Lock()
	now := time.Now().UTC()
	var duration time.Duration
	from := t.currentStage

	if !t.stageStartedAt.IsZero() {
		duration = now.Sub(t.stageStartedAt)
	}

	sanitizedDetails := SanitizeMessage(details)
	transition := StageTransition{
		FromStage: from,
		ToStage:   to,
		Timestamp: now,
		Duration:  duration,
		Details:   sanitizedDetails,
	}
	t.transitions = append(t.transitions, transition)
	t.currentStage = to
	t.currentStatus = StageStatusInProgress
	t.stageStartedAt = now
	t.lastProgress = nil

	history := make([]StageTransition, len(t.transitions))
	copy(history, t.transitions)
	t.mu.Unlock()

	event := ProgressEvent{
		EventID:      uuid.NewString(),
		AssessmentID: t.assessmentID,
		JobID:        t.jobID,
		TenantID:     t.tenantID,
		Scanner:      t.scanner,
		Stage:        to,
		StageStatus:  StageStatusInProgress,
		Timestamp:    now,
		Transitions:  history,
	}

	t.logger.Info("stage transition",
		zap.String("job_id", t.jobID),
		zap.String("scanner", t.scanner),
		zap.String("from_stage", string(from)),
		zap.String("to_stage", string(to)),
		zap.Duration("duration", duration),
	)

	return t.publisher.PublishProgress(ctx, event)
}

// ReportProgress updates and publishes the scanner progress within the current stage.
func (t *Tracker) ReportProgress(ctx context.Context, p ScannerProgress) error {
	t.mu.Lock()
	now := time.Now().UTC()
	p.UpdatedAt = now
	p.Message = SanitizeMessage(p.Message)
	t.lastProgress = &p

	currentStage := t.currentStage
	currentStatus := t.currentStatus
	history := make([]StageTransition, len(t.transitions))
	copy(history, t.transitions)
	t.mu.Unlock()

	event := ProgressEvent{
		EventID:      uuid.NewString(),
		AssessmentID: t.assessmentID,
		JobID:        t.jobID,
		TenantID:     t.tenantID,
		Scanner:      t.scanner,
		Stage:        currentStage,
		StageStatus:  currentStatus,
		Progress:     &p,
		Timestamp:    now,
		Transitions:  history,
	}

	return t.publisher.PublishProgress(ctx, event)
}

// FailStage marks the current stage as terminated prematurely (e.g. FAILED, CANCELLED, or TIMED_OUT).
func (t *Tracker) FailStage(ctx context.Context, status StageStatus, details string) error {
	t.mu.Lock()
	now := time.Now().UTC()
	var duration time.Duration
	if !t.stageStartedAt.IsZero() {
		duration = now.Sub(t.stageStartedAt)
	}

	sanitizedDetails := SanitizeMessage(details)
	transition := StageTransition{
		FromStage: t.currentStage,
		ToStage:   t.currentStage,
		Timestamp: now,
		Duration:  duration,
		Details:   fmt.Sprintf("[%s] %s", status, sanitizedDetails),
	}
	t.transitions = append(t.transitions, transition)
	t.currentStatus = status

	currentStage := t.currentStage
	history := make([]StageTransition, len(t.transitions))
	copy(history, t.transitions)
	lastProg := t.lastProgress
	t.mu.Unlock()

	event := ProgressEvent{
		EventID:      uuid.NewString(),
		AssessmentID: t.assessmentID,
		JobID:        t.jobID,
		TenantID:     t.tenantID,
		Scanner:      t.scanner,
		Stage:        currentStage,
		StageStatus:  status,
		Progress:     lastProg,
		Timestamp:    now,
		Transitions:  history,
	}

	t.logger.Info("stage terminated",
		zap.String("job_id", t.jobID),
		zap.String("scanner", t.scanner),
		zap.String("stage", string(currentStage)),
		zap.String("status", string(status)),
		zap.String("details", sanitizedDetails),
	)

	return t.publisher.PublishProgress(ctx, event)
}

// CompleteStage transitions the tracker to completion.
func (t *Tracker) CompleteStage(ctx context.Context, details string) error {
	t.mu.Lock()
	now := time.Now().UTC()
	var duration time.Duration
	if !t.stageStartedAt.IsZero() {
		duration = now.Sub(t.stageStartedAt)
	}

	sanitizedDetails := SanitizeMessage(details)
	transition := StageTransition{
		FromStage: t.currentStage,
		ToStage:   StageCompletion,
		Timestamp: now,
		Duration:  duration,
		Details:   sanitizedDetails,
	}
	t.transitions = append(t.transitions, transition)
	t.currentStage = StageCompletion
	t.currentStatus = StageStatusCompleted

	history := make([]StageTransition, len(t.transitions))
	copy(history, t.transitions)
	t.mu.Unlock()

	event := ProgressEvent{
		EventID:      uuid.NewString(),
		AssessmentID: t.assessmentID,
		JobID:        t.jobID,
		TenantID:     t.tenantID,
		Scanner:      t.scanner,
		Stage:        StageCompletion,
		StageStatus:  StageStatusCompleted,
		Timestamp:    now,
		Transitions:  history,
	}

	t.logger.Info("stage completed",
		zap.String("job_id", t.jobID),
		zap.String("scanner", t.scanner),
		zap.String("stage", string(StageCompletion)),
	)

	return t.publisher.PublishProgress(ctx, event)
}

// CurrentStage returns the current stage under observation.
func (t *Tracker) CurrentStage() Stage {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.currentStage
}

// CurrentStatus returns the current stage status.
func (t *Tracker) CurrentStatus() StageStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.currentStatus
}

// Transitions returns an immutable copy of all recorded stage transitions.
func (t *Tracker) Transitions() []StageTransition {
	t.mu.RLock()
	defer t.mu.RUnlock()
	copied := make([]StageTransition, len(t.transitions))
	copy(copied, t.transitions)
	return copied
}
