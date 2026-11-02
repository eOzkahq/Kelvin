package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type EnforcementPoint string

const (
	PointAssessmentCreate   EnforcementPoint = "ASSESSMENT_CREATE"
	PointAssessmentSchedule EnforcementPoint = "ASSESSMENT_SCHEDULE"
	PointWorkerExecution    EnforcementPoint = "WORKER_EXECUTION"
	PointProfileSelect      EnforcementPoint = "PROFILE_SELECT"
	PointFindingTriage      EnforcementPoint = "FINDING_TRIAGE"
	PointRemediationAction  EnforcementPoint = "REMEDIATION_ACTION"
	PointExceptionApproval  EnforcementPoint = "EXCEPTION_APPROVAL"
	PointIntegrationTrigger EnforcementPoint = "INTEGRATION_TRIGGER"
)

type JobAction string

const (
	JobActionContinue  JobAction = "CONTINUE"
	JobActionPause     JobAction = "PAUSE"
	JobActionTerminate JobAction = "TERMINATE"
	JobActionAuditOnly JobAction = "AUDIT_ONLY"
)

var (
	ErrQueuedJobPolicyViolation  = errors.New("queued job violates updated policy governance and cannot be dispatched")
	ErrActiveJobTerminated       = errors.New("in-progress job terminated due to critical policy violation")
	ErrMissingEnforcementPoint   = errors.New("enforcement point must be specified")
	ErrMissingResourceIdentifier = errors.New("resource identifier must be specified")
)

// EnforcementRequest wraps an operation evaluation request across any application boundary.
type EnforcementRequest struct {
	Point         EnforcementPoint
	PolicyType    PolicyType
	EvalContext   EvaluationContext
	ResourceID    string
	PolicyVersion int
}

// EnforcementVerdict records the decision and full explainability trace.
type EnforcementVerdict struct {
	ID            uuid.UUID
	Point         EnforcementPoint
	ResourceID    string
	SubjectID     string
	OrgID         uuid.UUID
	Allowed       bool
	Action        PolicyAction
	Decision      PolicyDecision
	PolicyVersion int
	EnforcedAt    time.Time
}

// JobContext represents metadata of a queued or active scanning job.
type JobContext struct {
	JobID          uuid.UUID
	OrganizationID uuid.UUID
	WorkspaceID    uuid.UUID
	TargetID       string
	ScannerID      string
	QueuedAt       time.Time
	StartedAt      *time.Time
	Attributes     map[string]any
}

// EnforcementGatekeeper unifies policy evaluations across API, queue, worker, and webhook boundaries.
type EnforcementGatekeeper struct {
	mu      sync.RWMutex
	engine  *PolicyEngine
	records []EnforcementVerdict
}

func NewEnforcementGatekeeper(engine *PolicyEngine) *EnforcementGatekeeper {
	return &EnforcementGatekeeper{
		engine:  engine,
		records: make([]EnforcementVerdict, 0),
	}
}

// Enforce synchronously evaluates policy at any application boundary with audit recording.
func (g *EnforcementGatekeeper) Enforce(ctx context.Context, req EnforcementRequest) (*EnforcementVerdict, error) {
	if req.Point == "" {
		return nil, ErrMissingEnforcementPoint
	}
	if req.ResourceID == "" {
		return nil, ErrMissingResourceIdentifier
	}
	if req.PolicyVersion <= 0 {
		req.PolicyVersion = 1
	}

	pType := req.PolicyType
	if pType == "" {
		if req.EvalContext.OperationType != "" {
			pType = PolicyType(req.EvalContext.OperationType)
		} else {
			switch req.Point {
			case PointAssessmentCreate, PointAssessmentSchedule, PointWorkerExecution, PointProfileSelect:
				pType = PolicyTypeScanExecution
			case PointFindingTriage, PointRemediationAction:
				pType = PolicyTypeFindingAction
			default:
				pType = PolicyTypeIntegrationAccess
			}
		}
	}

	decision, err := g.engine.Evaluate(ctx, req.EvalContext, pType)
	if err != nil {
		// Fail-closed enforcement
		verdict := &EnforcementVerdict{
			ID:            uuid.New(),
			Point:         req.Point,
			ResourceID:    req.ResourceID,
			SubjectID:     req.EvalContext.SubjectID,
			OrgID:         req.EvalContext.OrganizationID,
			Allowed:       false,
			Action:        ActionDeny,
			Decision:      decision,
			PolicyVersion: req.PolicyVersion,
			EnforcedAt:    time.Now().UTC(),
		}
		g.recordVerdict(verdict)
		return verdict, fmt.Errorf("%w: %v", ErrPolicyEvaluationFailed, err)
	}

	verdict := &EnforcementVerdict{
		ID:            uuid.New(),
		Point:         req.Point,
		ResourceID:    req.ResourceID,
		SubjectID:     req.EvalContext.SubjectID,
		OrgID:         req.EvalContext.OrganizationID,
		Allowed:       decision.Allowed,
		Action:        decision.Action,
		Decision:      decision,
		PolicyVersion: req.PolicyVersion,
		EnforcedAt:    time.Now().UTC(),
	}
	g.recordVerdict(verdict)

	if !decision.Allowed {
		switch decision.Action {
		case ActionRequireApproval:
			return verdict, ErrPolicyRequiresApproval
		default:
			return verdict, ErrPolicyBlocked
		}
	}

	return verdict, nil
}

// ValidateQueuedJob re-evaluates policies when a worker dequeues a job to ensure queued work doesn't bypass policy updates.
func (g *EnforcementGatekeeper) ValidateQueuedJob(ctx context.Context, job JobContext) (*EnforcementVerdict, error) {
	evalCtx := EvaluationContext{
		TenantID:       job.OrganizationID,
		OrganizationID: job.OrganizationID,
		WorkspaceID:    job.WorkspaceID,
		TargetID:       job.TargetID,
		SubjectID:      "system:worker",
		OperationType:  string(PolicyTypeScanExecution),
		Attributes:     job.Attributes,
	}

	verdict, err := g.Enforce(ctx, EnforcementRequest{
		Point:         PointWorkerExecution,
		EvalContext:   evalCtx,
		ResourceID:    job.JobID.String(),
		PolicyVersion: 1,
	})
	if err != nil {
		return verdict, fmt.Errorf("%w: %v", ErrQueuedJobPolicyViolation, err)
	}

	return verdict, nil
}

// EvaluateActiveJobOnPolicyChange determines whether an in-progress scan should continue, pause, or terminate.
func (g *EnforcementGatekeeper) EvaluateActiveJobOnPolicyChange(
	ctx context.Context,
	job JobContext,
	updatedRule PolicyRule,
) (JobAction, error) {
	evalCtx := EvaluationContext{
		TenantID:       job.OrganizationID,
		OrganizationID: job.OrganizationID,
		WorkspaceID:    job.WorkspaceID,
		TargetID:       job.TargetID,
		SubjectID:      "system:worker",
		OperationType:  string(updatedRule.Type),
		Attributes:     job.Attributes,
	}

	// Check if updated rule condition applies
	if updatedRule.Condition != nil {
		applies, err := updatedRule.Condition(ctx, evalCtx)
		if err != nil {
			// Fail-closed for condition errors
			return JobActionTerminate, ErrPolicyEvaluationFailed
		}
		if applies {
			if updatedRule.Action == ActionDeny {
				// Level 0 platform invariant violations or explicit denial halts execution immediately
				if updatedRule.Scope == ScopePlatform || updatedRule.Precedence < 100 {
					return JobActionTerminate, ErrActiveJobTerminated
				}
				return JobActionPause, nil
			}
		}
	}

	return JobActionContinue, nil
}

func (g *EnforcementGatekeeper) recordVerdict(verdict *EnforcementVerdict) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.records = append(g.records, *verdict)
}

func (g *EnforcementGatekeeper) GetRecords(resourceID string) []EnforcementVerdict {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var matching []EnforcementVerdict
	for _, r := range g.records {
		if r.ResourceID == resourceID {
			matching = append(matching, r)
		}
	}
	return matching
}
