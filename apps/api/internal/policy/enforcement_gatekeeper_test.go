package policy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatekeeper_SynchronousBoundaries(t *testing.T) {
	ctx := context.Background()
	recorder := &mockAuditRecorder{}
	engine := NewPolicyEngine(recorder)
	gatekeeper := NewEnforcementGatekeeper(engine)

	orgID := uuid.New()
	wsID := uuid.New()

	// Register rules:
	// Rule 1: Allow assessment creation for verified org users
	ruleAllow := PolicyRule{
		ID:         "rule-allow-assessments",
		Name:       "Allow assessments for verified org",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopeOrganization,
		Precedence: 150,
		Action:     ActionAllow,
		Reason:     "Allowed by org baseline",
		Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
			return eval.OperationType == string(PolicyTypeScanExecution), nil
		},
	}
	engine.RegisterRule(ruleAllow)

	// Rule 2: Require approval for high-risk data export
	ruleExportApproval := PolicyRule{
		ID:         "rule-export-approval",
		Name:       "Require approval for data export",
		Type:       PolicyTypeDataExport,
		Scope:      ScopeOrganization,
		Precedence: 120,
		Action:     ActionRequireApproval,
		Reason:     "Data export requires security sign-off",
		Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
			return eval.OperationType == string(PolicyTypeDataExport), nil
		},
	}
	engine.RegisterRule(ruleExportApproval)

	t.Run("assessment creation enforcement allows compliant operation", func(t *testing.T) {
		req := EnforcementRequest{
			Point: PointAssessmentCreate,
			EvalContext: EvaluationContext{
				TenantID:       orgID,
				OrganizationID: orgID,
				WorkspaceID:    wsID,
				SubjectID:      "user-alice",
				OperationType:  string(PolicyTypeScanExecution),
			},
			ResourceID:    "assessment-req-1",
			PolicyVersion: 1,
		}

		verdict, err := gatekeeper.Enforce(ctx, req)
		require.NoError(t, err)
		assert.True(t, verdict.Allowed)
		assert.Equal(t, ActionAllow, verdict.Action)
		assert.Equal(t, PointAssessmentCreate, verdict.Point)
	})

	t.Run("data export enforcement mandates approval", func(t *testing.T) {
		req := EnforcementRequest{
			Point: PointIntegrationTrigger,
			EvalContext: EvaluationContext{
				TenantID:       orgID,
				OrganizationID: orgID,
				WorkspaceID:    wsID,
				SubjectID:      "user-alice",
				OperationType:  string(PolicyTypeDataExport),
			},
			ResourceID:    "export-task-1",
			PolicyVersion: 1,
		}

		verdict, err := gatekeeper.Enforce(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPolicyRequiresApproval)
		assert.False(t, verdict.Allowed)
		assert.Equal(t, ActionRequireApproval, verdict.Action)
	})

	t.Run("unconfigured operation defaults to fail-closed denial", func(t *testing.T) {
		req := EnforcementRequest{
			Point: PointFindingTriage,
			EvalContext: EvaluationContext{
				TenantID:       orgID,
				OrganizationID: orgID,
				WorkspaceID:    wsID,
				SubjectID:      "user-bob",
				OperationType:  "UNKNOWN_OP",
			},
			ResourceID:    "finding-123",
			PolicyVersion: 1,
		}

		verdict, err := gatekeeper.Enforce(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPolicyBlocked)
		assert.False(t, verdict.Allowed)
		assert.Equal(t, ActionDeny, verdict.Action)
	})
}

func TestGatekeeper_QueuedWorkReValidation(t *testing.T) {
	ctx := context.Background()
	recorder := &mockAuditRecorder{}
	engine := NewPolicyEngine(recorder)
	gatekeeper := NewEnforcementGatekeeper(engine)

	orgID := uuid.New()
	wsID := uuid.New()
	targetID := "production-payment-gateway"

	// Initially, policy allows scan execution
	ruleAllow := PolicyRule{
		ID:         "rule-scan-allow",
		Name:       "Scan execution baseline",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopeOrganization,
		Precedence: 150,
		Action:     ActionAllow,
		Reason:     "Scan execution permitted",
		Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
			return true, nil
		},
	}
	engine.RegisterRule(ruleAllow)

	job := JobContext{
		JobID:          uuid.New(),
		OrganizationID: orgID,
		WorkspaceID:    wsID,
		TargetID:       targetID,
		ScannerID:      "nuclei-standard",
		QueuedAt:       time.Now().UTC().Add(-10 * time.Minute),
	}

	// 1. Before policy change: queued validation passes
	verdict, err := gatekeeper.ValidateQueuedJob(ctx, job)
	require.NoError(t, err)
	assert.True(t, verdict.Allowed)

	// 2. Organization policy updates: Blacklist production-payment-gateway targets
	ruleBlacklistTarget := PolicyRule{
		ID:         "rule-blacklist-payment",
		Name:       "Blacklist Payment Gateway Targets",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopeOrganization,
		Precedence: 50, // Higher precedence than baseline allow rule
		Action:     ActionDeny,
		Reason:     "Critical payment infrastructure scanning prohibited",
		Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
			return eval.TargetID == targetID, nil
		},
	}
	engine.RegisterRule(ruleBlacklistTarget)

	// 3. Worker dequeues job now: ValidateQueuedJob blocks execution!
	verdictBlocked, err := gatekeeper.ValidateQueuedJob(ctx, job)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrQueuedJobPolicyViolation)
	assert.False(t, verdictBlocked.Allowed)
	assert.Equal(t, ActionDeny, verdictBlocked.Action)
}

func TestGatekeeper_ActiveJobPolicyChange(t *testing.T) {
	ctx := context.Background()
	recorder := &mockAuditRecorder{}
	engine := NewPolicyEngine(recorder)
	gatekeeper := NewEnforcementGatekeeper(engine)

	orgID := uuid.New()
	wsID := uuid.New()
	jobID := uuid.New()

	job := JobContext{
		JobID:          jobID,
		OrganizationID: orgID,
		WorkspaceID:    wsID,
		TargetID:       "internal-host.local",
		ScannerID:      "zap-baseline",
		QueuedAt:       time.Now().UTC().Add(-30 * time.Minute),
	}

	t.Run("platform invariant denial terminates in-progress job", func(t *testing.T) {
		platformDeny := PolicyRule{
			ID:         "platform-rule-forbidden-intrusive",
			Name:       "Platform Forbidden Scan",
			Type:       PolicyTypeScanExecution,
			Scope:      ScopePlatform,
			Precedence: 10,
			Action:     ActionDeny,
			Reason:     "Emergency platform freeze",
			Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
				return true, nil
			},
		}

		action, err := gatekeeper.EvaluateActiveJobOnPolicyChange(ctx, job, platformDeny)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrActiveJobTerminated)
		assert.Equal(t, JobActionTerminate, action)
	})

	t.Run("organization level denial pauses in-progress job", func(t *testing.T) {
		orgPause := PolicyRule{
			ID:         "org-rule-pause-target",
			Name:       "Pause Target Scans",
			Type:       PolicyTypeScanExecution,
			Scope:      ScopeOrganization,
			Precedence: 150,
			Action:     ActionDeny,
			Reason:     "Target maintenance started",
			Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
				return true, nil
			},
		}

		action, err := gatekeeper.EvaluateActiveJobOnPolicyChange(ctx, job, orgPause)
		require.NoError(t, err)
		assert.Equal(t, JobActionPause, action)
	})

	t.Run("unrelated policy rule allows job to continue", func(t *testing.T) {
		unrelatedRule := PolicyRule{
			ID:         "unrelated-rule",
			Name:       "Export restrictions",
			Type:       PolicyTypeDataExport,
			Scope:      ScopeOrganization,
			Precedence: 150,
			Action:     ActionDeny,
			Condition: func(_ context.Context, eval EvaluationContext) (bool, error) {
				return false, nil
			},
		}

		action, err := gatekeeper.EvaluateActiveJobOnPolicyChange(ctx, job, unrelatedRule)
		require.NoError(t, err)
		assert.Equal(t, JobActionContinue, action)
	})
}
