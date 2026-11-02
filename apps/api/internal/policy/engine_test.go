package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

type mockAuditRecorder struct {
	events []audit.Event
}

func (m *mockAuditRecorder) Record(ctx context.Context, evt audit.Event) error {
	m.events = append(m.events, evt)
	return nil
}

func TestPolicyEngine_PrecedenceAndInvariants(t *testing.T) {
	ctx := context.Background()
	mockAudit := &mockAuditRecorder{}
	engine := NewPolicyEngine(mockAudit)

	orgID := uuid.New()
	workspaceID := uuid.New()

	// 1. Level 0: Platform Security Invariant (Precedence 10)
	// Platform prohibits scans against internal localhost/127.0.0.1
	engine.RegisterRule(PolicyRule{
		ID:         "platform_disallow_loopback",
		Name:       "Platform Invariant: Prohibit Localhost Scanning",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopePlatform,
		Precedence: 10,
		Condition: func(ctx context.Context, evalCtx EvaluationContext) (bool, error) {
			target, _ := evalCtx.Attributes["target"].(string)
			return target == "127.0.0.1" || target == "localhost", nil
		},
		Action: ActionDeny,
		Reason: "Scanning loopback addresses is strictly prohibited by platform security invariants",
	})

	// 2. Level 1: Organization Baseline (Precedence 100)
	// Organization allows all scans for their domain
	engine.RegisterRule(PolicyRule{
		ID:         "org_allow_all_targets",
		Name:       "Org Rule: Allow Target Scans",
		Type:       PolicyTypeScanExecution,
		Scope:      ScopeOrganization,
		Precedence: 100,
		Condition: func(ctx context.Context, evalCtx EvaluationContext) (bool, error) {
			return true, nil
		},
		Action: ActionAllow,
		Reason: "Organization allows target scans by default",
	})

	t.Run("platform invariant overrides organization allow rule", func(t *testing.T) {
		evalCtx := EvaluationContext{
			OrganizationID: orgID,
			WorkspaceID:    workspaceID,
			SubjectID:      "user-1",
			OperationType:  "START_SCAN",
			Attributes: map[string]any{
				"target": "127.0.0.1",
			},
		}

		decision, err := engine.Evaluate(ctx, evalCtx, PolicyTypeScanExecution)
		if err != nil {
			t.Fatalf("unexpected error evaluating: %v", err)
		}
		if decision.Allowed {
			t.Errorf("expected platform invariant to deny scan, but was allowed")
		}
		if decision.MatchedRuleID != "platform_disallow_loopback" {
			t.Errorf("expected matched rule platform_disallow_loopback, got %s", decision.MatchedRuleID)
		}
		if decision.EvaluatedScope != ScopePlatform {
			t.Errorf("expected scope PLATFORM, got %s", decision.EvaluatedScope)
		}
	})

	t.Run("organization allow rule applies when platform invariant does not trigger", func(t *testing.T) {
		evalCtx := EvaluationContext{
			OrganizationID: orgID,
			WorkspaceID:    workspaceID,
			SubjectID:      "user-1",
			OperationType:  "START_SCAN",
			Attributes: map[string]any{
				"target": "api.corp.example.com",
			},
		}

		decision, err := engine.Evaluate(ctx, evalCtx, PolicyTypeScanExecution)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !decision.Allowed {
			t.Errorf("expected scan to be allowed by organization policy")
		}
		if decision.MatchedRuleID != "org_allow_all_targets" {
			t.Errorf("expected matched rule org_allow_all_targets, got %s", decision.MatchedRuleID)
		}
	})
}

func TestPolicyEngine_FailClosedAndApproval(t *testing.T) {
	ctx := context.Background()
	engine := NewPolicyEngine(nil)

	orgID := uuid.New()
	workspaceID := uuid.New()

	// Flaky rule that errors out
	engine.RegisterRule(PolicyRule{
		ID:         "error_prone_rule",
		Name:       "Faulty External Check",
		Type:       PolicyTypeTargetAdmission,
		Scope:      ScopeWorkspace,
		Precedence: 50,
		Condition: func(ctx context.Context, evalCtx EvaluationContext) (bool, error) {
			return false, errors.New("connection timeout to external compliance catalog")
		},
		Action: ActionAllow,
		Reason: "Allow if catalog check passes",
	})

	// Rule requiring approval
	engine.RegisterRule(PolicyRule{
		ID:         "prod_export_approval",
		Name:       "Production Export Approval Required",
		Type:       PolicyTypeDataExport,
		Scope:      ScopeOrganization,
		Precedence: 100,
		Condition: func(ctx context.Context, evalCtx EvaluationContext) (bool, error) {
			env, _ := evalCtx.Attributes["env"].(string)
			return env == "production", nil
		},
		Action: ActionRequireApproval,
		Reason: "Exporting production vulnerability data requires SecOps approval",
	})

	t.Run("fail-closed behavior on condition error", func(t *testing.T) {
		evalCtx := EvaluationContext{
			OrganizationID: orgID,
			WorkspaceID:    workspaceID,
			SubjectID:      "user-1",
		}

		decision, err := engine.Evaluate(ctx, evalCtx, PolicyTypeTargetAdmission)
		if !errors.Is(err, ErrPolicyEvaluationFailed) {
			t.Fatalf("expected ErrPolicyEvaluationFailed, got %v", err)
		}
		if decision.Allowed {
			t.Errorf("fail-closed must deny access on evaluation error")
		}
		if decision.Action != ActionDeny {
			t.Errorf("expected ActionDeny, got %s", decision.Action)
		}
	})

	t.Run("enforce wrapper handles require-approval verdict", func(t *testing.T) {
		evalCtx := EvaluationContext{
			OrganizationID: orgID,
			WorkspaceID:    workspaceID,
			SubjectID:      "user-1",
			Attributes: map[string]any{
				"env": "production",
			},
		}

		err := engine.Enforce(ctx, evalCtx, PolicyTypeDataExport)
		if !errors.Is(err, ErrPolicyRequiresApproval) {
			t.Fatalf("expected ErrPolicyRequiresApproval, got %v", err)
		}
	})

	t.Run("default deny when no rules match", func(t *testing.T) {
		evalCtx := EvaluationContext{
			OrganizationID: orgID,
			WorkspaceID:    workspaceID,
			SubjectID:      "user-1",
		}

		decision, err := engine.Evaluate(ctx, evalCtx, PolicyTypeFindingAction)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Allowed {
			t.Errorf("expected default deny when no rules match")
		}
		if len(decision.AuditTrail) == 0 {
			t.Errorf("expected non-empty audit trail")
		}
	})
}
