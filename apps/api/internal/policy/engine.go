package policy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrPolicyBlocked          = errors.New("operation blocked by enterprise policy governance")
	ErrPolicyRequiresApproval = errors.New("operation requires authorized policy exception or administrative approval")
	ErrPolicyEvaluationFailed = errors.New("policy evaluation error: defaulting to fail-closed denial")
)

type PolicyType string

const (
	PolicyTypeScanExecution    PolicyType = "SCAN_EXECUTION"
	PolicyTypeTargetAdmission  PolicyType = "TARGET_ADMISSION"
	PolicyTypeFindingAction    PolicyType = "FINDING_ACTION"
	PolicyTypeDataExport       PolicyType = "DATA_EXPORT"
	PolicyTypeIntegrationAccess PolicyType = "INTEGRATION_ACCESS"
)

type PolicyScope string

const (
	ScopePlatform     PolicyScope = "PLATFORM"     // Priority 0-99 (Immutable platform baseline)
	ScopeOrganization PolicyScope = "ORGANIZATION" // Priority 100-199
	ScopeWorkspace    PolicyScope = "WORKSPACE"    // Priority 200-299
	ScopeTarget       PolicyScope = "TARGET"       // Priority 300-399
)

type PolicyAction string

const (
	ActionAllow           PolicyAction = "ALLOW"
	ActionDeny            PolicyAction = "DENY"
	ActionRequireApproval PolicyAction = "REQUIRE_APPROVAL"
)

// EvaluationContext captures the full security and operational parameters for a policy evaluation request.
type EvaluationContext struct {
	TenantID       uuid.UUID         `json:"tenant_id"`
	OrganizationID uuid.UUID         `json:"organization_id"`
	WorkspaceID    uuid.UUID         `json:"workspace_id"`
	TargetID       string            `json:"target_id,omitempty"`
	SubjectID      string            `json:"subject_id"`
	Roles          []string          `json:"roles"`
	Permissions    map[string]bool   `json:"permissions"`
	OperationType  string            `json:"operation_type"`
	Attributes     map[string]any    `json:"attributes"`
}

// ConditionFunc evaluates whether a policy rule applies to the current context.
type ConditionFunc func(ctx context.Context, evalCtx EvaluationContext) (bool, error)

// PolicyRule defines an individual policy statement.
type PolicyRule struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Type       PolicyType    `json:"type"`
	Scope      PolicyScope   `json:"scope"`
	Precedence int           `json:"precedence"` // Lower integer evaluates first
	Condition  ConditionFunc `json:"-"`
	Action     PolicyAction  `json:"action"`
	Reason     string        `json:"reason"`
}

// PolicyDecision records the explainable verdict resulting from policy evaluation.
type PolicyDecision struct {
	Action         PolicyAction `json:"action"`
	Allowed        bool         `json:"allowed"`
	Reason         string       `json:"reason"`
	MatchedRuleID  string       `json:"matched_rule_id,omitempty"`
	EvaluatedScope PolicyScope  `json:"evaluated_scope,omitempty"`
	Timestamp      time.Time    `json:"timestamp"`
	AuditTrail     []string     `json:"audit_trail"` // Step-by-step explainability trace
}

// PolicyEngine provides centralized, deterministic, hierarchical policy evaluation and enforcement.
type PolicyEngine struct {
	mu    sync.RWMutex
	rules []PolicyRule
	audit audit.Recorder
}

func NewPolicyEngine(audit audit.Recorder) *PolicyEngine {
	return &PolicyEngine{
		audit: audit,
	}
}

// RegisterRule adds a policy rule and maintains deterministic precedence order.
func (e *PolicyEngine) RegisterRule(rule PolicyRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = append(e.rules, rule)
	sort.SliceStable(e.rules, func(i, j int) bool {
		if e.rules[i].Precedence != e.rules[j].Precedence {
			return e.rules[i].Precedence < e.rules[j].Precedence
		}
		return e.rules[i].ID < e.rules[j].ID
	})
}

// Evaluate performs deterministic hierarchical rule evaluation with Fail-Closed guarantees.
func (e *PolicyEngine) Evaluate(ctx context.Context, evalCtx EvaluationContext, policyType PolicyType) (PolicyDecision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	var auditTrail []string

	for _, rule := range e.rules {
		if rule.Type != policyType {
			continue
		}

		auditTrail = append(auditTrail, fmt.Sprintf("Evaluating [%s] rule %q (Precedence: %d)", rule.Scope, rule.Name, rule.Precedence))

		matched, err := rule.Condition(ctx, evalCtx)
		if err != nil {
			// Fail-Closed Invariant: Any evaluation failure immediately denies access
			failClosedDecision := PolicyDecision{
				Action:         ActionDeny,
				Allowed:        false,
				Reason:         fmt.Sprintf("Fail-closed: rule %q evaluation failed: %v", rule.Name, err),
				MatchedRuleID:  rule.ID,
				EvaluatedScope: rule.Scope,
				Timestamp:      now,
				AuditTrail:     append(auditTrail, fmt.Sprintf("ERROR in rule %q: %v -> FAIL_CLOSED DENY", rule.Name, err)),
			}
			e.recordPolicyAudit(ctx, evalCtx, failClosedDecision)
			return failClosedDecision, fmt.Errorf("%w: %v", ErrPolicyEvaluationFailed, err)
		}

		if matched {
			auditTrail = append(auditTrail, fmt.Sprintf("Rule %q MATCHED -> Action: %s (%s)", rule.Name, rule.Action, rule.Reason))

			decision := PolicyDecision{
				Action:         rule.Action,
				Allowed:        rule.Action == ActionAllow,
				Reason:         rule.Reason,
				MatchedRuleID:  rule.ID,
				EvaluatedScope: rule.Scope,
				Timestamp:      now,
				AuditTrail:     auditTrail,
			}

			e.recordPolicyAudit(ctx, evalCtx, decision)
			return decision, nil
		}
	}

	// Default verdict if no rule matched: Default Deny (Principle of Least Privilege)
	auditTrail = append(auditTrail, "No rules matched -> Default Deny enforced")
	defaultDecision := PolicyDecision{
		Action:         ActionDeny,
		Allowed:        false,
		Reason:         "Default deny: no matching policy rule allowed this operation",
		Timestamp:      now,
		AuditTrail:     auditTrail,
	}

	e.recordPolicyAudit(ctx, evalCtx, defaultDecision)
	return defaultDecision, nil
}

// Enforce executes evaluation and converts non-allow verdicts into clean, non-sensitive errors.
func (e *PolicyEngine) Enforce(ctx context.Context, evalCtx EvaluationContext, policyType PolicyType) error {
	decision, err := e.Evaluate(ctx, evalCtx, policyType)
	if err != nil {
		return err
	}

	switch decision.Action {
	case ActionAllow:
		return nil
	case ActionRequireApproval:
		return fmt.Errorf("%w: %s", ErrPolicyRequiresApproval, decision.Reason)
	case ActionDeny:
		return fmt.Errorf("%w: %s", ErrPolicyBlocked, decision.Reason)
	default:
		return ErrPolicyBlocked
	}
}

func (e *PolicyEngine) recordPolicyAudit(ctx context.Context, evalCtx EvaluationContext, decision PolicyDecision) {
	if e.audit == nil {
		return
	}
	var actorUUID *uuid.UUID
	if u, err := uuid.Parse(evalCtx.SubjectID); err == nil {
		actorUUID = &u
	}
	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    &evalCtx.OrganizationID,
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      fmt.Sprintf("policy.%s", decision.Action),
		EntityType:  "policy_decision",
		CreatedAt:   decision.Timestamp,
	}
	_ = e.audit.Record(ctx, evt)
}
