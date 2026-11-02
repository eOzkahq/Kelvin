package policy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidOrganizationID      = errors.New("assignment: missing or invalid organization id")
	ErrInvalidAssignee            = errors.New("assignment: assignee type and id cannot be empty")
	ErrInactiveAssignee           = errors.New("assignment: assignee is not active or not in organization")
	ErrCircularEscalationDetected = errors.New("assignment: circular escalation path detected")
	ErrMaxEscalationLevelExceeded = errors.New("assignment: maximum escalation level exceeded")
	ErrManualOverrideForbidden   = errors.New("assignment: manual override requires authorized actor")
	ErrRuleNotFound               = errors.New("assignment: assignment rule not found")
	ErrEmptyRuleName              = errors.New("assignment: rule name cannot be empty")
)

type AssigneeType string

const (
	AssigneeUser AssigneeType = "USER"
	AssigneeTeam AssigneeType = "TEAM"
)

type AssignmentSource string

const (
	SourceRuleMatch       AssignmentSource = "RULE_MATCH"
	SourceDefaultFallback AssignmentSource = "DEFAULT_FALLBACK"
	SourceEscalation      AssignmentSource = "ESCALATION"
	SourceManualOverride  AssignmentSource = "MANUAL_OVERRIDE"
)

type EscalationTrigger string

const (
	TriggerSLAWarning  EscalationTrigger = "SLA_WARNING"
	TriggerSLABreached EscalationTrigger = "SLA_BREACHED"
	TriggerTimeElapsed EscalationTrigger = "TIME_ELAPSED"
)

const MaxEscalationDepth = 5

// EntityValidator verifies that users or teams belong to the organization and are active.
type EntityValidator interface {
	ValidateActiveEntity(ctx context.Context, orgID uuid.UUID, assigneeType AssigneeType, assigneeID string) (bool, error)
}

// MemoryEntityValidator provides a thread-safe directory validator for tests and isolated services.
type MemoryEntityValidator struct {
	mu       sync.RWMutex
	entities map[uuid.UUID]map[string]bool // key: orgID -> map["USER:alice" / "TEAM:secops"] -> isActive
}

func NewMemoryEntityValidator() *MemoryEntityValidator {
	return &MemoryEntityValidator{
		entities: make(map[uuid.UUID]map[string]bool),
	}
}

func (v *MemoryEntityValidator) RegisterEntity(orgID uuid.UUID, assigneeType AssigneeType, id string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.entities[orgID]; !exists {
		v.entities[orgID] = make(map[string]bool)
	}
	key := fmt.Sprintf("%s:%s", assigneeType, strings.TrimSpace(id))
	v.entities[orgID][key] = true
}

func (v *MemoryEntityValidator) DeactivateEntity(orgID uuid.UUID, assigneeType AssigneeType, id string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if orgMap, exists := v.entities[orgID]; exists {
		key := fmt.Sprintf("%s:%s", assigneeType, strings.TrimSpace(id))
		orgMap[key] = false
	}
}

func (v *MemoryEntityValidator) ValidateActiveEntity(_ context.Context, orgID uuid.UUID, assigneeType AssigneeType, assigneeID string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	orgMap, exists := v.entities[orgID]
	if !exists {
		return false, nil
	}
	key := fmt.Sprintf("%s:%s", assigneeType, strings.TrimSpace(assigneeID))
	return orgMap[key], nil
}

// AssignmentRule defines match criteria and assignee targets.
type AssignmentRule struct {
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	Name                 string
	Description          string
	Priority             int // Lower number = higher precedence (e.g. 10 before 100)
	WorkspaceID          *uuid.UUID
	TargetTag            string
	VulnerabilityClass   string
	MinSeverity          string
	AssigneeType         AssigneeType
	AssigneeID           string
	FallbackAssigneeType AssigneeType
	FallbackAssigneeID   string
	Version              int
	IsActive             bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// EscalationPolicy defines rule- or org-level escalation rules upon SLA triggers.
type EscalationPolicy struct {
	ID                     uuid.UUID
	OrganizationID         uuid.UUID
	AssignmentRuleID       *uuid.UUID
	Name                   string
	TriggerCondition       EscalationTrigger
	TriggerThresholdMins   int
	EscalationLevel        int
	EscalateToType         AssigneeType
	EscalateToID           string
	NextEscalationPolicyID *uuid.UUID
	IsActive               bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// FindingContext contains metadata evaluated by assignment and escalation engines.
type FindingContext struct {
	OrganizationID         uuid.UUID
	WorkspaceID            uuid.UUID
	FindingID              uuid.UUID
	TargetTag              string
	VulnerabilityClass     string
	Severity               string
	CurrentAssigneeType    AssigneeType
	CurrentAssigneeID      string
	IsManualOverride       bool
	CurrentEscalationLevel int
}

// AssignmentResult documents the deterministic outcome of rule evaluation or escalation.
type AssignmentResult struct {
	ExecutionID      uuid.UUID
	OrganizationID   uuid.UUID
	FindingID        uuid.UUID
	RuleID           *uuid.UUID
	RuleVersion      int
	AssignedToType   AssigneeType
	AssignedToID     string
	AssignmentSource AssignmentSource
	EscalationLevel  int
	ActorID          string
	Reason           string
	ExecutedAt       time.Time
}

// AssignmentEscalationService coordinates automated assignment, escalation paths, and override audits.
type AssignmentEscalationService struct {
	mu             sync.RWMutex
	validator      EntityValidator
	rules          map[uuid.UUID][]*AssignmentRule
	escalations    map[uuid.UUID][]*EscalationPolicy
	defaultOwners  map[uuid.UUID]AssignmentResult
	executions     []AssignmentResult
}

func NewAssignmentEscalationService(validator EntityValidator) *AssignmentEscalationService {
	return &AssignmentEscalationService{
		validator:     validator,
		rules:         make(map[uuid.UUID][]*AssignmentRule),
		escalations:   make(map[uuid.UUID][]*EscalationPolicy),
		defaultOwners: make(map[uuid.UUID]AssignmentResult),
		executions:    make([]AssignmentResult, 0),
	}
}

// SetDefaultFallback sets the organization-wide fallback owner when no rules match.
func (s *AssignmentEscalationService) SetDefaultFallback(orgID uuid.UUID, assigneeType AssigneeType, assigneeID string) error {
	if orgID == uuid.Nil {
		return ErrInvalidOrganizationID
	}
	assigneeID = strings.TrimSpace(assigneeID)
	if assigneeID == "" {
		return ErrInvalidAssignee
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.defaultOwners[orgID] = AssignmentResult{
		OrganizationID:   orgID,
		AssignedToType:   assigneeType,
		AssignedToID:     assigneeID,
		AssignmentSource: SourceDefaultFallback,
		Reason:           "organization default fallback owner",
	}
	return nil
}

// ConfigureAssignmentRule registers or updates an assignment rule with version incrementing.
func (s *AssignmentEscalationService) ConfigureAssignmentRule(ctx context.Context, rule *AssignmentRule) (*AssignmentRule, error) {
	if rule == nil {
		return nil, errors.New("assignment: rule cannot be nil")
	}
	if rule.OrganizationID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}
	if strings.TrimSpace(rule.Name) == "" {
		return nil, ErrEmptyRuleName
	}
	rule.AssigneeID = strings.TrimSpace(rule.AssigneeID)
	if rule.AssigneeID == "" {
		return nil, ErrInvalidAssignee
	}

	// Validate that primary assignee is valid and active in organization
	active, err := s.validator.ValidateActiveEntity(ctx, rule.OrganizationID, rule.AssigneeType, rule.AssigneeID)
	if err != nil {
		return nil, fmt.Errorf("assignment: error validating assignee: %w", err)
	}
	if !active {
		return nil, ErrInactiveAssignee
	}

	// If fallback is provided, validate it as well
	if strings.TrimSpace(rule.FallbackAssigneeID) != "" {
		fbActive, err := s.validator.ValidateActiveEntity(ctx, rule.OrganizationID, rule.FallbackAssigneeType, rule.FallbackAssigneeID)
		if err != nil {
			return nil, fmt.Errorf("assignment: error validating fallback assignee: %w", err)
		}
		if !fbActive {
			return nil, fmt.Errorf("fallback assignee is inactive or invalid: %w", ErrInactiveAssignee)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
		rule.Version = 1
		rule.CreatedAt = time.Now().UTC()
		rule.UpdatedAt = rule.CreatedAt
		rule.IsActive = true
		s.rules[rule.OrganizationID] = append(s.rules[rule.OrganizationID], rule)
	} else {
		// Existing rule update: increment version
		var found bool
		for i, existing := range s.rules[rule.OrganizationID] {
			if existing.ID == rule.ID {
				rule.Version = existing.Version + 1
				rule.CreatedAt = existing.CreatedAt
				rule.UpdatedAt = time.Now().UTC()
				s.rules[rule.OrganizationID][i] = rule
				found = true
				break
			}
		}
		if !found {
			return nil, ErrRuleNotFound
		}
	}

	// Keep rules sorted by priority ASC
	sort.SliceStable(s.rules[rule.OrganizationID], func(i, j int) bool {
		return s.rules[rule.OrganizationID][i].Priority < s.rules[rule.OrganizationID][j].Priority
	})

	return rule, nil
}

// ConfigureEscalationPolicy registers an escalation policy with cycle detection.
func (s *AssignmentEscalationService) ConfigureEscalationPolicy(ctx context.Context, policy *EscalationPolicy) (*EscalationPolicy, error) {
	if policy == nil {
		return nil, errors.New("escalation: policy cannot be nil")
	}
	if policy.OrganizationID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}
	policy.EscalateToID = strings.TrimSpace(policy.EscalateToID)
	if policy.EscalateToID == "" {
		return nil, ErrInvalidAssignee
	}
	if policy.EscalationLevel > MaxEscalationDepth {
		return nil, ErrMaxEscalationLevelExceeded
	}

	// Validate target entity
	active, err := s.validator.ValidateActiveEntity(ctx, policy.OrganizationID, policy.EscalateToType, policy.EscalateToID)
	if err != nil {
		return nil, fmt.Errorf("escalation: error validating escalation target: %w", err)
	}
	if !active {
		return nil, ErrInactiveAssignee
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
		policy.CreatedAt = time.Now().UTC()
		policy.UpdatedAt = policy.CreatedAt
		policy.IsActive = true
	} else {
		policy.UpdatedAt = time.Now().UTC()
	}

	// Build map to check for circular paths
	policiesMap := make(map[uuid.UUID]*EscalationPolicy)
	for _, p := range s.escalations[policy.OrganizationID] {
		policiesMap[p.ID] = p
	}
	policiesMap[policy.ID] = policy

	if err := s.detectEscalationCycle(policy, policiesMap); err != nil {
		return nil, err
	}

	// Upsert policy
	var updated bool
	for i, existing := range s.escalations[policy.OrganizationID] {
		if existing.ID == policy.ID {
			s.escalations[policy.OrganizationID][i] = policy
			updated = true
			break
		}
	}
	if !updated {
		s.escalations[policy.OrganizationID] = append(s.escalations[policy.OrganizationID], policy)
	}

	// Sort by escalation level ASC
	sort.SliceStable(s.escalations[policy.OrganizationID], func(i, j int) bool {
		return s.escalations[policy.OrganizationID][i].EscalationLevel < s.escalations[policy.OrganizationID][j].EscalationLevel
	})

	return policy, nil
}

func (s *AssignmentEscalationService) detectEscalationCycle(start *EscalationPolicy, policies map[uuid.UUID]*EscalationPolicy) error {
	visited := make(map[uuid.UUID]bool)
	curr := start

	depth := 0
	for curr != nil {
		if depth > MaxEscalationDepth {
			return ErrMaxEscalationLevelExceeded
		}
		if visited[curr.ID] {
			return ErrCircularEscalationDetected
		}
		visited[curr.ID] = true
		depth++

		if curr.NextEscalationPolicyID == nil {
			break
		}
		next, exists := policies[*curr.NextEscalationPolicyID]
		if !exists {
			break
		}
		curr = next
	}
	return nil
}

// EvaluateAssignment evaluates configured rules against finding metadata and assigns the best match.
func (s *AssignmentEscalationService) EvaluateAssignment(ctx context.Context, finding FindingContext) (*AssignmentResult, error) {
	if finding.OrganizationID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}

	s.mu.RLock()
	rules := s.rules[finding.OrganizationID]
	defaultOwner, hasDefault := s.defaultOwners[finding.OrganizationID]
	s.mu.RUnlock()

	for _, rule := range rules {
		if !rule.IsActive {
			continue
		}
		if !s.matchesRule(rule, finding) {
			continue
		}

		// Check primary assignee activity
		active, _ := s.validator.ValidateActiveEntity(ctx, finding.OrganizationID, rule.AssigneeType, rule.AssigneeID)
		if active {
			res := s.recordExecution(finding, &rule.ID, rule.Version, rule.AssigneeType, rule.AssigneeID, SourceRuleMatch, 0, "system", fmt.Sprintf("Matched rule %s", rule.Name))
			return res, nil
		}

		// Try rule fallback if primary is inactive
		if rule.FallbackAssigneeID != "" {
			fbActive, _ := s.validator.ValidateActiveEntity(ctx, finding.OrganizationID, rule.FallbackAssigneeType, rule.FallbackAssigneeID)
			if fbActive {
				res := s.recordExecution(finding, &rule.ID, rule.Version, rule.FallbackAssigneeType, rule.FallbackAssigneeID, SourceDefaultFallback, 0, "system", fmt.Sprintf("Primary inactive for rule %s; used rule fallback", rule.Name))
				return res, nil
			}
		}
	}

	// No rule matched or all matched assignees were inactive -> use organization default
	if hasDefault {
		res := s.recordExecution(finding, nil, 1, defaultOwner.AssignedToType, defaultOwner.AssignedToID, SourceDefaultFallback, 0, "system", defaultOwner.Reason)
		return res, nil
	}

	return nil, ErrInactiveAssignee
}

// EvaluateEscalation triggers escalation based on SLA status.
func (s *AssignmentEscalationService) EvaluateEscalation(ctx context.Context, finding FindingContext, trigger EscalationTrigger) (*AssignmentResult, error) {
	if finding.OrganizationID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}
	if finding.IsManualOverride {
		return nil, errors.New("escalation: automated escalation skipped due to active manual override")
	}

	s.mu.RLock()
	policies := s.escalations[finding.OrganizationID]
	s.mu.RUnlock()

	nextLevel := finding.CurrentEscalationLevel + 1
	if nextLevel > MaxEscalationDepth {
		return nil, ErrMaxEscalationLevelExceeded
	}

	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}
		if policy.TriggerCondition != trigger {
			continue
		}
		if policy.EscalationLevel != nextLevel {
			continue
		}

		// Ensure escalation does not assign to same entity
		if policy.EscalateToType == finding.CurrentAssigneeType && policy.EscalateToID == finding.CurrentAssigneeID {
			continue
		}

		active, _ := s.validator.ValidateActiveEntity(ctx, finding.OrganizationID, policy.EscalateToType, policy.EscalateToID)
		if !active {
			continue
		}

		res := s.recordExecution(
			finding,
			policy.AssignmentRuleID,
			1,
			policy.EscalateToType,
			policy.EscalateToID,
			SourceEscalation,
			nextLevel,
			"system:escalation",
			fmt.Sprintf("Escalated to level %d via policy %s on %s", nextLevel, policy.Name, trigger),
		)
		return res, nil
	}

	return nil, fmt.Errorf("no eligible escalation policy found for level %d trigger %s", nextLevel, trigger)
}

// ManualOverride forces assignment to an authorized entity and flags subsequent automated overrides.
func (s *AssignmentEscalationService) ManualOverride(
	ctx context.Context,
	finding FindingContext,
	actorID string,
	assigneeType AssigneeType,
	assigneeID string,
	reason string,
) (*AssignmentResult, error) {
	if finding.OrganizationID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}
	if strings.TrimSpace(actorID) == "" {
		return nil, ErrManualOverrideForbidden
	}
	assigneeID = strings.TrimSpace(assigneeID)
	if assigneeID == "" {
		return nil, ErrInvalidAssignee
	}

	active, err := s.validator.ValidateActiveEntity(ctx, finding.OrganizationID, assigneeType, assigneeID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrInactiveAssignee
	}

	res := s.recordExecution(
		finding,
		nil,
		1,
		assigneeType,
		assigneeID,
		SourceManualOverride,
		finding.CurrentEscalationLevel,
		actorID,
		reason,
	)
	return res, nil
}

func (s *AssignmentEscalationService) matchesRule(rule *AssignmentRule, finding FindingContext) bool {
	if rule.WorkspaceID != nil && *rule.WorkspaceID != finding.WorkspaceID {
		return false
	}
	if rule.TargetTag != "" && !strings.EqualFold(rule.TargetTag, finding.TargetTag) {
		return false
	}
	if rule.VulnerabilityClass != "" && !strings.EqualFold(rule.VulnerabilityClass, finding.VulnerabilityClass) {
		return false
	}
	if rule.MinSeverity != "" && severityWeight(finding.Severity) < severityWeight(rule.MinSeverity) {
		return false
	}
	return true
}

func severityWeight(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func (s *AssignmentEscalationService) recordExecution(
	finding FindingContext,
	ruleID *uuid.UUID,
	ruleVersion int,
	toType AssigneeType,
	toID string,
	source AssignmentSource,
	level int,
	actorID string,
	reason string,
) *AssignmentResult {
	res := &AssignmentResult{
		ExecutionID:      uuid.New(),
		OrganizationID:   finding.OrganizationID,
		FindingID:        finding.FindingID,
		RuleID:           ruleID,
		RuleVersion:      ruleVersion,
		AssignedToType:   toType,
		AssignedToID:     toID,
		AssignmentSource: source,
		EscalationLevel:  level,
		ActorID:          actorID,
		Reason:           reason,
		ExecutedAt:       time.Now().UTC(),
	}

	s.mu.Lock()
	s.executions = append(s.executions, *res)
	s.mu.Unlock()

	return res
}

func (s *AssignmentEscalationService) GetExecutionHistory(findingID uuid.UUID) []AssignmentResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var history []AssignmentResult
	for _, exec := range s.executions {
		if exec.FindingID == findingID {
			history = append(history, exec)
		}
	}
	return history
}
