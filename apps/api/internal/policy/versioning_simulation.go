package policy

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
	ErrVersionNotFound         = errors.New("policy versioning: version not found")
	ErrDraftAlreadyPublished   = errors.New("policy versioning: published or archived versions cannot be edited")
	ErrUnauthorizedPublisher   = errors.New("policy versioning: actor not authorized to publish or rollback policies")
	ErrInvalidPolicyType       = errors.New("policy versioning: policy type cannot be empty")
	ErrEmptyRules              = errors.New("policy versioning: policy must contain at least one rule")
	ErrActiveVersionNotFound   = errors.New("policy versioning: no active published version found")
)

type PolicyVersionStatus string

const (
	StatusDraft     PolicyVersionStatus = "DRAFT"
	StatusPublished PolicyVersionStatus = "PUBLISHED"
	StatusArchived  PolicyVersionStatus = "ARCHIVED"
)

type PolicyAuditAction string

const (
	AuditCreateDraft PolicyAuditAction = "CREATE_DRAFT"
	AuditUpdateDraft PolicyAuditAction = "UPDATE_DRAFT"
	AuditSimulate    PolicyAuditAction = "SIMULATE"
	AuditPublish     PolicyAuditAction = "PUBLISH"
	AuditRollback    PolicyAuditAction = "ROLLBACK"
)

// PolicyDefinitionVersion represents an immutable or draft version of a policy specification.
type PolicyDefinitionVersion struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	PolicyType     PolicyType
	Version        int
	Status         PolicyVersionStatus
	Rules          []PolicyRule
	AuthorID       string
	PublishedBy    string
	PublishedAt    *time.Time
	ChangeSummary  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ImpactItem captures the diff for a single corpus item under simulation.
type ImpactItem struct {
	ResourceID      string
	PreviousAction  PolicyAction
	SimulatedAction PolicyAction
	Changed         bool
	Reason          string
}

// SimulationResult reports the dry-run impact of candidate policy rules.
type SimulationResult struct {
	RunID                 uuid.UUID
	PolicyVersionID       uuid.UUID
	ExecutedBy            string
	TotalEvaluated        int
	AllowedCount          int
	DeniedCount           int
	ApprovalRequiredCount int
	ConflictsDetected     int
	ConflictDetails       []string
	ImpactDetails         []ImpactItem
	ExecutedAt            time.Time
}

// PolicyAuditRecord records all policy lifecycle state alterations.
type PolicyAuditRecord struct {
	ID              uuid.UUID
	OrganizationID  uuid.UUID
	PolicyVersionID *uuid.UUID
	ActorID         string
	Action          PolicyAuditAction
	Details         string
	CreatedAt       time.Time
}

// PolicyVersioningService coordinates drafting, simulating, publishing, rolling back, and auditing policies.
type PolicyVersioningService struct {
	mu        sync.RWMutex
	validator RiskApproverValidator
	versions  map[uuid.UUID]*PolicyDefinitionVersion
	audits    []PolicyAuditRecord
}

func NewPolicyVersioningService(validator RiskApproverValidator) *PolicyVersioningService {
	return &PolicyVersioningService{
		validator: validator,
		versions:  make(map[uuid.UUID]*PolicyDefinitionVersion),
		audits:    make([]PolicyAuditRecord, 0),
	}
}

// CreateDraft initializes a new draft policy definition.
func (s *PolicyVersioningService) CreateDraft(
	_ context.Context,
	orgID uuid.UUID,
	pType PolicyType,
	authorID string,
	summary string,
	rules []PolicyRule,
) (*PolicyDefinitionVersion, error) {
	if orgID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}
	if pType == "" {
		return nil, ErrInvalidPolicyType
	}
	authorID = strings.TrimSpace(authorID)
	if authorID == "" {
		return nil, ErrInvalidAssignee
	}
	if len(rules) == 0 {
		return nil, ErrEmptyRules
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute next version number for this org & policy type
	maxVersion := 0
	for _, v := range s.versions {
		if v.OrganizationID == orgID && v.PolicyType == pType && v.Version > maxVersion {
			maxVersion = v.Version
		}
	}

	draft := &PolicyDefinitionVersion{
		ID:             uuid.New(),
		OrganizationID: orgID,
		PolicyType:     pType,
		Version:        maxVersion + 1,
		Status:         StatusDraft,
		Rules:          rules,
		AuthorID:       authorID,
		ChangeSummary:  strings.TrimSpace(summary),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	s.versions[draft.ID] = draft

	s.recordAudit(orgID, &draft.ID, authorID, AuditCreateDraft, fmt.Sprintf("Created draft version %d", draft.Version))
	return draft, nil
}

// UpdateDraft updates an existing draft before publication.
func (s *PolicyVersioningService) UpdateDraft(
	_ context.Context,
	draftID uuid.UUID,
	authorID string,
	summary string,
	rules []PolicyRule,
) (*PolicyDefinitionVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft, exists := s.versions[draftID]
	if !exists {
		return nil, ErrVersionNotFound
	}
	if draft.Status != StatusDraft {
		return nil, ErrDraftAlreadyPublished
	}
	if len(rules) == 0 {
		return nil, ErrEmptyRules
	}

	draft.Rules = rules
	draft.ChangeSummary = strings.TrimSpace(summary)
	draft.AuthorID = strings.TrimSpace(authorID)
	draft.UpdatedAt = time.Now().UTC()

	s.recordAudit(draft.OrganizationID, &draft.ID, authorID, AuditUpdateDraft, fmt.Sprintf("Updated draft version %d", draft.Version))
	return draft, nil
}

// SimulatePolicy dry-runs the policy version against test evaluation contexts without executing any scans.
func (s *PolicyVersioningService) SimulatePolicy(
	ctx context.Context,
	versionID uuid.UUID,
	executorID string,
	testCorpus []EvaluationContext,
) (*SimulationResult, error) {
	s.mu.RLock()
	ver, exists := s.versions[versionID]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrVersionNotFound
	}

	// Spin up isolated temporary simulation engine
	simEngine := NewPolicyEngine(&mockAuditRecorder{})
	for _, r := range ver.Rules {
		simEngine.RegisterRule(r)
	}

	result := &SimulationResult{
		RunID:           uuid.New(),
		PolicyVersionID: versionID,
		ExecutedBy:      strings.TrimSpace(executorID),
		TotalEvaluated:  len(testCorpus),
		ConflictDetails: make([]string, 0),
		ImpactDetails:   make([]ImpactItem, 0),
		ExecutedAt:      time.Now().UTC(),
	}

	// Check for conflicting contradictory rules in definition
	s.detectRuleConflicts(ver.Rules, result)

	// Dry run evaluation against test corpus
	for _, item := range testCorpus {
		decision, _ := simEngine.Evaluate(ctx, item, ver.PolicyType)

		switch decision.Action {
		case ActionAllow:
			result.AllowedCount++
		case ActionDeny:
			result.DeniedCount++
		case ActionRequireApproval:
			result.ApprovalRequiredCount++
		}

		result.ImpactDetails = append(result.ImpactDetails, ImpactItem{
			ResourceID:      item.TargetID,
			SimulatedAction: decision.Action,
			Reason:          decision.Reason,
		})
	}

	s.mu.Lock()
	s.recordAudit(ver.OrganizationID, &ver.ID, executorID, AuditSimulate, fmt.Sprintf("Simulated policy version %d over %d items", ver.Version, len(testCorpus)))
	s.mu.Unlock()

	return result, nil
}

func (s *PolicyVersioningService) detectRuleConflicts(rules []PolicyRule, res *SimulationResult) {
	// Look for rules with identical precedence and scope having contradictory actions
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			r1 := rules[i]
			r2 := rules[j]
			if r1.Precedence == r2.Precedence && r1.Scope == r2.Scope && r1.Action != r2.Action {
				res.ConflictsDetected++
				res.ConflictDetails = append(res.ConflictDetails, fmt.Sprintf("Contradictory actions at precedence %d between rule '%s' (%s) and '%s' (%s)", r1.Precedence, r1.Name, r1.Action, r2.Name, r2.Action))
			}
		}
	}
}

// PublishVersion publishes a draft policy, automatically archiving prior published versions.
func (s *PolicyVersioningService) PublishVersion(
	ctx context.Context,
	versionID uuid.UUID,
	publisherID string,
	publisherRole string,
) (*PolicyDefinitionVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ver, exists := s.versions[versionID]
	if !exists {
		return nil, ErrVersionNotFound
	}
	if ver.Status != StatusDraft {
		return nil, errors.New("policy versioning: only draft versions can be published")
	}

	// Verify publisher role
	authorized, err := s.validator.CanApproveRiskException(ctx, ver.OrganizationID, publisherID, publisherRole)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, ErrUnauthorizedPublisher
	}

	now := time.Now().UTC()

	// Archive any existing PUBLISHED version for this org & type
	for _, existing := range s.versions {
		if existing.OrganizationID == ver.OrganizationID && existing.PolicyType == ver.PolicyType && existing.Status == StatusPublished {
			existing.Status = StatusArchived
			existing.UpdatedAt = now
		}
	}

	ver.Status = StatusPublished
	ver.PublishedBy = strings.TrimSpace(publisherID)
	ver.PublishedAt = &now
	ver.UpdatedAt = now

	s.recordAudit(ver.OrganizationID, &ver.ID, publisherID, AuditPublish, fmt.Sprintf("Published policy version %d", ver.Version))
	return ver, nil
}

// RollbackToVersion creates a new published version reinstating rules from an earlier version.
func (s *PolicyVersioningService) RollbackToVersion(
	ctx context.Context,
	orgID uuid.UUID,
	pType PolicyType,
	targetVersionNum int,
	actorID string,
	actorRole string,
	reason string,
) (*PolicyDefinitionVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate actor authorization
	authorized, err := s.validator.CanApproveRiskException(ctx, orgID, actorID, actorRole)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, ErrUnauthorizedPublisher
	}

	// Find target version
	var targetVersion *PolicyDefinitionVersion
	maxVersion := 0
	for _, v := range s.versions {
		if v.OrganizationID == orgID && v.PolicyType == pType {
			if v.Version > maxVersion {
				maxVersion = v.Version
			}
			if v.Version == targetVersionNum {
				targetVersion = v
			}
		}
	}
	if targetVersion == nil {
		return nil, fmt.Errorf("target version %d not found: %w", targetVersionNum, ErrVersionNotFound)
	}

	now := time.Now().UTC()

	// Archive currently published version
	for _, existing := range s.versions {
		if existing.OrganizationID == orgID && existing.PolicyType == pType && existing.Status == StatusPublished {
			existing.Status = StatusArchived
			existing.UpdatedAt = now
		}
	}

	// Create new published rollback version
	rollbackVersion := &PolicyDefinitionVersion{
		ID:             uuid.New(),
		OrganizationID: orgID,
		PolicyType:     pType,
		Version:        maxVersion + 1,
		Status:         StatusPublished,
		Rules:          targetVersion.Rules,
		AuthorID:       strings.TrimSpace(actorID),
		PublishedBy:    strings.TrimSpace(actorID),
		PublishedAt:    &now,
		ChangeSummary:  fmt.Sprintf("Rollback to version %d: %s", targetVersionNum, strings.TrimSpace(reason)),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.versions[rollbackVersion.ID] = rollbackVersion

	s.recordAudit(orgID, &rollbackVersion.ID, actorID, AuditRollback, fmt.Sprintf("Rolled back to rules of version %d into new version %d", targetVersionNum, rollbackVersion.Version))
	return rollbackVersion, nil
}

func (s *PolicyVersioningService) recordAudit(orgID uuid.UUID, versionID *uuid.UUID, actorID string, action PolicyAuditAction, details string) {
	record := PolicyAuditRecord{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		PolicyVersionID: versionID,
		ActorID:         actorID,
		Action:          action,
		Details:         details,
		CreatedAt:       time.Now().UTC(),
	}
	s.audits = append(s.audits, record)
}

func (s *PolicyVersioningService) GetAuditLogs(orgID uuid.UUID) []PolicyAuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var logs []PolicyAuditRecord
	for _, a := range s.audits {
		if a.OrganizationID == orgID {
			logs = append(logs, a)
		}
	}
	return logs
}

func (s *PolicyVersioningService) GetVersion(versionID uuid.UUID) (*PolicyDefinitionVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, exists := s.versions[versionID]
	if !exists {
		return nil, ErrVersionNotFound
	}
	return v, nil
}
