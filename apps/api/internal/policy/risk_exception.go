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
	ErrInvalidFindingID            = errors.New("risk exception: invalid finding id")
	ErrEmptyRationale              = errors.New("risk exception: rationale and justification cannot be empty")
	ErrInvalidCategory             = errors.New("risk exception: invalid exception category")
	ErrDurationExceedsMax          = errors.New("risk exception: requested duration exceeds maximum allowed of 90 days")
	ErrDurationNonPositive         = errors.New("risk exception: requested duration must be positive")
	ErrSeparationOfDutiesViolation = errors.New("risk exception: separation of duties violation: requester cannot approve own exception")
	ErrUnauthorizedApproverRole    = errors.New("risk exception: approver role is not authorized to approve risk exceptions")
	ErrDuplicateApprover           = errors.New("risk exception: approver has already submitted a decision for this request")
	ErrExceptionNotPending         = errors.New("risk exception: request is not in pending status")
	ErrExceptionNotFound           = errors.New("risk exception: exception request not found")
	ErrRevocationForbidden         = errors.New("risk exception: only active approved exceptions can be revoked")
)

const (
	MaxExceptionDurationDays = 90

	CategoryBusinessJustification = "BUSINESS_JUSTIFICATION"
	CategoryFalsePositive         = "FALSE_POSITIVE_EXCEPTION"
	CategoryCompensatingControl   = "COMPENSATING_CONTROL"
	CategoryUpstreamDependency    = "UPSTREAM_DEPENDENCY"

	StatusPending  = "PENDING"
	StatusApproved = "APPROVED"
	StatusRejected = "REJECTED"
	StatusExpired  = "EXPIRED"
	StatusRevoked  = "REVOKED"
)

type DecisionType string

const (
	DecisionApproved DecisionType = "APPROVED"
	DecisionRejected DecisionType = "REJECTED"
)

// RiskApproverValidator verifies whether an actor possesses authorized roles for risk exception sign-off.
type RiskApproverValidator interface {
	CanApproveRiskException(ctx context.Context, orgID uuid.UUID, actorID string, actorRole string) (bool, error)
}

// MemoryRiskApproverValidator provides an in-memory validator for testing.
type MemoryRiskApproverValidator struct {
	mu              sync.RWMutex
	authorizedRoles map[string]bool
}

func NewMemoryRiskApproverValidator() *MemoryRiskApproverValidator {
	return &MemoryRiskApproverValidator{
		authorizedRoles: map[string]bool{
			"CISO":           true,
			"SECURITY_ADMIN": true,
			"ORG_ADMIN":      true,
			"SECOPS_LEAD":    true,
		},
	}
}

func (v *MemoryRiskApproverValidator) CanApproveRiskException(_ context.Context, _ uuid.UUID, _ string, actorRole string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.authorizedRoles[strings.ToUpper(strings.TrimSpace(actorRole))], nil
}

// RiskExceptionRequest represents a formal exception request.
type RiskExceptionRequest struct {
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	FindingID            uuid.UUID
	Category             string
	Severity             string
	Rationale            string
	CompensatingControls string
	RequesterID          string
	RequestedDays        int
	RequiresDualApproval bool
	Status               string
	ApprovedAt           *time.Time
	ExpiresAt            *time.Time
	ReviewDate           *time.Time
	Approvals            []ApprovalRecord
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// ApprovalRecord captures an individual sign-off decision in the approval chain.
type ApprovalRecord struct {
	ID                 uuid.UUID
	ExceptionRequestID uuid.UUID
	OrganizationID     uuid.UUID
	ApproverID         string
	ApproverRole       string
	Decision           DecisionType
	Comments           string
	CreatedAt          time.Time
}

// RiskExceptionService orchestrates risk exception requests, dual authorizations, and expiration.
type RiskExceptionService struct {
	mu        sync.RWMutex
	validator RiskApproverValidator
	requests  map[uuid.UUID]*RiskExceptionRequest
}

func NewRiskExceptionService(validator RiskApproverValidator) *RiskExceptionService {
	return &RiskExceptionService{
		validator: validator,
		requests:  make(map[uuid.UUID]*RiskExceptionRequest),
	}
}

// SubmitRequest creates and registers a formal risk exception request.
func (s *RiskExceptionService) SubmitRequest(
	_ context.Context,
	orgID uuid.UUID,
	findingID uuid.UUID,
	category string,
	severity string,
	rationale string,
	compensatingControls string,
	requesterID string,
	requestedDays int,
) (*RiskExceptionRequest, error) {
	if orgID == uuid.Nil {
		return nil, ErrInvalidOrganizationID
	}
	if findingID == uuid.Nil {
		return nil, ErrInvalidFindingID
	}
	if strings.TrimSpace(requesterID) == "" {
		return nil, ErrInvalidAssignee
	}
	if strings.TrimSpace(rationale) == "" {
		return nil, ErrEmptyRationale
	}
	if requestedDays <= 0 {
		return nil, ErrDurationNonPositive
	}
	if requestedDays > MaxExceptionDurationDays {
		return nil, ErrDurationExceedsMax
	}

	normCat := strings.ToUpper(strings.TrimSpace(category))
	switch normCat {
	case CategoryBusinessJustification, CategoryFalsePositive, CategoryCompensatingControl, CategoryUpstreamDependency:
	default:
		return nil, ErrInvalidCategory
	}

	normSev := strings.ToUpper(strings.TrimSpace(severity))
	requiresDual := normSev == "CRITICAL"

	req := &RiskExceptionRequest{
		ID:                   uuid.New(),
		OrganizationID:       orgID,
		FindingID:            findingID,
		Category:             normCat,
		Severity:             normSev,
		Rationale:            strings.TrimSpace(rationale),
		CompensatingControls: strings.TrimSpace(compensatingControls),
		RequesterID:          strings.TrimSpace(requesterID),
		RequestedDays:        requestedDays,
		RequiresDualApproval: requiresDual,
		Status:               StatusPending,
		Approvals:            make([]ApprovalRecord, 0),
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID] = req
	return req, nil
}

// ReviewRequest records an approver's decision (Approve or Reject) enforcing SoD and role authorization.
func (s *RiskExceptionService) ReviewRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approverID string,
	approverRole string,
	decision DecisionType,
	comments string,
) (*RiskExceptionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[requestID]
	if !exists {
		return nil, ErrExceptionNotFound
	}
	if req.Status != StatusPending {
		return nil, ErrExceptionNotPending
	}

	approverID = strings.TrimSpace(approverID)
	if approverID == "" {
		return nil, ErrInvalidAssignee
	}

	// Separation of duties defense: Requester cannot approve their own exception
	if req.RequesterID == approverID {
		return nil, ErrSeparationOfDutiesViolation
	}

	// Check if this approver has already signed off
	for _, app := range req.Approvals {
		if app.ApproverID == approverID {
			return nil, ErrDuplicateApprover
		}
	}

	// Verify approver role authorization
	authorized, err := s.validator.CanApproveRiskException(ctx, req.OrganizationID, approverID, approverRole)
	if err != nil {
		return nil, fmt.Errorf("risk exception: role validation failed: %w", err)
	}
	if !authorized {
		return nil, ErrUnauthorizedApproverRole
	}

	approval := ApprovalRecord{
		ID:                 uuid.New(),
		ExceptionRequestID: req.ID,
		OrganizationID:     req.OrganizationID,
		ApproverID:         approverID,
		ApproverRole:       approverRole,
		Decision:           decision,
		Comments:           strings.TrimSpace(comments),
		CreatedAt:          time.Now().UTC(),
	}
	req.Approvals = append(req.Approvals, approval)
	req.UpdatedAt = time.Now().UTC()

	// Handle decision
	if decision == DecisionRejected {
		req.Status = StatusRejected
		return req, nil
	}

	// If decision is APPROVED:
	if req.RequiresDualApproval {
		// Count approved decisions
		approvedCount := 0
		for _, a := range req.Approvals {
			if a.Decision == DecisionApproved {
				approvedCount++
			}
		}
		if approvedCount >= 2 {
			s.activateApprovedException(req)
		}
	} else {
		s.activateApprovedException(req)
	}

	return req, nil
}

func (s *RiskExceptionService) activateApprovedException(req *RiskExceptionRequest) {
	now := time.Now().UTC()
	req.Status = StatusApproved
	req.ApprovedAt = &now

	expires := now.Add(time.Duration(req.RequestedDays) * 24 * time.Hour)
	req.ExpiresAt = &expires

	// Review date set to 14 days before expiry or halfway if duration is short
	reviewDays := req.RequestedDays - 14
	if reviewDays <= 0 {
		reviewDays = req.RequestedDays / 2
	}
	reviewDate := now.Add(time.Duration(reviewDays) * 24 * time.Hour)
	req.ReviewDate = &reviewDate
}

// RevokeException explicitly revokes an active approved exception before natural expiry.
func (s *RiskExceptionService) RevokeException(
	ctx context.Context,
	requestID uuid.UUID,
	actorID string,
	actorRole string,
	reason string,
) (*RiskExceptionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[requestID]
	if !exists {
		return nil, ErrExceptionNotFound
	}
	if req.Status != StatusApproved {
		return nil, ErrRevocationForbidden
	}

	authorized, err := s.validator.CanApproveRiskException(ctx, req.OrganizationID, actorID, actorRole)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, ErrUnauthorizedApproverRole
	}

	req.Status = StatusRevoked
	req.UpdatedAt = time.Now().UTC()

	// Append revocation audit record
	revRecord := ApprovalRecord{
		ID:                 uuid.New(),
		ExceptionRequestID: req.ID,
		OrganizationID:     req.OrganizationID,
		ApproverID:         actorID,
		ApproverRole:       actorRole,
		Decision:           DecisionRejected,
		Comments:           fmt.Sprintf("REVOCATION: %s", strings.TrimSpace(reason)),
		CreatedAt:          time.Now().UTC(),
	}
	req.Approvals = append(req.Approvals, revRecord)

	return req, nil
}

// EvaluateExpirations evaluates active exceptions against current time and marks expired ones.
func (s *RiskExceptionService) EvaluateExpirations(now time.Time) []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expiredIDs []uuid.UUID
	for _, req := range s.requests {
		if req.Status == StatusApproved && req.ExpiresAt != nil && now.After(*req.ExpiresAt) {
			req.Status = StatusExpired
			req.UpdatedAt = now
			expiredIDs = append(expiredIDs, req.ID)
		}
	}
	return expiredIDs
}

// GetRequest retrieves a request by ID.
func (s *RiskExceptionService) GetRequest(requestID uuid.UUID) (*RiskExceptionRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, exists := s.requests[requestID]
	if !exists {
		return nil, ErrExceptionNotFound
	}
	return req, nil
}
