package findings

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// FindingStatus represents canonical lifecycle status.
type FindingStatus string

const (
	StatusNew           FindingStatus = "NEW"
	StatusOpen          FindingStatus = "OPEN" // Backward-compatible alias for StatusNew
	StatusConfirmed     FindingStatus = "CONFIRMED"
	StatusInProgress    FindingStatus = "IN_PROGRESS"
	StatusResolved      FindingStatus = "RESOLVED"
	StatusReopened      FindingStatus = "REOPENED"
	StatusFalsePositive FindingStatus = "FALSE_POSITIVE"
	StatusAcceptedRisk  FindingStatus = "ACCEPTED_RISK"
	StatusRiskAccepted  FindingStatus = "RISK_ACCEPTED" // Backward-compatible alias for StatusAcceptedRisk
)

var validStatuses = map[FindingStatus]bool{
	StatusNew:           true,
	StatusOpen:          true,
	StatusConfirmed:     true,
	StatusInProgress:    true,
	StatusResolved:      true,
	StatusReopened:      true,
	StatusFalsePositive: true,
	StatusAcceptedRisk:  true,
	StatusRiskAccepted:  true,
}

// CanonicalStatus maps legacy/alias statuses to canonical representation.
func CanonicalStatus(s FindingStatus) FindingStatus {
	switch s {
	case StatusOpen:
		return StatusNew
	case StatusRiskAccepted:
		return StatusAcceptedRisk
	default:
		return s
	}
}

// FindingEventType records historical triage and redetection events.
type FindingEventType string

const (
	EventCreated      FindingEventType = "CREATED"
	EventTriage       FindingEventType = "TRIAGE"
	EventRedetected   FindingEventType = "REDETECTED"
	EventAutoReopened FindingEventType = "AUTO_REOPENED"
	EventMerged       FindingEventType = "MERGED"
)

var (
	ErrInvalidStatus         = errors.New("findings: invalid finding status")
	ErrIllegalTransition     = errors.New("findings: illegal status transition")
	ErrSameStatus            = errors.New("findings: cannot transition to identical status")
	ErrAutomatedNotPermitted = errors.New("findings: automated scanner cannot trigger analyst-controlled state transition")
)

// ValidateTransition enforces Kelvin's finding lifecycle state machine rules.
func ValidateTransition(from, to FindingStatus) error {
	return ValidateTransitionWithActor(from, to, false)
}

// ValidateTransitionWithActor enforces state machine rules while checking whether automated scanners may trigger the change.
func ValidateTransitionWithActor(from, to FindingStatus, isAutomated bool) error {
	normFrom := CanonicalStatus(from)
	normTo := CanonicalStatus(to)

	if !validStatuses[from] && !validStatuses[normFrom] {
		return fmt.Errorf("%w: unknown source status %q", ErrInvalidStatus, from)
	}
	if !validStatuses[to] && !validStatuses[normTo] {
		return fmt.Errorf("%w: unknown target status %q", ErrInvalidStatus, to)
	}
	if normFrom == normTo {
		return fmt.Errorf("%w: already in status %q", ErrSameStatus, from)
	}

	// Scanner automation constraint: Automated runs can only auto-reopen RESOLVED findings
	if isAutomated {
		if normFrom == StatusResolved && (normTo == StatusReopened || normTo == StatusNew) {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s automatically", ErrAutomatedNotPermitted, from, to)
	}

	switch normFrom {
	case StatusNew:
		// NEW -> CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, IN_PROGRESS
		if normTo == StatusConfirmed || normTo == StatusFalsePositive || normTo == StatusAcceptedRisk || normTo == StatusInProgress {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	case StatusConfirmed:
		// CONFIRMED -> IN_PROGRESS, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED
		if normTo == StatusInProgress || normTo == StatusFalsePositive || normTo == StatusAcceptedRisk || normTo == StatusResolved {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	case StatusInProgress:
		// IN_PROGRESS -> RESOLVED, CONFIRMED
		if normTo == StatusResolved || normTo == StatusConfirmed {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	case StatusResolved:
		// RESOLVED -> REOPENED, IN_PROGRESS, NEW
		if normTo == StatusReopened || normTo == StatusInProgress || normTo == StatusNew {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	case StatusReopened:
		// REOPENED -> IN_PROGRESS, RESOLVED, CONFIRMED
		if normTo == StatusInProgress || normTo == StatusResolved || normTo == StatusConfirmed {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	case StatusFalsePositive:
		// FALSE_POSITIVE -> NEW (reconsidered by analyst)
		if normTo == StatusNew {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	case StatusAcceptedRisk:
		// ACCEPTED_RISK -> NEW (policy expiry / revocation), RESOLVED
		if normTo == StatusNew || normTo == StatusResolved {
			return nil
		}
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrIllegalTransition, from, to)

	default:
		return fmt.Errorf("%w: unhandled status %s", ErrIllegalTransition, from)
	}
}

// PersistentFinding represents a tenant-scoped finding tracked across assessments.
type PersistentFinding struct {
	ID                 uuid.UUID      `json:"id"`
	TenantID           uuid.UUID      `json:"tenant_id"`
	ProjectID          uuid.UUID      `json:"project_id"`
	AssessmentID       uuid.UUID      `json:"assessment_id"`
	JobID              uuid.UUID      `json:"job_id"`
	AssetID            *uuid.UUID     `json:"asset_id,omitempty"`
	CorrelationGroupID *uuid.UUID     `json:"correlation_group_id,omitempty"`
	Fingerprint        string         `json:"fingerprint"`
	Title              string         `json:"title"`
	Severity           string         `json:"severity"`
	Confidence         float64        `json:"confidence"`
	CVSSScore          *float64       `json:"cvss_score,omitempty"`
	CWEID              string         `json:"cwe_id,omitempty"`
	CVEIDs             []string       `json:"cve_ids"`
	Status             FindingStatus  `json:"status"`
	AffectedEndpoint   string         `json:"affected_endpoint,omitempty"`
	ScannerData        map[string]any `json:"scanner_data"`
	Tags               []string       `json:"tags"`
	FirstSeenAt        time.Time      `json:"first_seen_at"`
	LastSeenAt         time.Time      `json:"last_seen_at"`
	FirstJobID         uuid.UUID      `json:"first_job_id"`
	LastJobID          *uuid.UUID     `json:"last_job_id,omitempty"`
	OccurrenceCount    int64          `json:"occurrence_count"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// FindingObservation represents an immutable occurrence from a specific assessment.
type FindingObservation struct {
	ID           uuid.UUID      `json:"id"`
	TenantID     uuid.UUID      `json:"tenant_id"`
	FindingID    uuid.UUID      `json:"finding_id"`
	AssessmentID uuid.UUID      `json:"assessment_id"`
	JobID        uuid.UUID      `json:"job_id"`
	ScannerID    string         `json:"scanner_id"`
	ObservedAt   time.Time      `json:"observed_at"`
	EvidenceRefs []string       `json:"evidence_refs"`
	RawMetadata  map[string]any `json:"raw_metadata"`
	CreatedAt    time.Time      `json:"created_at"`
}

// FindingEvent records an immutable audit trail entry for a status or ownership change.
type FindingEvent struct {
	ID            uuid.UUID        `json:"id"`
	TenantID      uuid.UUID        `json:"tenant_id"`
	FindingID     uuid.UUID        `json:"finding_id"`
	FromStatus    *FindingStatus   `json:"from_status,omitempty"`
	ToStatus      FindingStatus    `json:"to_status"`
	EventType     FindingEventType `json:"event_type"`
	ActorUserID   *uuid.UUID       `json:"actor_user_id,omitempty"`
	Note          string           `json:"note,omitempty"`
	CorrelationID uuid.UUID        `json:"correlation_id"`
	CreatedAt     time.Time        `json:"created_at"`
}

// IngestObservation updates a persistent finding upon observing a new assessment occurrence.
// If the finding was previously RESOLVED, it is automatically reopened (REOPENED).
// Analyst-controlled states (CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK) are preserved without status overwrite.
func IngestObservation(finding *PersistentFinding, obs FindingObservation, corrID uuid.UUID) (*FindingEvent, error) {
	if finding.TenantID != obs.TenantID {
		return nil, fmt.Errorf("findings: tenant mismatch between finding (%s) and observation (%s)", finding.TenantID, obs.TenantID)
	}

	finding.OccurrenceCount++
	finding.LastSeenAt = obs.ObservedAt
	finding.LastJobID = &obs.JobID
	finding.UpdatedAt = time.Now().UTC()

	var event *FindingEvent

	// Auto-reopening rule: If an issue was resolved but is re-observed, transition to REOPENED
	if CanonicalStatus(finding.Status) == StatusResolved {
		oldStatus := StatusResolved
		finding.Status = StatusReopened
		event = &FindingEvent{
			ID:            uuid.New(),
			TenantID:      finding.TenantID,
			FindingID:     finding.ID,
			FromStatus:    &oldStatus,
			ToStatus:      StatusReopened,
			EventType:     EventAutoReopened,
			Note:          fmt.Sprintf("Automatically reopened upon redetection by scanner %s in job %s", obs.ScannerID, obs.JobID),
			CorrelationID: corrID,
			CreatedAt:     time.Now().UTC(),
		}
	} else {
		currentStatus := finding.Status
		event = &FindingEvent{
			ID:            uuid.New(),
			TenantID:      finding.TenantID,
			FindingID:     finding.ID,
			FromStatus:    &currentStatus,
			ToStatus:      currentStatus,
			EventType:     EventRedetected,
			Note:          fmt.Sprintf("Observed by scanner %s in job %s", obs.ScannerID, obs.JobID),
			CorrelationID: corrID,
			CreatedAt:     time.Now().UTC(),
		}
	}

	return event, nil
}
