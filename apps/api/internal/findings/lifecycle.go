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
	StatusOpen          FindingStatus = "OPEN"
	StatusConfirmed     FindingStatus = "CONFIRMED"
	StatusFalsePositive FindingStatus = "FALSE_POSITIVE"
	StatusRiskAccepted  FindingStatus = "RISK_ACCEPTED"
	StatusResolved      FindingStatus = "RESOLVED"
)

var validStatuses = map[FindingStatus]bool{
	StatusOpen:          true,
	StatusConfirmed:     true,
	StatusFalsePositive: true,
	StatusRiskAccepted:  true,
	StatusResolved:      true,
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
	ErrInvalidStatus     = errors.New("findings: invalid finding status")
	ErrIllegalTransition = errors.New("findings: illegal status transition")
	ErrSameStatus        = errors.New("findings: cannot transition to identical status")
)

// ValidateTransition enforces Kelvin's finding lifecycle state machine rules.
func ValidateTransition(from, to FindingStatus) error {
	if !validStatuses[from] {
		return fmt.Errorf("%w: unknown source status %q", ErrInvalidStatus, from)
	}
	if !validStatuses[to] {
		return fmt.Errorf("%w: unknown target status %q", ErrInvalidStatus, to)
	}
	if from == to {
		return fmt.Errorf("%w: already in status %q", ErrSameStatus, from)
	}

	switch from {
	case StatusOpen:
		// OPEN can transition to any triage or resolution state
		return nil
	case StatusConfirmed:
		// CONFIRMED can be resolved, marked false positive, risk-accepted, or set back to open
		return nil
	case StatusFalsePositive:
		// Reconsideration allows reopening
		if to == StatusOpen || to == StatusConfirmed {
			return nil
		}
		return fmt.Errorf("%w: cannot transition FALSE_POSITIVE directly to %s", ErrIllegalTransition, to)
	case StatusRiskAccepted:
		// Expired or revoked risk acceptance transitions back to open, confirmed, or resolved
		if to == StatusOpen || to == StatusConfirmed || to == StatusResolved {
			return nil
		}
		return fmt.Errorf("%w: cannot transition RISK_ACCEPTED directly to %s", ErrIllegalTransition, to)
	case StatusResolved:
		// Redetection or re-opening
		if to == StatusOpen || to == StatusConfirmed {
			return nil
		}
		return fmt.Errorf("%w: cannot transition RESOLVED directly to %s", ErrIllegalTransition, to)
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
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	FindingID     uuid.UUID      `json:"finding_id"`
	AssessmentID  uuid.UUID      `json:"assessment_id"`
	JobID         uuid.UUID      `json:"job_id"`
	ScannerID     string         `json:"scanner_id"`
	ObservedAt    time.Time      `json:"observed_at"`
	EvidenceRefs  []string       `json:"evidence_refs"`
	RawMetadata   map[string]any `json:"raw_metadata"`
	CreatedAt     time.Time      `json:"created_at"`
}

// CorrelationGroup models a logical group of related findings across scanners or targets.
type CorrelationGroup struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	RuleType    string    `json:"rule_type"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
// If the finding was previously RESOLVED, it is automatically reopened (AUTO_REOPENED).
func IngestObservation(finding *PersistentFinding, obs FindingObservation, corrID uuid.UUID) (*FindingEvent, error) {
	if finding.TenantID != obs.TenantID {
		return nil, fmt.Errorf("findings: tenant mismatch between finding (%s) and observation (%s)", finding.TenantID, obs.TenantID)
	}

	finding.OccurrenceCount++
	finding.LastSeenAt = obs.ObservedAt
	finding.LastJobID = &obs.JobID
	finding.UpdatedAt = time.Now().UTC()

	var event *FindingEvent

	// Auto-reopening rule: If an issue was resolved but is re-observed, reopen it
	if finding.Status == StatusResolved {
		oldStatus := StatusResolved
		finding.Status = StatusOpen
		event = &FindingEvent{
			ID:            uuid.New(),
			TenantID:      finding.TenantID,
			FindingID:     finding.ID,
			FromStatus:    &oldStatus,
			ToStatus:      StatusOpen,
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
