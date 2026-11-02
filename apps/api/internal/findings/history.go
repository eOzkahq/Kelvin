// Package findings provides finding observation timeline aggregation, assessment history,
// and recurrence tracking over time.
//
// See docs/architecture/ASSESSMENT_HISTORY_AND_OBSERVATION_TIMELINE.md.
package findings

import (
	"sort"
	"time"

	"github.com/google/uuid"
)

// ScannerExecutionState classifies whether the scanner ran and found the vulnerability,
// or whether the scanner was omitted/skipped from the scan profile.
type ScannerExecutionState string

const (
	ScannerExecutedDetected ScannerExecutionState = "EXECUTED_DETECTED"
	ScannerNotRun           ScannerExecutionState = "SCANNER_NOT_RUN"
	ScannerExecutedNoMatch  ScannerExecutionState = "EXECUTED_NO_MATCH"
)

// ObservationPresenceState classifies the vulnerability's state at observation time.
type ObservationPresenceState string

const (
	PresenceInitialDiscovery ObservationPresenceState = "INITIAL_DISCOVERY"
	PresenceStillPresent     ObservationPresenceState = "STILL_PRESENT"
	PresenceRecurring        ObservationPresenceState = "RECURRING"
)

// ObservationTimelineEntry encapsulates a single chronological observation event.
type ObservationTimelineEntry struct {
	ObservationID       uuid.UUID                `json:"observation_id"`
	AssessmentID        uuid.UUID                `json:"assessment_id"`
	JobID               uuid.UUID                `json:"job_id"`
	ScannerID           string                   `json:"scanner_id"`
	ObservedAt          time.Time                `json:"observed_at"`
	IsPartialAssessment bool                     `json:"is_partial_assessment"`
	AssessmentStatus    string                   `json:"assessment_status"`
	ScannerExecution    ScannerExecutionState    `json:"scanner_execution"`
	PresenceState       ObservationPresenceState `json:"presence_state"`
	EvidenceCount       int                      `json:"evidence_count"`
	Metadata            map[string]any           `json:"metadata,omitempty"`
}

// FindingObservationTimeline aggregates the full assessment history for a finding.
type FindingObservationTimeline struct {
	FindingID         uuid.UUID                  `json:"finding_id"`
	TenantID          uuid.UUID                  `json:"tenant_id"`
	FirstObservedAt   time.Time                  `json:"first_observed_at"`
	LastObservedAt    time.Time                  `json:"last_observed_at"`
	TotalObservations int                        `json:"total_observations"`
	CurrentStatus     FindingStatus              `json:"current_status"`
	Timeline          []ObservationTimelineEntry `json:"timeline"`
}

// BuildObservationTimeline aggregates and enriches a finding's observation records into
// a chronological timeline, distinguishing partial assessments and preserving scanner provenance.
func BuildObservationTimeline(finding *PersistentFinding, rawObservations []*FindingObservation) *FindingObservationTimeline {
	if finding == nil {
		return nil
	}

	res := &FindingObservationTimeline{
		FindingID:         finding.ID,
		TenantID:          finding.TenantID,
		FirstObservedAt:   finding.FirstSeenAt,
		LastObservedAt:    finding.LastSeenAt,
		TotalObservations: len(rawObservations),
		CurrentStatus:     finding.Status,
		Timeline:          make([]ObservationTimelineEntry, 0, len(rawObservations)),
	}

	if len(rawObservations) == 0 {
		return res
	}

	// Sort observations chronologically ascending
	sorted := make([]*FindingObservation, len(rawObservations))
	copy(sorted, rawObservations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ObservedAt.Before(sorted[j].ObservedAt)
	})

	if res.FirstObservedAt.IsZero() {
		res.FirstObservedAt = sorted[0].ObservedAt
	}
	if res.LastObservedAt.IsZero() {
		res.LastObservedAt = sorted[len(sorted)-1].ObservedAt
	}

	for i, obs := range sorted {
		isPartial := false
		asmtStatus := "COMPLETED"

		if obs.RawMetadata != nil {
			if p, ok := obs.RawMetadata["partial_scan"].(bool); ok && p {
				isPartial = true
				asmtStatus = "COMPLETED_WITH_WARNINGS"
			}
			if s, ok := obs.RawMetadata["assessment_status"].(string); ok && s != "" {
				asmtStatus = s
			}
		}

		presence := PresenceStillPresent
		if i == 0 {
			presence = PresenceInitialDiscovery
		} else if finding.Status == StatusReopened {
			presence = PresenceRecurring
		}

		entry := ObservationTimelineEntry{
			ObservationID:       obs.ID,
			AssessmentID:        obs.AssessmentID,
			JobID:               obs.JobID,
			ScannerID:           obs.ScannerID,
			ObservedAt:          obs.ObservedAt,
			IsPartialAssessment: isPartial,
			AssessmentStatus:    asmtStatus,
			ScannerExecution:    ScannerExecutedDetected,
			PresenceState:       presence,
			EvidenceCount:       len(obs.EvidenceRefs),
			Metadata:            obs.RawMetadata,
		}

		res.Timeline = append(res.Timeline, entry)
	}

	return res
}
