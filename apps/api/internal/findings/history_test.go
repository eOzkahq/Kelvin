package findings_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/findings"
)

func TestBuildObservationTimeline(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	t0 := time.Now().UTC().AddDate(0, 0, -30)
	t1 := time.Now().UTC().AddDate(0, 0, -15)
	t2 := time.Now().UTC()

	finding := &findings.PersistentFinding{
		ID:          findingID,
		TenantID:    tenantID,
		Status:      findings.StatusConfirmed,
		FirstSeenAt: t0,
		LastSeenAt:  t2,
	}

	obs1 := &findings.FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: uuid.New(),
		JobID:        uuid.New(),
		ScannerID:    "zap",
		ObservedAt:   t0,
		EvidenceRefs: []string{"ev-1"},
	}

	obs2 := &findings.FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: uuid.New(),
		JobID:        uuid.New(),
		ScannerID:    "nuclei",
		ObservedAt:   t1,
		EvidenceRefs: []string{"ev-2", "ev-3"},
		RawMetadata: map[string]any{
			"partial_scan": true,
		},
	}

	obs3 := &findings.FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: uuid.New(),
		JobID:        uuid.New(),
		ScannerID:    "builtin.http_security_headers",
		ObservedAt:   t2,
		EvidenceRefs: []string{"ev-4"},
	}

	// Pass in arbitrary order to test sorting
	timeline := findings.BuildObservationTimeline(finding, []*findings.FindingObservation{obs2, obs3, obs1})

	require.NotNil(t, timeline)
	assert.Equal(t, findingID, timeline.FindingID)
	assert.Equal(t, tenantID, timeline.TenantID)
	assert.Equal(t, 3, timeline.TotalObservations)
	assert.Len(t, timeline.Timeline, 3)

	// Chronological ordering check
	assert.Equal(t, obs1.ID, timeline.Timeline[0].ObservationID)
	assert.Equal(t, findings.PresenceInitialDiscovery, timeline.Timeline[0].PresenceState)
	assert.False(t, timeline.Timeline[0].IsPartialAssessment)

	assert.Equal(t, obs2.ID, timeline.Timeline[1].ObservationID)
	assert.Equal(t, findings.PresenceStillPresent, timeline.Timeline[1].PresenceState)
	assert.True(t, timeline.Timeline[1].IsPartialAssessment)
	assert.Equal(t, "COMPLETED_WITH_WARNINGS", timeline.Timeline[1].AssessmentStatus)

	assert.Equal(t, obs3.ID, timeline.Timeline[2].ObservationID)
	assert.Equal(t, findings.PresenceStillPresent, timeline.Timeline[2].PresenceState)
	assert.False(t, timeline.Timeline[2].IsPartialAssessment)
}
