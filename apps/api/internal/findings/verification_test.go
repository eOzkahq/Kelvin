package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerificationOutcome_IsValid(t *testing.T) {
	valid := []VerificationOutcome{
		VerificationOutcomeVerified,
		VerificationOutcomeFailed,
		VerificationOutcomeInconclusive,
		VerificationOutcomeAssessmentFailed,
	}
	for _, o := range valid {
		assert.True(t, o.IsValid())
	}
	assert.False(t, VerificationOutcome("UNKNOWN").IsValid())
}

func TestRemediationVerificationService(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()

	setupService := func() (*RemediationVerificationService, *MemoryRemediationRepository, *MemoryFindingStore, *PersistentFinding, *RemediationTask) {
		repo := NewMemoryRemediationRepository()
		wfService := NewRemediationWorkflowService(repo)
		store := NewMemoryFindingStore()

		finding := &PersistentFinding{
			ID:               uuid.New(),
			TenantID:         tenantID,
			ProjectID:        projectID,
			Fingerprint:      "fp-cve-2024-1234",
			Status:           StatusConfirmed,
			AffectedEndpoint: "https://app.kelvin.internal",
			ScannerData: map[string]any{
				"tool_name":    "nuclei",
				"scanner_type": "nuclei",
			},
			Severity:    "HIGH",
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		store.Save(finding)

		task, err := NewRemediationTask(tenantID, finding.ID, "Patch CVE-2024-1234", "Apply patch", "Upgrade package", "alice", nil)
		if err != nil {
			panic(err)
		}
		task.State = RemediationStateReadyForVerification
		_ = repo.CreateTask(ctx, task)

		service := NewRemediationVerificationService(repo, wfService, store)
		return service, repo, store, finding, task
	}

	t.Run("successful verification: flaw resolved", func(t *testing.T) {
		service, repo, store, finding, task := setupService()

		assessmentID := uuid.New()
		data := VerificationAssessmentData{
			AssessmentID:         assessmentID,
			Status:               "COMPLETED",
			Target:               "https://app.kelvin.internal",
			ActiveScanners:       []string{"nuclei"},
			ObservedFingerprints: []string{"fp-other-vuln"}, // original fp not detected!
		}

		result, err := service.VerifyRemediation(ctx, tenantID, task.ID, data, "verifier-1")
		require.NoError(t, err)

		assert.Equal(t, VerificationOutcomeVerified, result.Outcome)
		assert.Equal(t, RemediationStateCompleted, result.NewTaskState)
		assert.Equal(t, StatusResolved, result.NewFindingState)

		// Verify task in repo
		updatedTask, err := repo.GetTask(ctx, tenantID, task.ID)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateCompleted, updatedTask.State)
		require.NotNil(t, updatedTask.VerificationAssessmentID)
		assert.Equal(t, assessmentID, *updatedTask.VerificationAssessmentID)

		// Verify finding in store
		updatedFinding, err := store.GetFindingByID(ctx, tenantID, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusResolved, updatedFinding.Status)
	})

	t.Run("failed verification: flaw still detected", func(t *testing.T) {
		service, repo, store, finding, task := setupService()

		assessmentID := uuid.New()
		data := VerificationAssessmentData{
			AssessmentID:         assessmentID,
			Status:               "COMPLETED",
			Target:               "https://app.kelvin.internal",
			ActiveScanners:       []string{"nuclei"},
			ObservedFingerprints: []string{"fp-cve-2024-1234"}, // still present!
		}

		result, err := service.VerifyRemediation(ctx, tenantID, task.ID, data, "verifier-1")
		require.NoError(t, err)

		assert.Equal(t, VerificationOutcomeFailed, result.Outcome)
		assert.Equal(t, RemediationStateReopened, result.NewTaskState)

		updatedTask, err := repo.GetTask(ctx, tenantID, task.ID)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateReopened, updatedTask.State)

		// Finding stays confirmed because it was not resolved prior
		updatedFinding, err := store.GetFindingByID(ctx, tenantID, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusConfirmed, updatedFinding.Status)
	})

	t.Run("inconclusive verification: missing scanner coverage", func(t *testing.T) {
		service, repo, store, finding, task := setupService()

		assessmentID := uuid.New()
		data := VerificationAssessmentData{
			AssessmentID:         assessmentID,
			Status:               "COMPLETED",
			Target:               "https://app.kelvin.internal",
			ActiveScanners:       []string{"zap"}, // nuclei was NOT executed
			ObservedFingerprints: []string{},
		}

		result, err := service.VerifyRemediation(ctx, tenantID, task.ID, data, "verifier-1")
		require.NoError(t, err)

		assert.Equal(t, VerificationOutcomeInconclusive, result.Outcome)
		assert.Equal(t, RemediationStateReadyForVerification, result.NewTaskState)
		assert.Equal(t, StatusConfirmed, result.NewFindingState)

		// Verify task stayed READY_FOR_VERIFICATION
		updatedTask, err := repo.GetTask(ctx, tenantID, task.ID)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateReadyForVerification, updatedTask.State)

		// Finding status untouched
		updatedFinding, err := store.GetFindingByID(ctx, tenantID, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusConfirmed, updatedFinding.Status)
	})

	t.Run("assessment failed: inconclusive verification", func(t *testing.T) {
		service, repo, _, _, task := setupService()

		assessmentID := uuid.New()
		data := VerificationAssessmentData{
			AssessmentID:   assessmentID,
			Status:         "FAILED",
			Target:         "https://app.kelvin.internal",
			ActiveScanners: []string{"nuclei"},
		}

		result, err := service.VerifyRemediation(ctx, tenantID, task.ID, data, "verifier-1")
		require.NoError(t, err)

		assert.Equal(t, VerificationOutcomeAssessmentFailed, result.Outcome)
		assert.Equal(t, RemediationStateReadyForVerification, result.NewTaskState)

		updatedTask, err := repo.GetTask(ctx, tenantID, task.ID)
		require.NoError(t, err)
		assert.Equal(t, RemediationStateReadyForVerification, updatedTask.State)
	})

	t.Run("task not ready for verification error", func(t *testing.T) {
		service, repo, _, _, task := setupService()
		task.State = RemediationStateOpen
		_ = repo.UpdateTask(ctx, task)

		data := VerificationAssessmentData{
			AssessmentID: uuid.New(),
			Status:       "COMPLETED",
		}

		_, err := service.VerifyRemediation(ctx, tenantID, task.ID, data, "verifier-1")
		assert.ErrorIs(t, err, ErrTaskNotReadyForVerification)
	})

	t.Run("target scope mismatch error", func(t *testing.T) {
		service, _, _, _, task := setupService()

		data := VerificationAssessmentData{
			AssessmentID:   uuid.New(),
			Status:         "COMPLETED",
			Target:         "https://other-unrelated-domain.com",
			ActiveScanners: []string{"nuclei"},
		}

		_, err := service.VerifyRemediation(ctx, tenantID, task.ID, data, "verifier-1")
		assert.ErrorIs(t, err, ErrScopeMismatch)
	})

	t.Run("cross tenant rejection", func(t *testing.T) {
		service, _, _, _, task := setupService()
		otherTenant := uuid.New()

		data := VerificationAssessmentData{
			AssessmentID: uuid.New(),
			Status:       "COMPLETED",
		}

		_, err := service.VerifyRemediation(ctx, otherTenant, task.ID, data, "attacker")
		assert.ErrorIs(t, err, ErrTenantMismatch)
	})
}
