package httpapi_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/apps/api/internal/idempotency"
	"github.com/kelvin/kelvin/apps/api/pkg/job"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type dummyJobStore struct{}

func (d dummyJobStore) Transition(ctx context.Context, id string, to job.State, workerID string) error {
	return nil
}

type dummyIdempotencyStore struct{}

func (d dummyIdempotencyStore) Get(ctx context.Context, key string) (*idempotency.Record, error) {
	return nil, idempotency.ErrNotFound
}
func (d dummyIdempotencyStore) SetInProgress(ctx context.Context, key, tenantID, payloadHash string) error {
	return nil
}
func (d dummyIdempotencyStore) SetCompleted(ctx context.Context, key string, statusCode int, body []byte, headers map[string]string) error {
	return nil
}

func TestServerCompositionValidation(t *testing.T) {
	cfg := config.Config{
		Env:         config.EnvDevelopment,
		Development: true,
		Evidence: config.EvidenceConfig{
			SigningKey: "super-secret-key-32-bytes-minimum-length-req",
		},
	}
	log := zap.NewNop()

	t.Run("Development mode allows unwired stores", func(t *testing.T) {
		srv := httpapi.New(cfg, log)
		err := srv.ValidateDependencies(false)
		assert.NoError(t, err)
	})

	t.Run("Production mode fails fast when stores are nil", func(t *testing.T) {
		srv := httpapi.New(cfg, log)
		err := srv.ValidateDependencies(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "job store is required")

		// Wire job store
		srv.SetJobStore(dummyJobStore{})
		err = srv.ValidateDependencies(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "finding store is required")

		// Wire finding store with PostgresFindingRepository
		findingRepo := findings.NewPostgresFindingRepository(nil)
		srv.SetFindingStore(findingRepo)
		err = srv.ValidateDependencies(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "idempotency store is required")

		// Wire idempotency store
		srv.SetIdempotencyStore(dummyIdempotencyStore{})
		err = srv.ValidateDependencies(true)
		assert.NoError(t, err)
	})
}

func TestPostgresFindingRepositoryImplementsStore(t *testing.T) {
	repo := findings.NewPostgresFindingRepository(nil)
	assert.NotNil(t, repo)

	// Invariants check: calling with nil tenant returns ErrTenantRequired
	ctx := context.Background()
	_, err := repo.GetEvidenceByFindingID(ctx, uuid.Nil, uuid.New())
	assert.ErrorIs(t, err, findings.ErrTenantRequired)

	_, err = repo.GetEvidenceByID(ctx, uuid.Nil, uuid.New())
	assert.ErrorIs(t, err, findings.ErrTenantRequired)

	_, _, err = repo.GetObservationsByAssessment(ctx, uuid.Nil, uuid.New())
	assert.ErrorIs(t, err, findings.ErrTenantRequired)

	_, err = repo.SearchFindings(ctx, findings.FindingSearchQuery{TenantID: uuid.Nil})
	assert.ErrorIs(t, err, findings.ErrMissingTenantID)

	_, err = repo.GetDashboardMetrics(ctx, uuid.Nil)
	assert.ErrorIs(t, err, findings.ErrMissingTenantID)
}
