package evidence_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

func TestIngestFindingEvidence_Success(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	svc := evidence.NewIngestionService(repo)

	tenantID := uuid.New().String()
	projectID := uuid.New().String()
	assessmentID := uuid.New().String()
	jobID := uuid.New().String()
	findingID := uuid.New().String()
	observationID := uuid.New().String()

	rawEvidences := []normalization.Evidence{
		{
			Type:            "HEADER_DUMP",
			ContentType:     "text/plain",
			ContentRedacted: "Content-Security-Policy: <missing>\r\nX-Frame-Options: <missing>",
			RedactedFields:  []string{},
		},
		{
			Type:            "HTTP_REQUEST_RESPONSE",
			ContentType:     "text/plain",
			ContentRedacted: "GET /admin HTTP/1.1\r\nAuthorization: [REDACTED]\r\n\r\n403 Forbidden",
			RedactedFields:  []string{"Authorization"},
		},
	}

	ingestCtx := evidence.IngestContext{
		TenantID:          tenantID,
		ProjectID:         projectID,
		AssessmentID:      assessmentID,
		JobID:             jobID,
		FindingID:         findingID,
		ObservationID:     observationID,
		ScannerName:       "builtin.http_headers",
		IsTrustedWorkflow: true,
	}

	items, err := svc.IngestFindingEvidence(ctx, ingestCtx, rawEvidences)
	require.NoError(t, err)
	require.Len(t, items, 2)

	assert.Equal(t, evidence.TypeSecurityHeaderDiff, items[0].EvidenceType)
	assert.Equal(t, evidence.TypeHTTPObservation, items[1].EvidenceType)
	assert.Equal(t, evidence.ProvenanceCuratedFinding, items[0].Provenance)
	assert.Equal(t, evidence.ProvenanceCuratedFinding, items[1].Provenance)
	assert.Equal(t, evidence.RedactionSanitizedPresentation, items[1].RedactionStatus)

	// Verify links
	links, err := repo.GetLinksByFindingID(ctx, tenantID, findingID)
	require.NoError(t, err)
	require.Len(t, links, 2)
	assert.True(t, links[0].IsPrimary)
	assert.False(t, links[1].IsPrimary)

	// Verify retrieve by finding ID
	associated, err := repo.GetEvidenceByFindingID(ctx, tenantID, findingID)
	require.NoError(t, err)
	require.Len(t, associated, 2)
}

func TestIngestFindingEvidence_OversizedRejection(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	svc := evidence.NewIngestionService(repo)

	oversizedPayload := strings.Repeat("A", evidence.MaxEvidenceSizeBytes+10)

	rawEvidences := []normalization.Evidence{
		{
			Type:            "HTTP_RESPONSE",
			ContentType:     "text/plain",
			ContentRedacted: oversizedPayload,
		},
	}

	ingestCtx := evidence.IngestContext{
		TenantID:          uuid.New().String(),
		ProjectID:         uuid.New().String(),
		AssessmentID:      uuid.New().String(),
		JobID:             uuid.New().String(),
		FindingID:         uuid.New().String(),
		IsTrustedWorkflow: true,
	}

	_, err := svc.IngestFindingEvidence(ctx, ingestCtx, rawEvidences)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrEvidenceOversized)
}

func TestIngestFindingEvidence_UntrustedWorkflow(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	svc := evidence.NewIngestionService(repo)

	rawEvidences := []normalization.Evidence{
		{
			Type:            "RAW_OUTPUT",
			ContentType:     "text/plain",
			ContentRedacted: "some raw output",
		},
	}

	ingestCtx := evidence.IngestContext{
		TenantID:          uuid.New().String(),
		ProjectID:         uuid.New().String(),
		AssessmentID:      uuid.New().String(),
		JobID:             uuid.New().String(),
		FindingID:         uuid.New().String(),
		IsTrustedWorkflow: false, // Untrusted caller
	}

	_, err := svc.IngestFindingEvidence(ctx, ingestCtx, rawEvidences)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrUnauthorizedSource)
}

func TestIngestFindingEvidence_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	svc := evidence.NewIngestionService(repo)

	tenantA := uuid.New().String()
	tenantB := uuid.New().String()

	rawEvidences := []normalization.Evidence{
		{
			Type:            "TLS_CERTIFICATE",
			ContentType:     "text/plain",
			ContentRedacted: "CN=example.com, Issuer=Let's Encrypt",
		},
	}

	items, err := svc.IngestFindingEvidence(ctx, evidence.IngestContext{
		TenantID:          tenantA,
		ProjectID:         uuid.New().String(),
		AssessmentID:      uuid.New().String(),
		JobID:             uuid.New().String(),
		FindingID:         uuid.New().String(),
		IsTrustedWorkflow: true,
	}, rawEvidences)
	require.NoError(t, err)
	require.Len(t, items, 1)

	// Attempt cross-tenant access
	_, err = repo.GetEvidenceByID(ctx, tenantB, items[0].ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrTenantMismatch)
}
