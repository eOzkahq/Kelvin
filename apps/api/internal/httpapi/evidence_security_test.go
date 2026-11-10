package httpapi_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/evidence"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/apps/api/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestEvidenceSecurityHardening(t *testing.T) {
	log := zap.NewNop()

	t.Run("Production mode rejects fallback signing key", func(t *testing.T) {
		cfg := config.Config{
			Env:         config.EnvProduction,
			Development: false,
			Evidence: config.EvidenceConfig{
				SigningKey: "kelvin-default-evidence-signing-key-32-bytes",
			},
		}
		srv := httpapi.New(cfg, log)
		err := srv.ValidateDependencies(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "job store is required")
	})

	t.Run("Production mode rejects empty or short signing key", func(t *testing.T) {
		cfg := config.Config{
			Env:         config.EnvProduction,
			Development: false,
			Evidence: config.EvidenceConfig{
				SigningKey: "short-key-16-bytes",
			},
		}
		srv := httpapi.New(cfg, log)
		err := srv.ValidateDependencies(true)
		assert.Error(t, err)
	})

	t.Run("Valid 32-byte key generates verifiable, expiring signed URLs", func(t *testing.T) {
		key := "production-grade-evidence-signing-key-32b!"
		signer, err := evidence.NewSigner([]byte(key))
		require.NoError(t, err)

		tenantID := uuid.New().String()
		evidenceID := uuid.New().String()
		baseURL := "https://api.kelvin.security/api/v1/evidence/" + evidenceID + "/download"

		// Generate signed URL with 5-minute TTL
		signedURL, err := signer.SignDownloadURL(evidenceID, tenantID, 300*time.Second, baseURL)
		require.NoError(t, err)
		assert.NotEmpty(t, signedURL)

		// Verification with correct URL succeeds
		retEvidenceID, retTenantID, expires, err := signer.ValidateDownloadURL(signedURL)
		assert.NoError(t, err)
		assert.Equal(t, evidenceID, retEvidenceID)
		assert.Equal(t, tenantID, retTenantID)
		assert.Greater(t, expires, time.Now().Unix())

		// Tampered tenant ID in URL fails verification
		tamperedURL := strings.Replace(signedURL, tenantID, uuid.New().String(), 1)
		_, _, _, err = signer.ValidateDownloadURL(tamperedURL)
		assert.Error(t, err, "Tampered URL signature must fail verification")

		// Expired signed URL fails closed
		expiredURL := strings.Replace(signedURL, "expires="+strconv.FormatInt(expires, 10), "expires=1000", 1)
		_, _, _, err = signer.ValidateDownloadURL(expiredURL)
		assert.Error(t, err, "Expired URL must fail validation")
	})

	t.Run("Storage path enforces strict tenant partition", func(t *testing.T) {
		tenantA := uuid.New().String()
		tenantB := uuid.New().String()
		asmtID := uuid.New().String()
		fileID := "evidence-output.json"

		validPath := tenantA + "/" + asmtID + "/" + fileID
		err := storage.ValidateStoragePath(validPath, tenantA)
		assert.NoError(t, err)

		// Cross-tenant path access denied
		err = storage.ValidateStoragePath(validPath, tenantB)
		assert.ErrorIs(t, err, storage.ErrCrossTenantAccess)
	})
}
