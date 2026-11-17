package adapters_test

import (
	"context"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestRegisterDefaultAdapters(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("Registers all 5 MVP adapters cleanly", func(t *testing.T) {
		registry := adapters.NewRegistry()
		fakeExec := sandbox.NewFake()

		err := adapters.RegisterDefaultAdapters(registry, fakeExec)
		require.NoError(t, err)

		names := registry.Names()
		assert.Len(t, names, 5)
		assert.Contains(t, names, adapters.ScannerHTTPPreflight)
		assert.Contains(t, names, adapters.ScannerHTTPHeaders)
		assert.Contains(t, names, adapters.ScannerTLSAssessor)
		assert.Contains(t, names, adapters.ScannerNuclei)
		assert.Contains(t, names, adapters.ScannerZAPBaseline)

		err = registry.Initialize(ctx, logger)
		require.NoError(t, err)

		// Verify all 5 adapters are available
		for _, name := range names {
			meta, ok := registry.Metadata(name)
			assert.True(t, ok)
			assert.Equal(t, adapters.AvailabilityAvailable, meta.Availability)
		}
	})

	t.Run("Default verifiers return pinned version policies", func(t *testing.T) {
		nucleiVer, err := adapters.DefaultNucleiVerifier(ctx)
		require.NoError(t, err)
		assert.Equal(t, "3.3.7", nucleiVer.ScannerVersion)
		assert.Equal(t, "1.0.0", nucleiVer.AdapterVersion)
		assert.Equal(t, "kelvin.safe.web.v1", nucleiVer.TemplateCatalogVersion)
		assert.NotEmpty(t, nucleiVer.ImageDigest)

		zapVer, err := adapters.DefaultZAPVerifier(ctx)
		require.NoError(t, err)
		assert.Equal(t, "2.15.0", zapVer.ScannerVersion)
		assert.Equal(t, "1.0.0", zapVer.AdapterVersion)
		assert.NotEmpty(t, zapVer.ImageDigest)
	})

	t.Run("DefaultScopePolicyProvider resolves host accurately", func(t *testing.T) {
		task := adapters.Task{
			Target: "https://secure.example.com:8443/api/v1/resource",
		}
		policy, err := adapters.DefaultScopePolicyProvider(ctx, task)
		require.NoError(t, err)
		assert.Contains(t, policy.Domains, "secure.example.com")
	})

	t.Run("OCI runners enforce scope policy before execution", func(t *testing.T) {
		fakeExec := sandbox.NewFake()
		nucleiRunner := adapters.NewOCINucleiRunner(fakeExec)
		zapRunner := adapters.NewOCIZAPRunner(fakeExec)

		// Loopback target should be rejected by both runners
		loopbackTask := adapters.Task{
			Target: "http://127.0.0.1:8080/admin",
		}
		_, err := nucleiRunner(ctx, loopbackTask)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rejected by scope policy")

		_, err = zapRunner(ctx, loopbackTask)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rejected by scope policy")
	})
}
