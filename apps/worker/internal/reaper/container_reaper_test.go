package reaper

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/workspace"
	"go.uber.org/zap"
)

type mockContainerRuntime struct {
	mu         sync.Mutex
	containers []ContainerInfo
	removed    []string
}

func (m *mockContainerRuntime) ListContainers(ctx context.Context, filter string) ([]ContainerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ContainerInfo, len(m.containers))
	copy(out, m.containers)
	return out, nil
}

func (m *mockContainerRuntime) RemoveContainer(ctx context.Context, idOrName string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed = append(m.removed, idOrName)
	return nil
}

func TestOrphanContainerReaper_ReapsExitedContainers(t *testing.T) {
	runtime := &mockContainerRuntime{
		containers: []ContainerInfo{
			{
				ID:      "c-1",
				Names:   []string{"/kelvin-job-exited-1"},
				State:   "exited",
				Created: time.Now().Add(-5 * time.Minute).Unix(),
			},
			{
				ID:      "c-2",
				Names:   []string{"/caddy-proxy"},
				State:   "exited", // non-kelvin container must not be touched
				Created: time.Now().Add(-10 * time.Minute).Unix(),
			},
			{
				ID:      "c-3",
				Names:   []string{"/kelvin-job-active-1"},
				State:   "running",
				Created: time.Now().Add(-5 * time.Minute).Unix(),
			},
		},
	}

	reaper := NewOrphanContainerReaper(runtime, 30*time.Minute, zap.NewNop())
	reaped, err := reaper.ReapOrphans(context.Background())
	if err != nil {
		t.Fatalf("unexpected error during reap: %v", err)
	}

	if reaped != 1 {
		t.Fatalf("expected 1 reaped container, got %d", reaped)
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.removed) != 1 || runtime.removed[0] != "/kelvin-job-exited-1" {
		t.Fatalf("expected /kelvin-job-exited-1 to be removed, got: %v", runtime.removed)
	}
}

func TestOrphanContainerReaper_ReapsOldRunningContainers(t *testing.T) {
	runtime := &mockContainerRuntime{
		containers: []ContainerInfo{
			{
				ID:      "c-stale",
				Names:   []string{"/kelvin-job-stale"},
				State:   "running",
				Created: time.Now().Add(-2 * time.Hour).Unix(), // 2 hours old > 30m maxAge
			},
			{
				ID:      "c-fresh",
				Names:   []string{"/kelvin-job-fresh"},
				State:   "running",
				Created: time.Now().Add(-5 * time.Minute).Unix(), // 5 minutes old < 30m maxAge
			},
		},
	}

	reaper := NewOrphanContainerReaper(runtime, 30*time.Minute, zap.NewNop())
	reaped, err := reaper.ReapOrphans(context.Background())
	if err != nil {
		t.Fatalf("unexpected error during reap: %v", err)
	}

	if reaped != 1 {
		t.Fatalf("expected 1 reaped container, got %d", reaped)
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.removed) != 1 || runtime.removed[0] != "/kelvin-job-stale" {
		t.Fatalf("expected /kelvin-job-stale to be removed, got: %v", runtime.removed)
	}
}

func TestCompositeReaper_SweepsAllSubsystems(t *testing.T) {
	store := &mockStore{reaped: 2}
	runtime := &mockContainerRuntime{
		containers: []ContainerInfo{
			{
				ID:      "c-dead",
				Names:   []string{"/kelvin-job-dead"},
				State:   "dead",
				Created: time.Now().Add(-10 * time.Minute).Unix(),
			},
		},
	}

	// Create real temporary workspace manager
	tempDir := t.TempDir()
	wsManager, err := workspace.NewManager(tempDir, zap.NewNop())
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	// Create an old workspace directory
	tenantDir := filepath.Join(tempDir, "tenants", "test-tenant-1", "runs", "test-run-1")
	_ = os.MkdirAll(tenantDir, 0700)
	oldTime := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(tenantDir, oldTime, oldTime)

	compReaper := NewCompositeReaper(
		store,
		runtime,
		wsManager,
		100*time.Millisecond,
		30*time.Minute,
		zap.NewNop(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := compReaper.ReapOnce(ctx); err != nil {
		t.Fatalf("ReapOnce returned error: %v", err)
	}

	// 1. Verify store reaped
	if store.calls() != 1 {
		t.Errorf("expected 1 store reap call, got %d", store.calls())
	}

	// 2. Verify container reaped
	runtime.mu.Lock()
	if len(runtime.removed) != 1 || runtime.removed[0] != "/kelvin-job-dead" {
		t.Errorf("expected /kelvin-job-dead to be removed, got: %v", runtime.removed)
	}
	runtime.mu.Unlock()

	// 3. Verify workspace reaped
	if _, err := os.Stat(tenantDir); !os.IsNotExist(err) {
		t.Errorf("expected old workspace directory %q to be removed, stat err: %v", tenantDir, err)
	}
}
