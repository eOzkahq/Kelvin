package reaper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockStore is a test double for storeIface.
type mockStore struct {
	mu      sync.Mutex
	reapErr error
	reaped  int64
	callCnt int
	lastCtx context.Context
}

func (m *mockStore) ReapStalled(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCnt++
	m.lastCtx = ctx
	if m.reapErr != nil {
		return 0, m.reapErr
	}
	return m.reaped, nil
}

func (m *mockStore) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCnt
}

func TestReaperRunsInitialScan(t *testing.T) {
	store := &mockStore{reaped: 3}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{Interval: time.Hour}, store)
	}()

	// Wait for the initial scan to complete.
	time.Sleep(50 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if store.calls() < 1 {
		t.Fatalf("expected at least one reap call, got %d", store.calls())
	}
}

func TestReaperPropagatesStoreErrors(t *testing.T) {
	store := &mockStore{reapErr: errors.New("db down")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{Interval: 10 * time.Millisecond}, store)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if store.calls() < 1 {
		t.Fatalf("expected at least one reap call, got %d", store.calls())
	}
}

func TestReaperRespectsContextCancellation(t *testing.T) {
	store := &mockStore{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, zap.NewNop(), Config{Interval: time.Hour}, store)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run should return nil on cancellation, got %v", err)
	}
}

func TestReapOnceHandlesZeroReaped(t *testing.T) {
	store := &mockStore{reaped: 0}
	ctx := context.Background()
	if err := reapOnce(ctx, zap.NewNop(), store); err != nil {
		t.Fatalf("reapOnce returned error: %v", err)
	}
	if store.calls() != 1 {
		t.Fatalf("expected 1 reap call, got %d", store.calls())
	}
}

var _ = time.Second
