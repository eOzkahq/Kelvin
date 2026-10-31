package idempotency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"github.com/stretchr/testify/require"
)

// mockStore is a thread-safe in-memory Store for testing.
type mockStore struct {
	mu      map[string]*Record
	muLock  *sync.RWMutex
	failGet bool
}

func newMockStore() *mockStore {
	return &mockStore{
		mu:     make(map[string]*Record),
		muLock: &sync.RWMutex{},
	}
}

func (m *mockStore) Get(ctx context.Context, key string) (*Record, error) {
	m.muLock.RLock()
	defer m.muLock.RUnlock()
	if m.failGet {
		return nil, errors.New("store read failure")
	}
	rec, ok := m.mu[key]
	if !ok {
		return nil, ErrNotFound
	}
	// Return a copy to avoid callers mutating the stored record.
	cp := *rec
	return &cp, nil
}

func (m *mockStore) SetInProgress(ctx context.Context, key, tenantID, payloadHash string) error {
	m.muLock.Lock()
	defer m.muLock.Unlock()
	if _, exists := m.mu[key]; exists {
		return ErrAlreadyExists
	}
	m.mu[key] = &Record{
		Key:         key,
		TenantID:    tenantID,
		Status:      StatusInProgress,
		PayloadHash: payloadHash,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	return nil
}

func (m *mockStore) SetCompleted(ctx context.Context, key string, statusCode int, body []byte, headers map[string]string) error {
	m.muLock.Lock()
	defer m.muLock.Unlock()
	rec, ok := m.mu[key]
	if !ok {
		return ErrNotFound
	}
	rec.Status = StatusCompleted
	rec.ResponseCode = statusCode
	rec.ResponseBody = body
	rec.ResponseHdrs = headers
	rec.UpdatedAt = time.Now().UTC()
	m.mu[key] = rec
	return nil
}

func (m *mockStore) setFailGet(fail bool) {
	m.muLock.Lock()
	defer m.muLock.Unlock()
	m.failGet = fail
}

// testHandler returns a handler that echoes the request body and method.
func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"created"}`))
	})
}

// withTenant sets a tenant ID in the request context.
func withTenant(r *http.Request, id uuid.UUID) *http.Request {
	ctx, err := tenant.WithID(r.Context(), id)
	if err != nil {
		return r
	}
	return r.WithContext(ctx)
}

func TestMiddlewarePassesThroughNonMutatingMethods(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	req.Header.Set(IdempotencyKeyHeader, uuid.New().String())
	rec := httptest.NewRecorder()

	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.Equal(t, `{"status":"created"}`, rec.Body.String())
}

func TestMiddlewarePassesThroughWithoutIdempotencyKey(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
}

func TestMiddlewareValidatesUUIDKey(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", nil)
	req.Header.Set(IdempotencyKeyHeader, "not-a-uuid")
	req = withTenant(req, uuid.New())
	rec := httptest.NewRecorder()

	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestMiddlewareRequiresTenantContext(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", nil)
	req.Header.Set(IdempotencyKeyHeader, uuid.New().String())
	// No tenant context set
	rec := httptest.NewRecorder()

	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareFirstRequestSucceedsAndCaches(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	tenantID := uuid.New()
	idemKey := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req = withTenant(req, tenantID)
	rec := httptest.NewRecorder()

	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.Equal(t, `{"status":"created"}`, rec.Body.String())

	// Verify record was stored as COMPLETED.
	sk := storeKey(tenantID, idemKey.String())
	rec2, err := store.Get(context.Background(), sk)
	require.NoError(t, err)
	require.Equal(t, StatusCompleted, rec2.Status)
	require.Equal(t, 201, rec2.ResponseCode)
	require.Equal(t, `{"status":"created"}`, string(rec2.ResponseBody))
}

func TestMiddlewareDuplicateWithSamePayloadReturnsCached(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	tenantID := uuid.New()
	idemKey := uuid.New()
	body := `{"name":"test"}`

	// First request.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req1 = withTenant(req1, tenantID)
	rec1 := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusCreated, rec1.Code)

	// Second request with same key and body - should get cached response.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req2 = withTenant(req2, tenantID)
	rec2 := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusCreated, rec2.Code)
	require.Equal(t, `{"status":"created"}`, rec2.Body.String())
	require.Equal(t, rec1.Header().Get("Content-Type"), rec2.Header().Get("Content-Type"))
}

func TestMiddlewareDuplicateWithDifferentPayloadReturns422(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	tenantID := uuid.New()
	idemKey := uuid.New()

	// First request with body A.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(`{"name":"A"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req1 = withTenant(req1, tenantID)
	rec1 := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusCreated, rec1.Code)

	// Second request with same key but body B - should get 422.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(`{"name":"B"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req2 = withTenant(req2, tenantID)
	rec2 := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusUnprocessableEntity, rec2.Code)

	// Verify error is a validation problem.
	var problem struct {
		Type string `json:"type"`
	}
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &problem))
	require.Equal(t, kelvinerrors.ProblemValidationFailed, problem.Type)
}

func TestMiddlewareInProgressReturns409(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	tenantID := uuid.New()
	idemKey := uuid.New()

	// Manually set IN_PROGRESS record.
	sk := storeKey(tenantID, idemKey.String())
	err := store.SetInProgress(context.Background(), sk, tenantID.String(), "hash-a")
	require.NoError(t, err)

	// Request with same key - should get 409.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", nil)
	req.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req = withTenant(req, tenantID)
	rec := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
}

func TestMiddlewareCrossTenantNoLeakage(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	next := testHandler()

	tenantA := uuid.New()
	tenantB := uuid.New()
	idemKey := uuid.New()
	body := `{"name":"tenant-a-resource"}`

	// Tenant A creates a resource with idempotency key.
	reqA := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(body))
	reqA.Header.Set("Content-Type", "application/json")
	reqA.Header.Set(IdempotencyKeyHeader, idemKey.String())
	reqA = withTenant(reqA, tenantA)
	recA := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(recA, reqA)
	require.Equal(t, http.StatusCreated, recA.Code)

	// Tenant B uses the same idempotency key with a different body - should
	// NOT see Tenant A's cached response. It should process normally.
	reqB := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(`{"name":"tenant-b-resource"}`))
	reqB.Header.Set("Content-Type", "application/json")
	reqB.Header.Set(IdempotencyKeyHeader, idemKey.String())
	reqB = withTenant(reqB, tenantB)
	recB := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(recB, reqB)

	require.Equal(t, http.StatusCreated, recB.Code)
	// Tenant B got their own response, not Tenant A's.
	require.Equal(t, `{"status":"created"}`, recB.Body.String())

	// Verify both records exist independently.
	skA := storeKey(tenantA, idemKey.String())
	skB := storeKey(tenantB, idemKey.String())
	recA2, err := store.Get(context.Background(), skA)
	require.NoError(t, err)
	require.Equal(t, tenantA.String(), recA2.TenantID)
	recB2, err := store.Get(context.Background(), skB)
	require.NoError(t, err)
	require.Equal(t, tenantB.String(), recB2.TenantID)
}

func TestMiddlewareStoreReadFailureReturns500(t *testing.T) {
	store := newMockStore()
	store.setFailGet(true)
	mw := NewMiddleware(store)
	next := testHandler()

	tenantID := uuid.New()
	idemKey := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", nil)
	req.Header.Set(IdempotencyKeyHeader, idemKey.String())
	req = withTenant(req, tenantID)
	rec := httptest.NewRecorder()

	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// countingHandler wraps testHandler and counts invocations.
type countingHandler struct {
	next  http.Handler
	count int
	mu    sync.Mutex
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.count++
	c := h.count
	h.mu.Unlock()
	h.next.ServeHTTP(w, r)
	_ = c
}

func newCountingHandler() *countingHandler {
	return &countingHandler{next: testHandler()}
}

func TestMiddlewareRaceConcurrentRequests(t *testing.T) {
	store := newMockStore()
	mw := NewMiddleware(store)
	handler := newCountingHandler()

	tenantID := uuid.New()
	idemKey := uuid.New()
	body := `{"name":"concurrent"}`

	results := make(chan int, 10)

	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(IdempotencyKeyHeader, idemKey.String())
			req = withTenant(req, tenantID)
			rec := httptest.NewRecorder()
			mw.Wrap(handler).ServeHTTP(rec, req)
			results <- rec.Code
		}()
	}

	successCount := 0
	conflictCount := 0
	for i := 0; i < 10; i++ {
		code := <-results
		switch code {
		case http.StatusCreated:
			successCount++
		case http.StatusConflict:
			conflictCount++
		}
	}

	// Exactly one request should invoke the inner handler; all others should
	// either get 409 (in-progress) or a cached 201 response.
	require.Equal(t, 1, handler.count)
	require.Equal(t, 10, successCount+conflictCount)
	// At least one success (the one that invoked the handler).
	require.GreaterOrEqual(t, successCount, 1)
}

var _ = bytes.MinRead
