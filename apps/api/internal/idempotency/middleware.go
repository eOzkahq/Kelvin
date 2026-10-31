// Package idempotency provides HTTP middleware for duplicate prevention on
// state-mutating endpoints via the Idempotency-Key header.
//
// Middleware flow for a state-mutating request carrying Idempotency-Key:
//
//  1. Validate the key is a UUID.
//  2. Read the request body and compute SHA-256(payload).
//  3. Look up (tenant_id, key) in the store:
//     - Not found  → create IN_PROGRESS record, call handler, capture
//     response, store COMPLETED, replay captured response.
//     - IN_PROGRESS → 409 Conflict (duplicate in-flight).
//     - COMPLETED   → if payload hash matches, replay cached response;
//     if it differs, 422 Unprocessable Entity.
//
// Cross-tenant isolation: the store key includes tenant_id, so a key from
// Tenant A can never match Tenant B's record. Records expire after a
// configurable TTL (default 24 h).
package idempotency

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

// IdempotencyKeyHeader is the HTTP header name for idempotency keys.
const IdempotencyKeyHeader = "Idempotency-Key"

// Middleware wraps an http.Handler with idempotency protection for
// state-mutating endpoints.
type Middleware struct {
	store Store
}

// NewMiddleware creates a new idempotency middleware backed by store.
func NewMiddleware(store Store) *Middleware {
	return &Middleware{store: store}
}

// Wrap returns an http.Handler that applies idempotency checks around next.
// Requests without an Idempotency-Key header, or with non-state-mutating
// methods, pass through unchanged.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isStateMutating(r.Method) {
			next.ServeHTTP(w, r)
			return
		}

		key := r.Header.Get(IdempotencyKeyHeader)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Validate key is a UUID.
		if _, err := uuid.Parse(key); err != nil {
			writeProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   IdempotencyKeyHeader,
				Code:    "invalid_idempotency_key",
				Message: "Idempotency-Key must be a valid UUID",
			}}))
			return
		}

		// Tenant context is required for scoped idempotency.
		tenantID, err := tenant.ID(r.Context())
		if err != nil {
			writeProblem(w, r, kelvinerrors.NewUnauthenticated("tenant context required for idempotency"))
			return
		}

		// Read body and compute payload hash; restore body for downstream.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeProblem(w, r, kelvinerrors.NewInternal(err))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		payloadHash := sha256Hex(body)

		sk := storeKey(tenantID, key)

		// Check existing record.
		record, err := m.store.Get(r.Context(), sk)
		switch {
		case errors.Is(err, ErrNotFound):
			// Attempt to claim the key atomically. Only one concurrent
			// request can succeed; the other gets ErrAlreadyExists.
			if err := m.store.SetInProgress(r.Context(), sk, tenantID.String(), payloadHash); err != nil {
				if errors.Is(err, ErrAlreadyExists) {
					// Another request created the record first; re-fetch and
					// handle as an existing record.
					rec, getErr := m.store.Get(r.Context(), sk)
					if getErr != nil {
						writeProblem(w, r, kelvinerrors.NewInternal(getErr))
						return
					}
					handleExisting(w, r, rec, payloadHash)
					return
				}
				writeProblem(w, r, kelvinerrors.NewInternal(err))
				return
			}

			// We own the key: process the request and capture the response.
			rec := &responseRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)

			// Cache the completed response for replay.
			if err := m.store.SetCompleted(r.Context(), sk, rec.statusCode(), rec.body.Bytes(), rec.headersMap()); err != nil {
				// Best-effort cache: response was already sent, log and continue.
			}

			// Write captured response to the real writer.
			rec.writeTo(w)
			return

		case err != nil:
			writeProblem(w, r, kelvinerrors.NewInternal(err))
			return
		default:
			handleExisting(w, r, record, payloadHash)
			return
		}
	})
}

// handleExisting processes a request that found an existing idempotency record.
func handleExisting(w http.ResponseWriter, r *http.Request, record *Record, payloadHash string) {
	switch record.Status {
	case StatusInProgress:
		writeProblem(w, r, kelvinerrors.NewConflict("a request with this Idempotency-Key is already being processed"))
		return
	case StatusCompleted:
		if record.PayloadHash != payloadHash {
			writeProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   IdempotencyKeyHeader,
				Code:    "idempotency_key_payload_conflict",
				Message: "a request with this Idempotency-Key was previously submitted with a different payload",
			}}))
			return
		}
		// Replay the cached response.
		for k, v := range record.ResponseHdrs {
			w.Header().Set(k, v)
		}
		w.WriteHeader(record.ResponseCode)
		_, _ = w.Write(record.ResponseBody)
		return
	}
}

// isStateMutating reports whether the HTTP method modifies state.
func isStateMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// writeProblem writes an RFC 7807 Problem Details response.
func writeProblem(w http.ResponseWriter, r *http.Request, apiErr *kelvinerrors.API) {
	problem := apiErr.Problem(
		"", // correlation ID not available without logging package import
		r.URL.Path,
		time.Now().UTC().Format(time.RFC3339),
	)
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	if apiErr.Status == http.StatusServiceUnavailable || apiErr.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "30")
	}
	w.WriteHeader(apiErr.Status)
	_ = json.NewEncoder(w).Encode(problem)
}

// responseRecorder captures an HTTP response so it can be cached for idempotent
// replay. It buffers body and headers rather than forwarding to the real
// writer until writeTo is called.
type responseRecorder struct {
	http.ResponseWriter
	status  int
	body    bytes.Buffer
	hdrs    http.Header
	started bool
}

func (rec *responseRecorder) Header() http.Header {
	if rec.hdrs == nil {
		rec.hdrs = make(http.Header)
	}
	return rec.hdrs
}

func (rec *responseRecorder) WriteHeader(code int) {
	if !rec.started {
		rec.status = code
		rec.started = true
	}
	// Do NOT forward to the underlying writer; we capture for replay.
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if !rec.started {
		rec.status = http.StatusOK
		rec.started = true
	}
	rec.body.Write(b)
	return len(b), nil
}

// statusCode returns the captured status code (200 if never set).
func (rec *responseRecorder) statusCode() int {
	if rec.status == 0 {
		return http.StatusOK
	}
	return rec.status
}

// headersMap returns the captured headers as a flat map[string]string.
func (rec *responseRecorder) headersMap() map[string]string {
	h := make(map[string]string, len(rec.hdrs))
	for k, vv := range rec.hdrs {
		if len(vv) > 0 {
			h[k] = vv[0]
		}
	}
	return h
}

// writeTo replays the captured response to dst.
func (rec *responseRecorder) writeTo(dst http.ResponseWriter) {
	if rec.hdrs != nil {
		for k, vv := range rec.hdrs {
			for _, v := range vv {
				dst.Header().Add(k, v)
			}
		}
	}
	dst.WriteHeader(rec.statusCode())
	_, _ = dst.Write(rec.body.Bytes())
}

// cloneHeaderMap returns a copy of h as an http.Header.
func cloneHeaderMap(h map[string]string) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out.Set(k, v)
	}
	return out
}
