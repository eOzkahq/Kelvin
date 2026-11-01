package concurrency

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrInvalidRequest indicates missing or malformed fields on an acquisition request.
	ErrInvalidRequest = errors.New("concurrency: invalid slot acquisition request")
)

// Request defines the criteria for acquiring execution concurrency capacity.
type Request struct {
	JobID    string        `json:"job_id"`
	TenantID string        `json:"tenant_id"`
	Scanner  string        `json:"scanner"`
	TTL      time.Duration `json:"ttl,omitempty"`
}

// Validate ensures all required identification fields are present.
func (r Request) Validate() error {
	if r.JobID == "" {
		return fmt.Errorf("%w: job_id is required", ErrInvalidRequest)
	}
	if r.TenantID == "" {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if r.Scanner == "" {
		return fmt.Errorf("%w: scanner is required", ErrInvalidRequest)
	}
	return nil
}

// Lease represents a temporarily acquired, observable concurrency slot.
type Lease struct {
	LeaseID    string    `json:"lease_id"`
	JobID      string    `json:"job_id"`
	TenantID   string    `json:"tenant_id"`
	Scanner    string    `json:"scanner"`
	AcquiredAt time.Time `json:"acquired_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Expired returns true if the lease duration has elapsed.
func (l Lease) Expired(now time.Time) bool {
	return now.After(l.ExpiresAt)
}

// NewLease creates a valid lease with a unique identifier and expiration timestamp.
func NewLease(req Request, ttl time.Duration) Lease {
	now := time.Now().UTC()
	return Lease{
		LeaseID:    uuid.NewString(),
		JobID:      req.JobID,
		TenantID:   req.TenantID,
		Scanner:    req.Scanner,
		AcquiredAt: now,
		ExpiresAt:  now.Add(ttl),
	}
}
