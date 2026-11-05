package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/redis/go-redis/v9"
)

// DLQEntry encapsulates metadata for a permanently failed or poison-pill job.
type DLQEntry struct {
	ID        string    `json:"id"`
	Message   Message   `json:"message"`
	Reason    string    `json:"reason"`
	Attempts  int       `json:"attempts"`
	FailedAt  time.Time `json:"failed_at"`
	LastError string    `json:"last_error"`
}

// IDeadLetterQueue defines the contract for handling poison pill messages.
type IDeadLetterQueue interface {
	SendToDLQ(ctx context.Context, delivery Delivery, reason string, lastErr error) error
	ListDLQ(ctx context.Context, limit int64) ([]DLQEntry, error)
	ReDrive(ctx context.Context, entryID string, targetQueue IJobQueue) error
	Purge(ctx context.Context) error
}

// RedisDLQ implements IDeadLetterQueue backed by Redis Streams.
type RedisDLQ struct {
	client redis.UniversalClient
	stream string
}

// NewRedisDLQ creates a new RedisDLQ instance.
func NewRedisDLQ(client redis.UniversalClient, stream string) *RedisDLQ {
	if stream == "" {
		stream = "kelvin:jobs:dlq"
	}
	return &RedisDLQ{
		client: client,
		stream: stream,
	}
}

// SendToDLQ routes a poison-pill job to the Dead-Letter Queue stream.
func (d *RedisDLQ) SendToDLQ(ctx context.Context, delivery Delivery, reason string, lastErr error) error {
	if d.client == nil {
		return errors.New("dlq: redis client is required")
	}

	errStr := ""
	if lastErr != nil {
		errStr = lastErr.Error()
	}

	entry := DLQEntry{
		ID:        delivery.Message.ID,
		Message:   delivery.Message,
		Reason:    reason,
		Attempts:  delivery.Attempts,
		FailedAt:  time.Now().UTC(),
		LastError: errStr,
	}

	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("dlq: failed to marshal entry: %w", err)
	}

	args := &redis.XAddArgs{
		Stream: d.stream,
		ID:     "*",
		Values: map[string]interface{}{
			"payload":    string(entryBytes),
			"job_id":     delivery.Message.ID,
			"tenant_id":  delivery.Message.TenantID,
			"failed_at":  entry.FailedAt.Format(time.RFC3339),
			"last_error": errStr,
		},
	}

	return d.client.XAdd(ctx, args).Err()
}

// ListDLQ retrieves the most recent failed jobs from the DLQ stream.
func (d *RedisDLQ) ListDLQ(ctx context.Context, limit int64) ([]DLQEntry, error) {
	if d.client == nil {
		return nil, errors.New("dlq: redis client is required")
	}
	if limit <= 0 {
		limit = 50
	}

	streams, err := d.client.XRevRangeN(ctx, d.stream, "+", "-", limit).Result()
	if err != nil {
		return nil, fmt.Errorf("dlq: failed to query stream: %w", err)
	}

	entries := make([]DLQEntry, 0, len(streams))
	for _, xmsg := range streams {
		payload, ok := xmsg.Values["payload"].(string)
		if !ok {
			continue
		}
		var entry DLQEntry
		if err := json.Unmarshal([]byte(payload), &entry); err == nil {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// ReDrive re-enqueues a DLQ job back into the active job queue for re-execution.
func (d *RedisDLQ) ReDrive(ctx context.Context, entryID string, targetQueue IJobQueue) error {
	if d.client == nil || targetQueue == nil {
		return errors.New("dlq: client and targetQueue are required")
	}

	// Query DLQ entries to find the matching entry
	entries, err := d.ListDLQ(ctx, 500)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.ID == entryID || entry.Message.ID == entryID {
			// Re-enqueue
			entry.Message.WorkerToken = ""
			return targetQueue.Enqueue(ctx, entry.Message)
		}
	}

	return errors.New("dlq: entry not found")
}

// Purge clears all entries in the DLQ stream.
func (d *RedisDLQ) Purge(ctx context.Context) error {
	if d.client == nil {
		return errors.New("dlq: redis client is required")
	}
	return d.client.Del(ctx, d.stream).Err()
}

// CalculateBackoff computes an exponential backoff duration with full jitter.
// Formula: min(maxBackoff, base * 2^(attempt-1)) + random jitter.
func CalculateBackoff(attempt int, base, maxBackoff time.Duration) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	if base <= 0 {
		base = 1 * time.Second
	}
	if maxBackoff <= 0 {
		maxBackoff = 60 * time.Second
	}

	multiplier := math.Pow(2, float64(attempt-1))
	backoffNanos := float64(base.Nanoseconds()) * multiplier

	if backoffNanos > float64(maxBackoff.Nanoseconds()) {
		backoffNanos = float64(maxBackoff.Nanoseconds())
	}

	// Add 10-25% random jitter to avoid thundering herd problem
	jitter := rand.Float64() * 0.25 * backoffNanos
	finalDuration := time.Duration(backoffNanos + jitter)

	if finalDuration > maxBackoff {
		return maxBackoff
	}
	return finalDuration
}
