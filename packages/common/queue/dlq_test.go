package queue

import (
	"context"
	"testing"
	"time"
)

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name       string
		attempt    int
		baseDelay  time.Duration
		maxDelay   time.Duration
		minExpect  time.Duration
		maxExpect  time.Duration
	}{
		{
			name:      "attempt 0 or 1 baseline",
			attempt:   1,
			baseDelay: 2 * time.Second,
			maxDelay:  30 * time.Second,
			minExpect: 2 * time.Second,
			maxExpect: 3 * time.Second, // 2s + up to 25% jitter
		},
		{
			name:      "attempt 2 doubles",
			attempt:   2,
			baseDelay: 2 * time.Second,
			maxDelay:  30 * time.Second,
			minExpect: 4 * time.Second,
			maxExpect: 6 * time.Second, // 4s + jitter
		},
		{
			name:      "attempt 3 quadruples",
			attempt:   3,
			baseDelay: 2 * time.Second,
			maxDelay:  30 * time.Second,
			minExpect: 8 * time.Second,
			maxExpect: 12 * time.Second,
		},
		{
			name:      "attempt 10 capped at max delay",
			attempt:   10,
			baseDelay: 2 * time.Second,
			maxDelay:  30 * time.Second,
			minExpect: 30 * time.Second,
			maxExpect: 40 * time.Second, // 30s + up to 25% jitter
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := CalculateBackoff(tt.attempt, tt.baseDelay, tt.maxDelay)
			if backoff < tt.minExpect || backoff > tt.maxExpect {
				t.Errorf("CalculateBackoff(%d) = %v, expected in [%v, %v]", tt.attempt, backoff, tt.minExpect, tt.maxExpect)
			}
		})
	}
}

func TestDLQNilClientError(t *testing.T) {
	dlq := NewRedisDLQ(nil, "kelvin:jobs:dlq")

	err := dlq.SendToDLQ(context.Background(), Delivery{}, "test-reason", nil)
	if err == nil {
		t.Errorf("expected error when sending to DLQ with nil client")
	}

	_, err = dlq.ListDLQ(context.Background(), 10)
	if err == nil {
		t.Errorf("expected error when listing DLQ with nil client")
	}

	err = dlq.Purge(context.Background())
	if err == nil {
		t.Errorf("expected error when purging DLQ with nil client")
	}
}
