package progress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPublisher streams progress events to Redis Pub/Sub channels and caches the latest progress hash.
type RedisPublisher struct {
	client redis.UniversalClient
	prefix string
}

// NewRedisPublisher constructs a Redis-backed progress event publisher.
func NewRedisPublisher(client redis.UniversalClient, prefix string) (*RedisPublisher, error) {
	if client == nil {
		return nil, errors.New("progress: redis client is required")
	}
	if prefix == "" {
		prefix = "kelvin"
	}
	return &RedisPublisher{
		client: client,
		prefix: prefix,
	}, nil
}

// PublishProgress marshals the event and publishes it to Redis Pub/Sub and updates the latest job progress key.
func (r *RedisPublisher) PublishProgress(ctx context.Context, event ProgressEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("progress: failed to marshal progress event: %w", err)
	}

	channel := fmt.Sprintf("%s:events:progress:%s", r.prefix, event.AssessmentID)
	jobKey := fmt.Sprintf("%s:job:%s:progress", r.prefix, event.JobID)

	pipe := r.client.Pipeline()
	pipe.Publish(ctx, channel, payload)

	values := map[string]any{
		"event_id":     event.EventID,
		"stage":        string(event.Stage),
		"stage_status": string(event.StageStatus),
		"updated_at":   event.Timestamp.Format(time.RFC3339Nano),
	}
	if event.Progress != nil {
		if event.Progress.Percentage != nil {
			values["percentage"] = fmt.Sprintf("%.2f", *event.Progress.Percentage)
		}
		values["message"] = event.Progress.Message
		values["items_completed"] = event.Progress.ItemsCompleted
		values["items_total"] = event.Progress.ItemsTotal
		values["units"] = event.Progress.Units
	}

	pipe.HSet(ctx, jobKey, values)
	pipe.Expire(ctx, jobKey, 24*time.Hour)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("progress: failed to publish to redis: %w", err)
	}
	return nil
}
