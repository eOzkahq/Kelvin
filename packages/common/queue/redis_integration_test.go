package queue

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Run with docker compose up -d redis and KELVIN_REDIS_ADDR=localhost:6379.
func TestRedisQueueLifecycle(t *testing.T) {
	addr := os.Getenv("KELVIN_REDIS_ADDR")
	if addr == "" {
		t.Skip("set KELVIN_REDIS_ADDR to a disposable Redis 7 instance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("KELVIN_REDIS_PASSWORD")})
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	prefix := "kelvin:test:" + uuid.NewString()
	defer func() {
		keys, _ := client.Keys(context.Background(), prefix+"*").Result()
		if len(keys) > 0 {
			_ = client.Del(context.Background(), keys...).Err()
		}
	}()
	q, err := NewRedis(client, RedisConfig{Prefix: prefix, Group: "test-workers", Consumer: "test-worker", Block: 20 * time.Millisecond, Backoff: 20 * time.Millisecond, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	m := validMessage
	m.ID = uuid.NewString()
	m.AssessmentID = uuid.NewString()
	m.TenantID = uuid.NewString()
	if err = q.Enqueue(ctx, m); err != nil {
		t.Fatal(err)
	}
	d, err := q.Consume(ctx, "test-worker")
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Heartbeat(ctx, m.ID, "test-worker", time.Minute); err != nil {
		t.Fatal(err)
	}
	if worker, err := client.Get(ctx, prefix+":heartbeat:"+m.ID).Result(); err != nil || worker != "test-worker" {
		t.Fatalf("heartbeat worker=%q err=%v", worker, err)
	}
	if err = q.Complete(ctx, d); err != nil {
		t.Fatal(err)
	}
	s, err := q.GetStatus(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "COMPLETED" {
		t.Fatalf("status=%+v", s)
	}

	m.ID = uuid.NewString()
	if err = q.Enqueue(ctx, m); err != nil {
		t.Fatal(err)
	}
	d, err = q.Consume(ctx, "test-worker")
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Fail(ctx, d, os.ErrDeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	d, err = q.Consume(ctx, "test-worker")
	if err != nil {
		t.Fatal(err)
	}
	if d.Attempts != 2 {
		t.Fatalf("retry count=%d", d.Attempts)
	}
	if err = q.Fail(ctx, d, os.ErrDeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	s, err = q.GetStatus(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "DEAD_LETTER" {
		t.Fatalf("status=%+v", s)
	}
	if n, err := client.XLen(ctx, prefix+":dlq").Result(); err != nil || n != 1 {
		t.Fatalf("dead letter count=%d err=%v", n, err)
	}
}
