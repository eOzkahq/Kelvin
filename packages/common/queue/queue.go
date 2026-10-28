// Package queue provides a backend-neutral assessment queue contract, message
// validation, a Redis Streams implementation, and an in-memory test adapter.
package queue

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kelvin/kelvin/packages/common/validation"
	"github.com/redis/go-redis/v9"
)

var ErrInvalidMessage = errors.New("invalid queue message")
var ErrNotFound = errors.New("queue message not found")

type Message struct {
	Version       int             `json:"version"`
	ID            string          `json:"id"`
	AssessmentID  string          `json:"assessment_id"`
	TenantID      string          `json:"tenant_id"`
	CorrelationID string          `json:"correlation_id"`
	Type          string          `json:"type"`
	Payload       json.RawMessage `json:"payload"`
	MaxAttempts   int             `json:"max_attempts"`
	WorkerToken   string          `json:"worker_token,omitempty"`
}

func (m Message) Validate() error {
	if m.Version != 1 || !validation.IsUUID(m.ID) || !validation.IsUUID(m.AssessmentID) || !validation.IsUUID(m.TenantID) ||
		!validation.IsCorrelationID(m.CorrelationID) || !validation.IsWireEnum(m.Type) || len(m.Type) > 64 || m.MaxAttempts < 1 || m.MaxAttempts > 20 {
		return fmt.Errorf("%w: required fields or bounds failed", ErrInvalidMessage)
	}
	payload := bytes.TrimSpace(m.Payload)
	if len(payload) == 0 || !json.Valid(payload) || string(payload) == "null" || payload[0] != '{' {
		return fmt.Errorf("%w: payload must be a JSON object", ErrInvalidMessage)
	}
	if m.WorkerToken != "" && len(m.WorkerToken) > 4096 {
		return fmt.Errorf("%w: worker token too long", ErrInvalidMessage)
	}
	return nil
}

type Status struct {
	State     string    `json:"state"`
	Attempts  int       `json:"attempts"`
	UpdatedAt time.Time `json:"updated_at"`
	LastError string    `json:"last_error,omitempty"`
}
type Delivery struct {
	Message    Message
	DeliveryID string
	Attempts   int
}

// IJobQueue is the queue boundary shared by producers and consumers.
type IJobQueue interface {
	Enqueue(context.Context, Message) error
	Consume(context.Context, string) (Delivery, error)
	Complete(context.Context, Delivery) error
	Fail(context.Context, Delivery, error) error
	Cancel(context.Context, string) error
	GetStatus(context.Context, string) (Status, error)
	Heartbeat(context.Context, string, string, time.Duration) error
}

type RedisConfig struct {
	Prefix, Group, Consumer string
	WorkerID                string
	TokenSecret             []byte
	TokenTTL                time.Duration
	MaxAttempts             int
	Backoff                 time.Duration
	Block                   time.Duration
}
type RedisQueue struct {
	client redis.UniversalClient
	cfg    RedisConfig
}

func NewRedis(client redis.UniversalClient, cfg RedisConfig) (*RedisQueue, error) {
	if client == nil {
		return nil, errors.New("queue: redis client is required")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "kelvin:jobs"
	}
	if cfg.Group == "" {
		cfg.Group = "workers"
	}
	if cfg.Consumer == "" {
		cfg.Consumer = "worker"
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.MaxAttempts > 20 {
		return nil, errors.New("queue: max attempts cannot exceed 20")
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	if cfg.Block <= 0 {
		cfg.Block = time.Second
	}
	return &RedisQueue{client: client, cfg: cfg}, nil
}
func (q *RedisQueue) stream() string               { return q.cfg.Prefix + ":stream" }
func (q *RedisQueue) dlq() string                  { return q.cfg.Prefix + ":dlq" }
func (q *RedisQueue) statusKey(id string) string   { return q.cfg.Prefix + ":status:" + id }
func (q *RedisQueue) attemptsKey(id string) string { return q.cfg.Prefix + ":attempts:" + id }
func (q *RedisQueue) delayed() string              { return q.cfg.Prefix + ":delayed" }

func (q *RedisQueue) ensureGroup(ctx context.Context) error {
	err := q.client.XGroupCreateMkStream(ctx, q.stream(), q.cfg.Group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}
func (q *RedisQueue) Enqueue(ctx context.Context, m Message) error {
	if m.ID == "" {
		return fmt.Errorf("%w: job ID must be assigned by the producer", ErrInvalidMessage)
	}
	if m.Version == 0 {
		m.Version = 1
	}
	if m.MaxAttempts == 0 {
		m.MaxAttempts = q.cfg.MaxAttempts
	}
	if m.WorkerToken == "" && len(q.cfg.TokenSecret) >= 32 && q.cfg.WorkerID != "" {
		token, err := (WorkerTokens{Secret: q.cfg.TokenSecret, TTL: q.cfg.TokenTTL}).Issue(m.ID, q.cfg.WorkerID)
		if err != nil {
			return err
		}
		m.WorkerToken = token
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if err := q.ensureGroup(ctx); err != nil {
		return fmt.Errorf("queue create consumer group: %w", err)
	}
	b, _ := json.Marshal(m)
	now := time.Now().UTC()
	pipe := q.client.TxPipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: q.stream(), Values: map[string]any{"message": b, "job_id": m.ID}})
	pipe.HSet(ctx, q.statusKey(m.ID), "state", "QUEUED", "attempts", 0, "updated_at", now.Format(time.RFC3339Nano))
	_, err := pipe.Exec(ctx)
	return err
}

func (q *RedisQueue) Consume(ctx context.Context, consumer string) (Delivery, error) {
	if err := q.ensureGroup(ctx); err != nil {
		return Delivery{}, err
	}
	if consumer == "" {
		consumer = q.cfg.Consumer
	}
	for {
		if err := q.promote(ctx); err != nil {
			return Delivery{}, err
		}
		pending, _, claimErr := q.client.XAutoClaim(ctx, &redis.XAutoClaimArgs{Stream: q.stream(), Group: q.cfg.Group, Consumer: consumer, MinIdle: time.Minute, Start: "0-0", Count: 1}).Result()
		if claimErr == nil && len(pending) > 0 {
			d, ok, err := q.decodeDelivery(ctx, pending[0])
			if err != nil {
				return Delivery{}, err
			}
			if ok {
				return d, nil
			}
		} else if claimErr != nil && !strings.Contains(claimErr.Error(), "unknown command") {
			return Delivery{}, claimErr
		}
		rows, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: q.cfg.Group, Consumer: consumer, Streams: []string{q.stream(), ">"}, Count: 1, Block: q.cfg.Block}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return Delivery{}, err
		}
		if len(rows) == 0 || len(rows[0].Messages) == 0 {
			continue
		}
		d, ok, err := q.decodeDelivery(ctx, rows[0].Messages[0])
		if err != nil {
			return Delivery{}, err
		}
		if ok {
			return d, nil
		}
	}
}

func (q *RedisQueue) decodeDelivery(ctx context.Context, r redis.XMessage) (Delivery, bool, error) {
	var raw string
	switch value := r.Values["message"].(type) {
	case string:
		raw = value
	case []byte:
		raw = string(value)
	}
	if raw == "" {
		_ = q.client.XAdd(ctx, &redis.XAddArgs{Stream: q.dlq(), Values: map[string]any{"raw": fmt.Sprint(r.Values), "reason": "missing message field"}}).Err()
		_ = q.client.XAck(ctx, q.stream(), q.cfg.Group, r.ID).Err()
		return Delivery{}, false, nil
	}
	var m Message
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF || m.Validate() != nil {
		_ = q.client.XAdd(ctx, &redis.XAddArgs{Stream: q.dlq(), Values: map[string]any{"raw": raw, "reason": "malformed queue message"}}).Err()
		_ = q.client.XAck(ctx, q.stream(), q.cfg.Group, r.ID).Err()
		return Delivery{}, false, nil
	}
	if len(q.cfg.TokenSecret) >= 32 {
		if err := (WorkerTokens{Secret: q.cfg.TokenSecret}).Verify(m.WorkerToken, m.ID, q.cfg.WorkerID); err != nil {
			_ = q.client.XAdd(ctx, &redis.XAddArgs{Stream: q.dlq(), Values: map[string]any{"message": raw, "job_id": m.ID, "reason": "worker token validation failed"}}).Err()
			_ = q.client.XAck(ctx, q.stream(), q.cfg.Group, r.ID).Err()
			return Delivery{}, false, nil
		}
	}
	state, _ := q.client.HGet(ctx, q.statusKey(m.ID), "state").Result()
	if state == "CANCELLED" {
		_ = q.client.XAck(ctx, q.stream(), q.cfg.Group, r.ID).Err()
		return Delivery{}, false, nil
	}
	attempts, _ := q.client.Incr(ctx, q.attemptsKey(m.ID)).Result()
	_ = q.client.HSet(ctx, q.statusKey(m.ID), "state", "RUNNING", "attempts", attempts, "updated_at", time.Now().UTC().Format(time.RFC3339Nano)).Err()
	return Delivery{Message: m, DeliveryID: r.ID, Attempts: int(attempts)}, true, nil
}

func (q *RedisQueue) Complete(ctx context.Context, d Delivery) error {
	state, err := q.client.HGet(ctx, q.statusKey(d.Message.ID), "state").Result()
	if err != nil {
		return err
	}
	if state == "CANCELLED" {
		_ = q.client.XAck(ctx, q.stream(), q.cfg.Group, d.DeliveryID).Err()
		return errors.New("queue job was cancelled")
	}
	if state != "RUNNING" {
		return fmt.Errorf("queue: cannot complete job in state %s", state)
	}
	pipe := q.client.TxPipeline()
	pipe.XAck(ctx, q.stream(), q.cfg.Group, d.DeliveryID)
	pipe.HSet(ctx, q.statusKey(d.Message.ID), "state", "COMPLETED", "updated_at", time.Now().UTC().Format(time.RFC3339Nano))
	_, err = pipe.Exec(ctx)
	return err
}
func (q *RedisQueue) Fail(ctx context.Context, d Delivery, cause error) error {
	state, e := q.client.HGet(ctx, q.statusKey(d.Message.ID), "state").Result()
	if e != nil {
		return e
	}
	if state == "CANCELLED" {
		return q.client.XAck(ctx, q.stream(), q.cfg.Group, d.DeliveryID).Err()
	}
	if state != "RUNNING" {
		return fmt.Errorf("queue: cannot fail job in state %s", state)
	}
	if d.Attempts <= 0 {
		n, e := q.client.Get(ctx, q.attemptsKey(d.Message.ID)).Int()
		if e != nil && e != redis.Nil {
			return e
		}
		d.Attempts = n
	}
	maxAttempts := d.Message.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = q.cfg.MaxAttempts
	}
	why := "unspecified failure"
	if cause != nil {
		why = cause.Error()
	}
	if len(why) > 1024 {
		why = why[:1024]
	}
	pipe := q.client.TxPipeline()
	pipe.XAck(ctx, q.stream(), q.cfg.Group, d.DeliveryID)
	if d.Attempts >= maxAttempts {
		pipe.XAdd(ctx, &redis.XAddArgs{Stream: q.dlq(), Values: map[string]any{"message": mustJSON(d.Message), "job_id": d.Message.ID, "attempts": d.Attempts, "reason": why}})
		pipe.HSet(ctx, q.statusKey(d.Message.ID), "state", "DEAD_LETTER", "attempts", d.Attempts, "last_error", why, "updated_at", time.Now().UTC().Format(time.RFC3339Nano))
	} else {
		exponent := max(0, min(d.Attempts-1, 10))
		delay := q.cfg.Backoff * time.Duration(1<<exponent)
		encoded := mustJSON(d.Message)
		entry := mustJSON(map[string]any{"message": string(encoded), "attempts": d.Attempts, "error": why})
		pipe.ZAdd(ctx, q.delayed(), redis.Z{Score: float64(time.Now().Add(delay).UnixMilli()), Member: entry})
		pipe.HSet(ctx, q.statusKey(d.Message.ID), "state", "RETRY_WAIT", "attempts", d.Attempts, "last_error", why, "updated_at", time.Now().UTC().Format(time.RFC3339Nano))
	}
	_, err := pipe.Exec(ctx)
	return err
}
func (q *RedisQueue) promote(ctx context.Context) error {
	items, err := q.client.ZRangeByScore(ctx, q.delayed(), &redis.ZRangeBy{Min: "-inf", Max: fmt.Sprint(time.Now().UnixMilli()), Offset: 0, Count: 100}).Result()
	if err != nil {
		return err
	}
	for _, v := range items {
		var entry struct {
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(v), &entry) != nil {
			_, _ = q.client.ZRem(ctx, q.delayed(), v).Result()
			continue
		}
		_, err = q.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
			p.XAdd(ctx, &redis.XAddArgs{Stream: q.stream(), Values: map[string]any{"message": entry.Message}})
			p.ZRem(ctx, q.delayed(), v)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
func (q *RedisQueue) Cancel(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("queue: job ID required")
	}
	if err := q.client.HSet(ctx, q.statusKey(id), "state", "CANCELLED", "updated_at", time.Now().UTC().Format(time.RFC3339Nano)).Err(); err != nil {
		return err
	}
	return nil
}
func (q *RedisQueue) GetStatus(ctx context.Context, id string) (Status, error) {
	v, e := q.client.HGetAll(ctx, q.statusKey(id)).Result()
	if e != nil {
		return Status{}, e
	}
	if len(v) == 0 {
		return Status{}, ErrNotFound
	}
	attempts, _ := strconv.Atoi(v["attempts"])
	updated, _ := time.Parse(time.RFC3339Nano, v["updated_at"])
	return Status{State: v["state"], Attempts: attempts, UpdatedAt: updated, LastError: v["last_error"]}, nil
}
func (q *RedisQueue) Heartbeat(ctx context.Context, id, worker string, ttl time.Duration) error {
	if id == "" || worker == "" || ttl <= 0 {
		return errors.New("queue: heartbeat requires job, worker and positive ttl")
	}
	return q.client.Set(ctx, q.cfg.Prefix+":heartbeat:"+id, worker, ttl).Err()
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// MemoryQueue is a dependency-free adapter for unit tests and local development.
type MemoryQueue struct {
	mu        sync.Mutex
	notify    chan struct{}
	items     []Delivery
	status    map[string]Status
	cancelled map[string]bool
}

func NewMemory() *MemoryQueue {
	return &MemoryQueue{notify: make(chan struct{}, 1), status: map[string]Status{}, cancelled: map[string]bool{}}
}
func (m *MemoryQueue) Enqueue(_ context.Context, msg Message) error {
	if msg.ID == "" {
		return fmt.Errorf("%w: job ID must be assigned by the producer", ErrInvalidMessage)
	}
	if msg.Version == 0 {
		msg.Version = 1
	}
	if err := msg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, Delivery{Message: msg})
	m.status[msg.ID] = Status{State: "QUEUED", UpdatedAt: time.Now().UTC()}
	select {
	case m.notify <- struct{}{}:
	default:
	}
	return nil
}
func (m *MemoryQueue) Consume(ctx context.Context, _ string) (Delivery, error) {
	for {
		m.mu.Lock()
		if len(m.items) > 0 {
			d := m.items[0]
			m.items = m.items[1:]
			if m.cancelled[d.Message.ID] {
				m.mu.Unlock()
				continue
			}
			d.Attempts++
			m.status[d.Message.ID] = Status{State: "RUNNING", Attempts: d.Attempts, UpdatedAt: time.Now().UTC()}
			m.mu.Unlock()
			return d, nil
		}
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return Delivery{}, ctx.Err()
		case <-m.notify:
		}
	}
}
func (m *MemoryQueue) Complete(_ context.Context, d Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.status[d.Message.ID]; !ok {
		return ErrNotFound
	}
	s := m.status[d.Message.ID]
	if s.State == "CANCELLED" {
		return errors.New("queue job was cancelled")
	}
	if s.State != "RUNNING" {
		return fmt.Errorf("queue: job %s is not running", d.Message.ID)
	}
	s.State = "COMPLETED"
	s.UpdatedAt = time.Now().UTC()
	m.status[d.Message.ID] = s
	return nil
}
func (m *MemoryQueue) Fail(_ context.Context, d Delivery, e error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.status[d.Message.ID]
	if !ok {
		return ErrNotFound
	}
	if s.State == "CANCELLED" {
		return nil
	}
	if s.State != "RUNNING" {
		return fmt.Errorf("queue: job %s is not running", d.Message.ID)
	}
	max := d.Message.MaxAttempts
	if max < 1 {
		max = 5
	}
	s.Attempts = d.Attempts
	s.UpdatedAt = time.Now().UTC()
	if d.Attempts >= max {
		s.State = "DEAD_LETTER"
	} else {
		s.State = "RETRY_WAIT"
		if e != nil {
			s.LastError = e.Error()
		}
		d.DeliveryID = ""
		m.items = append(m.items, d)
		select {
		case m.notify <- struct{}{}:
		default:
		}
	}
	m.status[d.Message.ID] = s
	return nil
}
func (m *MemoryQueue) Cancel(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.status[id]
	if !ok {
		return ErrNotFound
	}
	if s.State == "COMPLETED" || s.State == "DEAD_LETTER" {
		return errors.New("queue: cannot cancel terminal job")
	}
	m.cancelled[id] = true
	s.State = "CANCELLED"
	s.UpdatedAt = time.Now().UTC()
	m.status[id] = s
	return nil
}
func (m *MemoryQueue) GetStatus(_ context.Context, id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.status[id]
	if !ok {
		return Status{}, ErrNotFound
	}
	return s, nil
}
func (m *MemoryQueue) Heartbeat(context.Context, string, string, time.Duration) error { return nil }

// WorkerTokens issues short-lived HMAC tokens scoped to one job and worker.
type WorkerTokens struct {
	Secret []byte
	TTL    time.Duration
	Now    func() time.Time
}

func (t WorkerTokens) Issue(jobID, workerID string) (string, error) {
	if len(t.Secret) < 32 || jobID == "" || workerID == "" {
		return "", errors.New("queue: token secret (32 bytes), job ID and worker ID required")
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	ttl := t.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	payload, _ := json.Marshal(map[string]any{"job_id": jobID, "worker_id": workerID, "exp": now().Add(ttl).Unix()})
	raw := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, t.Secret)
	_, _ = mac.Write([]byte(raw))
	return raw + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (t WorkerTokens) Verify(token, jobID, workerID string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(t.Secret) < 32 {
		return errors.New("queue: invalid worker token")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return errors.New("queue: invalid worker token")
	}
	mac := hmac.New(sha256.New, t.Secret)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return errors.New("queue: invalid worker token signature")
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return errors.New("queue: invalid worker token")
	}
	var c struct {
		JobID    string `json:"job_id"`
		WorkerID string `json:"worker_id"`
		Exp      int64  `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil || c.JobID != jobID || c.WorkerID != workerID {
		return errors.New("queue: worker token scope mismatch")
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	if now().Unix() >= c.Exp {
		return errors.New("queue: worker token expired")
	}
	return nil
}
