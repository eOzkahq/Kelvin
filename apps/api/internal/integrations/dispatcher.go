package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	HeaderEventID   = "X-Kelvin-Event-Id"
	HeaderTimestamp = "X-Kelvin-Timestamp"
	HeaderSignature = "X-Kelvin-Signature"

	MaxDeliveryAttempts = 5
	DeliveryTimeout     = 10 * time.Second
	MaxResponseBytes    = 64 * 1024 // 64 KB response snippet ceiling
	DefaultReplayWindow = 5 * time.Minute
)

var (
	ErrDeliveryNotFound       = errors.New("dispatcher: delivery record not found")
	ErrSignatureMismatch      = errors.New("dispatcher: signature verification failed")
	ErrReplayWindowExpired    = errors.New("dispatcher: webhook timestamp outside replay protection tolerance window")
	ErrInvalidSignatureHeader = errors.New("dispatcher: invalid signature header format")
)

type DeliveryStatus string

const (
	StatusDeliveryPending      DeliveryStatus = "PENDING"
	StatusDeliverySuccess      DeliveryStatus = "SUCCESS"
	StatusDeliveryPendingRetry DeliveryStatus = "PENDING_RETRY"
	StatusDeliveryDeadLetter   DeliveryStatus = "DEAD_LETTER"
)

// DeliveryRecord tracks the full state and attempt history of an individual webhook dispatch.
type DeliveryRecord struct {
	ID                 uuid.UUID      `json:"id"`
	EventID            uuid.UUID      `json:"event_id"`
	SubscriptionID     uuid.UUID      `json:"subscription_id"`
	OrganizationID     uuid.UUID      `json:"organization_id"`
	EventType          string         `json:"event_type"`
	Payload            map[string]any `json:"payload"`
	Status             DeliveryStatus `json:"status"`
	Attempts           int            `json:"attempts"`
	LastStatusCode     int            `json:"last_status_code,omitempty"`
	LastError          string         `json:"last_error,omitempty"`
	ResponseSnippet    string         `json:"response_snippet,omitempty"`
	DurationMs         int64          `json:"duration_ms"`
	NextRetryAt        *time.Time     `json:"next_retry_at,omitempty"`
	DeliveredAt        *time.Time     `json:"delivered_at,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// HTTPClient interface for testable outbound requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WebhookDispatcher orchestrates reliable delivery, signature generation, retries, and replay protection.
type WebhookDispatcher struct {
	mu          sync.RWMutex
	subManager  *WebhookSubscriptionManager
	client      HTTPClient
	deliveries  map[uuid.UUID]*DeliveryRecord
}

func NewWebhookDispatcher(subManager *WebhookSubscriptionManager, client HTTPClient) *WebhookDispatcher {
	if client == nil {
		client = &http.Client{
			Timeout: DeliveryTimeout,
		}
	}
	return &WebhookDispatcher{
		subManager: subManager,
		client:     client,
		deliveries: make(map[uuid.UUID]*DeliveryRecord),
	}
}

// Dispatch synchronous/asynchronous event delivery to an active subscription with HMAC-SHA256 signing.
func (d *WebhookDispatcher) Dispatch(
	ctx context.Context,
	eventID uuid.UUID,
	sub *WebhookSubscription,
	eventType string,
	payload map[string]any,
) (*DeliveryRecord, error) {
	if eventID == uuid.Nil {
		eventID = uuid.New()
	}

	secret, err := d.subManager.GetDecryptedSecretForDispatcher(ctx, sub.ID)
	if err != nil {
		return nil, fmt.Errorf("dispatcher: failed to obtain signing secret: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("dispatcher: payload serialization failed: %w", err)
	}

	now := time.Now().UTC()
	record := &DeliveryRecord{
		ID:             uuid.New(),
		EventID:        eventID,
		SubscriptionID: sub.ID,
		OrganizationID: sub.OrganizationID,
		EventType:      eventType,
		Payload:        payload,
		Status:         StatusDeliveryPending,
		Attempts:       0,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	d.mu.Lock()
	d.deliveries[record.ID] = record
	d.mu.Unlock()

	d.executeAttempt(ctx, record, sub.EndpointURL, secret, payloadBytes)
	return record, nil
}

func (d *WebhookDispatcher) executeAttempt(
	ctx context.Context,
	record *DeliveryRecord,
	endpointURL string,
	secret string,
	payloadBytes []byte,
) {
	record.Attempts++
	record.UpdatedAt = time.Now().UTC()

	timestamp := time.Now().UTC().Unix()
	sigHeader := CalculateSignature(secret, timestamp, payloadBytes)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(payloadBytes))
	if err != nil {
		d.handleFailure(record, 0, err.Error(), "")
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(HeaderEventID, record.EventID.String())
	httpReq.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	httpReq.Header.Set(HeaderSignature, sigHeader)

	start := time.Now()
	resp, err := d.client.Do(httpReq)
	record.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		d.handleFailure(record, 0, err.Error(), "")
		return
	}
	defer resp.Body.Close()

	record.LastStatusCode = resp.StatusCode

	// Read response snippet up to 64KB
	snippetBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	record.ResponseSnippet = string(snippetBytes)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		now := time.Now().UTC()
		record.Status = StatusDeliverySuccess
		record.DeliveredAt = &now
		record.NextRetryAt = nil
		record.LastError = ""
	} else {
		d.handleFailure(record, resp.StatusCode, fmt.Sprintf("HTTP %d received from destination", resp.StatusCode), record.ResponseSnippet)
	}
}

func (d *WebhookDispatcher) handleFailure(record *DeliveryRecord, statusCode int, errMsg, snippet string) {
	record.LastStatusCode = statusCode
	record.LastError = errMsg
	record.ResponseSnippet = snippet

	if record.Attempts < MaxDeliveryAttempts {
		record.Status = StatusDeliveryPendingRetry
		// Exponential backoff: 2^(attempts-1) seconds (1s, 2s, 4s, 8s, 16s...)
		backoffSec := int(math.Pow(2, float64(record.Attempts-1)))
		retryTime := time.Now().UTC().Add(time.Duration(backoffSec) * time.Second)
		record.NextRetryAt = &retryTime
	} else {
		record.Status = StatusDeliveryDeadLetter
		record.NextRetryAt = nil
	}
}

// Redeliver allows manual or automated redelivery of a failed/dead-lettered webhook.
func (d *WebhookDispatcher) Redeliver(ctx context.Context, deliveryID uuid.UUID) (*DeliveryRecord, error) {
	d.mu.Lock()
	record, exists := d.deliveries[deliveryID]
	d.mu.Unlock()

	if !exists {
		return nil, ErrDeliveryNotFound
	}

	sub, exists := d.subManager.subscriptions[record.SubscriptionID]
	if !exists {
		return nil, ErrSubscriptionNotFound
	}

	secret, err := d.subManager.GetDecryptedSecretForDispatcher(ctx, sub.ID)
	if err != nil {
		return nil, err
	}

	payloadBytes, err := json.Marshal(record.Payload)
	if err != nil {
		return nil, err
	}

	// Reset attempt status for redelivery
	record.Status = StatusDeliveryPending
	d.executeAttempt(ctx, record, sub.EndpointURL, secret, payloadBytes)
	return record, nil
}

func (d *WebhookDispatcher) GetDelivery(deliveryID uuid.UUID) (*DeliveryRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	r, exists := d.deliveries[deliveryID]
	if !exists {
		return nil, ErrDeliveryNotFound
	}
	return r, nil
}

// CalculateSignature computes Stripe-compatible HMAC-SHA256 signature in format "t=<timestamp>,v1=<hex_sig>".
func CalculateSignature(secret string, timestamp int64, payload []byte) string {
	signingInput := fmt.Sprintf("%d.%s", timestamp, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sigHex := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", timestamp, sigHex)
}

// VerifySignature provides signature and replay-window validation for webhook consumers.
func VerifySignature(secret string, payload []byte, sigHeader string, maxSkew time.Duration) (bool, error) {
	if maxSkew <= 0 {
		maxSkew = DefaultReplayWindow
	}

	// Parse header "t=<timestamp>,v1=<sig>"
	var tsStr, actualSig string
	parts := strings.Split(sigHeader, ",")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "t":
				tsStr = kv[1]
			case "v1":
				actualSig = kv[1]
			}
		}
	}

	if tsStr == "" || actualSig == "" {
		return false, ErrInvalidSignatureHeader
	}

	tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, ErrInvalidSignatureHeader
	}

	// Replay protection tolerance check
	eventTime := time.Unix(tsUnix, 0).UTC()
	now := time.Now().UTC()

	if eventTime.Before(now.Add(-maxSkew)) || eventTime.After(now.Add(5*time.Second)) {
		return false, ErrReplayWindowExpired
	}

	// Recompute expected HMAC
	signingInput := fmt.Sprintf("%d.%s", tsUnix, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(actualSig), []byte(expectedSig)) {
		return false, ErrSignatureMismatch
	}

	return true, nil
}
