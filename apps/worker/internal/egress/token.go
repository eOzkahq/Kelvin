package egress

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrMissingToken = errors.New("egress: missing proxy execution token")
	ErrInvalidToken = errors.New("egress: invalid proxy execution token")
	ErrExpiredToken = errors.New("egress: expired proxy execution token")
)

const (
	DefaultTokenTTL = 30 * time.Minute
	TokenPrefix     = "kelvin-egress-"
)

// ExecutionToken represents an ephemeral, cryptographically secure execution token
// binding scanner proxy traffic to a specific assessment job execution context.
type ExecutionToken struct {
	Token        string    `json:"token"`
	JobID        string    `json:"job_id"`
	TenantID     string    `json:"tenant_id"`
	AssessmentID string    `json:"assessment_id"`
	Scanner      string    `json:"scanner"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired reports whether the execution token has passed its expiration deadline.
func (t *ExecutionToken) IsExpired() bool {
	if t == nil {
		return true
	}
	return time.Now().UTC().After(t.ExpiresAt)
}

// GenerateExecutionToken creates an ephemeral cryptographically random token bound
// to the specified job, tenant, and assessment.
func GenerateExecutionToken(jobID, tenantID, assessmentID, scanner string, ttl time.Duration) (*ExecutionToken, error) {
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("egress: failed to generate secure token entropy: %w", err)
	}
	rawToken := TokenPrefix + hex.EncodeToString(bytes)
	now := time.Now().UTC()
	return &ExecutionToken{
		Token:        rawToken,
		JobID:        jobID,
		TenantID:     tenantID,
		AssessmentID: assessmentID,
		Scanner:      scanner,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}, nil
}

// TokenManager is a thread-safe registry of active ephemeral execution tokens.
type TokenManager struct {
	mu     sync.RWMutex
	tokens map[string]*ExecutionToken
}

// NewTokenManager initializes a new in-memory TokenManager.
func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens: make(map[string]*ExecutionToken),
	}
}

// Issue generates and registers a new ephemeral execution token.
func (m *TokenManager) Issue(jobID, tenantID, assessmentID, scanner string, ttl time.Duration) (*ExecutionToken, error) {
	t, err := GenerateExecutionToken(jobID, tenantID, assessmentID, scanner, ttl)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Token] = t
	return t, nil
}

// Register adds an existing ExecutionToken into the manager.
func (m *TokenManager) Register(t *ExecutionToken) {
	if t == nil || t.Token == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Token] = t
}

// Validate verifies whether a token string is authentic and unexpired.
func (m *TokenManager) Validate(tokenStr string) (*ExecutionToken, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, ErrMissingToken
	}

	m.mu.RLock()
	t, exists := m.tokens[tokenStr]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrInvalidToken
	}
	if t.IsExpired() {
		m.Revoke(tokenStr)
		return nil, ErrExpiredToken
	}
	return t, nil
}

// Revoke removes an execution token from the registry.
func (m *TokenManager) Revoke(tokenStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, tokenStr)
}

// RevokeJob revokes all tokens issued for a specific job ID.
func (m *TokenManager) RevokeJob(jobID string) {
	if jobID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.tokens {
		if v.JobID == jobID {
			delete(m.tokens, k)
		}
	}
}

// ActiveCount returns the number of active registered tokens.
func (m *TokenManager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().UTC()
	count := 0
	for _, t := range m.tokens {
		if now.Before(t.ExpiresAt) {
			count++
		}
	}
	return count
}

// ExtractProxyToken extracts the authorization token from HTTP request headers.
// It checks Proxy-Authorization first, then Authorization, supporting Bearer
// and Basic authentication formats.
func ExtractProxyToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		header = r.Header.Get("Authorization")
	}
	if header == "" {
		return ""
	}

	trimmed := strings.TrimSpace(header)
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		return strings.TrimSpace(trimmed[7:])
	}

	if strings.HasPrefix(strings.ToLower(trimmed), "basic ") {
		payload := strings.TrimSpace(trimmed[6:])
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return ""
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			return parts[1] // password
		}
		return parts[0] // username
	}

	return trimmed
}
