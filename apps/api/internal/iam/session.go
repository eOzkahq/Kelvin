package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrSessionNotFound     = errors.New("user session not found")
	ErrSessionRevoked      = errors.New("session has been revoked")
	ErrSessionExpired      = errors.New("session has exceeded maximum absolute lifetime")
	ErrSessionIdleTimeout  = errors.New("session expired due to inactivity timeout")
	ErrMFARequired         = errors.New("organization security policy requires multi-factor authentication (MFA)")
	ErrStepUpAuthRequired  = errors.New("step-up reauthentication required for high-risk action")
	ErrInvalidPolicyLimits = errors.New("session policy exceeds platform safety boundaries")
)

const (
	ActionSessionPolicyConfigured = "session.policy_configured"
	ActionSessionCreated          = "session.created"
	ActionSessionRevoked          = "session.revoked"
	ActionSessionStepUpVerified   = "session.step_up_verified"
)

// SessionPolicy controls authentication lifetime and security constraints for an organization.
type SessionPolicy struct {
	ID                       uuid.UUID `json:"id"`
	OrganizationID          uuid.UUID `json:"organization_id"`
	MaxIdleMinutes           int       `json:"max_idle_minutes"`            // e.g. 15 mins (platform max 120)
	MaxLifetimeHours         int       `json:"max_lifetime_hours"`          // e.g. 12 hrs (platform max 24)
	MaxConcurrentSessions    int       `json:"max_concurrent_sessions"`    // e.g. 5
	RequireMFA              bool      `json:"require_mfa"`
	RequireStepUpReauth      bool      `json:"require_step_up_reauth"`
	ReauthGracePeriodSeconds int       `json:"reauth_grace_period_seconds"` // e.g. 300s (5m)
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// DefaultSessionPolicy returns safe enterprise defaults.
func DefaultSessionPolicy(orgID uuid.UUID) *SessionPolicy {
	now := time.Now().UTC()
	return &SessionPolicy{
		ID:                       uuid.New(),
		OrganizationID:          orgID,
		MaxIdleMinutes:           15,
		MaxLifetimeHours:         12,
		MaxConcurrentSessions:    5,
		RequireMFA:              true,
		RequireStepUpReauth:      true,
		ReauthGracePeriodSeconds: 300,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
}

// UserSession records an active client login session.
type UserSession struct {
	ID               uuid.UUID `json:"id"`
	SessionID        string    `json:"session_id"` // Cryptographic high-entropy token
	OrganizationID   uuid.UUID `json:"organization_id"`
	UserID           string    `json:"user_id"`
	IPAddress        string    `json:"ip_address"`
	UserAgent        string    `json:"user_agent"`
	MFAVerified      bool      `json:"mfa_verified"`
	LastActivityAt   time.Time `json:"last_activity_at"`
	LastReauthAt     time.Time `json:"last_reauth_at"`
	Status           string    `json:"status"` // ACTIVE, REVOKED, EXPIRED
	RevocationReason string    `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"` // Absolute lifetime
}

// SessionRepository defines persistence operations for session policies and active user sessions.
type SessionRepository interface {
	SavePolicy(ctx context.Context, policy *SessionPolicy) error
	GetPolicy(ctx context.Context, orgID uuid.UUID) (*SessionPolicy, error)

	SaveSession(ctx context.Context, session *UserSession) error
	GetSession(ctx context.Context, sessionID string) (*UserSession, error)
	UpdateSession(ctx context.Context, session *UserSession) error
	ListActiveSessionsForUser(ctx context.Context, orgID uuid.UUID, userID string) ([]*UserSession, error)
}

// MemorySessionRepository provides an in-memory implementation of SessionRepository.
type MemorySessionRepository struct {
	mu       sync.RWMutex
	policies map[uuid.UUID]*SessionPolicy
	sessions map[string]*UserSession
}

func NewMemorySessionRepository() *MemorySessionRepository {
	return &MemorySessionRepository{
		policies: make(map[uuid.UUID]*SessionPolicy),
		sessions: make(map[string]*UserSession),
	}
}

func (m *MemorySessionRepository) SavePolicy(ctx context.Context, policy *SessionPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[policy.OrganizationID] = policy
	return nil
}

func (m *MemorySessionRepository) GetPolicy(ctx context.Context, orgID uuid.UUID) (*SessionPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[orgID]
	if !ok {
		return DefaultSessionPolicy(orgID), nil
	}
	return p, nil
}

func (m *MemorySessionRepository) SaveSession(ctx context.Context, session *UserSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.SessionID] = session
	return nil
}

func (m *MemorySessionRepository) GetSession(ctx context.Context, sessionID string) (*UserSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return s, nil
}

func (m *MemorySessionRepository) UpdateSession(ctx context.Context, session *UserSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[session.SessionID]; !ok {
		return ErrSessionNotFound
	}
	m.sessions[session.SessionID] = session
	return nil
}

func (m *MemorySessionRepository) ListActiveSessionsForUser(ctx context.Context, orgID uuid.UUID, userID string) ([]*UserSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*UserSession
	for _, s := range m.sessions {
		if s.OrganizationID == orgID && s.UserID == userID && s.Status == "ACTIVE" {
			list = append(list, s)
		}
	}
	return list, nil
}

// SessionService manages enterprise session security, MFA enforcement, and step-up authentication.
type SessionService struct {
	repo  SessionRepository
	audit audit.Recorder
}

func NewSessionService(repo SessionRepository, audit audit.Recorder) *SessionService {
	return &SessionService{
		repo:  repo,
		audit: audit,
	}
}

// ConfigurePolicy stores organization session security settings while enforcing platform boundaries.
func (s *SessionService) ConfigurePolicy(ctx context.Context, actorUserID string, policy *SessionPolicy) error {
	if policy.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	// Platform Security Boundaries: Organization cannot weaken security beyond baseline
	if policy.MaxIdleMinutes <= 0 || policy.MaxIdleMinutes > 120 {
		return fmt.Errorf("%w: idle timeout must be between 1 and 120 minutes", ErrInvalidPolicyLimits)
	}
	if policy.MaxLifetimeHours <= 0 || policy.MaxLifetimeHours > 24 {
		return fmt.Errorf("%w: absolute session lifetime must be between 1 and 24 hours", ErrInvalidPolicyLimits)
	}
	if policy.MaxConcurrentSessions <= 0 || policy.MaxConcurrentSessions > 20 {
		return fmt.Errorf("%w: max concurrent sessions must be between 1 and 20", ErrInvalidPolicyLimits)
	}
	if policy.ReauthGracePeriodSeconds < 30 || policy.ReauthGracePeriodSeconds > 3600 {
		return fmt.Errorf("%w: reauth grace period must be between 30 and 3600 seconds", ErrInvalidPolicyLimits)
	}

	now := time.Now().UTC()
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	if err := s.repo.SavePolicy(ctx, policy); err != nil {
		return err
	}

	s.recordAudit(ctx, policy.OrganizationID, actorUserID, ActionSessionPolicyConfigured, policy.ID)
	return nil
}

// CreateSession establishes an authenticated user session subject to MFA and concurrency policies.
func (s *SessionService) CreateSession(
	ctx context.Context,
	orgID uuid.UUID,
	userID string,
	ipAddress string,
	userAgent string,
	mfaVerified bool,
) (*UserSession, error) {
	policy, err := s.repo.GetPolicy(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// MFA Enforcement Check
	if policy.RequireMFA && !mfaVerified {
		return nil, ErrMFARequired
	}

	// Concurrent session limit check: evict oldest active session if limit exceeded
	activeSessions, err := s.repo.ListActiveSessionsForUser(ctx, orgID, userID)
	if err == nil && len(activeSessions) >= policy.MaxConcurrentSessions {
		// Sort by CreatedAt ascending to find oldest
		sort.Slice(activeSessions, func(i, j int) bool {
			return activeSessions[i].CreatedAt.Before(activeSessions[j].CreatedAt)
		})
		oldest := activeSessions[0]
		oldest.Status = "REVOKED"
		oldest.RevocationReason = "concurrent_limit_exceeded"
		_ = s.repo.UpdateSession(ctx, oldest)
	}

	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(policy.MaxLifetimeHours) * time.Hour)

	session := &UserSession{
		ID:               uuid.New(),
		SessionID:        sessionID,
		OrganizationID:   orgID,
		UserID:           userID,
		IPAddress:        ipAddress,
		UserAgent:        userAgent,
		MFAVerified:      mfaVerified,
		LastActivityAt:   now,
		LastReauthAt:     now,
		Status:           "ACTIVE",
		RevocationReason: "",
		CreatedAt:        now,
		ExpiresAt:        expiresAt,
	}

	if err := s.repo.SaveSession(ctx, session); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, orgID, userID, ActionSessionCreated, session.ID)
	return session, nil
}

// ValidateSession verifies session validity: revocation, absolute lifetime, idle timeout, and MFA.
func (s *SessionService) ValidateSession(ctx context.Context, sessionID string, now time.Time) (*UserSession, error) {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.Status == "REVOKED" {
		return nil, ErrSessionRevoked
	}

	policy, err := s.repo.GetPolicy(ctx, session.OrganizationID)
	if err != nil {
		return nil, err
	}

	// 1. Absolute Lifetime Check
	if now.After(session.ExpiresAt) {
		session.Status = "EXPIRED"
		session.RevocationReason = "absolute_lifetime_exceeded"
		_ = s.repo.UpdateSession(ctx, session)
		return nil, ErrSessionExpired
	}

	// 2. Inactivity / Idle Timeout Check
	idleDuration := now.Sub(session.LastActivityAt)
	if idleDuration > time.Duration(policy.MaxIdleMinutes)*time.Minute {
		session.Status = "EXPIRED"
		session.RevocationReason = "idle_timeout_exceeded"
		_ = s.repo.UpdateSession(ctx, session)
		return nil, ErrSessionIdleTimeout
	}

	// 3. MFA Policy Check
	if policy.RequireMFA && !session.MFAVerified {
		return nil, ErrMFARequired
	}

	// 4. Update last activity
	session.LastActivityAt = now
	_ = s.repo.UpdateSession(ctx, session)

	return session, nil
}

// RequireStepUpAuth verifies if step-up reauthentication is required for high-risk operations.
func (s *SessionService) RequireStepUpAuth(ctx context.Context, sessionID string, now time.Time) error {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	policy, err := s.repo.GetPolicy(ctx, session.OrganizationID)
	if err != nil {
		return err
	}

	if !policy.RequireStepUpReauth {
		return nil
	}

	graceDuration := time.Duration(policy.ReauthGracePeriodSeconds) * time.Second
	if now.Sub(session.LastReauthAt) > graceDuration {
		return ErrStepUpAuthRequired
	}

	return nil
}

// RecordStepUpAuth refreshes the step-up reauthentication timestamp after successful credential challenge.
func (s *SessionService) RecordStepUpAuth(ctx context.Context, sessionID string) error {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	session.LastReauthAt = now
	session.LastActivityAt = now

	if err := s.repo.UpdateSession(ctx, session); err != nil {
		return err
	}

	s.recordAudit(ctx, session.OrganizationID, session.UserID, ActionSessionStepUpVerified, session.ID)
	return nil
}

// RevokeSession terminates a session immediately.
func (s *SessionService) RevokeSession(ctx context.Context, sessionID, reason string) error {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.Status = "REVOKED"
	session.RevocationReason = reason

	if err := s.repo.UpdateSession(ctx, session); err != nil {
		return err
	}

	s.recordAudit(ctx, session.OrganizationID, session.UserID, ActionSessionRevoked, session.ID)
	return nil
}

// RevokeAllUserSessions revokes all active sessions for a user across the organization.
func (s *SessionService) RevokeAllUserSessions(ctx context.Context, orgID uuid.UUID, userID, reason string) error {
	active, err := s.repo.ListActiveSessionsForUser(ctx, orgID, userID)
	if err != nil {
		return err
	}

	for _, sess := range active {
		sess.Status = "REVOKED"
		sess.RevocationReason = reason
		_ = s.repo.UpdateSession(ctx, sess)
		s.recordAudit(ctx, orgID, userID, ActionSessionRevoked, sess.ID)
	}

	return nil
}

func (s *SessionService) recordAudit(ctx context.Context, orgID uuid.UUID, userID, action string, entityID uuid.UUID) {
	if s.audit == nil {
		return
	}
	var actorUUID *uuid.UUID
	if aID, err := uuid.Parse(userID); err == nil {
		actorUUID = &aID
	}
	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    &orgID,
		ActorUserID: actorUUID,
		ActorType:   audit.ActorUser,
		Action:      action,
		EntityType:  "user_session",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
