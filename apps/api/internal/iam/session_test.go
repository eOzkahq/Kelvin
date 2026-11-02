package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionService_PolicyConfiguration(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySessionRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSessionService(repo, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("configure valid session policy", func(t *testing.T) {
		p := &SessionPolicy{
			OrganizationID:          orgID,
			MaxIdleMinutes:           30,
			MaxLifetimeHours:         8,
			MaxConcurrentSessions:    3,
			RequireMFA:              true,
			RequireStepUpReauth:      true,
			ReauthGracePeriodSeconds: 300,
		}

		err := service.ConfigurePolicy(ctx, actorID, p)
		if err != nil {
			t.Fatalf("unexpected error configuring policy: %v", err)
		}

		saved, err := repo.GetPolicy(ctx, orgID)
		if err != nil {
			t.Fatalf("failed to get policy: %v", err)
		}
		if saved.MaxIdleMinutes != 30 || saved.MaxLifetimeHours != 8 {
			t.Errorf("policy values do not match expected")
		}
	})

	t.Run("reject excessive idle timeout beyond platform limit", func(t *testing.T) {
		p := &SessionPolicy{
			OrganizationID:          orgID,
			MaxIdleMinutes:           200, // Exceeds 120m max
			MaxLifetimeHours:         8,
			MaxConcurrentSessions:    3,
			ReauthGracePeriodSeconds: 300,
		}
		err := service.ConfigurePolicy(ctx, actorID, p)
		if !errors.Is(err, ErrInvalidPolicyLimits) {
			t.Fatalf("expected ErrInvalidPolicyLimits, got %v", err)
		}
	})

	t.Run("reject excessive lifetime beyond platform limit", func(t *testing.T) {
		p := &SessionPolicy{
			OrganizationID:          orgID,
			MaxIdleMinutes:           30,
			MaxLifetimeHours:         48, // Exceeds 24h max
			MaxConcurrentSessions:    3,
			ReauthGracePeriodSeconds: 300,
		}
		err := service.ConfigurePolicy(ctx, actorID, p)
		if !errors.Is(err, ErrInvalidPolicyLimits) {
			t.Fatalf("expected ErrInvalidPolicyLimits, got %v", err)
		}
	})
}

func TestSessionService_LifecycleAndValidation(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySessionRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSessionService(repo, mockAudit)

	orgID := uuid.New()
	userID := "usr_alice_42"

	policy := &SessionPolicy{
		OrganizationID:          orgID,
		MaxIdleMinutes:           15,
		MaxLifetimeHours:         12,
		MaxConcurrentSessions:    2,
		RequireMFA:              true,
		RequireStepUpReauth:      true,
		ReauthGracePeriodSeconds: 300,
	}
	_ = service.ConfigurePolicy(ctx, userID, policy)

	t.Run("reject session creation without required MFA", func(t *testing.T) {
		_, err := service.CreateSession(ctx, orgID, userID, "192.168.1.1", "Mozilla/5.0", false)
		if !errors.Is(err, ErrMFARequired) {
			t.Fatalf("expected ErrMFARequired, got %v", err)
		}
	})

	t.Run("create session with MFA successfully", func(t *testing.T) {
		sess, err := service.CreateSession(ctx, orgID, userID, "192.168.1.1", "Mozilla/5.0", true)
		if err != nil {
			t.Fatalf("unexpected error creating session: %v", err)
		}
		if sess.SessionID == "" {
			t.Errorf("expected valid session ID")
		}
		if sess.Status != "ACTIVE" {
			t.Errorf("expected status ACTIVE, got %s", sess.Status)
		}
	})

	t.Run("validate active session succeeds and updates activity", func(t *testing.T) {
		sess, _ := service.CreateSession(ctx, orgID, userID, "192.168.1.1", "Mozilla/5.0", true)
		now := time.Now().UTC().Add(5 * time.Minute)

		validated, err := service.ValidateSession(ctx, sess.SessionID, now)
		if err != nil {
			t.Fatalf("unexpected error validating session: %v", err)
		}
		if !validated.LastActivityAt.Equal(now) {
			t.Errorf("expected LastActivityAt updated to now")
		}
	})

	t.Run("idle timeout expiration", func(t *testing.T) {
		sess, _ := service.CreateSession(ctx, orgID, userID, "192.168.1.1", "Mozilla/5.0", true)
		now := sess.LastActivityAt.Add(20 * time.Minute) // Exceeds 15m idle

		_, err := service.ValidateSession(ctx, sess.SessionID, now)
		if !errors.Is(err, ErrSessionIdleTimeout) {
			t.Fatalf("expected ErrSessionIdleTimeout, got %v", err)
		}

		// Recheck session status
		reloaded, _ := repo.GetSession(ctx, sess.SessionID)
		if reloaded.Status != "EXPIRED" {
			t.Errorf("expected status EXPIRED")
		}
	})

	t.Run("absolute lifetime expiration", func(t *testing.T) {
		sess, _ := service.CreateSession(ctx, orgID, userID, "192.168.1.1", "Mozilla/5.0", true)
		now := sess.CreatedAt.Add(13 * time.Hour) // Exceeds 12h lifetime

		_, err := service.ValidateSession(ctx, sess.SessionID, now)
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("expected ErrSessionExpired, got %v", err)
		}
	})

	t.Run("immediate session revocation", func(t *testing.T) {
		sess, _ := service.CreateSession(ctx, orgID, userID, "192.168.1.1", "Mozilla/5.0", true)

		err := service.RevokeSession(ctx, sess.SessionID, "user_logged_out")
		if err != nil {
			t.Fatalf("unexpected error revoking session: %v", err)
		}

		_, err = service.ValidateSession(ctx, sess.SessionID, time.Now().UTC())
		if !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("expected ErrSessionRevoked, got %v", err)
		}
	})

	t.Run("concurrent session eviction of oldest session", func(t *testing.T) {
		// Limit is 2
		_ = service.RevokeAllUserSessions(ctx, orgID, "usr_bob", "cleanup")

		s1, _ := service.CreateSession(ctx, orgID, "usr_bob", "1.1.1.1", "UA1", true)
		time.Sleep(10 * time.Millisecond)
		s2, _ := service.CreateSession(ctx, orgID, "usr_bob", "1.1.1.2", "UA2", true)
		time.Sleep(10 * time.Millisecond)

		// Creating 3rd session must evict s1 (oldest)
		s3, err := service.CreateSession(ctx, orgID, "usr_bob", "1.1.1.3", "UA3", true)
		if err != nil {
			t.Fatalf("failed to create 3rd session: %v", err)
		}
		if s3.Status != "ACTIVE" {
			t.Errorf("expected 3rd session active")
		}

		// s1 must now be revoked
		s1Reloaded, _ := repo.GetSession(ctx, s1.SessionID)
		if s1Reloaded.Status != "REVOKED" {
			t.Errorf("expected s1 to be revoked due to concurrency limit, got %s", s1Reloaded.Status)
		}

		// s2 must still be active
		s2Reloaded, _ := repo.GetSession(ctx, s2.SessionID)
		if s2Reloaded.Status != "ACTIVE" {
			t.Errorf("expected s2 to remain active")
		}
	})
}

func TestSessionService_StepUpAuthentication(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySessionRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewSessionService(repo, mockAudit)

	orgID := uuid.New()
	userID := "usr_admin_100"

	sess, err := service.CreateSession(ctx, orgID, userID, "10.0.0.1", "UA", true)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	t.Run("step-up auth check passes within grace period", func(t *testing.T) {
		withinGrace := sess.LastReauthAt.Add(2 * time.Minute) // Grace is 5m (300s)
		err := service.RequireStepUpAuth(ctx, sess.SessionID, withinGrace)
		if err != nil {
			t.Fatalf("expected step-up check to pass, got: %v", err)
		}
	})

	t.Run("step-up auth check fails after grace period elapsed", func(t *testing.T) {
		afterGrace := sess.LastReauthAt.Add(6 * time.Minute) // Exceeds 5m grace
		err := service.RequireStepUpAuth(ctx, sess.SessionID, afterGrace)
		if !errors.Is(err, ErrStepUpAuthRequired) {
			t.Fatalf("expected ErrStepUpAuthRequired, got %v", err)
		}
	})

	t.Run("record step-up auth refreshes reauth timestamp", func(t *testing.T) {
		err := service.RecordStepUpAuth(ctx, sess.SessionID)
		if err != nil {
			t.Fatalf("failed to record step-up auth: %v", err)
		}

		err = service.RequireStepUpAuth(ctx, sess.SessionID, time.Now().UTC())
		if err != nil {
			t.Fatalf("expected step-up check to pass after refresh: %v", err)
		}
	})
}
