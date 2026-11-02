package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type mockTXTResolver struct {
	records map[string][]string
}

func newMockTXTResolver() *mockTXTResolver {
	return &mockTXTResolver{
		records: make(map[string][]string),
	}
}

func (m *mockTXTResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	recs, ok := m.records[domain]
	if !ok {
		return nil, errors.New("NXDOMAIN: no records")
	}
	return recs, nil
}

func TestDomainService_RegisterAndVerify(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryDomainRepository()
	resolver := newMockTXTResolver()
	mockAudit := &mockAuditRecorder{}
	service := NewDomainService(repo, resolver, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("register domain generates verification token", func(t *testing.T) {
		d, err := service.RegisterDomain(ctx, actorID, orgID, "corp.example.com", RoleReadOnlyViewer, true)
		if err != nil {
			t.Fatalf("unexpected error registering domain: %v", err)
		}
		if d.Status != DomainStatusPendingVerification {
			t.Errorf("expected status PENDING_VERIFICATION, got %s", d.Status)
		}
		if !d.JITEnabled {
			t.Errorf("expected JITEnabled true")
		}
		if d.DefaultRole != RoleReadOnlyViewer {
			t.Errorf("expected default role READ_ONLY_VIEWER, got %s", d.DefaultRole)
		}
		if d.VerificationToken == "" || len(d.VerificationToken) < 30 {
			t.Errorf("expected valid verification token, got %s", d.VerificationToken)
		}
		if len(mockAudit.events) != 1 || mockAudit.events[0].Action != ActionDomainRegistered {
			t.Errorf("expected audit event %s", ActionDomainRegistered)
		}
	})

	t.Run("reject invalid domain format", func(t *testing.T) {
		_, err := service.RegisterDomain(ctx, actorID, orgID, "nodotdomain", RoleReadOnlyViewer, true)
		if !errors.Is(err, ErrInvalidDomainFormat) {
			t.Fatalf("expected ErrInvalidDomainFormat, got %v", err)
		}

		_, err = service.RegisterDomain(ctx, actorID, orgID, "bad domain.com", RoleReadOnlyViewer, true)
		if !errors.Is(err, ErrInvalidDomainFormat) {
			t.Fatalf("expected ErrInvalidDomainFormat for spaces, got %v", err)
		}
	})

	t.Run("reject privileged administrative role as JIT default", func(t *testing.T) {
		_, err := service.RegisterDomain(ctx, actorID, orgID, "admin-domain.com", RoleOrgOwner, true)
		if !errors.Is(err, ErrPrivilegedJITForbidden) {
			t.Fatalf("expected ErrPrivilegedJITForbidden for RoleOrgOwner, got %v", err)
		}

		_, err = service.RegisterDomain(ctx, actorID, orgID, "admin-domain.com", RoleOrgAdmin, true)
		if !errors.Is(err, ErrPrivilegedJITForbidden) {
			t.Fatalf("expected ErrPrivilegedJITForbidden for RoleOrgAdmin, got %v", err)
		}
	})

	t.Run("verify domain success via DNS TXT record", func(t *testing.T) {
		d, _ := service.RegisterDomain(ctx, actorID, orgID, "verified.example.com", RoleReadOnlyViewer, true)
		resolver.records["verified.example.com"] = []string{d.VerificationToken}

		verified, err := service.VerifyDomain(ctx, actorID, d.ID)
		if err != nil {
			t.Fatalf("unexpected error verifying domain: %v", err)
		}
		if verified.Status != DomainStatusVerified {
			t.Errorf("expected status VERIFIED, got %s", verified.Status)
		}
		if verified.VerifiedAt == nil || verified.ExpiresAt == nil {
			t.Errorf("expected non-nil timestamps for verified domain")
		}
		if verified.ExpiresAt.Before(time.Now().Add(170 * 24 * time.Hour)) {
			t.Errorf("expected ~180 day expiration window")
		}
	})

	t.Run("verify domain fails when TXT record missing or wrong", func(t *testing.T) {
		d, _ := service.RegisterDomain(ctx, actorID, orgID, "unmatched.example.com", RoleReadOnlyViewer, true)
		resolver.records["unmatched.example.com"] = []string{"random-unrelated-txt-record"}

		_, err := service.VerifyDomain(ctx, actorID, d.ID)
		if !errors.Is(err, ErrDNSChallengeFailed) {
			t.Fatalf("expected ErrDNSChallengeFailed, got %v", err)
		}
	})

	t.Run("cannot register domain already verified by another org", func(t *testing.T) {
		otherOrgID := uuid.New()
		_, err := service.RegisterDomain(ctx, actorID, otherOrgID, "verified.example.com", RoleReadOnlyViewer, true)
		if !errors.Is(err, ErrDomainAlreadyClaimed) {
			t.Fatalf("expected ErrDomainAlreadyClaimed, got %v", err)
		}
	})
}

func TestDomainService_JITProvisioning(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryDomainRepository()
	resolver := newMockTXTResolver()
	mockAudit := &mockAuditRecorder{}
	service := NewDomainService(repo, resolver, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	d, _ := service.RegisterDomain(ctx, actorID, orgID, "enterprise.com", RoleSecurityAnalyst, true)
	resolver.records["enterprise.com"] = []string{d.VerificationToken}
	_, _ = service.VerifyDomain(ctx, actorID, d.ID)

	t.Run("successful JIT user provisioning", func(t *testing.T) {
		user, err := service.ProvisionJITUser(ctx, orgID, "sarah@enterprise.com", "Sarah Connor", "idp-sub-123")
		if err != nil {
			t.Fatalf("unexpected error during JIT provisioning: %v", err)
		}
		if user.Email != "sarah@enterprise.com" {
			t.Errorf("expected email sarah@enterprise.com, got %s", user.Email)
		}
		if user.Role != RoleSecurityAnalyst {
			t.Errorf("expected role %s, got %s", RoleSecurityAnalyst, user.Role)
		}
		if user.OrganizationID != orgID {
			t.Errorf("expected org ID %s, got %s", orgID, user.OrganizationID)
		}
	})

	t.Run("JIT provisioning fails if email domain is unverified", func(t *testing.T) {
		_, err := service.ProvisionJITUser(ctx, orgID, "attacker@gmail.com", "Attacker", "sub-456")
		if !errors.Is(err, ErrJITDomainNotVerified) {
			t.Fatalf("expected ErrJITDomainNotVerified, got %v", err)
		}
	})

	t.Run("JIT provisioning fails if domain verification has expired", func(t *testing.T) {
		expiredTime := time.Now().Add(-24 * time.Hour)
		d.ExpiresAt = &expiredTime
		_ = repo.Update(ctx, d)

		_, err := service.ProvisionJITUser(ctx, orgID, "sarah@enterprise.com", "Sarah Connor", "idp-sub-123")
		if !errors.Is(err, ErrJITDomainNotVerified) {
			t.Fatalf("expected ErrJITDomainNotVerified for expired domain, got %v", err)
		}

		// Restore expiration
		futureTime := time.Now().Add(180 * 24 * time.Hour)
		d.ExpiresAt = &futureTime
		_ = repo.Update(ctx, d)
	})

	t.Run("JIT provisioning fails if JIT is disabled", func(t *testing.T) {
		d.JITEnabled = false
		_ = repo.Update(ctx, d)

		_, err := service.ProvisionJITUser(ctx, orgID, "sarah@enterprise.com", "Sarah Connor", "idp-sub-123")
		if !errors.Is(err, ErrJITDisabled) {
			t.Fatalf("expected ErrJITDisabled, got %v", err)
		}
	})
}
