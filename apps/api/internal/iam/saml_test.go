package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSAMLService_ConfigureAndRollover(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySAMLConfigRepository()
	replay := NewMemorySAMLReplayCache()
	mockAudit := &mockAuditRecorder{}
	service := NewSAMLService(repo, replay, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()

	t.Run("configure SAML successfully", func(t *testing.T) {
		cfg := &SAMLConfig{
			OrganizationID: orgID,
			IdPEntityID:    "https://idp.okta.com/app/kelvin/sso/saml",
			SSOURL:         "https://idp.okta.com/app/kelvin/sso/saml/sso",
			SPEntityID:     "https://app.kelvin.security/saml/" + orgID.String(),
			ACSURL:         "https://app.kelvin.security/auth/saml/acs",
			IdPX509Cert:    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA12345PrimaryCert",
			Enabled:        true,
		}

		err := service.ConfigureSAML(ctx, actorID, cfg)
		if err != nil {
			t.Fatalf("unexpected error configuring SAML: %v", err)
		}

		saved, err := repo.GetByOrgID(ctx, orgID)
		if err != nil {
			t.Fatalf("failed to retrieve config: %v", err)
		}
		if saved.IdPEntityID != cfg.IdPEntityID {
			t.Errorf("expected IdPEntityID %s, got %s", cfg.IdPEntityID, saved.IdPEntityID)
		}
		if len(mockAudit.events) != 1 || mockAudit.events[0].Action != ActionSAMLConfigured {
			t.Errorf("expected audit event %s, got %+v", ActionSAMLConfigured, mockAudit.events)
		}
	})

	t.Run("stage secondary certificate for rollover", func(t *testing.T) {
		secondaryCert := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA67890SecondaryCert"
		err := service.RolloverCertificate(ctx, actorID, orgID, secondaryCert, false)
		if err != nil {
			t.Fatalf("failed to stage secondary cert: %v", err)
		}

		cfg, _ := repo.GetByOrgID(ctx, orgID)
		if cfg.IdPX509CertSecondary != secondaryCert {
			t.Errorf("expected secondary cert staged")
		}
	})

	t.Run("promote secondary to primary", func(t *testing.T) {
		secondaryCert := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA67890SecondaryCert"
		err := service.RolloverCertificate(ctx, actorID, orgID, secondaryCert, true)
		if err != nil {
			t.Fatalf("failed to promote cert: %v", err)
		}

		cfg, _ := repo.GetByOrgID(ctx, orgID)
		if cfg.IdPX509Cert != secondaryCert {
			t.Errorf("expected primary cert updated to secondary")
		}
		if cfg.IdPX509CertSecondary != "" {
			t.Errorf("expected secondary cert cleared after promotion")
		}
	})
}

func TestSAMLService_AuthnRequestAndAssertion(t *testing.T) {
	ctx := context.Background()
	repo := NewMemorySAMLConfigRepository()
	replay := NewMemorySAMLReplayCache()
	mockAudit := &mockAuditRecorder{}
	service := NewSAMLService(repo, replay, mockAudit)

	orgID := uuid.New()
	actorID := uuid.New().String()
	idpEntity := "https://idp.okta.com/saml/metadata"
	spEntity := "https://app.kelvin.security/saml/" + orgID.String()
	acsURL := "https://app.kelvin.security/auth/saml/acs"
	primaryCert := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA11111PrimaryCert"
	secondaryCert := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA22222SecondaryCert"

	cfg := &SAMLConfig{
		OrganizationID:       orgID,
		IdPEntityID:          idpEntity,
		SSOURL:               "https://idp.okta.com/saml/sso",
		SPEntityID:           spEntity,
		ACSURL:               acsURL,
		IdPX509Cert:          primaryCert,
		IdPX509CertSecondary: secondaryCert,
		Enabled:              true,
	}
	_ = service.ConfigureSAML(ctx, actorID, cfg)

	t.Run("generate SP-initiated AuthnRequest", func(t *testing.T) {
		req, err := service.GenerateAuthnRequest(ctx, orgID)
		if err != nil {
			t.Fatalf("unexpected error generating AuthnRequest: %v", err)
		}
		if req.ID == "" || req.ID[0] != '_' {
			t.Errorf("expected valid SAML request ID starting with underscore, got %s", req.ID)
		}
		if req.Issuer != spEntity {
			t.Errorf("expected issuer %s, got %s", spEntity, req.Issuer)
		}
		if req.Destination != "https://idp.okta.com/saml/sso" {
			t.Errorf("expected destination %s, got %s", cfg.SSOURL, req.Destination)
		}
	})

	baseAssertion := SAMLAssertion{
		ID:             "_assertion_uuid_1001",
		Issuer:         idpEntity,
		Audience:       spEntity,
		SubjectNameID:  "devsecops@enterprise.com",
		Recipient:      acsURL,
		NotBefore:      time.Now().Add(-5 * time.Minute),
		NotOnOrAfter:   time.Now().Add(5 * time.Minute),
		SignatureValid: true,
		SigningCert:    primaryCert,
		Attributes: map[string]string{
			"email":     "devsecops@enterprise.com",
			"firstName": "Dev",
			"lastName":  "Ops",
		},
	}

	t.Run("validate valid SAML assertion successfully", func(t *testing.T) {
		identity, err := service.ValidateAssertion(ctx, orgID, baseAssertion)
		if err != nil {
			t.Fatalf("unexpected error validating assertion: %v", err)
		}
		if identity.Email != "devsecops@enterprise.com" {
			t.Errorf("expected email devsecops@enterprise.com, got %s", identity.Email)
		}
		if identity.FirstName != "Dev" || identity.LastName != "Ops" {
			t.Errorf("expected name Dev Ops, got %s %s", identity.FirstName, identity.LastName)
		}
	})

	t.Run("replay protection: consuming assertion twice is rejected", func(t *testing.T) {
		_, err := service.ValidateAssertion(ctx, orgID, baseAssertion)
		if !errors.Is(err, ErrSAMLAssertionReplayed) {
			t.Fatalf("expected ErrSAMLAssertionReplayed, got %v", err)
		}
	})

	t.Run("reject issuer mismatch", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1002"
		a.Issuer = "https://rogue-idp.attacker.com"

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLIssuerMismatch) {
			t.Fatalf("expected ErrSAMLIssuerMismatch, got %v", err)
		}
	})

	t.Run("reject audience mismatch", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1003"
		a.Audience = "https://other-sp.com"

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLAudienceMismatch) {
			t.Fatalf("expected ErrSAMLAudienceMismatch, got %v", err)
		}
	})

	t.Run("reject recipient ACS URL mismatch", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1004"
		a.Recipient = "https://evil.com/acs"

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLRecipientMismatch) {
			t.Fatalf("expected ErrSAMLRecipientMismatch, got %v", err)
		}
	})

	t.Run("reject expired assertion", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1005"
		a.NotOnOrAfter = time.Now().Add(-10 * time.Minute)

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLAssertionExpired) {
			t.Fatalf("expected ErrSAMLAssertionExpired, got %v", err)
		}
	})

	t.Run("reject premature assertion", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1006"
		a.NotBefore = time.Now().Add(10 * time.Minute)

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLAssertionPremature) {
			t.Fatalf("expected ErrSAMLAssertionPremature, got %v", err)
		}
	})

	t.Run("reject invalid signature flag", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1007"
		a.SignatureValid = false

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLInvalidSignature) {
			t.Fatalf("expected ErrSAMLInvalidSignature, got %v", err)
		}
	})

	t.Run("reject untrusted certificate", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1008"
		a.SigningCert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAUntrustedCert999"

		_, err := service.ValidateAssertion(ctx, orgID, a)
		if !errors.Is(err, ErrSAMLInvalidSignature) {
			t.Fatalf("expected ErrSAMLInvalidSignature for untrusted cert, got %v", err)
		}
	})

	t.Run("secondary certificate succeeds during rollover window", func(t *testing.T) {
		a := baseAssertion
		a.ID = "_assertion_uuid_1009"
		a.SigningCert = secondaryCert

		identity, err := service.ValidateAssertion(ctx, orgID, a)
		if err != nil {
			t.Fatalf("expected secondary cert to succeed during rollover, got: %v", err)
		}
		if identity.Email != "devsecops@enterprise.com" {
			t.Errorf("expected devsecops@enterprise.com, got %s", identity.Email)
		}
	})
}
