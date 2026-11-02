package hierarchy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOrganizationSettingsValidation(t *testing.T) {
	// 1. Session duration exceeding platform max
	badSession := DefaultOrganizationSettings()
	badSession.Security.SessionMaxDurationSeconds = 100000 // > 86400
	if err := ValidateOrgSettings(badSession, &DefaultPlatformLimits); err == nil {
		t.Errorf("expected error for session duration exceeding 86400, got nil")
	}

	// 2. Evidence retention exceeding platform max
	badRetention := DefaultOrganizationSettings()
	badRetention.Retention.EvidenceRetentionDays = 500 // > 365
	if err := ValidateOrgSettings(badRetention, &DefaultPlatformLimits); err == nil {
		t.Errorf("expected error for evidence retention exceeding 365, got nil")
	}

	// 3. Audit retention below mandatory minimum
	badAudit := DefaultOrganizationSettings()
	badAudit.Retention.AuditLogRetentionDays = 30 // < 90
	if err := ValidateOrgSettings(badAudit, &DefaultPlatformLimits); err == nil {
		t.Errorf("expected error for audit retention below 90 days, got nil")
	}

	// 4. Unsupported scanner
	badScanner := DefaultOrganizationSettings()
	badScanner.Security.AllowedScanners = []string{"nuclei", "unsupported_hack_tool"}
	if err := ValidateOrgSettings(badScanner, &DefaultPlatformLimits); err == nil {
		t.Errorf("expected error for unsupported scanner, got nil")
	}
}

func TestConfigurationPrecedenceResolution(t *testing.T) {
	// Base org settings: allows [nuclei, zap, tls], session = 28800
	orgSettings := DefaultOrganizationSettings()
	orgSettings.Security.AllowedScanners = []string{"nuclei", "zap", "tls"}
	orgSettings.Security.SessionMaxDurationSeconds = 28800

	// Workspace overrides: session = 7200 (stricter), allowed scanners = [nuclei, rogue_scanner]
	wsSession := 7200
	wsScanProfile := "custom-ws-profile"
	wsSettings := &WorkspaceSettings{
		SessionMaxDurationSeconds: &wsSession,
		AllowedScanners:           []string{"nuclei", "rogue_scanner"}, // rogue_scanner should be filtered out
		DefaultScanProfileID:      &wsScanProfile,
	}

	effective, err := ComputeEffectiveConfig(orgSettings, wsSettings)
	if err != nil {
		t.Fatalf("failed to compute effective config: %v", err)
	}

	// Session duration overridden
	if effective.Security.SessionMaxDurationSeconds != 7200 {
		t.Errorf("expected session duration 7200, got %d", effective.Security.SessionMaxDurationSeconds)
	}

	// Allowed scanners filtered to only those permitted by org
	if len(effective.Security.AllowedScanners) != 1 || effective.Security.AllowedScanners[0] != "nuclei" {
		t.Errorf("expected allowed scanners to be filtered to [nuclei], got %v", effective.Security.AllowedScanners)
	}

	// Default scan profile overridden
	if effective.Workflow.DefaultScanProfileID != "custom-ws-profile" {
		t.Errorf("expected default scan profile 'custom-ws-profile', got %s", effective.Workflow.DefaultScanProfileID)
	}
}

func TestSettingsServiceVersioningAndAudit(t *testing.T) {
	settingsRepo := NewMemorySettingsRepository()
	hierarchyRepo := NewMemoryHierarchyRepository()
	auditMem := NewMemoryAuditRecorder()
	auditRecorder := NewHierarchyAuditRecorder(auditMem)
	hierarchySvc := NewHierarchyService(hierarchyRepo)
	settingsSvc := NewSettingsService(settingsRepo, hierarchyRepo, auditRecorder)
	ctx := context.Background()

	// 1. Setup Org with Owner and Member
	org, _ := hierarchySvc.CreateOrganization(ctx, "Oscorp", "oscorp", "user-norman")
	userHarry := "user-harry"
	_ = hierarchyRepo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         userHarry,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// 2. Member cannot update settings
	newSettings := DefaultOrganizationSettings()
	newSettings.Security.RequireMFA = true
	err := settingsSvc.UpdateSettings(ctx, org.ID, userHarry, newSettings)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized when member updates settings, got %v", err)
	}

	// 3. Owner updates settings
	err = settingsSvc.UpdateSettings(ctx, org.ID, "user-norman", newSettings)
	if err != nil {
		t.Fatalf("failed to update settings: %v", err)
	}

	latest, _ := settingsRepo.GetLatestSettings(ctx, org.ID)
	if latest.Version != 2 {
		t.Errorf("expected settings version 2, got %d", latest.Version)
	}
	if !latest.Security.RequireMFA {
		t.Errorf("expected RequireMFA to be true")
	}

	// 4. Update again to test version 3 and history
	newSettings2 := DefaultOrganizationSettings()
	newSettings2.Security.RequireMFA = true
	newSettings2.Retention.EvidenceRetentionDays = 120
	err = settingsSvc.UpdateSettings(ctx, org.ID, "user-norman", newSettings2)
	if err != nil {
		t.Fatalf("failed to update settings v3: %v", err)
	}

	history, _ := settingsRepo.GetSettingsHistory(ctx, org.ID)
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}
	if history[1].Version != 3 {
		t.Errorf("expected latest history entry version 3, got %d", history[1].Version)
	}

	// 5. Verify audit events recorded
	foundAuditEvent := false
	for _, e := range auditMem.Events {
		if e.Action == ActionOrgSettingsUpdated {
			foundAuditEvent = true
			break
		}
	}
	if !foundAuditEvent {
		t.Errorf("expected ActionOrgSettingsUpdated audit event")
	}
}
