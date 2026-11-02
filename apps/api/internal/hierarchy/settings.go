package hierarchy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidSettings       = errors.New("organization settings validation failed")
	ErrPlatformLimitExceeded = errors.New("organization setting violates platform immutable limit")
	ErrUnsupportedScanner    = errors.New("specified scanner is not supported by platform")
)

type SecuritySettings struct {
	RequireMFA                bool     `json:"require_mfa"`
	SessionMaxDurationSeconds int      `json:"session_max_duration_seconds"`
	AllowedScanners           []string `json:"allowed_scanners"`
	IPAllowlist               []string `json:"ip_allowlist"`
}

type RetentionSettings struct {
	EvidenceRetentionDays int `json:"evidence_retention_days"`
	ReportRetentionDays   int `json:"report_retention_days"`
	AuditLogRetentionDays int `json:"audit_log_retention_days"`
}

type WorkflowSettings struct {
	DefaultScanProfileID string `json:"default_scan_profile_id"`
	AutoApproveTriage    bool   `json:"auto_approve_triage"`
	NotificationEmail    string `json:"notification_email"`
}

type OrganizationSettings struct {
	Version   int               `json:"version"`
	Security  SecuritySettings  `json:"security"`
	Retention RetentionSettings `json:"retention"`
	Workflow  WorkflowSettings  `json:"workflow"`
}

type WorkspaceSettings struct {
	SessionMaxDurationSeconds *int     `json:"session_max_duration_seconds,omitempty"`
	AllowedScanners           []string `json:"allowed_scanners,omitempty"`
	DefaultScanProfileID      *string  `json:"default_scan_profile_id,omitempty"`
}

type EffectiveConfiguration struct {
	Security  SecuritySettings  `json:"security"`
	Retention RetentionSettings `json:"retention"`
	Workflow  WorkflowSettings  `json:"workflow"`
}

type PlatformLimits struct {
	MaxSessionDurationSeconds int
	MinSessionDurationSeconds int
	MaxEvidenceRetentionDays  int
	MaxReportRetentionDays    int
	MinAuditRetentionDays     int
	SupportedScanners         map[string]bool
}

var DefaultPlatformLimits = PlatformLimits{
	MaxSessionDurationSeconds: 86400, // 24 hours
	MinSessionDurationSeconds: 300,   // 5 minutes
	MaxEvidenceRetentionDays:  365,   // 1 year
	MaxReportRetentionDays:    730,   // 2 years
	MinAuditRetentionDays:     90,    // 90 days minimum
	SupportedScanners: map[string]bool{
		"nuclei": true,
		"zap":    true,
		"tls":    true,
	},
}

// DefaultOrganizationSettings returns standard defaults.
func DefaultOrganizationSettings() *OrganizationSettings {
	return &OrganizationSettings{
		Version: 1,
		Security: SecuritySettings{
			RequireMFA:                false,
			SessionMaxDurationSeconds: 28800, // 8 hours
			AllowedScanners:           []string{"nuclei", "zap", "tls"},
			IPAllowlist:               []string{},
		},
		Retention: RetentionSettings{
			EvidenceRetentionDays: 90,
			ReportRetentionDays:   365,
			AuditLogRetentionDays: 365,
		},
		Workflow: WorkflowSettings{
			DefaultScanProfileID: "standard-full",
			AutoApproveTriage:    false,
			NotificationEmail:    "",
		},
	}
}

// ValidateOrgSettings validates settings against platform hard limits.
func ValidateOrgSettings(settings *OrganizationSettings, limits *PlatformLimits) error {
	if limits == nil {
		limits = &DefaultPlatformLimits
	}

	// Session duration checks
	if settings.Security.SessionMaxDurationSeconds > limits.MaxSessionDurationSeconds {
		return fmt.Errorf("%w: session max duration %d exceeds platform limit %d",
			ErrPlatformLimitExceeded, settings.Security.SessionMaxDurationSeconds, limits.MaxSessionDurationSeconds)
	}
	if settings.Security.SessionMaxDurationSeconds < limits.MinSessionDurationSeconds {
		return fmt.Errorf("%w: session duration %d below platform minimum %d",
			ErrPlatformLimitExceeded, settings.Security.SessionMaxDurationSeconds, limits.MinSessionDurationSeconds)
	}

	// Retention ceiling checks
	if settings.Retention.EvidenceRetentionDays > limits.MaxEvidenceRetentionDays {
		return fmt.Errorf("%w: evidence retention %d days exceeds platform maximum %d",
			ErrPlatformLimitExceeded, settings.Retention.EvidenceRetentionDays, limits.MaxEvidenceRetentionDays)
	}
	if settings.Retention.ReportRetentionDays > limits.MaxReportRetentionDays {
		return fmt.Errorf("%w: report retention %d days exceeds platform maximum %d",
			ErrPlatformLimitExceeded, settings.Retention.ReportRetentionDays, limits.MaxReportRetentionDays)
	}
	if settings.Retention.AuditLogRetentionDays < limits.MinAuditRetentionDays {
		return fmt.Errorf("%w: audit log retention %d days is below platform mandatory minimum %d",
			ErrPlatformLimitExceeded, settings.Retention.AuditLogRetentionDays, limits.MinAuditRetentionDays)
	}

	// Scanner support validation
	if len(settings.Security.AllowedScanners) == 0 {
		return fmt.Errorf("%w: at least one scanner must be allowed", ErrInvalidSettings)
	}
	for _, scanner := range settings.Security.AllowedScanners {
		if !limits.SupportedScanners[scanner] {
			return fmt.Errorf("%w: scanner %q is unsupported", ErrUnsupportedScanner, scanner)
		}
	}

	return nil
}

// ComputeEffectiveConfig computes runtime configuration applying precedence:
// Platform Defaults -> Organization Settings -> Workspace Overrides.
func ComputeEffectiveConfig(
	orgSettings *OrganizationSettings,
	wsSettings *WorkspaceSettings,
) (*EffectiveConfiguration, error) {
	if orgSettings == nil {
		orgSettings = DefaultOrganizationSettings()
	}

	effective := &EffectiveConfiguration{
		Security: SecuritySettings{
			RequireMFA:                orgSettings.Security.RequireMFA,
			SessionMaxDurationSeconds: orgSettings.Security.SessionMaxDurationSeconds,
			AllowedScanners:           append([]string{}, orgSettings.Security.AllowedScanners...),
			IPAllowlist:               append([]string{}, orgSettings.Security.IPAllowlist...),
		},
		Retention: orgSettings.Retention,
		Workflow:  orgSettings.Workflow,
	}

	// Apply Workspace overrides if within org limits
	if wsSettings != nil {
		// Session duration override (can be stricter, not looser)
		if wsSettings.SessionMaxDurationSeconds != nil {
			val := *wsSettings.SessionMaxDurationSeconds
			if val <= orgSettings.Security.SessionMaxDurationSeconds && val >= DefaultPlatformLimits.MinSessionDurationSeconds {
				effective.Security.SessionMaxDurationSeconds = val
			}
		}

		// Allowed scanners override (must be a subset of org allowed scanners)
		if len(wsSettings.AllowedScanners) > 0 {
			orgAllowed := make(map[string]bool)
			for _, s := range orgSettings.Security.AllowedScanners {
				orgAllowed[s] = true
			}
			var filtered []string
			for _, s := range wsSettings.AllowedScanners {
				if orgAllowed[s] {
					filtered = append(filtered, s)
				}
			}
			if len(filtered) > 0 {
				effective.Security.AllowedScanners = filtered
			}
		}

		// Default scan profile override
		if wsSettings.DefaultScanProfileID != nil && *wsSettings.DefaultScanProfileID != "" {
			effective.Workflow.DefaultScanProfileID = *wsSettings.DefaultScanProfileID
		}
	}

	return effective, nil
}

// SettingsHistoryEntry records versioned organization configuration snapshots.
type SettingsHistoryEntry struct {
	ID              uuid.UUID             `json:"id"`
	OrganizationID  uuid.UUID             `json:"organization_id"`
	Version         int                   `json:"version"`
	Settings        *OrganizationSettings `json:"settings"`
	ChangedByUserID string                `json:"changed_by_user_id"`
	CreatedAt       time.Time             `json:"created_at"`
}

// SettingsRepository defines storage for versioned organization settings.
type SettingsRepository interface {
	SaveSettings(ctx context.Context, orgID uuid.UUID, settings *OrganizationSettings, actorUserID string) error
	GetLatestSettings(ctx context.Context, orgID uuid.UUID) (*OrganizationSettings, error)
	GetSettingsHistory(ctx context.Context, orgID uuid.UUID) ([]*SettingsHistoryEntry, error)
}

// MemorySettingsRepository provides a thread-safe in-memory store for settings history.
type MemorySettingsRepository struct {
	mu      sync.RWMutex
	latest  map[uuid.UUID]*OrganizationSettings
	history map[uuid.UUID][]*SettingsHistoryEntry
}

func NewMemorySettingsRepository() *MemorySettingsRepository {
	return &MemorySettingsRepository{
		latest:  make(map[uuid.UUID]*OrganizationSettings),
		history: make(map[uuid.UUID][]*SettingsHistoryEntry),
	}
}

func (m *MemorySettingsRepository) SaveSettings(ctx context.Context, orgID uuid.UUID, settings *OrganizationSettings, actorUserID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := &SettingsHistoryEntry{
		ID:              uuid.New(),
		OrganizationID:  orgID,
		Version:         settings.Version,
		Settings:        settings,
		ChangedByUserID: actorUserID,
		CreatedAt:       time.Now().UTC(),
	}

	m.latest[orgID] = settings
	m.history[orgID] = append(m.history[orgID], entry)
	return nil
}

func (m *MemorySettingsRepository) GetLatestSettings(ctx context.Context, orgID uuid.UUID) (*OrganizationSettings, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.latest[orgID]
	if !ok {
		return DefaultOrganizationSettings(), nil
	}
	return s, nil
}

func (m *MemorySettingsRepository) GetSettingsHistory(ctx context.Context, orgID uuid.UUID) ([]*SettingsHistoryEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.history[orgID], nil
}

// SettingsService coordinates organization settings updates, validation, and precedence resolution.
type SettingsService struct {
	settingsRepo   SettingsRepository
	hierarchyRepo  HierarchyRepository
	platformLimits *PlatformLimits
	audit          *HierarchyAuditRecorder
}

func NewSettingsService(
	settingsRepo SettingsRepository,
	hierarchyRepo HierarchyRepository,
	audit *HierarchyAuditRecorder,
) *SettingsService {
	return &SettingsService{
		settingsRepo:   settingsRepo,
		hierarchyRepo:  hierarchyRepo,
		platformLimits: &DefaultPlatformLimits,
		audit:          audit,
	}
}

// UpdateSettings validates and applies a new version of organization settings.
func (s *SettingsService) UpdateSettings(
	ctx context.Context,
	orgID uuid.UUID,
	actorUserID string,
	newSettings *OrganizationSettings,
) error {
	// Authorization: caller must be Org Owner or Admin
	mem, err := s.hierarchyRepo.GetOrgMembership(ctx, orgID, actorUserID)
	if err != nil {
		return err
	}
	if mem.Role != OrgRoleOwner && mem.Role != OrgRoleAdmin {
		return ErrUnauthorized
	}

	// Validate against platform limits
	if err := ValidateOrgSettings(newSettings, s.platformLimits); err != nil {
		return err
	}

	current, err := s.settingsRepo.GetLatestSettings(ctx, orgID)
	if err != nil {
		current = DefaultOrganizationSettings()
	}

	newSettings.Version = current.Version + 1

	if err := s.settingsRepo.SaveSettings(ctx, orgID, newSettings, actorUserID); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.RecordOrgLifecycleEvent(ctx, ActionOrgSettingsUpdated, &Organization{
			ID:     orgID,
			Status: OrgStateActive,
		}, actorUserID, map[string]interface{}{
			"version": newSettings.Version,
		})
	}

	return nil
}

// GetEffectiveConfig resolves runtime configuration considering platform defaults, org settings, and workspace overrides.
func (s *SettingsService) GetEffectiveConfig(
	ctx context.Context,
	orgID uuid.UUID,
	wsSettings *WorkspaceSettings,
) (*EffectiveConfiguration, error) {
	orgSettings, err := s.settingsRepo.GetLatestSettings(ctx, orgID)
	if err != nil {
		orgSettings = DefaultOrganizationSettings()
	}
	return ComputeEffectiveConfig(orgSettings, wsSettings)
}
