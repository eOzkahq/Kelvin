// Package evidence provides retention lifecycle scheduling, archival transitions,
// legal hold enforcement, and secure cryptographically-wiped evidence purges.
//
// See docs/architecture/EVIDENCE_RETENTION_EXPIRY_DELETION_POLICIES.md.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	// ErrLegalHoldEnforced is returned when attempting to delete evidence protected by an active legal hold.
	ErrLegalHoldEnforced = errors.New("retention: cannot purge evidence under active legal hold")

	// ErrEvidenceAlreadyPurged is returned when attempting to re-purge an already wiped evidence item.
	ErrEvidenceAlreadyPurged = errors.New("retention: evidence is already securely purged")
)

// RetentionSweepResult summarizes the outcomes of a retention lifecycle sweep.
type RetentionSweepResult struct {
	Scanned       int       `json:"scanned"`
	Archived      int       `json:"archived"`
	Purged        int       `json:"purged"`
	HeldProtected int       `json:"held_protected"`
	Failed        int       `json:"failed"`
	ExecutedAt    time.Time `json:"executed_at"`
}

// RetentionManager enforces retention policies, archival transitions, and secure purges.
type RetentionManager struct {
	repo    Repository
	storage StorageService
	policy  RetentionPolicy
	logger  *slog.Logger
}

// NewRetentionManager constructs a new RetentionManager.
func NewRetentionManager(
	repo Repository,
	storage StorageService,
	policy RetentionPolicy,
	logger *slog.Logger,
) *RetentionManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetentionManager{
		repo:    repo,
		storage: storage,
		policy:  policy,
		logger:  logger,
	}
}

// SetLegalHold applies or removes a legal hold on an evidence item.
func (m *RetentionManager) SetLegalHold(
	ctx context.Context,
	tenantID, evidenceID string,
	hold bool,
	reason string,
) error {
	item, err := m.repo.GetEvidenceByID(ctx, tenantID, evidenceID)
	if err != nil {
		return fmt.Errorf("fetch evidence for legal hold: %w", err)
	}

	item.IsLegalHold = hold
	item.LegalHoldReason = reason
	item.UpdatedAt = time.Now().UTC()

	if err := m.repo.UpdateEvidence(ctx, item); err != nil {
		return fmt.Errorf("update evidence legal hold: %w", err)
	}

	m.logger.InfoContext(ctx, "EVIDENCE_LEGAL_HOLD_UPDATED",
		"tenant_id", tenantID,
		"evidence_id", evidenceID,
		"is_legal_hold", hold,
		"reason", reason,
	)

	return nil
}

// EnforceRetentionSweep executes a full retention sweep across all tenants:
// 1. Archives active items whose active retention period has expired.
// 2. Securely purges archived items whose archive period has expired (unless under legal hold).
func (m *RetentionManager) EnforceRetentionSweep(ctx context.Context, now time.Time) (*RetentionSweepResult, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	res := &RetentionSweepResult{
		ExecutedAt: now,
	}

	// Fetch items whose expires_at is before now
	expiredItems, err := m.repo.ListExpiredEvidence(ctx, now)
	if err != nil {
		return res, fmt.Errorf("list expired evidence: %w", err)
	}

	res.Scanned = len(expiredItems)

	for _, item := range expiredItems {
		// Idempotency: skip if already purged
		if item.Status == StatusPurged {
			continue
		}

		// Check legal hold
		if item.IsLegalHold {
			res.HeldProtected++
			m.logger.InfoContext(ctx, "EVIDENCE_PURGE_SKIPPED_LEGAL_HOLD",
				"tenant_id", item.TenantID,
				"evidence_id", item.ID,
				"legal_hold_reason", item.LegalHoldReason,
			)
			continue
		}

		activeCutoff := item.CreatedAt.AddDate(0, 0, m.policy.ActiveDays)
		purgeCutoff := item.CreatedAt.AddDate(0, 0, m.policy.ActiveDays+m.policy.ArchivedDays)

		// 1. Transition Active -> Archived
		if item.Status == StatusActive && (now.After(activeCutoff) || now.Equal(activeCutoff)) && now.Before(purgeCutoff) {
			item.Status = StatusArchived
			item.UpdatedAt = now
			if err := m.repo.UpdateEvidence(ctx, item); err != nil {
				res.Failed++
				m.logger.ErrorContext(ctx, "failed to archive expired evidence", "evidence_id", item.ID, "err", err)
				continue
			}
			res.Archived++
			continue
		}

		// 2. Transition Archived -> Purged (Wipe Content & Overwrite Physical Storage)
		if now.After(purgeCutoff) || now.Equal(purgeCutoff) || item.Status == StatusArchived {
			if err := m.purgeItem(ctx, item, now); err != nil {
				res.Failed++
				m.logger.ErrorContext(ctx, "failed to securely purge evidence", "evidence_id", item.ID, "err", err)
				continue
			}
			res.Purged++
		}
	}

	return res, nil
}

// PurgeEvidenceItem manually triggers secure erasure of an evidence item.
func (m *RetentionManager) PurgeEvidenceItem(
	ctx context.Context,
	tenantID, evidenceID string,
	force bool,
) error {
	item, err := m.repo.GetEvidenceByID(ctx, tenantID, evidenceID)
	if err != nil {
		return fmt.Errorf("fetch evidence for purge: %w", err)
	}

	if item.IsLegalHold && !force {
		return ErrLegalHoldEnforced
	}

	if item.Status == StatusPurged {
		return ErrEvidenceAlreadyPurged
	}

	now := time.Now().UTC()
	return m.purgeItem(ctx, item, now)
}

func (m *RetentionManager) purgeItem(ctx context.Context, item *EvidenceItem, now time.Time) error {
	item.Status = StatusPurging
	_ = m.repo.UpdateEvidence(ctx, item)

	// Securely overwrite and delete storage object if exists
	if item.StorageRef != "" && m.storage != nil {
		if err := m.storage.SecurePurge(ctx, item.TenantID, item.ID); err != nil {
			item.Status = StatusPurgeFailed
			item.PurgeRetryCount++
			item.UpdatedAt = now
			_ = m.repo.UpdateEvidence(ctx, item)
			return fmt.Errorf("storage secure purge failed: %w", err)
		}
	}

	// Wipe inline database content
	item.InlineContent = ""
	item.StorageRef = ""
	item.WipedAt = &now
	item.Status = StatusPurged
	item.UpdatedAt = now

	if err := m.repo.UpdateEvidence(ctx, item); err != nil {
		return fmt.Errorf("update purged evidence record: %w", err)
	}

	m.logger.InfoContext(ctx, "EVIDENCE_SECURELY_PURGED",
		"tenant_id", item.TenantID,
		"evidence_id", item.ID,
		"finding_id", item.FindingID,
		"wiped_at", now,
	)

	return nil
}
